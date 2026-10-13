use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use chrono::{DateTime, Local, SecondsFormat, Timelike, Utc};
use codex_zectrix_dashboard::{
    DashboardConfig, ObservedDashboardState, ObservedQuota, ObservedQuotaWindow, PublishAttempt,
    PublishCoordinator, PublisherState, QuotaCache, RadarCache, RadarClient, RadarDisplayState,
    RadarFetch, RadarSemanticState, ZectrixPublisher,
};
use reqwest::blocking::{Client, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const QUOTA_CACHE_MAGIC: &[u8; 4] = b"ZXQ1";
const AUTH_CACHE_MAGIC: &[u8; 4] = b"ZXA1";
const AUTH_FILE_MAGIC: &[u8; 4] = b"ZXF1";
const RADAR_CACHE_MAGIC: &[u8; 4] = b"ZXR1";
const PUBLISHER_CACHE_MAGIC: &[u8; 4] = b"ZXP1";
const NONCE_LENGTH: usize = 12;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 1024 * 1024;
const USAGE_URL: &str = "https://chatgpt.com/backend-api/wham/usage";
const OAUTH_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const SIWC_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
const OAUTH_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const SIWC_RESOURCE: &str = "https://api.openai.com/v1";
const SIWC_DIRECT_SCOPE: &str = "chatgpt.tokens.use.direct";

#[derive(Clone, Deserialize, Serialize)]
struct CodexCredential {
    #[serde(default, rename = "type")]
    credential_type: String,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    id_token: String,
    #[serde(default)]
    account_id: String,
    #[serde(default)]
    expired: String,
    #[serde(default)]
    last_refresh: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    plan_type: String,
    #[serde(default)]
    use_siwc: bool,
    siwc: Option<SiwcCredential>,
}

#[derive(Clone, Deserialize, Serialize)]
struct SiwcCredential {
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    id_token: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    expired: String,
    #[serde(default)]
    last_refresh: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    scopes: Vec<String>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    id_token: String,
    #[serde(default)]
    scope: String,
    expires_in: i64,
}

#[derive(Deserialize, Serialize)]
struct CachedCredential {
    source_sha256: String,
    credential: CodexCredential,
}

struct LoadedCredential {
    credential: CodexCredential,
    source_sha256: String,
    source_json: Zeroizing<Vec<u8>>,
    stored_source: Zeroizing<Vec<u8>>,
    source_encrypted: bool,
}

struct CodexClient {
    http: Client,
    auth_path: PathBuf,
    auth_cache_path: PathBuf,
    cache_cipher: CacheCipher,
}

struct CacheCipher {
    key: Zeroizing<[u8; 32]>,
}

#[derive(Clone, Copy)]
struct QuotaPauseWindow {
    start_minute: u16,
    end_minute: u16,
}

struct QuotaPauseSchedule {
    windows: Vec<QuotaPauseWindow>,
}

impl QuotaPauseSchedule {
    fn parse(value: &str) -> Result<Self, String> {
        let mut windows = Vec::new();
        for entry in value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            let (start, end) = entry
                .split_once('-')
                .ok_or("QUOTA_PAUSE_WINDOWS 格式应为 HH:MM-HH:MM")?;
            let start_minute =
                parse_clock_minute(start).ok_or("QUOTA_PAUSE_WINDOWS 中的开始时间无效")?;
            let end_minute =
                parse_clock_minute(end).ok_or("QUOTA_PAUSE_WINDOWS 中的结束时间无效")?;
            if start_minute == end_minute {
                return Err("QUOTA_PAUSE_WINDOWS 不接受起止时间相同的时段".into());
            }
            windows.push(QuotaPauseWindow {
                start_minute,
                end_minute,
            });
        }
        Ok(Self { windows })
    }

    fn seconds_until_resume(&self) -> Option<u64> {
        if self.windows.is_empty() {
            return None;
        }
        let now = Local::now().time();
        let current_minute = (now.hour() * 60 + now.minute()) as u16;
        let current_second =
            u64::from(now.hour()) * 3_600 + u64::from(now.minute()) * 60 + u64::from(now.second());
        self.seconds_until_resume_at(current_minute, current_second)
    }

    fn seconds_until_resume_at(&self, current_minute: u16, current_second: u64) -> Option<u64> {
        self.windows
            .iter()
            .filter(|window| window.contains(current_minute))
            .map(|window| {
                let end_second = u64::from(window.end_minute) * 60;
                (end_second + 86_400 - current_second) % 86_400
            })
            .max()
            .map(|seconds| seconds.max(1))
    }
}

impl QuotaPauseWindow {
    fn contains(self, minute: u16) -> bool {
        if self.start_minute < self.end_minute {
            (self.start_minute..self.end_minute).contains(&minute)
        } else {
            minute >= self.start_minute || minute < self.end_minute
        }
    }
}

fn parse_clock_minute(value: &str) -> Option<u16> {
    let bytes = value.as_bytes();
    if bytes.len() != 5
        || bytes[2] != b':'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 2 || byte.is_ascii_digit())
    {
        return None;
    }
    let hour = value[..2].parse::<u16>().ok()?;
    let minute = value[3..].parse::<u16>().ok()?;
    if hour > 23 || minute > 59 {
        return None;
    }
    Some(hour * 60 + minute)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Codex 额度看板已停止：{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let data_dir = PathBuf::from(env_value("CODEX_ZECTRIX_DATA_DIR", "/data"));
    fs::create_dir_all(&data_dir)?;

    let cache_cipher = CacheCipher::from_environment()?;
    let auth_path = resolve_auth_path(&env_value("CODEX_AUTH_PATH", "/run/codex-auth"))?;
    let codex = CodexClient::new(auth_path, data_dir.join("codex-auth.cache"), cache_cipher)?;
    let zectrix_key = read_secret("ZECTRIX_API_KEY_FILE")?;
    let device_id = required_env("ZECTRIX_DEVICE_ID")?;
    let page_id = env_value("ZECTRIX_PAGE_ID", "1").parse::<u8>()?;
    if !(1..=5).contains(&page_id) {
        return Err("ZECTRIX_PAGE_ID 必须为 1 到 5".into());
    }
    let poll_seconds = env_value("QUOTA_POLL_SECONDS", "600").parse::<u64>()?;
    if poll_seconds < 60 {
        return Err("QUOTA_POLL_SECONDS 不能小于 60 秒".into());
    }
    let radar_poll_seconds = env_value("RADAR_POLL_SECONDS", "3600").parse::<u64>()?;
    if radar_poll_seconds < 60 {
        return Err("RADAR_POLL_SECONDS 不能小于 60 秒".into());
    }
    let base_url = env_value("ZECTRIX_API_BASE", "https://cloud.zectrix.com");
    let pause_schedule = QuotaPauseSchedule::parse(&env_value("QUOTA_PAUSE_WINDOWS", ""))?;
    let timezone = env_value("TZ", "Asia/Shanghai");
    let quota_cache_path = data_dir.join("quota.cache");
    let last_known_quota =
        load_encrypted::<ObservedQuota>(&quota_cache_path, &codex.cache_cipher, QUOTA_CACHE_MAGIC)
            .unwrap_or_else(|_| {
                eprintln!("额度缓存=不可用");
                None
            });
    let mut quota_cache = QuotaCache::new(last_known_quota.clone());
    let mut current_quota = last_known_quota.map(|mut quota| {
        quota.stale = true;
        quota
    });

    let radar_cache_path = data_dir.join("radar.cache");
    let last_known_radar = load_encrypted::<RadarSemanticState>(
        &radar_cache_path,
        &codex.cache_cipher,
        RADAR_CACHE_MAGIC,
    )
    .unwrap_or_else(|_| {
        eprintln!("重置雷达缓存=不可用");
        None
    })
    .unwrap_or_default();
    let mut radar_cache = RadarCache::new(last_known_radar);
    let mut radar_client = RadarClient::new("https://codex-resets.com/api/v1/status")?;

    let publisher_state_path = data_dir.join("publisher.cache");
    let publisher_state = load_encrypted::<PublisherState>(
        &publisher_state_path,
        &codex.cache_cipher,
        PUBLISHER_CACHE_MAGIC,
    )
    .unwrap_or_else(|_| {
        eprintln!("发布缓存=不可用");
        None
    })
    .unwrap_or_default();
    let mut coordinator = PublishCoordinator::new(
        DashboardConfig {
            previous_frame_hash: None,
        },
        publisher_state,
    );
    let mut publisher = ZectrixPublisher::new(&zectrix_key, base_url, device_id, page_id)?;

    let mut quota_deadline = Instant::now();
    let mut radar_deadline = quota_deadline;
    let mut quota_pause_active = false;
    loop {
        let now = unix_time_seconds()?;
        if Instant::now() >= quota_deadline {
            if let Some(until_resume) = pause_schedule.seconds_until_resume() {
                if !quota_pause_active {
                    eprintln!("额度轮询=暂停 TZ={timezone}");
                    quota_pause_active = true;
                }
                quota_deadline = Instant::now() + Duration::from_secs(until_resume.min(60));
            } else {
                if quota_pause_active {
                    eprintln!("额度轮询=恢复 TZ={timezone}");
                    quota_pause_active = false;
                }
                let result = codex.read_quota();
                let read_succeeded = result.is_ok();
                match quota_cache.update(result) {
                    Ok(quota) => {
                        if !quota.stale
                            && write_encrypted(
                                &quota_cache_path,
                                &quota,
                                &codex.cache_cipher,
                                QUOTA_CACHE_MAGIC,
                            )
                            .is_err()
                        {
                            eprintln!("额度缓存=写入失败");
                        }
                        current_quota = Some(quota);
                    }
                    Err(_) => {
                        current_quota = None;
                        eprintln!("额度轮询=失败 且无可用缓存");
                    }
                }
                quota_deadline = Instant::now()
                    + Duration::from_secs(if read_succeeded { poll_seconds } else { 60 });
            }
        }

        if Instant::now() >= radar_deadline {
            let mut next_interval = Duration::from_secs(radar_poll_seconds);
            match radar_client.fetch() {
                RadarFetch::Modified(parsed) => {
                    radar_cache.accept(parsed, now);
                    if write_encrypted(
                        &radar_cache_path,
                        radar_cache.semantic(),
                        &codex.cache_cipher,
                        RADAR_CACHE_MAGIC,
                    )
                    .is_err()
                    {
                        radar_cache.mark_failed();
                        eprintln!("重置雷达缓存=写入失败");
                    } else {
                        eprintln!("重置雷达=已更新");
                    }
                }
                RadarFetch::NotModified => radar_cache.confirm_unchanged(now),
                RadarFetch::Failed {
                    retry_after_seconds,
                    ..
                } => {
                    radar_cache.mark_failed();
                    next_interval = Duration::from_secs(retry_after_seconds.unwrap_or(60).max(60));
                    eprintln!("重置雷达=暂不可用");
                }
            }
            radar_deadline = Instant::now() + next_interval;
        }

        if let Some(quota) = current_quota.clone() {
            let radar = radar_cache.display(now);
            coordinator.observe(
                ObservedDashboardState {
                    quota: quota.clone(),
                    radar: radar.clone(),
                },
                now,
            );
            let attempt = coordinator.try_publish(now, &mut publisher)?;
            let poll_status = if quota.stale {
                "使用上次额度"
            } else {
                "可用"
            };
            eprintln!(
                "额度={poll_status} 重置雷达={} 发布={}",
                radar_display_label(radar),
                publish_result_label(attempt)
            );
            if write_encrypted(
                &publisher_state_path,
                coordinator.state(),
                &codex.cache_cipher,
                PUBLISHER_CACHE_MAGIC,
            )
            .is_err()
            {
                eprintln!("发布状态缓存=写入失败");
            }
        }

        let wait = quota_deadline
            .saturating_duration_since(Instant::now())
            .min(radar_deadline.saturating_duration_since(Instant::now()));
        thread::sleep(wait);
    }
}

impl CodexClient {
    fn new(
        auth_path: PathBuf,
        auth_cache_path: PathBuf,
        cache_cipher: CacheCipher,
    ) -> Result<Self, Box<dyn Error>> {
        let http = Client::builder().timeout(Duration::from_secs(70)).build()?;
        Ok(Self {
            http,
            auth_path,
            auth_cache_path,
            cache_cipher,
        })
    }

    fn read_quota(&self) -> Result<ObservedQuota, String> {
        let LoadedCredential {
            mut credential,
            source_sha256,
            source_json,
            stored_source,
            source_encrypted,
        } = self.load_credential()?;
        let source_credential: CodexCredential =
            serde_json::from_slice(&source_json).map_err(|_| "Codex 登录 JSON 格式无效")?;
        if credential.should_refresh(unix_time_seconds().map_err(|_| "系统时间不可用")?) {
            self.refresh_credential(&mut credential)?;
            self.save_credential(&credential, &source_sha256)?;
        }
        let mut response = self.request_usage(&credential)?;
        if response.0 == 401 {
            self.refresh_credential(&mut credential)?;
            self.save_credential(&credential, &source_sha256)?;
            response = self.request_usage(&credential)?;
        }
        if !(200..300).contains(&response.0) {
            return Err("Codex 用量接口返回错误状态".into());
        }
        let quota = parse_usage_response(
            &response.1,
            unix_time_seconds().map_err(|_| "系统时间不可用")?,
        )?;
        if !source_encrypted || !same_auth_state(&source_credential, &credential) {
            match encrypt_source_file(
                &self.auth_path,
                &stored_source,
                &source_json,
                &credential,
                &self.cache_cipher,
            ) {
                Ok(encrypted_source_sha256) => {
                    if self
                        .save_credential(&credential, &encrypted_source_sha256)
                        .is_err()
                    {
                        eprintln!("登录凭证文件已加密；认证缓存写入失败");
                    } else {
                        eprintln!("额度查询成功；本机加密登录凭证已同步");
                    }
                }
                Err(_) if source_encrypted => {
                    eprintln!("额度查询成功；本机加密凭证文件同步失败，令牌仍保存在加密缓存")
                }
                Err(_) => eprintln!("额度查询成功；登录 JSON 加密失败，明文文件保留"),
            }
        }
        Ok(quota)
    }

    fn load_credential(&self) -> Result<LoadedCredential, String> {
        let stored_source =
            Zeroizing::new(fs::read(&self.auth_path).map_err(|_| "无法读取 Codex 登录 JSON")?);
        let source_encrypted = stored_source.starts_with(AUTH_FILE_MAGIC);
        let source = if source_encrypted {
            self.cache_cipher.decrypt(&stored_source, AUTH_FILE_MAGIC)?
        } else {
            Zeroizing::new(stored_source.to_vec())
        };
        if source.len() > MAX_CREDENTIAL_BYTES {
            return Err("Codex 登录 JSON 超过大小限制".into());
        }
        let source_sha256 = format!("{:x}", Sha256::digest(source.as_slice()));
        if let Ok(Some(cached)) = load_encrypted::<CachedCredential>(
            &self.auth_cache_path,
            &self.cache_cipher,
            AUTH_CACHE_MAGIC,
        ) && cached.source_sha256 == source_sha256
        {
            cached.credential.validate()?;
            return Ok(LoadedCredential {
                credential: cached.credential,
                source_sha256,
                source_json: source,
                stored_source,
                source_encrypted,
            });
        }
        let credential: CodexCredential =
            serde_json::from_slice(&source).map_err(|_| "Codex 登录 JSON 格式无效")?;
        credential.validate()?;
        Ok(LoadedCredential {
            credential,
            source_sha256,
            source_json: source,
            stored_source,
            source_encrypted,
        })
    }

    fn save_credential(
        &self,
        credential: &CodexCredential,
        source_sha256: &str,
    ) -> Result<(), String> {
        let cache = CachedCredential {
            source_sha256: source_sha256.to_owned(),
            credential: credential.clone(),
        };
        write_encrypted(
            &self.auth_cache_path,
            &cache,
            &self.cache_cipher,
            AUTH_CACHE_MAGIC,
        )
        .map_err(|_| "无法保存加密的 Codex 登录状态".to_owned())
    }

    fn request_usage(&self, credential: &CodexCredential) -> Result<(u16, String), String> {
        let token = credential
            .active_access_token()
            .ok_or("登录 JSON 缺少访问令牌")?;
        let account_id = credential
            .account_id()
            .ok_or("登录 JSON 缺少 ChatGPT 账号标识")?;
        let response = self
            .http
            .get(USAGE_URL)
            .bearer_auth(token)
            .header("ChatGPT-Account-Id", account_id)
            .header("Accept", "application/json")
            .header("User-Agent", "codex_cli_rs/0.1.0")
            .send()
            .map_err(|_| "Codex 用量请求失败")?;
        let status = response.status().as_u16();
        let body = read_response_body(response)?;
        Ok((status, body))
    }

    fn refresh_credential(&self, credential: &mut CodexCredential) -> Result<(), String> {
        if credential.use_siwc {
            self.refresh_siwc(credential)
        } else {
            self.refresh_oauth(credential)
        }
    }

    fn refresh_oauth(&self, credential: &mut CodexCredential) -> Result<(), String> {
        if credential.refresh_token.trim().is_empty() {
            return Err("登录 JSON 缺少 OAuth 刷新令牌".into());
        }
        let response = self
            .http
            .post(OAUTH_TOKEN_URL)
            .form(&[
                ("client_id", OAUTH_CLIENT_ID),
                ("grant_type", "refresh_token"),
                ("refresh_token", credential.refresh_token.as_str()),
                ("scope", "openid profile email"),
            ])
            .send()
            .map_err(|_| "Codex OAuth 刷新请求失败")?;
        let token = decode_token_response(response)?;
        if token.access_token.trim().is_empty() {
            return Err("Codex OAuth 刷新响应缺少访问令牌".into());
        }
        credential.access_token = token.access_token;
        if !token.refresh_token.trim().is_empty() {
            credential.refresh_token = token.refresh_token;
        }
        if !token.id_token.trim().is_empty() {
            credential.account_id =
                jwt_account_id(&token.id_token).unwrap_or_else(|| credential.account_id.clone());
            credential.id_token = token.id_token;
        }
        credential.expired = expiry_string(token.expires_in)?;
        credential.last_refresh = now_rfc3339()?;
        Ok(())
    }

    fn refresh_siwc(&self, credential: &mut CodexCredential) -> Result<(), String> {
        let siwc = credential.siwc.as_mut().ok_or("登录 JSON 缺少 SIWC 凭证")?;
        if siwc.refresh_token.trim().is_empty() || siwc.client_id.trim().is_empty() {
            return Err("SIWC 凭证缺少刷新令牌或 client_id".into());
        }
        let response = self
            .http
            .post(SIWC_TOKEN_URL)
            .form(&[
                ("grant_type", "refresh_token"),
                ("client_id", siwc.client_id.as_str()),
                ("refresh_token", siwc.refresh_token.as_str()),
                ("resource", SIWC_RESOURCE),
            ])
            .send()
            .map_err(|_| "SIWC OAuth 刷新请求失败")?;
        let token = decode_token_response(response)?;
        if token.access_token.trim().is_empty() || token.refresh_token.trim().is_empty() {
            return Err("SIWC OAuth 刷新响应缺少令牌".into());
        }
        let scopes = token
            .scope
            .split_whitespace()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        if !scopes.iter().any(|scope| scope == SIWC_DIRECT_SCOPE) {
            return Err("SIWC 刷新令牌不包含直接访问所需权限".into());
        }
        siwc.access_token = token.access_token;
        siwc.refresh_token = token.refresh_token;
        if !token.id_token.trim().is_empty() {
            credential.account_id =
                jwt_account_id(&token.id_token).unwrap_or_else(|| credential.account_id.clone());
            siwc.id_token = token.id_token;
        }
        siwc.expired = expiry_string(token.expires_in)?;
        siwc.last_refresh = now_rfc3339()?;
        siwc.scope = token.scope;
        siwc.scopes = scopes;
        Ok(())
    }
}

impl CodexCredential {
    fn validate(&self) -> Result<(), String> {
        if !self.credential_type.eq_ignore_ascii_case("codex") {
            return Err("登录 JSON 的 type 字段不是 codex".into());
        }
        if self.use_siwc && self.siwc.is_none() {
            return Err("登录 JSON 启用了 SIWC，但缺少 siwc 凭证".into());
        }
        let has_access = self.active_access_token().is_some();
        let has_refresh = self.active_refresh_token().is_some();
        if !has_access && !has_refresh {
            return Err("登录 JSON 缺少可用的 Codex 令牌".into());
        }
        Ok(())
    }

    fn active_access_token(&self) -> Option<&str> {
        let token = if self.use_siwc {
            self.siwc.as_ref()?.access_token.as_str()
        } else {
            self.access_token.as_str()
        };
        (!token.trim().is_empty()).then_some(token)
    }

    fn active_refresh_token(&self) -> Option<&str> {
        let token = if self.use_siwc {
            self.siwc.as_ref()?.refresh_token.as_str()
        } else {
            self.refresh_token.as_str()
        };
        (!token.trim().is_empty()).then_some(token)
    }

    fn account_id(&self) -> Option<String> {
        let direct = self.account_id.trim();
        if !direct.is_empty() {
            return Some(direct.to_owned());
        }
        let id_token = if self.use_siwc {
            self.siwc
                .as_ref()
                .map(|siwc| siwc.id_token.as_str())
                .filter(|token| !token.trim().is_empty())
                .or_else(|| (!self.id_token.trim().is_empty()).then_some(self.id_token.as_str()))
        } else {
            (!self.id_token.trim().is_empty()).then_some(self.id_token.as_str())
        }?;
        jwt_account_id(id_token)
    }

    fn should_refresh(&self, now: i64) -> bool {
        let (access_token, expired) = if self.use_siwc {
            let Some(siwc) = self.siwc.as_ref() else {
                return true;
            };
            (siwc.access_token.as_str(), siwc.expired.as_str())
        } else {
            (self.access_token.as_str(), self.expired.as_str())
        };
        if access_token.trim().is_empty() {
            return true;
        }
        parse_expiry(expired).is_some_and(|expires| expires <= now.saturating_add(180))
    }
}

fn same_auth_state(left: &CodexCredential, right: &CodexCredential) -> bool {
    left.credential_type == right.credential_type
        && left.access_token == right.access_token
        && left.refresh_token == right.refresh_token
        && left.id_token == right.id_token
        && left.account_id == right.account_id
        && left.expired == right.expired
        && left.last_refresh == right.last_refresh
        && left.use_siwc == right.use_siwc
        && match (&left.siwc, &right.siwc) {
            (Some(left), Some(right)) => {
                left.access_token == right.access_token
                    && left.refresh_token == right.refresh_token
                    && left.id_token == right.id_token
                    && left.client_id == right.client_id
                    && left.device_id == right.device_id
                    && left.expired == right.expired
                    && left.last_refresh == right.last_refresh
                    && left.scope == right.scope
                    && left.scopes == right.scopes
            }
            (None, None) => true,
            _ => false,
        }
}

impl CacheCipher {
    fn from_environment() -> Result<Self, Box<dyn Error>> {
        let key_text = read_secret("CACHE_ENCRYPTION_KEY_FILE")?;
        let secret_key = Zeroizing::new(decode_hex_key(key_text.as_str())?);
        let machine_id_path = env_value("HOST_MACHINE_ID_FILE", "/run/host-machine-id");
        let machine_id = fs::read_to_string(machine_id_path)?;
        let bytes = derive_machine_key(&secret_key, machine_id.as_str())?;
        Ok(Self {
            key: Zeroizing::new(bytes),
        })
    }

    fn encrypt(&self, plaintext: &[u8], magic: &[u8; 4]) -> Result<Vec<u8>, String> {
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| "缓存加密初始化失败")?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: magic,
                },
            )
            .map_err(|_| "缓存加密失败")?;
        let mut output = Vec::with_capacity(magic.len() + NONCE_LENGTH + ciphertext.len());
        output.extend_from_slice(magic);
        output.extend_from_slice(&nonce);
        output.extend_from_slice(&ciphertext);
        Ok(output)
    }

    fn decrypt(&self, bytes: &[u8], magic: &[u8; 4]) -> Result<Zeroizing<Vec<u8>>, String> {
        if bytes.len() < magic.len() + NONCE_LENGTH + 16 || &bytes[..magic.len()] != magic {
            return Err("加密缓存格式无效".into());
        }
        let cipher =
            Aes256Gcm::new_from_slice(self.key.as_ref()).map_err(|_| "缓存解密初始化失败")?;
        let nonce = Nonce::from_slice(&bytes[magic.len()..magic.len() + NONCE_LENGTH]);
        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &bytes[magic.len() + NONCE_LENGTH..],
                    aad: magic,
                },
            )
            .map_err(|_| String::from("缓存解密失败"))?;
        Ok(Zeroizing::new(plaintext))
    }
}

fn derive_machine_key(secret_key: &[u8; 32], machine_id: &str) -> Result<[u8; 32], String> {
    let machine_id = machine_id.trim();
    if machine_id.len() != 32 || !machine_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("宿主机 machine-id 必须是 32 位十六进制值".into());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"codex-zectrix-machine-bound-cache-v1\0");
    hasher.update(secret_key);
    hasher.update(machine_id.to_ascii_lowercase().as_bytes());
    let digest = hasher.finalize();
    let mut key = [0_u8; 32];
    key.copy_from_slice(&digest);
    Ok(key)
}

fn read_response_body(response: Response) -> Result<String, String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err("上游响应超过大小限制".into());
    }
    let mut limited = response.take((MAX_RESPONSE_BYTES + 1) as u64);
    let mut body = Vec::new();
    limited
        .read_to_end(&mut body)
        .map_err(|_| "无法读取上游响应")?;
    if body.len() > MAX_RESPONSE_BYTES {
        return Err("上游响应超过大小限制".into());
    }
    String::from_utf8(body).map_err(|_| "上游响应不是有效 UTF-8".to_owned())
}

fn decode_token_response(response: Response) -> Result<TokenResponse, String> {
    if !response.status().is_success() {
        return Err("OpenAI OAuth 刷新接口返回错误状态".into());
    }
    let body = read_response_body(response)?;
    let token: TokenResponse =
        serde_json::from_str(&body).map_err(|_| "OpenAI OAuth 刷新响应格式无效")?;
    if token.expires_in <= 0 {
        return Err("OpenAI OAuth 刷新响应的有效期无效".into());
    }
    Ok(token)
}

fn resolve_auth_path(configured_path: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = PathBuf::from(configured_path);
    if path.is_file() {
        return Ok(path);
    }
    if !path.is_dir() {
        return Err(format!("Codex 凭证路径不存在：{}", path.display()).into());
    }
    let mut json_files = fs::read_dir(&path)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|entry| {
            entry.is_file()
                && entry
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
        })
        .collect::<Vec<_>>();
    json_files.sort();
    match json_files.as_slice() {
        [auth_file] => Ok(auth_file.clone()),
        [] => Err(format!("凭证目录中没有 JSON 文件：{}", path.display()).into()),
        _ => Err(format!(
            "凭证目录中有多个 JSON 文件，请只保留一个或用 CODEX_AUTH_PATH 指定文件：{}",
            path.display()
        )
        .into()),
    }
}

fn jwt_account_id(id_token: &str) -> Option<String> {
    let payload = id_token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()?;
    let claims: Value = serde_json::from_slice(&decoded).ok()?;
    claims
        .get("https://api.openai.com/auth")
        .and_then(|auth| {
            auth.get("chatgpt_account_id")
                .or_else(|| auth.get("account_id"))
        })
        .or_else(|| claims.get("chatgpt_account_id"))
        .or_else(|| claims.get("account_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn parse_expiry(value: &str) -> Option<i64> {
    let value = value.trim();
    if let Ok(timestamp) = value.parse::<i64>() {
        return Some(if timestamp > 10_000_000_000 {
            timestamp / 1000
        } else {
            timestamp
        });
    }
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.timestamp())
}

fn expiry_string(expires_in: i64) -> Result<String, String> {
    let timestamp = unix_time_seconds()
        .map_err(|_| "系统时间不可用")?
        .saturating_add(expires_in);
    DateTime::<Utc>::from_timestamp(timestamp, 0)
        .ok_or_else(|| "OAuth 到期时间无效".to_owned())
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn now_rfc3339() -> Result<String, String> {
    let now = unix_time_seconds().map_err(|_| "系统时间不可用")?;
    DateTime::<Utc>::from_timestamp(now, 0)
        .ok_or_else(|| "系统时间无效".to_owned())
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn parse_usage_response(body: &str, now: i64) -> Result<ObservedQuota, String> {
    let value: Value = serde_json::from_str(body).map_err(|_| "Codex 用量响应格式无效")?;
    let rate_limit = value
        .get("rate_limit")
        .or_else(|| value.get("rate_limits"))
        .ok_or("Codex 用量响应缺少额度窗口")?;
    let mut windows = Vec::new();
    for (aliases, fallback_minutes) in [
        (&["five_hour", "primary_window", "primary"][..], Some(300)),
        (
            &["weekly", "secondary_window", "secondary"][..],
            Some(10_080),
        ),
    ] {
        let Some(window) = aliases.iter().find_map(|key| rate_limit.get(*key)) else {
            continue;
        };
        if window.is_null() {
            continue;
        }
        let used = number_field(window, &["used_percent", "usedPercent"])
            .or_else(|| {
                number_field(window, &["percent_left", "percentLeft"])
                    .map(|remaining| 100.0 - remaining)
            })
            .ok_or("Codex 额度窗口缺少使用比例")?;
        if !(0.0..=100.0).contains(&used) {
            return Err("Codex 额度使用比例无效".into());
        }
        let minutes = number_field(
            window,
            &[
                "window_minutes",
                "windowMinutes",
                "window_duration_mins",
                "windowDurationMins",
            ],
        )
        .or_else(|| number_field(window, &["limit_window_seconds"]).map(|seconds| seconds / 60.0))
        .map(|minutes| minutes.round() as u32)
        .or(fallback_minutes)
        .filter(|minutes| *minutes > 0)
        .ok_or("Codex 额度窗口缺少时长")?;
        let resets_at = timestamp_field(window, &["reset_at", "resetAt", "resetsAt"])
            .or_else(|| {
                number_field(window, &["reset_after_seconds", "resetAfterSeconds"])
                    .map(|seconds| now.saturating_add(seconds.round() as i64))
            })
            .ok_or("Codex 额度窗口缺少重置时间")?;
        windows.push((
            minutes,
            ObservedQuotaWindow {
                name: quota_window_name(minutes),
                used_percent: used.round() as u8,
                resets_at_epoch_seconds: resets_at,
            },
        ));
    }
    windows.sort_by_key(|(minutes, _)| *minutes);
    let windows = windows
        .into_iter()
        .map(|(_, window)| window)
        .collect::<Vec<_>>();
    if windows.is_empty() {
        return Err("Codex 用量响应没有可用额度窗口".into());
    }
    let reset_credits = value
        .get("rate_limit_reset_credits")
        .or_else(|| value.get("rateLimitResetCredits"))
        .and_then(|credits| number_field(credits, &["available_count", "availableCount"]))
        .filter(|count| *count >= 0.0)
        .map(|count| count as u64)
        .unwrap_or_default();
    Ok(ObservedQuota {
        windows,
        reset_credits,
        stale: false,
    })
}

fn encrypt_source_file(
    path: &Path,
    expected_stored_source: &[u8],
    source_json: &[u8],
    credential: &CodexCredential,
    cipher: &CacheCipher,
) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "无法确认登录 JSON 文件")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("登录 JSON 必须是普通文件，不能是符号链接".into());
    }

    let mut value: Value =
        serde_json::from_slice(source_json).map_err(|_| "无法安全更新登录 JSON 内容")?;
    let object = value
        .as_object_mut()
        .ok_or("Codex 登录 JSON 顶层必须是对象")?;
    set_string_field(object, "type", &credential.credential_type);
    set_string_field(object, "access_token", &credential.access_token);
    set_string_field(object, "refresh_token", &credential.refresh_token);
    set_string_field(object, "id_token", &credential.id_token);
    set_string_field(object, "account_id", &credential.account_id);
    set_string_field(object, "expired", &credential.expired);
    set_string_field(object, "last_refresh", &credential.last_refresh);
    set_string_field(object, "email", &credential.email);
    set_string_field(object, "plan_type", &credential.plan_type);
    if object.contains_key("use_siwc") || credential.use_siwc {
        object.insert("use_siwc".into(), Value::Bool(credential.use_siwc));
    }
    if let Some(siwc) = &credential.siwc {
        let siwc_object = object
            .entry("siwc")
            .or_insert_with(|| Value::Object(Default::default()))
            .as_object_mut()
            .ok_or("Codex 登录 JSON 的 siwc 字段格式无效")?;
        set_string_field(siwc_object, "access_token", &siwc.access_token);
        set_string_field(siwc_object, "refresh_token", &siwc.refresh_token);
        set_string_field(siwc_object, "id_token", &siwc.id_token);
        set_string_field(siwc_object, "client_id", &siwc.client_id);
        set_string_field(siwc_object, "device_id", &siwc.device_id);
        set_string_field(siwc_object, "expired", &siwc.expired);
        set_string_field(siwc_object, "last_refresh", &siwc.last_refresh);
        set_string_field(siwc_object, "scope", &siwc.scope);
        if siwc_object.contains_key("scopes") || !siwc.scopes.is_empty() {
            siwc_object.insert("scopes".into(), serde_json::json!(&siwc.scopes));
        }
    }

    let updated_json =
        Zeroizing::new(serde_json::to_vec(&value).map_err(|_| "无法序列化加密前的登录 JSON")?);
    if updated_json.len() > MAX_CREDENTIAL_BYTES {
        return Err("Codex 登录 JSON 超过大小限制".into());
    }
    let updated_credential: CodexCredential =
        serde_json::from_slice(&updated_json).map_err(|_| "加密前的登录 JSON 格式无效")?;
    updated_credential.validate()?;

    let encrypted = cipher.encrypt(&updated_json, AUTH_FILE_MAGIC)?;
    let verified = cipher.decrypt(&encrypted, AUTH_FILE_MAGIC)?;
    if verified.as_slice() != updated_json.as_slice() {
        return Err("登录 JSON 加密校验失败".into());
    }
    let _: CodexCredential =
        serde_json::from_slice(&verified).map_err(|_| "登录 JSON 加密后的内容校验失败")?;

    let current_source = Zeroizing::new(fs::read(path).map_err(|_| "无法复核登录 JSON 文件")?);
    if current_source.as_slice() != expected_stored_source {
        return Err("登录 JSON 在读取期间发生变化，已取消覆盖".into());
    }
    write_bytes_atomic(path, &encrypted).map_err(|_| "无法原子替换登录 JSON")?;
    Ok(format!("{:x}", Sha256::digest(updated_json.as_slice())))
}

fn set_string_field(object: &mut serde_json::Map<String, Value>, key: &str, value: &str) {
    if object.contains_key(key) || !value.is_empty() {
        object.insert(key.to_owned(), Value::String(value.to_owned()));
    }
}

fn number_field(object: &Value, keys: &[&str]) -> Option<f64> {
    keys.iter().find_map(|key| {
        let value = object.get(*key)?;
        value
            .as_f64()
            .or_else(|| value.as_str()?.parse::<f64>().ok())
    })
}

fn timestamp_field(object: &Value, keys: &[&str]) -> Option<i64> {
    let value = keys.iter().find_map(|key| object.get(*key))?;
    let timestamp = value.as_i64().or_else(|| {
        let raw = value.as_str()?;
        raw.parse::<i64>().ok().or_else(|| {
            DateTime::parse_from_rfc3339(raw)
                .ok()
                .map(|timestamp| timestamp.timestamp())
        })
    })?;
    Some(if timestamp > 10_000_000_000 {
        timestamp / 1000
    } else {
        timestamp
    })
}

fn quota_window_name(minutes: u32) -> String {
    if minutes.is_multiple_of(24 * 60) {
        format!("{} 天", minutes / (24 * 60))
    } else if minutes.is_multiple_of(60) {
        format!("{} 小时", minutes / 60)
    } else {
        format!("{minutes} 分钟")
    }
}

fn load_encrypted<T: DeserializeOwned>(
    path: &Path,
    cipher: &CacheCipher,
    magic: &[u8; 4],
) -> Result<Option<T>, String> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("无法读取加密缓存".into()),
    };
    let plaintext = cipher.decrypt(&bytes, magic)?;
    serde_json::from_slice(&plaintext)
        .map(Some)
        .map_err(|_| "加密缓存内容无效".into())
}

fn write_encrypted<T: Serialize>(
    path: &Path,
    value: &T,
    cipher: &CacheCipher,
    magic: &[u8; 4],
) -> Result<(), Box<dyn Error>> {
    let plaintext = Zeroizing::new(serde_json::to_vec(value)?);
    let encrypted = cipher
        .encrypt(&plaintext, magic)
        .map_err(std::io::Error::other)?;
    write_bytes_atomic(path, &encrypted)
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let parent = path.parent().ok_or("缓存路径缺少父目录")?;
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .ok_or("目标文件路径无效")?
        .to_string_lossy();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let temp_path = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp_path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    replace_file(&temp_path, path)?;
    #[cfg(unix)]
    if let Ok(directory) = fs::File::open(parent) {
        let _ = directory.sync_all();
    }
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::rename(source, target)
}

#[cfg(windows)]
fn replace_file(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::copy(source, target)?;
    fs::remove_file(source)
}

fn decode_hex_key(text: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let text = text.trim();
    if text.len() != 64 {
        return Err("CACHE_ENCRYPTION_KEY_FILE 必须包含 64 位十六进制密钥".into());
    }
    let mut key = [0_u8; 32];
    for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let high = hex_nibble(pair[0]).ok_or("缓存加密密钥必须是十六进制")?;
        let low = hex_nibble(pair[1]).ok_or("缓存加密密钥必须是十六进制")?;
        key[index] = (high << 4) | low;
    }
    Ok(key)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn read_secret(variable: &str) -> Result<Zeroizing<String>, Box<dyn Error>> {
    let path = required_env(variable)?;
    let bytes = fs::read(path)?;
    let value = String::from_utf8(bytes)?;
    let value = value.trim_end_matches(['\r', '\n']).to_owned();
    if value.trim().is_empty() {
        return Err(format!("{variable} 指向的密钥文件为空").into());
    }
    Ok(Zeroizing::new(value))
}

fn required_env(name: &str) -> Result<String, Box<dyn Error>> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("缺少必需环境变量 {name}").into()),
    }
}

fn env_value(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn unix_time_seconds() -> Result<i64, Box<dyn Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        .try_into()?)
}

fn publish_result_label(attempt: PublishAttempt) -> &'static str {
    match attempt {
        PublishAttempt::Idle => "无待发布画面",
        PublishAttempt::Deferred { .. } => "稍后重试",
        PublishAttempt::Unchanged => "画面未变化",
        PublishAttempt::Published => "已上传",
        PublishAttempt::Failed => "上传失败",
        PublishAttempt::ReservationFailed => "保留上传状态失败",
    }
}

fn radar_display_label(state: RadarDisplayState) -> &'static str {
    match state {
        RadarDisplayState::Unavailable => "雷达不可用",
        RadarDisplayState::NoActiveWatch => "暂无预测",
        RadarDisplayState::ActiveWatch { stale: true, .. } => "缓存预测",
        RadarDisplayState::ActiveWatch { stale: false, .. } => "有预测",
        RadarDisplayState::Confirmed { .. } => "重置已记录",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MACHINE_ID: &str = "0123456789abcdef0123456789abcdef";

    fn test_cipher(machine_id: &str) -> CacheCipher {
        let secret = [0x5a; 32];
        CacheCipher {
            key: Zeroizing::new(derive_machine_key(&secret, machine_id).unwrap()),
        }
    }

    fn random_test_cipher(machine_id: &str) -> CacheCipher {
        let mut secret = Zeroizing::new([0_u8; 32]);
        for chunk in secret.chunks_mut(12) {
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            chunk.copy_from_slice(&nonce[..chunk.len()]);
        }
        CacheCipher {
            key: Zeroizing::new(derive_machine_key(&secret, machine_id).unwrap()),
        }
    }

    #[test]
    fn machine_key_is_bound_to_a_valid_machine_id() {
        let secret = [0x3c; 32];
        let first = derive_machine_key(&secret, TEST_MACHINE_ID).unwrap();
        let same = derive_machine_key(&secret, TEST_MACHINE_ID).unwrap();
        let other = derive_machine_key(&secret, "fedcba9876543210fedcba9876543210").unwrap();

        assert!(first == same);
        assert!(first != other);
        assert!(derive_machine_key(&secret, "invalid").is_err());
    }

    #[test]
    fn parses_cpa_primary_and_secondary_quota_windows() {
        let observed = parse_usage_response(
            r#"{"rate_limits":{"primary":{"used_percent":32.6,"window_minutes":300,"reset_after_seconds":3600},"secondary":{"used_percent":71,"window_minutes":10080,"reset_at":1800000000}}}"#,
            1_700_000_000,
        )
        .unwrap();

        assert_eq!(observed.windows.len(), 2);
        assert_eq!(observed.windows[0].name, "5 小时");
        assert_eq!(observed.windows[0].used_percent, 33);
        assert_eq!(observed.windows[0].resets_at_epoch_seconds, 1_700_003_600);
        assert_eq!(observed.windows[1].name, "7 天");
        assert_eq!(observed.windows[1].used_percent, 71);
        assert_eq!(observed.windows[1].resets_at_epoch_seconds, 1_800_000_000);
    }

    #[test]
    fn parses_rfc3339_and_numeric_oauth_expiry_values() {
        assert_eq!(parse_expiry("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_expiry("0"), Some(0));
        assert_eq!(parse_expiry("invalid"), None);
    }

    #[test]
    fn quota_pause_windows_support_multiple_and_cross_midnight_ranges() {
        let schedule = QuotaPauseSchedule::parse("23:00-07:00,12:30-13:30").unwrap();
        assert!(schedule.windows[0].contains(23 * 60));
        assert!(schedule.windows[0].contains(6 * 60 + 59));
        assert!(!schedule.windows[0].contains(7 * 60));
        assert!(schedule.windows[1].contains(12 * 60 + 30));
        assert!(!schedule.windows[1].contains(13 * 60 + 30));
        assert!(QuotaPauseSchedule::parse("24:00-01:00").is_err());
        assert!(QuotaPauseSchedule::parse("09:00-09:00").is_err());

        let overlap = QuotaPauseSchedule::parse("23:00-03:00,02:00-07:00").unwrap();
        assert_eq!(overlap.seconds_until_resume_at(150, 9_000), Some(16_200));
        assert_eq!(overlap.seconds_until_resume_at(8 * 60, 28_800), None);
    }

    #[test]
    fn encrypts_source_atomically_and_preserves_unknown_cpa_fields() {
        let directory = std::env::temp_dir().join(format!(
            "codex-zectrix-auth-test-{}-{}",
            std::process::id(),
            unix_time_seconds().unwrap()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("account.json");
        let source = br#"{"type":"codex","access_token":"old-access","refresh_token":"old-refresh","id_token":"old-id","account_id":"test-account","expired":"2000-01-01T00:00:00Z","last_refresh":"","email":"test@example.invalid","plan_type":"plus","disabled":false,"excluded_models":["example"],"custom":{"keep":true}}"#;
        fs::write(&path, source).unwrap();
        let mut credential: CodexCredential = serde_json::from_slice(source).unwrap();
        credential.access_token = "rotated-access".into();
        credential.refresh_token = "rotated-refresh".into();
        credential.expired = "2099-01-01T00:00:00Z".into();
        let cipher = test_cipher(TEST_MACHINE_ID);

        encrypt_source_file(&path, source, source, &credential, &cipher).unwrap();

        let stored = fs::read(&path).unwrap();
        assert!(stored.starts_with(AUTH_FILE_MAGIC));
        assert!(
            !stored
                .windows(b"old-refresh".len())
                .any(|chunk| chunk == b"old-refresh")
        );
        let clear = cipher.decrypt(&stored, AUTH_FILE_MAGIC).unwrap();
        let value: Value = serde_json::from_slice(&clear).unwrap();
        assert_eq!(value["refresh_token"], "rotated-refresh");
        assert_eq!(value["custom"]["keep"], true);
        assert!(!value["disabled"].as_bool().unwrap());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    #[ignore = "需要明确指定一份测试用登录 JSON 并访问 Codex OAuth/额度接口"]
    fn live_quota_read_refreshes_and_encrypts_the_test_credential() {
        let auth_path = PathBuf::from(
            std::env::var("CODEX_LIVE_TEST_AUTH_PATH")
                .expect("请设置 CODEX_LIVE_TEST_AUTH_PATH 指向测试用 JSON 副本"),
        );
        let original = Zeroizing::new(fs::read(&auth_path).unwrap());
        let mut source: Value = serde_json::from_slice(&original).unwrap();
        let expiry = if source["use_siwc"].as_bool().unwrap_or(false) {
            &mut source["siwc"]["expired"]
        } else {
            &mut source["expired"]
        };
        *expiry = Value::String("2000-01-01T00:00:00Z".into());
        let expired_source = Zeroizing::new(serde_json::to_vec(&source).unwrap());
        write_bytes_atomic(&auth_path, &expired_source).unwrap();

        let cipher = random_test_cipher(TEST_MACHINE_ID);
        let cache_path = PathBuf::from(".trash").join(format!(
            "live-codex-auth-cache-{}-{}.bin",
            std::process::id(),
            unix_time_seconds().unwrap()
        ));
        let client = CodexClient::new(auth_path.clone(), cache_path, cipher).unwrap();
        let quota = match client.read_quota() {
            Ok(quota) => quota,
            Err(_) => {
                if let Ok(loaded) = client.load_credential()
                    && !loaded.source_encrypted
                {
                    let _ = encrypt_source_file(
                        &auth_path,
                        &loaded.stored_source,
                        &loaded.source_json,
                        &loaded.credential,
                        &client.cache_cipher,
                    );
                }
                panic!("真实额度读取、OAuth 刷新或加密验证失败");
            }
        };
        assert!((1..=2).contains(&quota.windows.len()));

        let loaded = client.load_credential().unwrap();
        assert!(loaded.source_encrypted);
        assert!(loaded.stored_source.starts_with(AUTH_FILE_MAGIC));
        assert!(loaded.credential.active_access_token().is_some());
        assert!(loaded.credential.active_refresh_token().is_some());
        assert!(loaded.credential.should_refresh(i64::MAX - 1));
        let value: Value = serde_json::from_slice(&loaded.source_json).unwrap();
        for field in ["disabled", "excluded_models", "request_retry", "websockets"] {
            assert!(value.get(field).is_some(), "字段 {field} 未保留");
        }
    }
}
