use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::Read;
use std::time::Duration;
use thiserror::Error;

const NO_WATCH_FRESH_SECONDS: i64 = 2 * 60 * 60;
const CONFIRMATION_FRESH_SECONDS: i64 = 24 * 60 * 60;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetKind {
    Regular,
    ResetCredit,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetConfirmation {
    pub kind: ResetKind,
    pub announced_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RadarWatch {
    pub reset_chance_percent: Option<u8>,
    pub forecast_window: String,
    pub observed_at_epoch_seconds: i64,
    pub expires_at_epoch_seconds: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RadarSemanticState {
    pub latest_reset: Option<ResetConfirmation>,
    pub active_watch: Option<RadarWatch>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedRadarStatus {
    semantic: RadarSemanticState,
    explicit_no_watch: bool,
    invalid_capability: bool,
}

impl ParsedRadarStatus {
    fn has_usable_capability(&self) -> bool {
        self.explicit_no_watch
            || self.semantic.latest_reset.is_some()
            || self.semantic.active_watch.is_some()
    }

    pub fn has_invalid_capability(&self) -> bool {
        self.invalid_capability
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum RadarDisplayState {
    #[default]
    Unavailable,
    NoActiveWatch,
    ActiveWatch {
        forecast_window: String,
        reset_chance_percent: Option<u8>,
        stale: bool,
    },
    Confirmed {
        kind: ResetKind,
        stale: bool,
    },
}

#[derive(Clone, Debug, Default)]
pub struct RadarCache {
    semantic: RadarSemanticState,
    no_watch_fresh_until_epoch_seconds: Option<i64>,
    fresh_observation: bool,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RadarReason {
    #[default]
    None,
    Network,
    RateLimited,
    UpstreamUnavailable,
    InvalidResponse,
    ResponseTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RadarFetch {
    Modified(ParsedRadarStatus),
    NotModified,
    Failed {
        reason: RadarReason,
        retry_after_seconds: Option<u64>,
    },
}

#[derive(Debug, Error)]
pub enum RadarParseError {
    #[error("invalid radar JSON")]
    Json(#[from] serde_json::Error),
    #[error("invalid radar envelope")]
    InvalidEnvelope,
}

pub struct RadarClient {
    client: reqwest::blocking::Client,
    endpoint: String,
    etag: Option<String>,
}

impl RadarClient {
    pub fn new(endpoint: impl Into<String>) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::blocking::Client::builder()
                .connect_timeout(Duration::from_secs(3))
                .timeout(Duration::from_secs(5))
                .build()?,
            endpoint: endpoint.into(),
            etag: None,
        })
    }

    pub fn fetch(&mut self) -> RadarFetch {
        let mut request = self.client.get(&self.endpoint);
        if let Some(etag) = &self.etag {
            request = request.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let mut response = match request.send() {
            Ok(response) => response,
            Err(_) => return failed(RadarReason::Network),
        };
        match response.status() {
            reqwest::StatusCode::NOT_MODIFIED if self.etag.is_some() => {
                return RadarFetch::NotModified;
            }
            reqwest::StatusCode::NOT_MODIFIED => {
                return failed(RadarReason::InvalidResponse);
            }
            reqwest::StatusCode::TOO_MANY_REQUESTS => {
                let retry_after_seconds = response
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_retry_after);
                return RadarFetch::Failed {
                    reason: RadarReason::RateLimited,
                    retry_after_seconds,
                };
            }
            status if !status.is_success() => {
                return failed(RadarReason::UpstreamUnavailable);
            }
            _ => {}
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES)
        {
            return failed(RadarReason::ResponseTooLarge);
        }
        let etag = response
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let mut body = Vec::new();
        if response
            .by_ref()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .is_err()
        {
            return failed(RadarReason::Network);
        }
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return failed(RadarReason::ResponseTooLarge);
        }
        let Ok(body) = std::str::from_utf8(&body) else {
            return failed(RadarReason::InvalidResponse);
        };
        let parsed = match parse_reset_radar_status(body) {
            Ok(parsed) if parsed.has_usable_capability() => parsed,
            _ => return failed(RadarReason::InvalidResponse),
        };
        self.etag = etag;
        RadarFetch::Modified(parsed)
    }
}

fn parse_retry_after(value: &str) -> Option<u64> {
    value.parse().ok().or_else(|| {
        let retry_at = DateTime::parse_from_rfc2822(value).ok()?;
        let wait_nanoseconds = retry_at
            .signed_duration_since(Utc::now())
            .num_nanoseconds()?
            .max(0);
        u64::try_from(wait_nanoseconds.saturating_add(999_999_999) / 1_000_000_000).ok()
    })
}

fn failed(reason: RadarReason) -> RadarFetch {
    RadarFetch::Failed {
        reason,
        retry_after_seconds: None,
    }
}

impl RadarCache {
    pub fn new(semantic: RadarSemanticState) -> Self {
        Self {
            semantic,
            no_watch_fresh_until_epoch_seconds: None,
            fresh_observation: false,
        }
    }

    pub fn accept(&mut self, parsed: ParsedRadarStatus, observed_at_epoch_seconds: i64) {
        self.semantic = parsed.semantic;
        self.no_watch_fresh_until_epoch_seconds = parsed
            .explicit_no_watch
            .then_some(observed_at_epoch_seconds.saturating_add(NO_WATCH_FRESH_SECONDS));
        self.fresh_observation = true;
    }

    pub fn mark_failed(&mut self) {
        self.fresh_observation = false;
    }

    pub fn confirm_unchanged(&mut self, observed_at_epoch_seconds: i64) {
        if self.no_watch_fresh_until_epoch_seconds.is_some() {
            self.no_watch_fresh_until_epoch_seconds =
                Some(observed_at_epoch_seconds.saturating_add(NO_WATCH_FRESH_SECONDS));
        }
        self.fresh_observation = true;
    }

    pub fn semantic(&self) -> &RadarSemanticState {
        &self.semantic
    }

    pub fn display(&self, now_epoch_seconds: i64) -> RadarDisplayState {
        let confirmation = self.semantic.latest_reset.as_ref().filter(|reset| {
            reset.announced_at_epoch_seconds <= now_epoch_seconds
                && now_epoch_seconds.saturating_sub(reset.announced_at_epoch_seconds)
                    < CONFIRMATION_FRESH_SECONDS
        });
        let watch = self.semantic.active_watch.as_ref().filter(|watch| {
            watch.observed_at_epoch_seconds <= now_epoch_seconds
                && now_epoch_seconds < watch.expires_at_epoch_seconds
        });

        if let Some(watch) = watch.filter(|watch| {
            confirmation.is_none_or(|reset| {
                watch.observed_at_epoch_seconds > reset.announced_at_epoch_seconds
            })
        }) {
            return RadarDisplayState::ActiveWatch {
                forecast_window: watch.forecast_window.clone(),
                reset_chance_percent: watch.reset_chance_percent,
                stale: !self.fresh_observation,
            };
        }
        if let Some(confirmation) = confirmation {
            return RadarDisplayState::Confirmed {
                kind: confirmation.kind,
                stale: !self.fresh_observation,
            };
        }
        if self
            .no_watch_fresh_until_epoch_seconds
            .is_some_and(|fresh_until| now_epoch_seconds <= fresh_until)
        {
            return RadarDisplayState::NoActiveWatch;
        }
        RadarDisplayState::Unavailable
    }
}

pub fn parse_reset_radar_status(input: &str) -> Result<ParsedRadarStatus, RadarParseError> {
    let root: Value = serde_json::from_str(input)?;
    let data = root
        .get("data")
        .and_then(Value::as_object)
        .ok_or(RadarParseError::InvalidEnvelope)?;
    let latest_reset_value = data
        .get("latest_reset")
        .ok_or(RadarParseError::InvalidEnvelope)?;
    let active_watch_value = data
        .get("active_watch")
        .ok_or(RadarParseError::InvalidEnvelope)?;
    let latest_reset = parse_confirmation(latest_reset_value);
    let explicit_no_watch = active_watch_value.is_null();
    let active_watch = parse_watch(active_watch_value);
    let invalid_capability = (!latest_reset_value.is_null() && latest_reset.is_none())
        || (!active_watch_value.is_null() && active_watch.is_none());
    Ok(ParsedRadarStatus {
        semantic: RadarSemanticState {
            latest_reset,
            active_watch,
        },
        explicit_no_watch,
        invalid_capability,
    })
}

fn parse_confirmation(value: &Value) -> Option<ResetConfirmation> {
    if value.is_null() {
        return None;
    }
    let kind = match value.get("reset_type")?.as_str()? {
        "regular" => ResetKind::Regular,
        "banked" => ResetKind::ResetCredit,
        _ => return None,
    };
    Some(ResetConfirmation {
        kind,
        announced_at_epoch_seconds: parse_timestamp(value.get("announced_at")?.as_str()?)?,
    })
}

fn parse_watch(value: &Value) -> Option<RadarWatch> {
    let level = value.get("level")?.as_str()?;
    if !matches!(level, "elevated" | "strong") {
        return None;
    }
    let reset_chance_percent = match value.get("reset_chance_percent")? {
        Value::Null => None,
        value => Some(
            u8::try_from(value.as_u64()?)
                .ok()
                .filter(|value| *value <= 100)?,
        ),
    };
    let forecast_window = value.get("forecast_window")?.as_str()?.trim();
    if forecast_window.is_empty() {
        return None;
    }
    let observed_at_epoch_seconds = parse_timestamp(value.get("observed_at")?.as_str()?)?;
    let expires_at_epoch_seconds = parse_timestamp(value.get("expires_at")?.as_str()?)?;
    if expires_at_epoch_seconds <= observed_at_epoch_seconds {
        return None;
    }
    Some(RadarWatch {
        reset_chance_percent,
        forecast_window: forecast_window.into(),
        observed_at_epoch_seconds,
        expires_at_epoch_seconds,
    })
}

fn parse_timestamp(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OBSERVED_AT: i64 = 1_767_225_600;

    #[test]
    fn parses_retry_after_delta_and_http_date() {
        assert_eq!(parse_retry_after("30"), Some(30));
        assert_eq!(parse_retry_after("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_retry_after("invalid"), None);
    }

    #[test]
    fn parses_rfc3339_timestamps_with_chrono() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_timestamp("invalid"), None);
    }

    #[test]
    fn parses_reset_confirmation_and_active_watch() {
        let parsed = parse_reset_radar_status(
            r#"{"data":{"latest_reset":{"reset_type":"banked","announced_at":"2025-12-31T23:59:59Z"},"active_watch":{"level":"strong","reset_chance_percent":83,"forecast_window":"Next 24 hours","observed_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z"}}}"#,
        )
        .unwrap();

        assert!(!parsed.has_invalid_capability());
        assert_eq!(
            parsed.semantic.latest_reset,
            Some(ResetConfirmation {
                kind: ResetKind::ResetCredit,
                announced_at_epoch_seconds: OBSERVED_AT - 1,
            })
        );
        assert_eq!(
            parsed.semantic.active_watch,
            Some(RadarWatch {
                reset_chance_percent: Some(83),
                forecast_window: "Next 24 hours".into(),
                observed_at_epoch_seconds: OBSERVED_AT,
                expires_at_epoch_seconds: OBSERVED_AT + 86_400,
            })
        );

        let mut cache = RadarCache::default();
        cache.accept(parsed, OBSERVED_AT);
        assert_eq!(
            cache.display(OBSERVED_AT + 1),
            RadarDisplayState::ActiveWatch {
                forecast_window: "Next 24 hours".into(),
                reset_chance_percent: Some(83),
                stale: false,
            }
        );
    }

    #[test]
    fn treats_missing_chance_as_unknown_and_marks_failed_fetch_stale() {
        let parsed = parse_reset_radar_status(
            r#"{"data":{"latest_reset":null,"active_watch":{"level":"elevated","reset_chance_percent":null,"forecast_window":"Today","observed_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z"}}}"#,
        )
        .unwrap();
        let mut cache = RadarCache::default();
        cache.accept(parsed, OBSERVED_AT);

        assert_eq!(
            cache.display(OBSERVED_AT + 1),
            RadarDisplayState::ActiveWatch {
                forecast_window: "Today".into(),
                reset_chance_percent: None,
                stale: false,
            }
        );

        cache.mark_failed();
        assert_eq!(
            cache.display(OBSERVED_AT + 1),
            RadarDisplayState::ActiveWatch {
                forecast_window: "Today".into(),
                reset_chance_percent: None,
                stale: true,
            }
        );
    }

    #[test]
    fn keeps_explicit_no_watch_distinct_from_unavailable_after_expiry() {
        let parsed =
            parse_reset_radar_status(r#"{"data":{"latest_reset":null,"active_watch":null}}"#)
                .unwrap();
        let mut cache = RadarCache::default();
        cache.accept(parsed, OBSERVED_AT);

        assert_eq!(
            cache.display(OBSERVED_AT + 1),
            RadarDisplayState::NoActiveWatch
        );
        assert_eq!(
            cache.display(OBSERVED_AT + NO_WATCH_FRESH_SECONDS + 1),
            RadarDisplayState::Unavailable
        );
    }

    #[test]
    #[ignore = "需要访问 Codex Resets 公共状态 API"]
    fn live_status_fetches_a_usable_capability() {
        let mut client = RadarClient::new("https://codex-resets.com/api/v1/status").unwrap();
        match client.fetch() {
            RadarFetch::Modified(parsed) => assert!(!parsed.has_invalid_capability()),
            RadarFetch::NotModified => panic!("首次请求不能返回 304"),
            RadarFetch::Failed { reason, .. } => panic!("实时雷达请求失败：{reason:?}"),
        }
    }
}
