# Codex 额度与重置雷达

Linux 后台服务：读取你放入固定目录的 CPA Codex 登录 JSON，定时获取剩余额度和公开重置信号，再把一张 400×300 看板图片推送到 ZECTRIX NOTE4。项目不启动或监控 CPA，不保存图片历史；设备上的新图会覆盖旧图。

## 获取与构建

推送 `v*` 标签后，GitHub Actions 会先运行格式检查、Clippy 和测试。全部通过后，工作流自动创建 GitHub Release，并附上 `x86_64` Linux GNU 二进制压缩包及 SHA-256 校验文件。该二进制适用于 x86_64 Linux，运行环境需提供 glibc 2.35 或更高版本。

也可以在 Linux x86_64 主机从源码构建：

```sh
cargo build --locked --release --target x86_64-unknown-linux-gnu --bin codex_quota_companion
```

## 部署

以下示例使用 systemd。服务以独立的 `codex-quota` 用户运行，认证文件和运行缓存放在 `/var/lib/codex-quota`。

1. 创建服务账户和数据目录：

   ```sh
   sudo useradd --system --home-dir /var/lib/codex-quota --create-home --shell /usr/sbin/nologin codex-quota
   sudo install -d -o codex-quota -g codex-quota -m 700 /var/lib/codex-quota/auths /var/lib/codex-quota/data /var/lib/codex-quota/secrets
   sudo install -d -m 755 /opt/codex-quota
   ```

2. 下载 Release 压缩包及其 `.sha256` 文件，运行 `sha256sum -c codex-quota-companion-linux-x86_64-gnu.tar.gz.sha256` 校验，再将压缩包解压到 `/opt/codex-quota/`。将 `.env.example` 安装为 systemd 环境文件并限制读取权限：

   ```sh
   sudo tar -xzf codex-quota-companion-linux-x86_64-gnu.tar.gz -C /opt/codex-quota
   sudo install -o root -g root -m 600 /opt/codex-quota/.env.example /var/lib/codex-quota/service.env
   sudoedit /var/lib/codex-quota/service.env
   ```

3. 编辑 `service.env`，填写 ZECTRIX 设备 ID。默认时区为 `Asia/Shanghai`。可将 `TZ` 改为其他 IANA 时区，并用 `QUOTA_PAUSE_WINDOWS` 设置每天暂停额度请求的时段，例如 `23:00-07:00,12:30-13:30`。雷达轮询在暂停期间继续运行。

4. **复制** CPA 导出的单个 Codex 登录 JSON 到 `/var/lib/codex-quota/auths/`，不要指向 CPA 正在读写的原始 auth 目录。看板会独立轮换 OAuth Token 并加密覆盖这份副本，不能让 CPA 与看板同时维护同一个登录文件。确保该目录中只有一个 `.json` 文件，并设置权限：

   ```sh
   sudo chown codex-quota:codex-quota /var/lib/codex-quota/auths/*.json
   sudo chmod 600 /var/lib/codex-quota/auths/*.json
   ```

5. 将 ZECTRIX API Key 写入 `service.env` 指定的密钥文件，并生成本机缓存密钥：

   ```sh
   sudo -u codex-quota sh -c 'umask 077; openssl rand -hex 32 > /var/lib/codex-quota/secrets/cache_encryption_key'
   ```

   用 `sudoedit` 将 ZECTRIX API Key 写入 `/var/lib/codex-quota/secrets/zectrix_api_key`，然后运行 `sudo chown codex-quota:codex-quota /var/lib/codex-quota/secrets/zectrix_api_key && sudo chmod 600 /var/lib/codex-quota/secrets/zectrix_api_key`。

6. 创建 `/etc/systemd/system/codex-quota.service`：

   ```ini
   [Unit]
   Description=Codex 额度看板发布服务
   Wants=network-online.target
   After=network-online.target

   [Service]
   Type=simple
   User=codex-quota
   Group=codex-quota
   WorkingDirectory=/opt/codex-quota
   EnvironmentFile=/var/lib/codex-quota/service.env
   ExecStart=/opt/codex-quota/codex_quota_companion
   Restart=always
   RestartSec=10
   NoNewPrivileges=true
   ProtectSystem=strict
   ProtectHome=true
   ReadWritePaths=/var/lib/codex-quota

   [Install]
   WantedBy=multi-user.target
   ```

7. 启动服务并查看日志：

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now codex-quota
   sudo journalctl -u codex-quota -f
   ```

## 凭证与数据

首次成功读取额度后，服务会先保留 CPA JSON 中的未知字段和刷新后的令牌，再尝试把 JSON 原子替换为 AES-256-GCM 密文。密文保留原文件名；加密或写入失败时，服务会保留明文源文件并在日志中报告。读取、刷新或额度解析失败时，服务不会加密或覆盖源文件。

普通 OAuth 与 CPA SIWC 凭证会在到期前刷新。额度接口返回 401 时，服务也会刷新并重试。除此之外，`CODEX_AUTH_REFRESH_SECONDS`（默认 3600 秒）会独立、定期刷新 Token；配置 `0` 则关闭定时刷新，但不会禁用额度读取期间的到期刷新与手动刷新。**即使处于额度暂停时段，独立 OAuth 刷新仍正常运行。**刷新后的令牌写入加密凭证和 `/var/lib/codex-quota/data/` 中的加密缓存。请保留该目录、`cache_encryption_key` 和宿主机 `/etc/machine-id`；换机后必须重新导入 CPA JSON。文件替换不能保证擦除 SSD、快照或日志文件系统中已释放的数据块。

手动刷新 OAuth Token：`codex_quota_companion --refresh-auth`（或向本机监听地址发送 `POST /auth/refresh`）。命令返回 `202 Accepted` 代表已排队，**不代表刷新已经成功**；应查看 systemd 日志确认结果。原有 `--trigger-refresh` / `POST /refresh` 现可强制触发额度与雷达轮询，并允许手动请求绕过额度暂停窗口。控制端仅能绑定 loopback 地址，远程使用请通过 SSH 或 Tailscale 转发。

额度来自 ChatGPT 的 `/backend-api/wham/usage` 接口。该内部接口的响应格式或访问策略可能变化。重置雷达读取 [Codex Resets](https://codex-resets.com/) 的公开 API；公开公告和预测不代表 OpenAI 承诺，也不能证明个人额度已经重置。接口失败时显示不可用状态或保留仍有效的缓存，不生成推测数据。

## CLI 交互控制模式 (跨平台支持 Windows & Linux)

本程序采用单二进制架构设计，支持守护进程常驻模式与命令行交互工具模式：

```bash
# 1. 查看帮助与版本
codex_quota_companion --help
codex_quota_companion --version

# 2. 本地离线渲染 400x300 1-bit 看板预览图 (无需网络与设备，验证渲染引擎)
codex_quota_companion --preview [output.png]

# 3. 探活远程或本地常驻守护进程健康状态
codex_quota_companion --check [127.0.0.1:9595]

# 4. 远程触发服务立即拉取最新额度与雷达数据并推送上屏
codex_quota_companion --trigger-refresh [127.0.0.1:9595]

# 5. 独立强制刷新 OAuth Token（不触发额度请求、不向屏幕推送）
codex_quota_companion --refresh-auth [127.0.0.1:9595]

# 6. 指定自定义环境变量文件启动
codex_quota_companion --env /path/to/custom.env
```

---

## 配置

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CODEX_AUTH_PATH` | `/run/codex-auth` | 登录 JSON 文件或只含一个 JSON 的目录 |
| `CODEX_ZECTRIX_DATA_DIR` | `/data` | 加密运行缓存目录 |
| `ZECTRIX_DEVICE_ID` | 必填 | NOTE4 设备 ID |
| `ZECTRIX_PAGE_ID` | `1` | 推送页面，范围为 1–5 |
| `ZECTRIX_API_BASE` | `https://cloud.zectrix.com` | ZECTRIX API 地址 |
| `ZECTRIX_API_KEY_FILE` | 必填 | 保存 ZECTRIX API Key 的文件 |
| `CACHE_ENCRYPTION_KEY_FILE` | 必填 | 32 字节随机密钥的 64 位十六进制编码文件 |
| `HOST_MACHINE_ID_FILE` | `/run/host-machine-id` | Linux 宿主机 `machine-id` 文件 |
| `QUOTA_POLL_SECONDS` | `1800` | 额度轮询间隔，最小 60 秒 |
| `RADAR_POLL_SECONDS` | `3600` | 雷达独立保底轮询间隔，最小 60 秒；每次实际额度轮询时也同步更新雷达 |
| `CODEX_AUTH_REFRESH_SECONDS` | `3600` | 独立强制刷新 OAuth Token 间隔，0 关闭自动刷新，非零最小 60 秒 |
| `QUOTA_PAUSE_WINDOWS` | 空 | 每日暂停时段，例如 `23:00-07:00` |
| `TZ` | `Asia/Shanghai` | 暂停时段使用的 IANA 时区 |

`.env.example` 提供了适用于本仓库 systemd 部署的路径示例。将它用作 `EnvironmentFile` 前，确认密钥文件和登录目录的所有者及权限正确。

## 许可证

[MIT](./LICENSE)
