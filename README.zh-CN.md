[English](README.md) | **简体中文**

# quota-mcp

AI 订阅账户的**用量 / 额度追踪服务**：把散在各家官网控制台里的余额、订阅到期、节流窗口聚到一个地方，同时提供 **REST 管理面**和 **MCP 查询面**——agent（Hermes、Claude Code 等）加一条配置就能直接问「我的额度还剩多少」。

现已支持两个平台：

| 平台 | 数据来源 | 凭据形式 | 能看什么 |
|---|---|---|---|
| **StepFun**（阶跃星辰，`.ai` 国际站 / `.com` 国内站） | `platform.stepfun.{ai,com}` 控制台 Connect RPC | 浏览器会话（Oasis-Token，~2 h，自动续期）+ 可选 plan key | 订阅套餐与到期日、5 小时/周/订阅额度、名下 access key、会话健康 |
| **Command Code**（commandcode.ai） | `api.commandcode.ai` 未公开 `/alpha/*` 端点 | 一把 Bearer API key | GOAT/Pro/Max 等套餐、5 小时/周/月度窗口、余额、账期请求统计 |

特性：

- **密文落库**：凭据 AES-256-GCM 加密后存 SQLite（纯 Go 驱动，无 CGO），接口只回掩码
- **StepFun 会话自动续期**：后台每 60s 检查，TTL < 20 min 自动续；过期后续期会拿到降级的设备令牌，有护栏检测并拒绝落库
- **双鉴权面**：StepFun 的 plan key（永久）与 console 会话（限额数据）分开管理、分开探测，verdict 以永久面为准
- **MCP 只读**：查询面（列表/探测/汇总）开放给 agent；登记/续期/删除等写操作只走 REST
- 单二进制，无外部依赖（SQLite 内置）

## 快速开始

```bash
go build -o quota-mcp ./cmd/quota-mcp

# 生产请显式设置主密钥（64 hex 字符），否则按机器特征派生，换机器旧密文读不出
export QUOTA_MCP_MASTER_KEY=$(openssl rand -hex 32)

./quota-mcp -db data/quota-mcp.db -listen 127.0.0.1:8780
```

启动后：

- `http://127.0.0.1:8780/healthz` 健康检查
- `http://127.0.0.1:8780/api/stepfun/accounts` REST 列表
- `http://127.0.0.1:8780/mcp` MCP 端点

## 登记账户

### Command Code（两条凭据面）

**alpha / api_key 面**最简单，是一把永久 Bearer key：

```bash
curl -X POST http://127.0.0.1:8780/api/commandcode/accounts \
  -H 'Content-Type: application/json' \
  -d '{"service":"cc-myname","api_key":"user_xxx","label":"主力"}'
```

key 从 [commandcode.ai/settings/keys](https://commandcode.ai/settings/keys) 获取（只在创建时展示一次）。服务端先打 whoami 验证，被拒不落库。

**internal / 会话面**对应浏览器登录态：传 `session_text`（整段 `Cookie:` 头、`document.cookie` 串，或裸的 `__Secure-commandcode_prod_.session_token` 值）。服务端用 `billing/credits` 验证，探不通不落库。会话会过期，需从 CookieCloud 同步或重新从 DevTools 复制 cookie：

```bash
curl -X POST http://127.0.0.1:8780/api/commandcode/accounts \
  -H 'Content-Type: application/json' \
  -d '{"service":"cc-myname","session_text":"__Secure-commandcode_prod_.session_token=eyJ..."}'
```

两面并存时 api_key 优先。**每次登记都会覆盖本次提供的凭据面**——只带 `api_key` 重新登记会清掉已存的 session，反之亦然，轮换不会被静默跳过。

### StepFun（浏览器会话）

Oasis-Token 是 HttpOnly cookie，`document.cookie` 读不到，需要从浏览器 DevTools 的请求头里拷。把整段 `Cookie:` 头（或裸 token）贴给服务端：

```bash
curl -X POST http://127.0.0.1:8780/api/stepfun/accounts \
  -H 'Content-Type: application/json' \
  -d '{"service":"ai-412848664332275712","region":"ai","session_text":"Oasis-Token=eyJ...; Oasis-Webid=...","email":"me@example.com"}'
```

实测协议细节（移植时踩过的坑，均已处理）：

- `.ai` 的 Oasis-Token cookie 值是**两段 JWT 拼接**（8 段），console 只认整值，单取一段会 `token is illegal`
- 时间戳两站单位不同：`.ai` 返回秒级字符串，`.com` 返回毫秒数，按量级自动判断
- `.com` 的设备 token 只有 30 分钟寿命，且其 RefreshToken 会返回降级令牌——`.com` 会话需要定期重新导入
- 会话**过期后**再续期会拿到设备令牌（mode 1，数据面一律 `token is illegal`），所以必须过期前续；代码有降级护栏，检测到就不落库

## REST API

```
GET    /api/stepfun/accounts                     列表（掩码视图）
POST   /api/stepfun/accounts                     登记/更新（两条面至少探通一条才落库）
POST   /api/stepfun/accounts/{service}/probe     探测（console 认证失败自动续一次）
POST   /api/stepfun/accounts/{service}/renew     强制续期会话
POST   /api/stepfun/accounts/{service}/register?region=ai   注册匿名设备槽位（自测用）
DELETE /api/stepfun/accounts/{service}            删除
POST   /api/stepfun/probe                        全部探测（给 cron 用）

GET    /api/commandcode/accounts                 列表（掩码视图）
POST   /api/commandcode/accounts                 登记/更新（api_key 或 session_text；探通才落库）
POST   /api/commandcode/accounts/{service}/probe 探测
DELETE /api/commandcode/accounts/{service}        删除
POST   /api/commandcode/probe                    全部探测
```

## MCP 工具面（给 agent 查询）

两种接法，任选其一：

**1. Streamable HTTP**（挂载在 `/mcp`）——适合常驻部署。Hermes 的 `mcp_servers` 配置示例：

```yaml
mcp_servers:
  quota:
    url: http://<你的机器>:8780/mcp
```

**2. stdio**——适合客户端自行拉起服务的场景（Claude Code、容器、注册表一键安装）：

```bash
# 本地二进制
quota-mcp -stdio

# 或直接用发布好的镜像（零配置跑起来）
docker run -i --rm -v quota-mcp-data:/data ghcr.io/limitcool/quota-mcp:latest
```

Claude Code / 其他 MCP 客户端同理。

工具列表（全部只读）：

| 工具 | 说明 |
|---|---|
| `quota_list_accounts` | 列出全部账户：套餐、到期、剩余额度、会话/key 状态（掩码） |
| `quota_probe_account` | 实时探测单个账户（打上游，慢数秒） |
| `quota_probe_all` | 串行探测全部账户并刷新缓存 |
| `quota_status` | 汇总：各平台账户数、健康/限流/失效数量、每账户一句话状态 |
| `quota_check_alerts` | 触发中的告警：额度低于阈值、即将到期、会话掉线、key 失效、窗口超限 |
| `quota_report` | 定时播报 payload：各账户关键数字 + 当前告警 |

示例（问 agent「StepFun 额度还剩多少」→ 它调 `quota_status` / `quota_list_accounts`）：

```json
{
  "stepfun": {
    "total": 2, "healthy": 2, "attention": 0,
    "accounts": ["ai-4128…: 正常（10 模型）", "com-3766…: 正常（0 模型）"]
  },
  "commandcode": {
    "total": 1, "serving": 1, "limited": 0, "key_rejected": 0,
    "accounts": ["cc-limitcool: serving GOAT"]
  }
}
```

## 阈值告警 / 过期告警 / 定时播报

职责划分：**quota-mcp 负责“判定条件”**（它持有数据、有 60s 后台循环），**调度与投递是 agent 平台（hermes）的强项**。三种功能的接法：

### 1. 阈值告警 + 过期告警（事件驱动，push）

后台评估器：探测数据超 5 分钟自动刷新 → 规则评估 → SQLite 状态机（`alert_events`，firing/resolved）→ **只推跃迁瞬间**到 webhook（同一条告警不清除不重复推）。

规则五类：`credit_low`（剩余额度低于阈值）、`expiring_soon`（订阅/账期 N 天内结束）、`session_dead`（StepFun console 会话需重新导入）、`key_rejected`（Command Code key 401/403）、`window_limited`（节流窗口超限）。

```bash
QUOTA_MCP_ALERT_WEBHOOK_URL=http://<hermes>:8642/webhooks/quota \
QUOTA_MCP_ALERT_CREDIT_PCT=0.2 \
QUOTA_MCP_ALERT_EXPIRY_DAYS=7 \
./quota-mcp -listen 0.0.0.0:8780
```

跃迁时推送的 payload：

```json
{
  "source": "quota-mcp",
  "at": "2026-09-21T15:52:30Z",
  "fired":    [{"kind":"credit_low","provider":"stepfun","service":"ai-…","severity":"warn","title":"订阅额度即将耗尽","detail":"剩余 13%（阈值 20%），2026-10-20 重置"}],
  "resolved": []
}
```

**没有 webhook 也能用**（pull 模式）：hermes 的 cron 每 15–30 分钟跑一个 turn 调 `quota_check_alerts`（或 `GET /api/alerts?history=20`），有新告警就 `hermes send` 出去。

### 2. 定时播报（cron）

`quota_report`（或 `GET /api/report`）返回字段稳定的日报 payload：各账户套餐、到期、剩余额度、会话状态、窗口用量、请求统计 + 当前告警。hermes 已有的 9:30 cron 直接消费它：跑一个 turn 调工具 → 整理成消息 → `hermes send` 投递。quota-mcp 不重复造调度器。

### 3. 相关环境变量

| 变量 | 默认 | 含义 |
|---|---|---|
| `QUOTA_MCP_ALERT_CREDIT_PCT` | `0.2` | 剩余占比低于该值触发额度告警 |
| `QUOTA_MCP_ALERT_EXPIRY_DAYS` | `7` | 订阅/账期在该天数内结束触发到期告警 |
| `QUOTA_MCP_ALERT_WEBHOOK_URL` | — | 告警跃迁 POST 目标；空 = 只记账不推送（pull 模式） |

## 项目结构

```
cmd/quota-mcp/        入口（flag / env 配置，单端口双面）
internal/store/       SQLite + AES-256-GCM 加密 + 建表
internal/stepfun/     StepFun 协议客户端 + 账户登记册 + 后台续期器
internal/commandcode/ Command Code 协议客户端 + 账户登记册
internal/api/         REST 管理面（net/http，无框架）
internal/mcpsrv/      MCP 查询面（modelcontextprotocol/go-sdk）
internal/alerts/      告警规则 + firing/resolved 状态机 + webhook 推送
internal/digest/      定时播报 payload 组装
```

## 安全边界

- 密文只进库、不进日志、不回响应；任何接口只出掩码
- REST 含写操作，**只绑回环或内网**；要对外就把 MCP 面单独暴露（或加反代 +鉴权）
- 主密钥丢了 = 库里所有凭据读不出，请备份 `QUOTA_MCP_MASTER_KEY`

## Releases

每个 GitHub Release 附带 Linux / macOS / Windows（amd64 + arm64）二进制。取最新版：

```bash
# 例：linux amd64
curl -LO https://github.com/limitcool/quota-mcp/releases/latest/download/quota-mcp_linux_amd64
chmod +x quota-mcp_linux_amd64
```

## Docker

镜像发布在 `ghcr.io/limitcool/quota-mcp`（amd64 + arm64）：main 每次推送出 `:main`，打 tag 出 `:v1.0.0` / `:latest`。

```bash
docker run -d --name quota-mcp \
  -p 8780:8780 \
  -v quota-mcp-data:/data \
  -e QUOTA_MCP_MASTER_KEY=$(openssl rand -hex 32) \
  ghcr.io/limitcool/quota-mcp:latest
```

或用自带的 compose（`QUOTA_MCP_MASTER_KEY` 必填，写进 `.env`）：

```bash
echo "QUOTA_MCP_MASTER_KEY=$(openssl rand -hex 32)" > .env
docker compose up -d
```

数据库在 `/data` 卷里（`QUOTA_MCP_DB=/data/quota-mcp.db`）。**主密钥务必备份**——丢了库里所有凭据都读不出。

## License

MIT
