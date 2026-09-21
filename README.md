**English** | [简体中文](README.zh-CN.md)

# quota-mcp

A **usage & quota tracker for AI subscription accounts**. It pulls the balances, subscription expiry dates and rate-limit windows that are scattered across vendor dashboards into one place, and exposes them through both a **REST management API** and an **MCP query surface** — point your agent (Hermes, Claude Code, …) at it with one config line and it can answer "how much quota do I have left?" on its own.

Two platforms supported today:

| Platform | Data source | Credential | What you can see |
|---|---|---|---|
| **StepFun** (阶跃星辰, `.ai` intl / `.com` China) | `platform.stepfun.{ai,com}` console Connect RPC | Browser session (Oasis-Token, ~2 h, auto-renewed) + optional plan key | Plan & expiry, 5-hour / weekly / subscription credit windows, access keys under the account, session health |
| **Command Code** (commandcode.ai) | Undocumented `/alpha/*` endpoints on `api.commandcode.ai` | A single Bearer API key | Plan (GOAT/Pro/Max/…), 5-hour / weekly / monthly windows, balances, billing-period request stats |

Highlights:

- **Encrypted at rest**: credentials are AES-256-GCM encrypted into SQLite (pure-Go driver, no CGO); every endpoint returns masked views only
- **StepFun session auto-renewal**: a background goroutine checks every 60 s and renews any session whose TTL drops below 20 min. Renewing an *expired* session gets you a degraded device token — there is a guard that detects this and refuses to persist it
- **Dual auth planes**: StepFun's plan key (permanent) and console session (quota data) are managed and probed separately; the verdict is driven by the permanent plane
- **MCP is read-only**: the query surface (list / probe / summarize) is safe to hand to agents; enrol / renew / delete live on the REST side only
- Single binary, zero external services

## Quick start

```bash
go build -o quota-mcp ./cmd/quota-mcp

# In production set the master key explicitly (64 hex chars). Without it the key is
# derived from machine traits and old ciphertext becomes unreadable after a migration.
export QUOTA_MCP_MASTER_KEY=$(openssl rand -hex 32)

./quota-mcp -db data/quota-mcp.db -listen 127.0.0.1:8780
```

After startup:

- `http://127.0.0.1:8780/healthz` health check
- `http://127.0.0.1:8780/api/stepfun/accounts` REST list
- `http://127.0.0.1:8780/mcp` MCP endpoint

## Enrolling accounts

### Command Code (a single key — the easy one)

```bash
curl -X POST http://127.0.0.1:8780/api/commandcode/accounts \
  -H 'Content-Type: application/json' \
  -d '{"service":"cc-myname","api_key":"user_xxx","label":"primary"}'
```

Get the key from [commandcode.ai/settings/keys](https://commandcode.ai/settings/keys) (shown once at creation). The server validates it with `whoami` first and refuses to store a rejected key.

### StepFun (browser session)

`Oasis-Token` is an HttpOnly cookie, so `document.cookie` cannot read it — copy it from a request header in DevTools. Paste the whole `Cookie:` header (or the bare token) to the server:

```bash
curl -X POST http://127.0.0.1:8780/api/stepfun/accounts \
  -H 'Content-Type: application/json' \
  -d '{"service":"ai-412848664332275712","region":"ai","session_text":"Oasis-Token=eyJ...; Oasis-Webid=...","email":"me@example.com"}'
```

Protocol findings from real-world testing (all handled in code):

- The `.ai` `Oasis-Token` cookie value is **two JWTs concatenated** (8 segments); the console only accepts the whole value — a single segment gets you `token is illegal`
- Timestamp units differ per site: `.ai` returns second-level strings, `.com` returns milliseconds; the code infers by magnitude
- `.com` device tokens live only 30 minutes and its RefreshToken returns a degraded token — `.com` sessions need periodic re-import
- Renewing **after** expiry yields a device token (`mode 1`, data plane always `token is illegal`), so renewal must happen before expiry; a degradation guard refuses to store such tokens

## REST API

```
GET    /api/stepfun/accounts                     List (masked view)
POST   /api/stepfun/accounts                     Enrol/update (stored only if at least one plane probes OK)
POST   /api/stepfun/accounts/{service}/probe     Probe (auto-renews once on console auth failure)
POST   /api/stepfun/accounts/{service}/renew     Force-renew the console session
POST   /api/stepfun/accounts/{service}/register?region=ai   Register an anonymous device slot (self-test)
DELETE /api/stepfun/accounts/{service}           Delete
POST   /api/stepfun/probe                        Probe all (cron-friendly)

GET    /api/commandcode/accounts                 List (masked view)
POST   /api/commandcode/accounts                 Enrol (key validated via whoami first)
POST   /api/commandcode/accounts/{service}/probe Probe
DELETE /api/commandcode/accounts/{service}       Delete
POST   /api/commandcode/probe                    Probe all
```

## MCP surface (for agents)

Served as Streamable HTTP on `/mcp`. Example `mcp_servers` entry:

```yaml
mcp_servers:
  quota:
    url: http://<your-host>:8780/mcp
```

Works the same way from Claude Code or any other MCP client.

All tools are read-only:

| Tool | Description |
|---|---|
| `quota_list_accounts` | List every account: plan, expiry, remaining quota, session/key status (masked) |
| `quota_probe_account` | Live-probe one account (hits upstream, takes a few seconds) |
| `quota_probe_all` | Serially probe all accounts and refresh the cache |
| `quota_status` | Summary: per-platform counts of serving / limited / invalid / needs-relogin, plus a one-line status per account |

Example (`quota_status` output — what an agent would read to answer "how much quota is left?"):

```json
{
  "stepfun": {
    "total": 2, "healthy": 2, "attention": 0,
    "accounts": ["ai-4128…: ok (10 models)", "com-3766…: ok (0 models)"]
  },
  "commandcode": {
    "total": 1, "serving": 1, "limited": 0, "key_rejected": 0,
    "accounts": ["cc-limitcool: serving GOAT"]
  }
}
```

## Project layout

```
cmd/quota-mcp/        Entrypoint (flags/env config, one port serving both surfaces)
internal/store/       SQLite + AES-256-GCM encryption + schema
internal/stepfun/     StepFun protocol client + account registry + background renewer
internal/commandcode/ Command Code protocol client + account registry
internal/api/         REST management surface (net/http, no framework)
internal/mcpsrv/      MCP query surface (modelcontextprotocol/go-sdk)
```

## Security boundary

- Ciphertext goes to the DB only — never to logs, never to responses; every endpoint returns masks
- The REST surface contains writes: **bind it to loopback or a private network**. To expose it publicly, front it with a reverse proxy + auth and only publish the MCP path
- Losing the master key means every stored credential becomes unreadable — back up `QUOTA_MCP_MASTER_KEY`

## Releases

Binaries for Linux / macOS / Windows (amd64 + arm64) are attached to each GitHub Release. Grab the latest:

```bash
# example: linux amd64
curl -LO https://github.com/limitcool/quota-mcp/releases/latest/download/quota-mcp_linux_amd64
chmod +x quota-mcp_linux_amd64
```

## License

MIT
