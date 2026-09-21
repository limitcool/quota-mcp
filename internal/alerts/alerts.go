// Package alerts 实现阈值/过期告警引擎。
//
// 职责划分：quota-mcp 持有数据、有 60s 后台循环，所以**条件判定**放这边；
// 调度与投递（cron、发微信）是 hermes 的强项，那边只做消费：
//
//	quota_check_alerts / GET /api/alerts   当前触发的告警（pull 模式）
//	POST /webhook/alert                    状态跃迁时主动推（push 模式，配 QUOTA_MCP_ALERT_WEBHOOK_URL）
//	quota_report / GET /api/report         定时播报 payload（hermes cron 消费）
//
// 状态机：firing → resolved，同一 fingerprint 不重复触发；每次跃迁记历史，
// webhook 只推跃迁瞬间（notified 标记保证至少一次）。
package alerts

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Severity 告警级别。
type Severity string

const (
	SevInfo Severity = "info"
	SevWarn Severity = "warn"
	SevCrit Severity = "critical"
)

// 告警种类。
const (
	KindCreditLow     = "credit_low"     // 剩余额度低于阈值
	KindExpiringSoon  = "expiring_soon"  // 订阅即将到期
	KindSessionDead   = "session_dead"   // console 会话掉线，需重新登录
	KindKeyRejected   = "key_rejected"   // API key 被拒
	KindWindowLimited = "window_limited" // 节流窗口超限
)

// Alert 一条触发中的条件。指纹 = provider+service+kind，用于去重。
type Alert struct {
	Kind      string   `json:"kind"`
	Provider  string   `json:"provider"`
	Service   string   `json:"service"`
	Severity  Severity `json:"severity"`
	Title     string   `json:"title"`
	Detail    string   `json:"detail"`
	Value     any      `json:"value,omitempty"`
	Threshold any      `json:"threshold,omitempty"`
}

func (a Alert) fingerprint() string {
	sum := sha256.Sum256([]byte(a.Provider + "|" + a.Service + "|" + a.Kind))
	return hex.EncodeToString(sum[:8])
}

// Config 全局告警阈值（环境变量注入；按账户覆盖留给后续设置表）。
type Config struct {
	// CreditLowPct 剩余额度低于该百分比触发（0-1，默认 0.2）
	CreditLowPct float64
	// ExpiryDays 订阅在该天数内到期触发（默认 7）
	ExpiryDays int
}

func DefaultConfig() Config {
	return Config{CreditLowPct: 0.20, ExpiryDays: 7}
}

// ---------------------------------------------------------------- 规则评估（纯函数）

func lowerThan(rate any, threshold float64) (float64, bool) {
	v, ok := rate.(float64)
	if !ok {
		return 0, false
	}
	return v, v < threshold
}

// daysUntil ISO 时间距现在的天数（负 = 已过期）。
func daysUntil(iso string) (float64, bool) {
	if iso == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, iso)
	if err != nil {
		return 0, false
	}
	return time.Until(t).Hours() / 24, true
}

// evalStepfun 按 stepfun 视图（List 的返回元素）评估告警。
func evalStepfun(a map[string]any, cfg Config) []Alert {
	svc, _ := a["service"].(string)
	out := []Alert{}
	console, _ := a["console"].(map[string]any)

	// 会话掉线：plan 面（永久 key）不受影响，但额度数据没了。
	// 两个信号都认：探测时判定的 needs_relogin，以及列表视图实时算出的 expired。
	if a["session_state"] == "needs_relogin" || sessionExpired(a) {
		out = append(out, Alert{
			Kind: KindSessionDead, Provider: "stepfun", Service: svc, Severity: SevWarn,
			Title: "console 会话已掉线", Detail: "自动续期未救回，需从浏览器重新导入会话；plan key 不受影响",
		})
	}

	if console == nil {
		return out
	}
	// 订阅额度剩余不足
	if rl, ok := console["rate_limit"].(map[string]any); ok {
		if left, below := lowerThan(rl["credit_left_rate"], cfg.CreditLowPct); below {
			out = append(out, Alert{
				Kind: KindCreditLow, Provider: "stepfun", Service: svc, Severity: SevWarn,
				Title:  "订阅额度即将耗尽",
				Detail: fmt.Sprintf("剩余 %.0f%%（阈值 %.0f%%），%s 重置", left*100, cfg.CreditLowPct*100, textOr(rl["credit_reset_at"], "未知时间")),
				Value:  left, Threshold: cfg.CreditLowPct,
			})
		}
	}
	// 订阅即将到期
	if st, ok := console["status"].(map[string]any); ok && st["ok"] != false {
		if d, ok := daysUntil(textOr(st["valid_until"], "")); ok && d >= 0 && d <= float64(cfg.ExpiryDays) {
			sev := SevWarn
			if d <= 1 {
				sev = SevCrit
			}
			out = append(out, Alert{
				Kind: KindExpiringSoon, Provider: "stepfun", Service: svc, Severity: sev,
				Title: "订阅即将到期", Detail: fmt.Sprintf("有效期至 %s（剩 %.1f 天）", st["valid_until"], d),
				Value: d, Threshold: cfg.ExpiryDays,
			})
		}
	}
	return out
}

// evalCommandCode 按 commandcode 视图评估告警。
func evalCommandCode(a map[string]any, cfg Config) []Alert {
	svc, _ := a["service"].(string)
	out := []Alert{}

	switch a["verdict"] {
	case "key_rejected":
		out = append(out, Alert{
			Kind: KindKeyRejected, Provider: "commandcode", Service: svc, Severity: SevCrit,
			Title: "API key 已失效", Detail: "whoami 返回 401/403，请到 commandcode.ai/settings/keys 重新签发",
		})
		return out
	case "session_expired":
		out = append(out, Alert{
			Kind: KindSessionDead, Provider: "commandcode", Service: svc, Severity: SevCrit,
			Title: "会话已过期", Detail: "session_token 被拒（401），请重新同步 commandcode.ai 登录态（CookieCloud 或从 DevTools 手动复制 session cookie）",
		})
		return out
	case "unreachable":
		return out
	}

	// 窗口超限（5 小时 / 周 / 月）
	for _, k := range []struct{ field, label string }{
		{"five_hour", "5 小时"}, {"weekly", "周"}, {"monthly", "月度"},
	} {
		if w, ok := a[k.field].(map[string]any); ok && w["exceeded"] == true {
			out = append(out, Alert{
				Kind: KindWindowLimited, Provider: "commandcode", Service: svc, Severity: SevWarn,
				Title: k.label + "窗口已超限", Detail: "请求会被服务端拦掉，等窗口重置",
			})
		}
	}

	// 月度余额不足：剩余 / 套餐额度 < 阈值
	credits, _ := a["credits"].(map[string]any)
	plan, _ := a["plan"].(map[string]any)
	if credits != nil && plan != nil {
		remaining, ok1 := credits["monthly_credits"].(float64)
		cap, ok2 := plan["monthly_credits_cap"].(float64)
		if ok1 && ok2 && cap > 0 {
			left := remaining / cap
			if left < cfg.CreditLowPct {
				out = append(out, Alert{
					Kind: KindCreditLow, Provider: "commandcode", Service: svc, Severity: SevWarn,
					Title:  "月度额度即将耗尽",
					Detail: fmt.Sprintf("剩余 %.1f / %.0f credits（%.0f%%，阈值 %.0f%%）", remaining, cap, left*100, cfg.CreditLowPct*100),
					Value:  left, Threshold: cfg.CreditLowPct,
				})
			}
		}
	}

	// 账期即将结束（到期不续就停）
	if plan != nil {
		if d, ok := daysUntil(textOr(plan["current_period_end"], "")); ok && d >= 0 && d <= float64(cfg.ExpiryDays) {
			sev := SevWarn
			if d <= 1 {
				sev = SevCrit
			}
			out = append(out, Alert{
				Kind: KindExpiringSoon, Provider: "commandcode", Service: svc, Severity: sev,
				Title: "账期即将结束", Detail: fmt.Sprintf("账期至 %s（剩 %.1f 天）", plan["current_period_end"], d),
				Value: d, Threshold: cfg.ExpiryDays,
			})
		}
	}
	return out
}

func textOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

// sessionExpired 列表视图里实时算出的会话过期标记（不依赖探测时写回的 state）。
func sessionExpired(a map[string]any) bool {
	if s, ok := a["session"].(map[string]any); ok {
		if e, ok := s["expired"].(bool); ok {
			return e
		}
	}
	return false
}
