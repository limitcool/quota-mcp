package alerts

import (
	"strings"
	"testing"
	"time"
)

// 规则评估（纯函数，不打网络）。

func TestEvalStepfunCreditLow(t *testing.T) {
	cfg := Config{CreditLowPct: 0.2, ExpiryDays: 7}
	items := []map[string]any{{
		"service": "ai-412848664332275700",
		"console": map[string]any{
			"ok": true,
			"rate_limit": map[string]any{
				"credit_left_rate": 0.13,
				"credit_reset_at":  "2026-10-20T11:00:07Z",
			},
			"status": map[string]any{
				"ok":          true,
				"plan_name":   "Plus",
				"valid_until": "2026-12-04T06:02:47Z",
			},
		},
	}}
	got := evalStepfun(items[0], cfg)
	if len(got) != 1 || got[0].Kind != KindCreditLow {
		t.Fatalf("应触发一条 credit_low，得到 %+v", got)
	}
	if got[0].Severity != SevWarn {
		t.Fatalf("severity = %v", got[0].Severity)
	}
	if !strings.Contains(got[0].Detail, "13%") {
		t.Fatalf("详情应带剩余比例: %q", got[0].Detail)
	}
	// 高于阈值不触发
	items[0]["console"].(map[string]any)["rate_limit"].(map[string]any)["credit_left_rate"] = 0.5
	if n := len(evalStepfun(items[0], cfg)); n != 0 {
		t.Fatalf("额度充足不应触发，得到 %d 条", n)
	}
}

func TestEvalStepfunExpiringSoon(t *testing.T) {
	cfg := Config{CreditLowPct: 0.2, ExpiryDays: 7}
	base := func(validUntil string) map[string]any {
		return map[string]any{
			"service": "ai-x",
			"console": map[string]any{
				"ok":         true,
				"rate_limit": map[string]any{"credit_left_rate": 0.9},
				"status":     map[string]any{"ok": true, "valid_until": validUntil},
			},
		}
	}
	// 3 天后到期 → warn；1 天内 → critical；30 天后 → 不触发
	if got := evalStepfun(base(soon(3)), cfg); len(got) != 1 || got[0].Severity != SevWarn {
		t.Fatalf("3 天后期告警应 warn: %+v", got)
	}
	if got := evalStepfun(base(soon(0.5)), cfg); len(got) != 1 || got[0].Severity != SevCrit {
		t.Fatalf("12 小时内应 critical: %+v", got)
	}
	if got := evalStepfun(base(soon(30)), cfg); len(got) != 0 {
		t.Fatalf("30 天后不应触发: %+v", got)
	}
	// 已过期（负天数）不触发「即将到期」（那是事实而不是预警，面板上已显示）
	if got := evalStepfun(base(soon(-1)), cfg); len(got) != 0 {
		t.Fatalf("已过期不应触发即将到期: %+v", got)
	}
}

func TestEvalStepfunSessionDead(t *testing.T) {
	got := evalStepfun(map[string]any{"service": "com-x", "session_state": "needs_relogin"}, Config{})
	if len(got) != 1 || got[0].Kind != KindSessionDead || got[0].Severity != SevWarn {
		t.Fatalf("needs_relogin 应触发会话掉线告警: %+v", got)
	}
	// 没有 console 数据时也只报这一条（不连带报额度）
	if len(got) != 1 {
		t.Fatalf("应只有一条: %+v", got)
	}
}

func TestEvalStepfunConsoleDownDoesNotCryWolf(t *testing.T) {
	// console 整面不通但没掉线标记时，不制造额度/到期告警（数据不可信）
	got := evalStepfun(map[string]any{
		"service": "ai-x",
		"console": map[string]any{"ok": false, "status": map[string]any{"ok": false, "error": "unreachable"}},
	}, Config{})
	if len(got) != 0 {
		t.Fatalf("console 不可达不应触发额度/到期告警: %+v", got)
	}
}

func TestEvalCommandCode(t *testing.T) {
	cfg := Config{CreditLowPct: 0.2, ExpiryDays: 7}
	// key 被拒：直接 critical，不再评估其他
	got := evalCommandCode(map[string]any{"service": "cc-x", "verdict": "key_rejected"}, cfg)
	if len(got) != 1 || got[0].Kind != KindKeyRejected || got[0].Severity != SevCrit {
		t.Fatalf("key_rejected 应只触发一条 critical: %+v", got)
	}

	// 窗口超限 + 余额低 + 账期将尽
	full := map[string]any{
		"service":   "cc-x",
		"verdict":   "serving",
		"plan":      map[string]any{"plan_name": "GOAT", "monthly_credits_cap": 70.0, "current_period_end": soon(2)},
		"credits":   map[string]any{"monthly_credits": 8.0},
		"five_hour": map[string]any{"used": 14.0, "cap": 14.0, "exceeded": true},
		"weekly":    map[string]any{"used": 1.0, "cap": 35.0, "exceeded": false},
		"monthly":   map[string]any{"used": 62.0, "cap": 70.0, "exceeded": false},
	}
	kinds := map[string]bool{}
	for _, a := range evalCommandCode(full, cfg) {
		kinds[a.Kind] = true
	}
	for _, want := range []string{KindWindowLimited, KindCreditLow, KindExpiringSoon} {
		if !kinds[want] {
			t.Fatalf("应触发 %s，实际 %+v", want, kinds)
		}
	}
	// unreachable 不评估
	if got := evalCommandCode(map[string]any{"service": "cc-x", "verdict": "unreachable"}, cfg); len(got) != 0 {
		t.Fatalf("unreachable 不应触发: %+v", got)
	}
}

func TestFingerprintStable(t *testing.T) {
	a := Alert{Kind: KindCreditLow, Provider: "stepfun", Service: "ai-x"}
	b := Alert{Kind: KindCreditLow, Provider: "stepfun", Service: "ai-x"}
	c := Alert{Kind: KindCreditLow, Provider: "stepfun", Service: "ai-y"}
	if a.fingerprint() != b.fingerprint() {
		t.Fatal("同账户同规则指纹应稳定")
	}
	if a.fingerprint() == c.fingerprint() {
		t.Fatal("不同账户指纹应不同")
	}
}

// soon n 天后的 RFC3339 时间戳。
func soon(days float64) string {
	return nowISOOffset(days)
}

func nowISOOffset(days float64) string {
	return time.Now().UTC().Add(time.Duration(days * 24 * float64(time.Hour))).Format(time.RFC3339)
}

func TestEvalStepfunSessionExpiredLiveFlag(t *testing.T) {
	// 列表视图实时算出的 session.expired=true 也要触发（探测 state 可能陈旧）
	got := evalStepfun(map[string]any{
		"service": "ai-x",
		"session": map[string]any{"expired": true, "ttl_secs": -1441.0},
	}, Config{})
	if len(got) != 1 || got[0].Kind != KindSessionDead {
		t.Fatalf("session.expired 应触发会话掉线: %+v", got)
	}
}
