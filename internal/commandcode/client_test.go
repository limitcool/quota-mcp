package commandcode

import (
	"strings"
	"testing"
)

// 纯函数单测：字段双拼写兼容、时间戳三形态、套餐最长前缀、窗口归一。

func TestFieldAcceptsBothSpellings(t *testing.T) {
	snake := map[string]any{"monthly_credits": 18.5, "current_period_end": "2026-10-01T00:00:00Z"}
	camel := map[string]any{"monthlyCredits": 18.5, "currentPeriodEnd": "2026-10-01T00:00:00Z"}
	for _, v := range []map[string]any{snake, camel} {
		if f, ok := f64Of(field(v, "monthly_credits", "monthlyCredits")); !ok || f != 18.5 {
			t.Fatalf("monthly_credits = %v %v", f, ok)
		}
		if s := strOf(field(v, "current_period_end", "currentPeriodEnd")); s != "2026-10-01T00:00:00Z" {
			t.Fatalf("current_period_end = %q", s)
		}
	}
	// null 视为不存在，往后找别名
	if field(map[string]any{"a": nil, "b": 1}, "a", "b") != 1 {
		t.Fatal("null 后应继续找别名")
	}
	if field(map[string]any{}, "x") != nil {
		t.Fatal("缺失应返回 nil")
	}
}

func TestISOFromAnyHandlesAllTimestampForms(t *testing.T) {
	// 毫秒数
	if got := ISOFromAny(1_767_225_600_000.0); got != "2026-01-01T00:00:00Z" {
		t.Fatalf("ms → %q", got)
	}
	// 秒数（<1e12 按秒处理）
	if got := ISOFromAny(1_767_225_600.0); got != "2026-01-01T00:00:00Z" {
		t.Fatalf("secs → %q", got)
	}
	// ISO 字符串
	if got := ISOFromAny("2026-01-01T08:00:00+08:00"); got != "2026-01-01T00:00:00Z" {
		t.Fatalf("iso → %q", got)
	}
	// 纯数字字符串
	if got := ISOFromAny("1767225600"); got != "2026-01-01T00:00:00Z" {
		t.Fatalf("numeric string → %q", got)
	}
	for _, bad := range []any{nil, "", 0.0, "not-a-time"} {
		if got := ISOFromAny(bad); got != "" {
			t.Fatalf("ISOFromAny(%v) = %q, 期望空", bad, got)
		}
	}
}

func TestPlanInfoLongestPrefixWins(t *testing.T) {
	cases := []struct {
		planID  string
		name    string
		credits float64
		ok      bool
	}{
		{"individual-pro-v1", "Pro", 80, true},
		{"individual-pro", "Pro", 30, true},
		{"individual-goat", "GOAT", 70, true},
		{"INDIVIDUAL_ULTRA", "Ultra", 300, true}, // 大小写与下划线归一
		{"teams-pro", "Teams Pro", 40, true},
		{"individual-unknown-plan", "", 0, false},
		{"", "", 0, false},
	}
	for _, c := range cases {
		p, ok := planInfo(c.planID)
		if ok != c.ok || p.Name != c.name || p.MonthlyCredits != c.credits {
			t.Fatalf("planInfo(%q) = %+v %v, want %s/%v %v", c.planID, p, ok, c.name, c.credits, c.ok)
		}
	}
}

func TestNormalizeWindow(t *testing.T) {
	// camel + exceeded=false
	w := normalizeWindow(map[string]any{"used": 1.23, "cap": 5.0, "exceeded": false, "resetAt": 1_767_225_600_000.0})
	if w.Used != 1.23 || w.Cap != 5.0 || w.Exceeded || w.ResetAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("camel window = %+v", w)
	}
	// snake + reset_at 秒级
	w = normalizeWindow(map[string]any{"used": 1.2, "cap": 5.0, "exceeded": false, "reset_at": 1_767_225_600.0})
	if w.ResetAt != "2026-01-01T00:00:00Z" {
		t.Fatalf("snake window reset = %q", w.ResetAt)
	}
	// used>=cap 时即使没有 exceeded 字段也应判定超限
	w = normalizeWindow(map[string]any{"used": 5.0, "cap": 5.0, "resetAt": 0.0})
	if !w.Exceeded {
		t.Fatal("used>=cap 应判 exceeded")
	}
	// exceeded 可能是字符串 "true"
	w = normalizeWindow(map[string]any{"used": 9.0, "cap": 5.0, "exceeded": "true"})
	if !w.Exceeded {
		t.Fatalf("字符串 true 应判 exceeded: %+v", w)
	}
	// 空窗口
	w = normalizeWindow(nil)
	if w.Used != 0 || w.Cap != 0 || w.ResetAt != "" {
		t.Fatalf("空窗口 = %+v", w)
	}
}

func TestPickWindowAliases(t *testing.T) {
	wl := map[string]any{"five_hour": map[string]any{"used": 1.0}, "weekly": map[string]any{"used": 2.0}}
	if pickWindow(wl, "fiveHour", "five_hour", "rolling5h", "5h") == nil {
		t.Fatal("five_hour 应命中")
	}
	if pickWindow(wl, "weekly", "week") == nil {
		t.Fatal("weekly 应命中")
	}
	if pickWindow(wl, "monthly") != nil {
		t.Fatal("monthly 应未命中")
	}
}

func TestDeriveMonthly(t *testing.T) {
	out := map[string]any{
		"plan":    map[string]any{"plan_id": "individual-goat", "monthly_credits_cap": 70.0, "current_period_end": "2026-10-01T00:00:00Z"},
		"credits": map[string]any{"monthly_credits": 18.5},
	}
	m := deriveMonthly(out)
	if m["cap"] != 70.0 || m["used"] != 51.5 || m["exceeded"] != false || m["estimated"] != true {
		t.Fatalf("monthly = %+v", m)
	}
	if m["reset_at"] != "2026-10-01T00:00:00Z" {
		t.Fatalf("reset_at = %v", m["reset_at"])
	}
	// 未知套餐推不出窗口
	if deriveMonthly(map[string]any{"plan": map[string]any{"plan_id": "mystery"}}) != nil {
		t.Fatal("未知套餐应返回 nil")
	}
	// 没有套餐信息
	if deriveMonthly(map[string]any{}) != nil {
		t.Fatal("无套餐应返回 nil")
	}
}

func TestVerdict(t *testing.T) {
	cases := []struct {
		name string
		out  map[string]any
		want string
	}{
		{"serving", map[string]any{"account": map[string]any{"id": "u_1"}, "credits": map[string]any{"monthly_credits": 1.0}}, "serving"},
		{"serving via session (no account)", map[string]any{"credits": map[string]any{"monthly_credits": 1.0}, "cred_source": "session"}, "serving"},
		{"five hour exceeded", map[string]any{
			"account":   map[string]any{"id": "u_1"},
			"credits":   map[string]any{"monthly_credits": 1.0},
			"five_hour": map[string]any{"exceeded": true},
		}, "limited"},
		{"weekly exceeded", map[string]any{
			"account": map[string]any{"id": "u_1"},
			"credits": map[string]any{"monthly_credits": 1.0},
			"weekly":  map[string]any{"exceeded": true},
		}, "limited"},
		{"monthly exceeded", map[string]any{
			"account": map[string]any{"id": "u_1"},
			"credits": map[string]any{"monthly_credits": 1.0},
			"monthly": map[string]any{"exceeded": true},
		}, "limited"},
		{"key rejected", map[string]any{"account": nil, "verdict": "key_rejected"}, "key_rejected"},
		{"session expired", map[string]any{"session_state": "needs_refresh", "cred_source": "session"}, "session_expired"},
		{"unreachable", map[string]any{"account": nil}, "unreachable"},
		{"unreachable session", map[string]any{"cred_source": "session"}, "unreachable"},
	}
	for _, c := range cases {
		if got := verdict(c.out); got != c.want {
			t.Fatalf("%s: verdict = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestValidService(t *testing.T) {
	for _, ok := range []string{"cc-maxeagle", "cc_u_123", "a.b", "X9"} {
		if !validService(ok) {
			t.Fatalf("%q 应合法", ok)
		}
	}
	for _, bad := range []string{"", "bad name", "../etc", "a/b", "a;b"} {
		if validService(bad) {
			t.Fatalf("%q 应非法", bad)
		}
	}
}

func TestKeyRejectedErrorText(t *testing.T) {
	e := &Fail{Kind: FailKeyRejected, Code: 401}
	if !strings.Contains(e.Error(), "commandcode.ai/settings") {
		t.Fatalf("错误文本应指引去 settings: %q", e.Error())
	}
}

func TestParseSessionText(t *testing.T) {
	// 整串 document.cookie
	got, err := ParseSessionText("a=b; __Secure-commandcode_prod_.session_token=AQ7n7BNIxyz; __stripe_mid=s")
	if err != nil || got != "AQ7n7BNIxyz" {
		t.Fatalf("整串 cookie 解析失败: %q %v", got, err)
	}
	// Cookie 头行（大小写不敏感）
	got, err = ParseSessionText("Cookie: __SECURE-COMMANDCODE_PROD_.SESSION_TOKEN=TOK123; other=1")
	if err != nil || got != "TOK123" {
		t.Fatalf("Cookie 头解析失败: %q %v", got, err)
	}
	// 裸值
	got, err = ParseSessionText("AQ7n7BNI-opaque.token_value")
	if err != nil || got != "AQ7n7BNI-opaque.token_value" {
		t.Fatalf("裸值解析失败: %q %v", got, err)
	}
	// cookie 值带 %XX 转义应解码
	got, err = ParseSessionText("a=b; __Secure-commandcode_prod_.session_token=AQ7n%2Evalue; c=d")
	if err != nil || got != "AQ7n.value" {
		t.Fatalf("转义值未解码: %q %v", got, err)
	}
	// 空 / 找不到
	if _, err := ParseSessionText(""); err == nil {
		t.Fatal("空串应报错")
	}
	if _, err := ParseSessionText("foo=bar; baz=qux"); err == nil {
		t.Fatal("没有 session_token 应报错")
	}
}

// 名字在串尾且无 = 时不得 panic（曾 slice bounds out of range [41:40]），应回明确错误。
func TestParseSessionTextNameAtTailNoPanic(t *testing.T) {
	name := SessionCookieName
	inputs := []string{
		name,                 // 裸名字
		"Cookie: " + name,    // Cookie 头，名字在尾
		"a=b; " + name,       // cookie 串，名字在尾
		"a=b; " + name + " ", // 尾随空白
	}
	for _, in := range inputs {
		got, err := ParseSessionText(in)
		if err == nil {
			t.Fatalf("输入 %q 应报错，却得到 %q", in, got)
		}
		if got != "" {
			t.Fatalf("输入 %q 应返回空 token，却得到 %q", in, got)
		}
	}
}

// 裸值分支不得误收非 token：含 ',' 的输入拒绝；含 '=' 但 key 不是 session 名拒绝。
func TestParseSessionTextRejectsNonTokens(t *testing.T) {
	for _, in := range []string{
		"abc,def",   // ',' 是 cookie 分隔符，不可能是 token
		"abc=def==", // '=' 左侧不是 session 名
		"foo=bar",   // 普通键值
		"a=b, c=d",  // cookie 串但无 session_token
	} {
		got, err := ParseSessionText(in)
		if err == nil {
			t.Fatalf("输入 %q 本应拒绝，却原样回传 %q", in, got)
		}
	}
}

func TestCredentialModes(t *testing.T) {
	if (Credential{Key: "k"}).sessionMode() {
		t.Fatal("有 key 时不应走 session 模式")
	}
	if !(Credential{Session: "s"}).sessionMode() {
		t.Fatal("只有 session 时应走 session 模式")
	}
	if (Credential{Key: "k", Session: "s"}).sessionMode() {
		t.Fatal("两者都有时优先 key，不应走 session 模式")
	}
	if (Credential{Key: "k", Session: "s"}).describe() != "api_key" {
		t.Fatal("describe 应报 api_key")
	}
	if (Credential{Session: "s"}).describe() != "session" {
		t.Fatal("describe 应报 session")
	}
}

func TestSessionExpiredErrorText(t *testing.T) {
	e := &Fail{Kind: FailSessionExpired, Code: 401}
	if !strings.Contains(e.Error(), "CookieCloud") {
		t.Fatalf("session 过期错误文本应指引 CookieCloud: %q", e.Error())
	}
	if !e.NeedsRefresh() {
		t.Fatal("session 过期应 NeedsRefresh")
	}
}
