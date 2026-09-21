package stepfun

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// 以下用例移植自 keyhelm 的 Rust 单测，只覆盖不联网的纯逻辑。

func TestRegionParsesAndCarriesAppID(t *testing.T) {
	if r, ok := ParseRegion("oversea"); !ok || r != RegionAi {
		t.Fatalf("oversea → %v %v", r, ok)
	}
	if r, ok := ParseRegion(" CN "); !ok || r != RegionCom {
		t.Fatalf("CN → %v %v", r, ok)
	}
	if got := RegionAi.AppID(); got != "20700" {
		t.Fatalf("ai appId = %q", got)
	}
	if got := RegionCom.AppID(); got != "10300" {
		t.Fatalf("com appId = %q", got)
	}
	if _, ok := ParseRegion("nope"); ok {
		t.Fatal("nope 不应解析成功")
	}
	if got := RegionAi.Console(); got != "https://platform.stepfun.ai" {
		t.Fatalf("console = %q", got)
	}
	if got := RegionCom.API(); got != "https://api.stepfun.com" {
		t.Fatalf("api = %q", got)
	}
}

func TestMaskKeepsConsoleComparablePrefixAndSuffix(t *testing.T) {
	// 控制台显示 first6..last6，new-api 的 key_preview 是前 8 位，两者都要能对齐
	if got := Mask("3ljFHUabcdefghSC1BVp"); got != "3ljFHU..SC1BVp" {
		t.Fatalf("mask = %q", got)
	}
	if got := Mask("short"); got != "s…t" {
		t.Fatalf("mask short = %q", got)
	}
}

func TestSessionTextAcceptsCookieHeaderAndBareJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjIwMDAwMDAwMDB9.sig"
	for _, input := range []string{
		"acw_tc=abc; Oasis-Token=" + jwt + "; Oasis-Webid=deadbeef; other=1",
		"Oasis-Token: " + jwt + "\nOasis-Webid: deadbeef",
		"Oasis-Webid=deadbeef;Oasis-Token=" + jwt,
	} {
		s, err := ParseSessionText(input)
		if err != nil {
			t.Fatalf("拒绝 %q: %v", input, err)
		}
		if s.Token != jwt {
			t.Fatalf("token = %q", s.Token)
		}
		if s.Webid != "deadbeef" {
			t.Fatalf("webid = %q (%q)", s.Webid, input)
		}
	}
	// 裸 JWT 时自动补一个 32 hex 的 webid
	s, err := ParseSessionText(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Webid) != 32 {
		t.Fatalf("webid len = %d", len(s.Webid))
	}
	if _, err := ParseSessionText("nothing here"); err == nil {
		t.Fatal("空文本应报错")
	}
	if _, err := ParseSessionText("Oasis-Token=notajwt"); err == nil {
		t.Fatal("非 JWT 形状应报错")
	}
}

func TestSessionTextAcceptsConcatenatedJWTs(t *testing.T) {
	// 实测浏览器里 Oasis-Token cookie 是两段 JWT 拼接（8 段、中间夹空段），
	// console 只认整值：单取任何一段都回 token is illegal。解析器必须原样保留。
	a := "eyJhbGciOiJIUzI1NiJ9.eyJvYXNpc19pZCI6IjQxMjg0ODY2NDMzMjI3NzAwMCIsIm1vZGUiOjJ9.aaa"
	b := "eyJhbGciOiJIUzI1NiJ9.eyJvYXNpc19pZCI6IjQxMjg0ODY2NDMzMjI3NzEyIiwibW9kZSI6MX0.bbb"
	full := a + ".." + b
	s, err := ParseSessionText("Oasis-Token=" + full + "; Oasis-Webid=deadbeef")
	if err != nil {
		t.Fatalf("拼接 JWT 被拒: %v", err)
	}
	if s.Token != full {
		t.Fatalf("应原样保留整值，得到 %q", s.Token)
	}
	if s.UID() != "412848664332277000" {
		t.Fatalf("uid = %q", s.UID())
	}
	if s.Webid != "deadbeef" {
		t.Fatalf("webid = %q", s.Webid)
	}
	// 值里混了别的内容时，仍要能捞出第一个完整 JWT
	s2, err := ParseSessionText("Oasis-Token=" + a + " 后缀垃圾")
	if err != nil {
		t.Fatalf("混合文本被拒: %v", err)
	}
	if s2.Token != a {
		t.Fatalf("应捞出第一段 JWT，得到 %q", s2.Token)
	}
}

func TestSummaryNeverCarriesTheTokenItself(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJvYXNpc19pZCI6NDEyODQ4NjY0MzMyMjc1NzEyLCJleHAiOjIwMDAwMDAwMDAsIm1vZGUiOjJ9.sig"
	s := &Session{Token: jwt, Webid: "db42d03afbf4fe028e73af00e3991716"}
	v := SessionSummary(s)
	if v["uid"] != "412848664332275712" {
		t.Fatalf("uid = %v", v["uid"])
	}
	if v["mode"] != int64(2) {
		t.Fatalf("mode = %v", v["mode"])
	}
	if v["expired"] != false {
		t.Fatalf("expired = %v", v["expired"])
	}
	if v["token_len"] != len(jwt) {
		t.Fatalf("token_len = %v", v["token_len"])
	}
	dumped := mustJSON(v)
	if strings.Contains(dumped, "eyJ") {
		t.Fatalf("摘要里泄漏了 token: %s", dumped)
	}
}

func TestJWTClaimsAreReadWithoutVerifying(t *testing.T) {
	// exp=2000000000 (2033) — 只验证能读出来，不验证签名
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJ1aWQiOiI0MTI4NDg2NjQzMzIyNzU3MTIiLCJleHAiOjIwMDAwMDAwMDB9.sig"
	s := &Session{Token: jwt, Webid: "w"}
	exp, ok := s.exp()
	if !ok || exp != 2_000_000_000 {
		t.Fatalf("exp = %d %v", exp, ok)
	}
	if uid := s.UID(); uid != "412848664332275712" {
		t.Fatalf("uid = %q", uid)
	}
	if ttl, ok := s.TTL(); !ok || ttl <= 0 {
		t.Fatalf("ttl = %d %v", ttl, ok)
	}
}

func TestFailureClassificationCoversBothPlanes(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   FailKind
	}{
		{401, `{"message":"auth failed: token is missing"}`, FailTokenMissing},
		{401, "auth failed: token is illegal", FailTokenIllegal},
		{400, `{"code":"CODE_TOKEN_MISSING"}`, FailTokenMissing},
		{400, "oasis header is invalid", FailHeaderRejected},
		{401, "auth failed: token is expired", FailTokenExpired},
		{500, "boom", FailHTTP},
	}
	for _, c := range cases {
		if got := classify(c.status, c.body).Kind; got != c.want {
			t.Fatalf("classify(%d, %q) = %v, want %v", c.status, c.body, got, c.want)
		}
	}
	// 对齐前端：过期和非法都先试续期，缺 token 才是没登记过
	if !(&Fail{Kind: FailTokenIllegal}).ShouldAttemptRenew() {
		t.Fatal("illegal 应尝试续期")
	}
	if !(&Fail{Kind: FailTokenExpired}).ShouldAttemptRenew() {
		t.Fatal("expired 应尝试续期")
	}
	if (&Fail{Kind: FailTokenMissing}).ShouldAttemptRenew() {
		t.Fatal("missing 不应尝试续期")
	}
	if !(&Fail{Kind: FailTokenMissing}).NeedsRelogin() {
		t.Fatal("missing 应要求重新登录")
	}
}

func TestAcceptsBothJSONFieldSpells(t *testing.T) {
	snake := map[string]any{"five_hour_usage_left_rate": 0.42, "weekly_usage_reset_time": 1_780_000_000_000.0}
	camel := map[string]any{"fiveHourUsageLeftRate": 0.42, "weeklyUsageResetTime": 1_780_000_000_000.0}
	a := RenderRateLimit(snake)
	b := RenderRateLimit(camel)
	if a["five_hour_left_rate"] != 0.42 || b["five_hour_left_rate"] != 0.42 {
		t.Fatalf("left_rate: %v / %v", a["five_hour_left_rate"], b["five_hour_left_rate"])
	}
	if a["weekly_reset_at"] != b["weekly_reset_at"] {
		t.Fatalf("reset_at: %v vs %v", a["weekly_reset_at"], b["weekly_reset_at"])
	}
	if s, _ := a["weekly_reset_at"].(string); !strings.HasSuffix(s, "Z") {
		t.Fatalf("reset_at 不是 ISO: %v", a["weekly_reset_at"])
	}
}

func TestCreditWindowIsReadOutOfTheNestedMessage(t *testing.T) {
	v := map[string]any{
		"plan_credit_rate_limit": map[string]any{
			"subscription_Credit_left_rate":  0.9,
			"subscription_Credit_reset_time": 1_780_000_000_000.0,
		},
	}
	r := RenderRateLimit(v)
	if r["credit_left_rate"] != 0.9 {
		t.Fatalf("credit_left_rate = %v", r["credit_left_rate"])
	}
	if s, _ := r["credit_reset_at"].(string); !strings.HasSuffix(s, "Z") {
		t.Fatalf("credit_reset_at 不是 ISO: %v", r["credit_reset_at"])
	}
}

func TestEpochConversionIsStable(t *testing.T) {
	if got := ISOFromMs(1_767_225_600_000); got != "2026-01-01T00:00:00Z" {
		t.Fatalf("iso = %q", got)
	}
	// .ai 控制台返回的是秒级字符串（如 credit_reset_time=1792494007），不能当毫秒再除
	if got := ISOFromMs(1_792_494_007); got != "2026-10-20T11:00:07Z" {
		t.Fatalf("秒级时间戳 iso = %q", got)
	}
	if got := ISOFromMs(0); got != "" {
		t.Fatalf("iso(0) = %q", got)
	}
	if got := ISOFromSecs(2_000_000_000); got != "2033-05-18T03:33:20Z" {
		t.Fatalf("iso_from_secs = %q", got)
	}
}

func TestVerdictPrefersTheDurablePlane(t *testing.T) {
	acc := &Account{Service: "x", Region: RegionAi, AccessKey: "sk-aaaaaaaaaaaaaaa1"}
	if got := verdict(acc, map[string]any{"plan": map[string]any{"ok": true, "model_count": 7}}); got != "serving" {
		t.Fatalf("verdict = %q", got)
	}
	// console 会话掉了，但 plan 面还活着 → 仍然是 serving（不能因为会话过期报警）
	withSess := &Account{Service: "x", Region: RegionAi, AccessKey: "sk-x", Session: &Session{Token: "a.b.c", Webid: "w"}}
	got := verdict(withSess, map[string]any{
		"plan":    map[string]any{"ok": true, "model_count": 10},
		"console": map[string]any{"ok": true},
	})
	if got != "serving+quota" {
		t.Fatalf("verdict = %q", got)
	}
	if got := verdict(acc, map[string]any{"plan": map[string]any{"ok": true, "model_count": 2}}); got != "no_plan" {
		t.Fatalf("verdict = %q", got)
	}
	if got := verdict(acc, map[string]any{"plan": map[string]any{"ok": false, "kind": "token_illegal"}}); got != "not_serving" {
		t.Fatalf("verdict = %q", got)
	}
	if got := verdict(acc, map[string]any{"plan": map[string]any{"ok": false, "kind": "not_enrolled"}}); got != "key_not_enrolled" {
		t.Fatalf("verdict = %q", got)
	}
	// 只登记了会话（没 access_key）且控制台能打通 → console_only，绝不能报成 key_not_enrolled
	sessOnly := &Account{Service: "x", Region: RegionAi, Session: &Session{Token: "a.b.c", Webid: "w"}}
	if got := verdict(sessOnly, map[string]any{
		"plan":    map[string]any{"ok": false, "kind": "not_enrolled"},
		"console": map[string]any{"ok": true},
	}); got != "console_only" {
		t.Fatalf("session-only console ok verdict = %q, want console_only", got)
	}
	// 会话掉了（console 不通）且没 key → 才该是 key_not_enrolled
	if got := verdict(sessOnly, map[string]any{
		"plan":    map[string]any{"ok": false, "kind": "not_enrolled"},
		"console": map[string]any{"ok": false},
	}); got != "key_not_enrolled" {
		t.Fatalf("session-only console down verdict = %q", got)
	}
	if got := verdict(acc, map[string]any{"plan": map[string]any{"ok": false, "kind": "unreachable"}}); got != "unreachable" {
		t.Fatalf("verdict = %q", got)
	}
	if got := verdict(acc, map[string]any{}); got != "unknown" {
		t.Fatalf("verdict = %q", got)
	}
}

func TestValidService(t *testing.T) {
	for _, ok := range []string{"ai-412848664332275712", "cn_1380", "a.b", "X9"} {
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

func TestIsDegradedRenewal(t *testing.T) {
	// 登录态（mode 2）续成设备态（mode 1）= 降级，绝不能落库
	user := &Session{Token: jwtWith(map[string]any{"oasis_id": "412848664332275712", "mode": 2.0})}
	device := &Session{Token: jwtWith(map[string]any{"oasis_id": "380743381888032768", "mode": 1.0})}
	if !isDegradedRenewal(user, device) {
		t.Fatal("登录态续成设备态应判降级")
	}
	// 同 mode 2、同 uid = 正常续期
	fresh := &Session{Token: jwtWith(map[string]any{"oasis_id": "412848664332275712", "mode": 2.0, "exp": 2000000000.0})}
	if isDegradedRenewal(user, fresh) {
		t.Fatal("同账户续期不应判降级")
	}
	// uid 无故变化同样可疑（设备令牌的设备号不是账户号）
	other := &Session{Token: jwtWith(map[string]any{"oasis_id": "999999999999999999", "mode": 2.0})}
	if !isDegradedRenewal(user, other) {
		t.Fatal("uid 变化应判降级")
	}
	// 旧令牌读不出 mode 时不误判（老数据没有 mode 字段）
	legacy := &Session{Token: "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjIwMDAwMDAwMDB9.sig"}
	if isDegradedRenewal(legacy, fresh) {
		t.Fatal("旧令牌无 mode 不应误判降级")
	}
}

// jwtWith 拼一个只用于测试的 JWT（不验签，只读声明）。
func jwtWith(claims map[string]any) string {
	b, _ := json.Marshal(claims)
	return "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
}

// grab 在名字正好落在串尾时曾 from = i+1 > len(lower) 越界 panic（与 commandcode 同款）。
func TestGrabNameAtTailNoPanic(t *testing.T) {
	for _, in := range []string{
		"Oasis-Token",
		"Cookie: Oasis-Token",
		"a=b; Oasis-Token",
		"a=b; Oasis-Token ",
	} {
		if got := grab(in, "Oasis-Token"); got != "" {
			t.Fatalf("grab(%q) = %q, 期望空", in, got)
		}
	}
}
