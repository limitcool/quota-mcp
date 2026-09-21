// Package commandcode 实现 Command Code（commandcode.ai）的账户用量管理。
//
// 协议要点（来自社区项目 MAXeaglet/commandcode-usage 对未公开端点的逆向）：
//
// Command Code 的全部用量数据在 api.commandcode.ai 的 /alpha/* 下，鉴权统一是
// GET + Authorization: Bearer <api_key>——没有会话、没有续期，key 就是全部，
// 比 StepFun 的 Oasis 双面简单一个量级：
//
//	/alpha/whoami                        → 账户身份 user:{id,name,userName} + org:{id}
//	/alpha/billing/credits               → 余额 + 5 小时/周窗口 windowLimits
//	/alpha/billing/subscriptions?orgId=  → 套餐 planId/status/账期起止
//	/alpha/usage/summary                 → 账期内请求数/成功率/tokens/消耗
//
// 字段名未公开文档化，上游随时可能漂移，所以解析层对 snake_case / lowerCamelCase
// 双拼写做防御（与 stepfun 的 Field() 同一思路）；时间戳可能是毫秒数、秒数或
// ISO 字符串，按量级/格式自动判断。
package commandcode

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	// BaseURL 上游 API 根地址。开发时可由 env COMMANDCODE_API_BASE 指向本地 mock。
	BaseURL = "https://api.commandcode.ai"
	// UA 与社区面板保持一致
	UA = "commandcode-usage/1.0"
)

// FailKind 失败分类。
type FailKind string

const (
	// FailKeyRejected 401/403 = key 无效，无需继续打其余端点
	FailKeyRejected FailKind = "key_rejected"
	// FailHTTP 有响应但不是预期格式
	FailHTTP FailKind = "http_error"
	// FailTransport 网络层失败
	FailTransport FailKind = "unreachable"
)

// Fail 一次远程调用的失败。
type Fail struct {
	Kind FailKind
	Code int
	Msg  string
}

func (e *Fail) Error() string {
	switch e.Kind {
	case FailKeyRejected:
		return fmt.Sprintf("密钥被拒（HTTP %d）——请确认密钥有效，从 commandcode.ai/settings 获取", e.Code)
	case FailHTTP:
		return fmt.Sprintf("HTTP %d: %s", e.Code, e.Msg)
	case FailTransport:
		return fmt.Sprintf("网络不可达: %s", e.Msg)
	}
	return string(e.Kind)
}

var httpClient = &http.Client{Timeout: 25 * time.Second}

// get GET + Bearer 打一个 /alpha 端点。
func get(base, path, key string) (map[string]any, *Fail) {
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UA)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		// 密钥无效在第一个端点就会暴露，调用方应直接中止
		return nil, &Fail{Kind: FailKeyRejected, Code: resp.StatusCode}
	}
	if resp.StatusCode >= 400 {
		brief := []rune(string(raw))
		if len(brief) > 240 {
			brief = brief[:240]
		}
		return nil, &Fail{Kind: FailHTTP, Code: resp.StatusCode, Msg: string(brief)}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		brief := []rune(string(raw))
		if len(brief) > 200 {
			brief = brief[:200]
		}
		return nil, &Fail{Kind: FailHTTP, Code: resp.StatusCode, Msg: fmt.Sprintf("响应不是 JSON: %v (%s)", err, string(brief))}
	}
	return out, nil
}

// ---------------------------------------------------------------- 字段工具

// Field 取 JSON 字段，snake_case 与 lowerCamelCase 两种拼写都要接住。
func field(v map[string]any, names ...string) any {
	camel := func(s string) string {
		var b strings.Builder
		up := false
		for _, c := range s {
			if c == '_' {
				up = true
				continue
			}
			if up {
				b.WriteRune(toUpper(c))
				up = false
			} else {
				b.WriteRune(c)
			}
		}
		return b.String()
	}
	for _, n := range names {
		for _, key := range []string{n, camel(n)} {
			if x, ok := v[key]; ok && x != nil {
				return x
			}
		}
	}
	return nil
}

func toUpper(r rune) rune {
	if r >= 'a' && r <= 'z' {
		return r - 32
	}
	return r
}

func f64Of(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		var f float64
		if _, err := fmt.Sscanf(t, "%g", &f); err == nil {
			return f, true
		}
	}
	return 0, false
}

func i64Of(v any) (int64, bool) {
	f, ok := f64Of(v)
	if !ok {
		return 0, false
	}
	return int64(f), true
}

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func subOf(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

// ISOFromAny 时间戳 → ISO8601（UTC）。兼容毫秒数、秒数与 ISO 字符串：
// 小于 1e12 的数字按秒处理（1e12 秒 = 公元 33658 年，不可能是秒）。
func ISOFromAny(v any) string {
	switch t := v.(type) {
	case float64:
		ms := int64(t)
		if ms <= 0 {
			return ""
		}
		if ms < 1_000_000_000_000 {
			ms *= 1000
		}
		return isoFromMs(ms)
	case string:
		if t == "" {
			return ""
		}
		if parsed, err := time.Parse(time.RFC3339, t); err == nil {
			return parsed.UTC().Format("2006-01-02T15:04:05Z")
		}
		// 纯数字字符串按时间戳再试一次
		var n int64
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil && n > 0 {
			if n < 1_000_000_000_000 {
				n *= 1000
			}
			return isoFromMs(n)
		}
	}
	return ""
}

func isoFromMs(ms int64) string {
	if ms <= 0 {
		return ""
	}
	secs := ms / 1000
	days := secs / 86400
	rem := secs % 86400
	if rem < 0 {
		rem += 86400
		days--
	}
	y, m, d := civilFromDays(days)
	return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", y, m, d, rem/3600, (rem%3600)/60, rem%60)
}

// civilFromDays Howard Hinnant 的 days→civil 算法（与 stepfun 包同款）。
func civilFromDays(days int64) (int64, int, int) {
	z := days + 719468
	era := (z - 146096) / 146097
	if z >= 0 {
		era = z / 146097
	}
	doe := z - era*146097
	yoe := (doe - doe/1460 + doe/36524 - doe/146096) / 365
	y := yoe + era*400
	doy := doe - (365*yoe + yoe/4 - yoe/100)
	mp := (5*doy + 2) / 153
	d := doy - (153*mp+2)/5 + 1
	var m int
	if mp < 10 {
		m = int(mp + 3)
	} else {
		m = int(mp - 9)
	}
	if m <= 2 {
		y++
	}
	return y, m, int(d)
}

// ---------------------------------------------------------------- 套餐映射

// Plan 社区 CLI 的 planId → 套餐名与月度信用额映射。未知套餐 monthlyCredits 为 0
// （面板上标注「额度按套餐估算」）。
type Plan struct {
	Name           string
	MonthlyCredits float64
}

var knownPlans = map[string]Plan{
	"individual-go":       {"Go", 10},
	"individual-goat":     {"GOAT", 70},
	"individual-pro":      {"Pro", 30},
	"individual-pro-v1":   {"Pro", 80},
	"individual-provider": {"Provider", 15},
	"individual-max":      {"Max", 150},
	"individual-ultra":    {"Ultra", 300},
	"teams-pro":           {"Teams Pro", 40},
}

// planInfo 最长前缀优先：individual-pro-v1 应胜过 individual-pro。
func planInfo(planID string) (Plan, bool) {
	if planID == "" {
		return Plan{}, false
	}
	norm := strings.ToLower(strings.ReplaceAll(planID, "_", "-"))
	best := ""
	for p := range knownPlans {
		if strings.HasPrefix(norm, p) && len(p) > len(best) {
			best = p
		}
	}
	if best == "" {
		return Plan{}, false
	}
	return knownPlans[best], true
}

// ---------------------------------------------------------------- 窗口

// Window 一个节流窗口（5 小时滚动 / 周）。json tag 必须小写——
// 面板按 used/cap/exceeded/reset_at 取值，大写键会让整行不显示。
type Window struct {
	Used     float64 `json:"used"`
	Cap      float64 `json:"cap"`
	Exceeded bool    `json:"exceeded"`
	ResetAt  string  `json:"reset_at"`
}

// pickWindow windowLimits.fiveHour 也可能叫 five_hour / rolling5h / 5h
func pickWindow(wl map[string]any, names ...string) map[string]any {
	for _, n := range names {
		if m := subOf(field(wl, n)); m != nil {
			return m
		}
	}
	return nil
}

func normalizeWindow(raw map[string]any) Window {
	w := Window{}
	if raw == nil {
		return w
	}
	if f, ok := f64Of(field(raw, "used", "usage", "usedCredits", "used_credits")); ok {
		w.Used = f
	}
	if f, ok := f64Of(field(raw, "cap", "limit", "capCredits", "cap_credits")); ok {
		w.Cap = f
	}
	switch t := field(raw, "exceeded").(type) {
	case bool:
		w.Exceeded = t
	case string:
		w.Exceeded = t == "true"
	}
	if !w.Exceeded && w.Cap > 0 && w.Used >= w.Cap {
		w.Exceeded = true
	}
	w.ResetAt = ISOFromAny(field(raw, "resetAt", "reset_at", "resetsAt", "resets_at"))
	return w
}

// ---------------------------------------------------------------- 数据面

// Whoami 账户身份。
func Whoami(key string) (map[string]any, *Fail) {
	v, f := get(BaseURL, "/alpha/whoami", key)
	if f != nil {
		return nil, f
	}
	user := subOf(field(v, "user"))
	if user == nil {
		if data := subOf(field(v, "data")); data != nil {
			user = subOf(field(data, "user"))
		}
	}
	org := subOf(field(v, "org"))
	if org == nil {
		if data := subOf(field(v, "data")); data != nil {
			org = subOf(field(data, "org"))
		}
	}
	out := map[string]any{"id": "", "name": "", "user_name": "", "org_id": ""}
	if user != nil {
		out["id"] = strOf(field(user, "id"))
		out["name"] = strOf(field(user, "name"))
		out["user_name"] = orStr(strOf(field(user, "userName", "user_name")), strOf(field(user, "username")))
	}
	if org != nil {
		out["org_id"] = strOf(field(org, "id"))
	}
	return out, nil
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Credits 余额 + 5 小时/周窗口（面板的核心数据）。
func Credits(key string) (map[string]any, *Fail) {
	v, f := get(BaseURL, "/alpha/billing/credits", key)
	if f != nil {
		return nil, f
	}
	credits := subOf(field(v, "credits"))
	wl := subOf(field(v, "windowLimits"))
	if credits == nil && wl == nil {
		if data := subOf(field(v, "data")); data != nil {
			credits = subOf(field(data, "credits"))
			wl = subOf(field(data, "windowLimits"))
		}
	}
	out := map[string]any{
		"monthly_credits":   nil,
		"purchased_credits": nil,
		"free_credits":      nil,
		"plan_id":           "",
		"below_threshold":   false,
		"credit_threshold":  nil,
		// 账号整体限流状态：exceeded 直接指出是哪个窗口在拦（fiveHour/weekly）
		"limited":   wl != nil && field(wl, "limited") == true,
		"exceeded":  strOf(field(wlOrEmpty(wl), "exceeded")),
		"five_hour": nil,
		"weekly":    nil,
	}
	if credits != nil {
		if x, ok := f64Of(field(credits, "monthlyCredits", "monthly_credits")); ok {
			out["monthly_credits"] = x
		}
		if x, ok := f64Of(field(credits, "purchasedCredits", "purchased_credits")); ok {
			out["purchased_credits"] = x
		}
		if x, ok := f64Of(field(credits, "freeCredits", "free_credits")); ok {
			out["free_credits"] = x
		}
		out["plan_id"] = orStr(strOf(field(credits, "planId", "plan_id")), strOf(field(credits, "plan_id")))
		if field(credits, "belowThreshold", "below_threshold") == true {
			out["below_threshold"] = true
		}
		if x, ok := f64Of(field(credits, "creditThreshold", "credit_threshold")); ok {
			out["credit_threshold"] = x
		}
	}
	if wl != nil {
		if w := pickWindow(wl, "fiveHour", "five_hour", "rolling5h", "5h"); w != nil {
			out["five_hour"] = normalizeWindow(w)
		}
		if w := pickWindow(wl, "weekly", "week"); w != nil {
			out["weekly"] = normalizeWindow(w)
		}
	}
	return out, nil
}

func wlOrEmpty(wl map[string]any) map[string]any {
	if wl == nil {
		return map[string]any{}
	}
	return wl
}

// Subscriptions 套餐与账期。
func Subscriptions(key, orgID string) (map[string]any, *Fail) {
	path := "/alpha/billing/subscriptions"
	if orgID != "" {
		path += "?orgId=" + orgID
	}
	v, f := get(BaseURL, path, key)
	if f != nil {
		return nil, f
	}
	data := subOf(field(v, "data"))
	if data == nil {
		data = subOf(field(v, "subscription"))
	}
	if data == nil {
		return nil, &Fail{Kind: FailHTTP, Msg: "响应里没有 data/subscription"}
	}
	out := map[string]any{
		"plan_id":              strOf(field(data, "planId", "plan_id")),
		"status":               strOf(field(data, "status")),
		"current_period_end":   ISOFromAny(field(data, "currentPeriodEnd", "current_period_end")),
		"current_period_start": ISOFromAny(field(data, "currentPeriodStart", "current_period_start")),
		"cancel_at_period_end": field(data, "cancelAtPeriodEnd", "cancel_at_period_end") == true,
		"pending_phase":        field(data, "pendingPhase", "pending_phase"),
	}
	return out, nil
}

// UsageSummary 账期累计统计（请求数/成功率/tokens/消耗）。
func UsageSummary(key string) (map[string]any, *Fail) {
	v, f := get(BaseURL, "/alpha/usage/summary", key)
	if f != nil {
		return nil, f
	}
	u := subOf(field(v, "data"))
	if u == nil {
		u = v
	}
	out := map[string]any{
		"total_count":      0.0,
		"total_cost":       0.0,
		"average_cost":     nil,
		"success_rate":     nil,
		"completed_count":  0.0,
		"failed_count":     0.0,
		"total_tokens_in":  0.0,
		"total_tokens_out": 0.0,
		"total_credits":    0.0,
		"period_basis":     strOf(field(u, "periodBasis", "period_basis")),
	}
	for _, k := range []string{"totalCount", "total_count"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["total_count"] = x
			break
		}
	}
	for _, k := range []string{"totalCost", "total_cost"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["total_cost"] = x
			break
		}
	}
	for _, k := range []string{"averageCost", "average_cost"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["average_cost"] = x
			break
		}
	}
	for _, k := range []string{"successRate", "success_rate"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["success_rate"] = x
			break
		}
	}
	for _, k := range []string{"completedCount", "completed_count"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["completed_count"] = x
			break
		}
	}
	for _, k := range []string{"failedCount", "failed_count"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["failed_count"] = x
			break
		}
	}
	for _, k := range []string{"totalTokensIn", "total_tokens_in"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["total_tokens_in"] = x
			break
		}
	}
	for _, k := range []string{"totalTokensOut", "total_tokens_out"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["total_tokens_out"] = x
			break
		}
	}
	for _, k := range []string{"totalCredits", "total_credits"} {
		if x, ok := f64Of(field(u, k)); ok {
			out["total_credits"] = x
			break
		}
	}
	return out, nil
}
