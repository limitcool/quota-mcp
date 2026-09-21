// Package commandcode 实现 Command Code（commandcode.ai）的账户用量管理。
//
// 协议要点（来自社区项目 MAXeaglet/commandcode-usage 对未公开端点的逆向）：
//
// Command Code 有两条互不相通的鉴权面，和 StepFun 一样必须分别登记：
//
//	api_key 面（Bearer）：全部用量数据在 api.commandcode.ai 的 /alpha/* 下，
//	          GET + Authorization: Bearer <api_key>，key 就是全部。
//	          /alpha/whoami                        → 账户身份 user:{id,name,userName} + org:{id}
//	          /alpha/billing/credits               → 余额 + 5 小时/周窗口 windowLimits
//	          /alpha/billing/subscriptions?orgId=  → 套餐 planId/status/账期起止
//	          /alpha/usage/summary                 → 账期内请求数/成功率/tokens/消耗
//
//	session 面（Cookie）：浏览器登录后的同一批数据在 /internal/* 下，靠
//	          __Secure-commandcode_prod_.session_token 承载身份，不带任何 Bearer 头。
//	          端点与 /alpha 平级：/internal/billing/credits、/internal/billing/subscriptions、
//	          /internal/usage/summary、/internal/orgs。命令面板（浏览器）走的就是这一面，
//	          所以只要能从 CookieCloud 拿到 session_token，就不必让用户去 settings 抄 api_key。
//	          代价：会话会过期，需要到期后重新抓 CookieCloud；api_key 是永久凭据。
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
	"net/url"
	"strings"
	"time"
)

const (
	// BaseURL 上游 API 根地址。开发时可由 env COMMANDCODE_API_BASE 指向本地 mock。
	BaseURL = "https://api.commandcode.ai"
	// AlphaPrefix 永久 api_key 面（Bearer）。
	AlphaPrefix = "/alpha"
	// InternalPrefix 浏览器会话面（Cookie）。
	InternalPrefix = "/internal"
	// SessionCookieName 浏览器登录态 cookie 名。
	SessionCookieName = "__Secure-commandcode_prod_.session_token"
	// UA 与社区面板保持一致
	UA = "commandcode-usage/1.0"
)

// Credential 一次探测用的凭据：两条面二选一。都给了优先 api_key——
// 它是永久凭据，不会因为忘记刷 CookieCloud 而掉线。
type Credential struct {
	// Key /alpha 面 Bearer api_key。
	Key string
	// Session /internal 面 session cookie 值。
	Session string
}

// sessionMode 当前凭据是否只能走会话面。
func (c Credential) sessionMode() bool {
	return c.Key == "" && c.Session != ""
}

// describe 面板/告警里展示的凭据来源（不含值）。
func (c Credential) describe() string {
	if c.Key != "" {
		return "api_key"
	}
	return "session"
}

// FailKind 失败分类。
type FailKind string

const (
	// FailKeyRejected 401/403 = 凭据无效，无需继续打其余端点
	FailKeyRejected FailKind = "key_rejected"
	// FailSessionExpired session_token 过期/被注销：需要重新抓 CookieCloud
	FailSessionExpired FailKind = "session_expired"
	// FailHTTP 有响应但不是预期格式
	FailHTTP FailKind = "http_error"
	// FailTransport 网络层失败
	FailTransport FailKind = "unreachable"
)

// Fail 一次远程调用的失败。
type Fail struct {
	Kind  FailKind
	Code  int
	Msg   string
	Where string // 出错的端点族（"alpha" / "internal"），便于诊断
}

func (e *Fail) Error() string {
	switch e.Kind {
	case FailKeyRejected:
		return fmt.Sprintf("凭据被拒（HTTP %d）——请确认 api_key 有效（commandcode.ai/settings）或重新抓取 session_token", e.Code)
	case FailSessionExpired:
		return "session_token 已过期/被注销——请重新从 CookieCloud 同步 commandcode.ai 登录态"
	case FailHTTP:
		return fmt.Sprintf("HTTP %d: %s", e.Code, e.Msg)
	case FailTransport:
		return fmt.Sprintf("网络不可达: %s", e.Msg)
	}
	return string(e.Kind)
}

// NeedsRefresh 会话面失败是否属于「凭据过期、要人工重抓」。api_key 面永久有效，恒为 false。
func (e *Fail) NeedsRefresh() bool {
	return e.Kind == FailSessionExpired || e.Kind == FailKeyRejected
}

var httpClient = &http.Client{Timeout: 25 * time.Second}

// request 按凭据类型选鉴权方式与端点前缀打一个端点。
//
//	api_key 面：GET {base}/alpha/{path} + Authorization: Bearer
//	session 面：GET {base}/internal/{path} + Cookie: __Secure-commandcode_prod_.session_token=…
//
// path 传不带前缀的裸路径（如 "billing/credits"）。
func request(cred Credential, path string) (map[string]any, *Fail) {
	prefix, where := AlphaPrefix, "alpha"
	if cred.sessionMode() {
		prefix, where = InternalPrefix, "internal"
	}
	req, err := http.NewRequest(http.MethodGet, BaseURL+prefix+"/"+strings.TrimPrefix(path, "/"), nil)
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error(), Where: where}
	}
	if cred.sessionMode() {
		req.Header.Set("Cookie", SessionCookieName+"="+cred.Session)
	} else {
		req.Header.Set("Authorization", "Bearer "+cred.Key)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UA)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error(), Where: where}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error(), Where: where}
	}
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		// 会话面的 401 是「该重新抓 CookieCloud」；api_key 面的 401 是「key 无效」
		kind := FailKeyRejected
		if cred.sessionMode() {
			kind = FailSessionExpired
		}
		return nil, &Fail{Kind: kind, Code: resp.StatusCode, Where: where}
	}
	if resp.StatusCode >= 400 {
		brief := []rune(string(raw))
		if len(brief) > 240 {
			brief = brief[:240]
		}
		return nil, &Fail{Kind: FailHTTP, Code: resp.StatusCode, Msg: string(brief), Where: where}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		brief := []rune(string(raw))
		if len(brief) > 200 {
			brief = brief[:200]
		}
		return nil, &Fail{Kind: FailHTTP, Code: resp.StatusCode, Msg: fmt.Sprintf("响应不是 JSON: %v (%s)", err, string(brief)), Where: where}
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

// Whoami 账户身份。仅 api_key 面（/alpha）有 whoami；会话面没有身份端点，
// 调用方在 session 模式下应跳过。orgID 供订阅端点筛选用。
func Whoami(cred Credential) (map[string]any, *Fail) {
	v, f := request(cred, "whoami")
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
func Credits(cred Credential) (map[string]any, *Fail) {
	v, f := request(cred, "billing/credits")
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

// Subscriptions 套餐与账期。orgId 仅 api_key 面用得到；会话面端点自身知道身份，忽略它。
func Subscriptions(cred Credential, orgID string) (map[string]any, *Fail) {
	path := "billing/subscriptions"
	if cred.Key != "" && orgID != "" {
		path += "?orgId=" + orgID
	}
	v, f := request(cred, path)
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
func UsageSummary(cred Credential) (map[string]any, *Fail) {
	v, f := request(cred, "usage/summary")
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

// ---------------------------------------------------------------- 会话录入

// SessionCookieName 之外的别名字段：有的导出工具会把整段 Cookie 头抄进去。
// ParseSessionText 把这几种输入都吃下来，只回一个裸的 session_token 值。
//
// 接受：
//   - 整串 document.cookie（`a=b; __Secure-commandcode_prod_.session_token=…; c=d`）
//   - DevTools 里抄的 Cookie 头行
//   - 裸 token 值
func ParseSessionText(raw string) (string, error) {
	text := strings.NewReplacer("%0A", "\n", "%0D", "\r").Replace(strings.TrimSpace(raw))
	if text == "" {
		return "", fmt.Errorf("会话文本为空")
	}
	token := grabCookie(text, SessionCookieName)
	if token != "" {
		return token, nil
	}
	// 可能就是裸值：单段、无分隔符、无空白，且不含 cookie 分隔符 ',' 或 '='。
	// 含 ',' 的输入不可能是 token（',' 是 cookie 分隔符）；含 '=' 的走下面的键值兜底，
	// 那里会要求 '=' 左边的 key 确实是 session 名，避免把 "abc=def==" 之类误收成 token。
	// 名字本身不算值：只贴了 cookie 名（无 =）时应报「没找到」而不是把名字当 token。
	if !strings.ContainsAny(text, "; 	\r\n,=") && !strings.EqualFold(text, SessionCookieName) {
		return text, nil
	}
	// 兜底：从 = 分割的键值里找最像 session_token 的那个（名字大小写/下划线容错）
	norm := func(s string) string {
		return strings.ToLower(strings.NewReplacer("-", "", "_", "", ".", "").Replace(s))
	}
	want := norm(SessionCookieName)
	for _, part := range strings.FieldsFunc(text, func(r rune) bool {
		return r == ';' || r == '\n' || r == '\r'
	}) {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		if strings.Contains(norm(k), want) {
			if v = strings.TrimSpace(v); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("没找到 %s（贴整串 cookie、Cookie 头或裸值都行）", SessionCookieName)
}

// grabCookie 从 key=value 混排文本里取一个 cookie 值（名字按大小写不敏感匹配）。
func grabCookie(text, name string) string {
	lower := strings.ToLower(text)
	target := strings.ToLower(name)
	from := 0
	for {
		// 上一次匹配正好落在串尾时 from = i+1 > len(lower)，再切片会越界 panic。
		if from >= len(lower) {
			return ""
		}
		rel := strings.Index(lower[from:], target)
		if rel < 0 {
			return ""
		}
		i := from + rel + len(target)
		from = i + 1
		// 名字后必须紧跟 '='（允许一点空白）
		rest := strings.TrimLeft(text[i:], " 	")
		if !strings.HasPrefix(rest, "=") {
			continue
		}
		val := strings.TrimLeft(rest[1:], " 	")
		end := len(val)
		for idx, c := range val {
			if c == ';' || c == '\n' || c == '\r' || c == ' ' || c == '"' || c == ',' {
				end = idx
				break
			}
		}
		if v := strings.TrimSpace(val[:end]); v != "" {
			// cookie 值里可能带 %XX 转义（如 %20），统一解一次
			if dec, err := url.PathUnescape(v); err == nil && dec != "" {
				v = dec
			}
			return v
		}
	}
}

// SessionSummary 会话的可展示摘要（不含 token 值）。Command Code 的 session_token
// 是不透明串（非 JWT），解不出到期时间，所以只报存在性与长度掩码。
func SessionSummary(token string) map[string]any {
	return map[string]any{
		"present": token != "",
		"len":     len([]rune(token)),
		"mask":    maskOrNil(token),
	}
}
