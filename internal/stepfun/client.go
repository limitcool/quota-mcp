// Package stepfun 实现 StepFun（阶跃星辰）平台的多账户管理。
//
// 协议要点（移植自 keyhelm，均为实测结论）：
//
// StepFun 有两条互不相通的鉴权面，多账户管理必须同时持有：
//
//	plan 推理面：sk- access key，永久有效。
//	             GET {api}/step_plan/v1/models 的模型 id 数量本身就是订阅探针
//	             （无 plan=2，Plus=7/10），且不需要 console 会话，是面板的兜底真相。
//	console RPC 面：Oasis-Token（JWT，duration 恒为 7200 s）。
//	             走 Connect 风格同源代理：
//	             POST {console}/api/step.openapi.devcenter.Dashboard/{Method}
//	             鉴权只看 Oasis-* 头，不校验来源、不要求阿里云 WAF cookie。
//	             appId 分区域：.ai 只接受 20700，.com 只接受 10300，
//	             错则 oasis header is invalid。
//
// 会话能放在服务端长期管理，是因为续期不需要浏览器：
// POST {console}/passport/proto.api.passport.v1.PassportService/RegisterDevice {}
// 带齐 oasis-appid/platform/webid/did 四个头即返回 accessToken{raw,duration,mode}；
// RefreshToken {} 带上当前 token 又返回一张新的。请求体里 journal_b64 /
// encoded_device_info 全部可以省略——设备身份就是 webid/did 两个头，
// 所以我们自己造一个 webid 并始终复用它即可。
package stepfun

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// UA 与 console 前端保持一致，避免被 CDN 边缘节点差别对待。
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

const (
	dashboardService = "step.openapi.devcenter.Dashboard"
	passportService  = "proto.api.passport.v1.PassportService"
)

// Region 站点区域。Ai = 国际站（platform.stepfun.ai），Com = 国内站。
type Region int

const (
	RegionAi Region = iota
	RegionCom
)

// ParseRegion 解析区域别名（ai/oversea/intl/global、com/cn/china/domestic）。
func ParseRegion(s string) (Region, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ai", "oversea", "intl", "international", "global":
		return RegionAi, true
	case "com", "cn", "china", "domestic":
		return RegionCom, true
	}
	return RegionCom, false
}

func (r Region) String() string {
	if r == RegionAi {
		return "ai"
	}
	return "com"
}

// Console console（平台前端 + /api 代理）根地址。
func (r Region) Console() string {
	return fmt.Sprintf("https://platform.stepfun.%s", r.String())
}

// API OpenAI 兼容推理端点（plan 版在路径里多一段 /step_plan）。
func (r Region) API() string {
	return fmt.Sprintf("https://api.stepfun.%s", r.String())
}

// AppID Oasis-Appid：服务端会拒绝错误区域的 appId。
func (r Region) AppID() string {
	if r == RegionAi {
		return "20700"
	}
	return "10300"
}

// Session 一次 console 会话（等价于浏览器里的登录态）。
type Session struct {
	// Token Oasis-Token 的值（JWT，duration 恒为 7200 s）
	Token string
	// Webid Oasis-Webid / Oasis-Did：前端把同一个 uuid 同时用作两者
	Webid string
	// Refresh RefreshToken 返回的配套 long-lived 值，原样存着即可（续期实测只认头，不读它）
	Refresh string
}

func (s *Session) exp() (int64, bool) {
	v, ok := jwtClaim(s.Token, "exp")
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int64(f), true
}

// UID 会话背后的账号身份。签名后的用户 token 用 oasis_id；匿名设备 token 也是这个字段，
// 靠 mode 区分（mode=1 = 设备，SIGN_IN 才是登录态）。
func (s *Session) UID() string {
	for _, k := range []string{"oasis_id", "oasisId", "uid", "user_id", "userId", "sub"} {
		if v, ok := jwtClaim(s.Token, k); ok {
			switch t := v.(type) {
			case string:
				if t != "" {
					return t
				}
			case float64:
				return fmt.Sprintf("%d", int64(t))
			}
		}
	}
	return ""
}

func (s *Session) mode() (int64, bool) {
	v, ok := jwtClaim(s.Token, "mode")
	if !ok {
		return 0, false
	}
	f, ok := v.(float64)
	if !ok {
		return 0, false
	}
	return int64(f), true
}

// TTL 距离过期还有多少秒（负数 = 已过期）。
func (s *Session) TTL() (int64, bool) {
	e, ok := s.exp()
	if !ok {
		return 0, false
	}
	return e - time.Now().Unix(), true
}

func nowEpoch() int64 { return time.Now().Unix() }

// jwtClaim 解 JWT 中段的声明（不验签，只读声明——本来就只是拿它做过期判断）。
// token 可能是多段 JWT 拼接的整值（console 只认整值），claims 取第一段的载荷即可。
func jwtClaim(token, key string) (any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 3 || parts[1] == "" {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// 有些实现会发标准 base64（带 +/ 和填充），再兜一次
		raw, err = base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, false
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, false
	}
	v, ok := claims[key]
	return v, ok
}

// Mask 掩码：只保留首尾各 6 位，和控制台/新 API 的 key_preview 对齐，不构成凭据。
func Mask(v string) string {
	chars := []rune(v)
	if len(chars) <= 12 {
		if len(chars) == 0 {
			return ""
		}
		return fmt.Sprintf("%c…%c", chars[0], chars[len(chars)-1])
	}
	return fmt.Sprintf("%s..%s", string(chars[:6]), string(chars[len(chars)-6:]))
}

// NewWebid 造一个 32 位小写 hex 的 webid（前端 web_id 同格式，实测自造的同样能过 passport 校验）。
func NewWebid() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%032x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// FailKind 失败分类。分类是产品行为：token_expired 和 token_illegal
// 在面板上要显示成完全不同的两件事（前者能续，后者必须重新登录）。
type FailKind string

const (
	// FailTokenMissing 没带 token，或 token 已被服务端丢弃
	FailTokenMissing FailKind = "token_missing"
	// FailTokenIllegal token 形状对但签名/内容无效（多半是被注销了）
	FailTokenIllegal FailKind = "token_illegal"
	// FailTokenExpired 服务端说会话过期
	FailTokenExpired FailKind = "token_expired"
	// FailHeaderRejected 请求头组合被拒（appId 与区域不匹配时最常见）
	FailHeaderRejected FailKind = "header_rejected"
	// FailHTTP 拿到了 HTTP 响应但不是我们的错误格式
	FailHTTP FailKind = "http_error"
	// FailTransport 网络层失败
	FailTransport FailKind = "unreachable"
)

// Fail 一次远程调用的失败。
type Fail struct {
	Kind FailKind
	// Code/Msg 仅 FailHTTP / FailTransport 使用
	Code int
	Msg  string
}

func (e *Fail) Error() string {
	switch e.Kind {
	case FailTokenMissing:
		return "token is missing"
	case FailTokenIllegal:
		return "token is illegal"
	case FailTokenExpired:
		return "token expired"
	case FailHeaderRejected:
		return "oasis header is invalid"
	case FailHTTP:
		return fmt.Sprintf("HTTP %d: %s", e.Code, e.Msg)
	case FailTransport:
		return fmt.Sprintf("网络不可达: %s", e.Msg)
	}
	return string(e.Kind)
}

// ShouldAttemptRenew 该失败是否值得先试一次续期。对齐前端拦截器的判断：
// 它对 TOKEN_EXPIRED / TOKEN_ILLEGAL / 120000 都会先去 refreshToken，
// 只有续期本身也失败才清会话。TokenMissing 不在其列——那是根本没登记过会话。
func (e *Fail) ShouldAttemptRenew() bool {
	return e.Kind == FailTokenExpired || e.Kind == FailTokenIllegal
}

// NeedsRelogin 续期也救不回来 → 面板要显示「需要重新登录」而不是「探测失败」。
func (e *Fail) NeedsRelogin() bool {
	switch e.Kind {
	case FailTokenMissing, FailTokenIllegal, FailTokenExpired, FailHeaderRejected:
		return true
	}
	return false
}

func classify(status int, body string) *Fail {
	b := strings.ToLower(body)
	switch {
	case strings.Contains(b, "token is missing") || strings.Contains(b, "code_token_missing"):
		return &Fail{Kind: FailTokenMissing}
	case strings.Contains(b, "token is illegal"):
		return &Fail{Kind: FailTokenIllegal}
	case strings.Contains(b, "token expire") || strings.Contains(b, "token_expired") || strings.Contains(b, "expired"):
		return &Fail{Kind: FailTokenExpired}
	case strings.Contains(b, "oasis header") || strings.Contains(b, "app configuration is missing"):
		return &Fail{Kind: FailHeaderRejected}
	}
	brief := []rune(body)
	if len(brief) > 240 {
		brief = brief[:240]
	}
	return &Fail{Kind: FailHTTP, Code: status, Msg: string(brief)}
}

var httpClient = &http.Client{
	// 一个进程内复用同一个 Client：连接池会把已经打通的那个 CDN 边缘节点留着用。
	// 这个域名的 DNS 会返回多个边缘 IP，其中一些从某些网络根本连不上，
	// 而 TCP 握手要等满系统超时（实测 ~21 s）才换下一个——不设 connect 超时的话，
	// 一次多账户探测可能整轮都卡在黑名单 IP 上。
	Timeout: 25 * time.Second,
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	},
}

// call Connect(JSON) 调用：POST {base}/{service}/{Method}
func call(base, service, method string, region Region, sess *Session, req any) (map[string]any, *Fail) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &Fail{Kind: FailHTTP, Msg: err.Error()}
	}
	url := fmt.Sprintf("%s/%s/%s", base, service, method)
	httpReq, err := http.NewRequest(http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	origin := region.Console()
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("oasis-appid", region.AppID())
	httpReq.Header.Set("oasis-platform", "web")
	httpReq.Header.Set("oasis-webid", sess.Webid)
	httpReq.Header.Set("oasis-did", sess.Webid)
	httpReq.Header.Set("origin", origin)
	httpReq.Header.Set("referer", origin+"/")
	httpReq.Header.Set("user-agent", UA)
	// 空值必须整个头都不发：RegisterDevice 就是在「无 oasis-token」时才被接受的，
	// 发一个空的 oasis-token: 会被 passport 当成非法头。
	if sess.Token != "" {
		httpReq.Header.Set("oasis-token", sess.Token)
	}

	resp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	if resp.StatusCode >= 400 {
		return nil, classify(resp.StatusCode, string(raw))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, &Fail{Kind: FailHTTP, Code: resp.StatusCode, Msg: fmt.Sprintf("响应不是 JSON: %v", err)}
	}
	return out, nil
}

// Dashboard console 数据面调用（带账户会话）。
func Dashboard(region Region, sess *Session, method string, req any) (map[string]any, *Fail) {
	return call(region.Console()+"/api", dashboardService, method, region, sess, req)
}

// Field 取 JSON 字段，snake_case 与 lowerCamelCase 两种拼写都要接住，
// 否则上游换序列化风格就把面板打成 null。null 值视为不存在。
func Field(v map[string]any, names ...string) any {
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

func fieldF64(v map[string]any, names ...string) (float64, bool) {
	x := Field(v, names...)
	switch t := x.(type) {
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

func fieldI64(v map[string]any, names ...string) (int64, bool) {
	x := Field(v, names...)
	switch t := x.(type) {
	case float64:
		return int64(t), true
	case string:
		var n int64
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n, true
		}
	}
	return 0, false
}

func fieldStr(v map[string]any, names ...string) string {
	if x := Field(v, names...); x != nil {
		if s, ok := x.(string); ok {
			return s
		}
	}
	return ""
}

func fieldSub(v map[string]any, names ...string) map[string]any {
	if x := Field(v, names...); x != nil {
		if m, ok := x.(map[string]any); ok {
			return m
		}
	}
	return nil
}

// ISOFromMs 时间戳 → ISO8601（UTC）。0 或负数视为「无」。
// 上游单位不统一：.ai 控制台返回秒级字符串（"1792494007"），.com 返回毫秒数，
// 按量级自动判断（超过 1e11 视为毫秒；1e11 秒 = 公元 5138 年，不可能是秒）。
func ISOFromMs(v int64) string {
	if v <= 0 {
		return ""
	}
	if v > 100_000_000_000 {
		v /= 1000
	}
	return ISOFromSecs(v)
}

// ISOFromSecs 秒级时间戳 → ISO8601（UTC）。
func ISOFromSecs(secs int64) string {
	if secs <= 0 {
		return ""
	}
	days := secs / 86400
	rem := secs % 86400
	if rem < 0 {
		rem += 86400
		days--
	}
	y, m, d := civilFromDays(days)
	return fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", y, m, d, rem/3600, (rem%3600)/60, rem%60)
}

// civilFromDays Howard Hinnant 的 days→civil 算法。
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

// ---------------------------------------------------------------- 数据面方法

// PlanStatus 订阅状态：plan 名、到期时间、是否可续。
func PlanStatus(region Region, sess *Session) (map[string]any, *Fail) {
	v, f := Dashboard(region, sess, "GetStepPlanStatus", map[string]any{})
	if f != nil {
		return nil, f
	}
	sub := fieldSub(v, "subscription")
	def := fieldSub(v, "plan_definition", "planDefinition")
	out := map[string]any{
		"status":     nil,
		"plan_name":  nil,
		"plan_sku":   nil,
		"valid_until": "",
		"auto_renew": nil,
		"can_resign": nil,
	}
	if s := fieldStr(v, "desc"); s != "" {
		out["status"] = s
	} else if Field(v, "status") != nil {
		out["status"] = "ok"
	}
	if def != nil {
		if s := fieldStr(def, "name", "display_name", "displayName"); s != "" {
			out["plan_name"] = s
		}
		if s := fieldStr(def, "sku", "plan_sku", "planSku"); s != "" {
			out["plan_sku"] = s
		}
	}
	// 套餐名（Plus / Pro）实际在 subscription.name 里，plan_definition 只有 type/price
	if out["plan_name"] == nil && sub != nil {
		if s := fieldStr(sub, "name", "plan_name", "planName"); s != "" {
			out["plan_name"] = s
		}
	}
	if sub != nil {
		if ms, ok := fieldI64(sub, "end_time", "endTime", "expired_at", "valid_until"); ok {
			out["valid_until"] = ISOFromMs(ms)
		}
		out["auto_renew"] = Field(sub, "auto_renew", "autoRenew")
	}
	if b, ok := Field(v, "can_resign", "canResign").(bool); ok {
		out["can_resign"] = b
	}
	return out, nil
}

// RenderRateLimit 节流窗口（5 小时 + 周 + 订阅 credit）——就是编码 agent 被卡住的那两个窗口。
func RenderRateLimit(v map[string]any) map[string]any {
	out := map[string]any{
		"status":              nil,
		"desc":                nil,
		"five_hour_left_rate": nil,
		"five_hour_reset_at":  "",
		"weekly_left_rate":    nil,
		"weekly_reset_at":     "",
		"plan_family":         Field(v, "plan_family", "planFamily"),
		"credit_left_rate":    nil,
		"credit_reset_at":     "",
	}
	if s := fieldStr(v, "status", "desc"); s != "" {
		out["status"] = s
	}
	if s := fieldStr(v, "desc"); s != "" {
		out["desc"] = s
	}
	if f, ok := fieldF64(v, "five_hour_usage_left_rate", "fiveHourUsageLeftRate"); ok {
		out["five_hour_left_rate"] = f
	}
	if ms, ok := fieldI64(v, "five_hour_usage_reset_time", "fiveHourUsageResetTime"); ok {
		out["five_hour_reset_at"] = ISOFromMs(ms)
	}
	if f, ok := fieldF64(v, "weekly_usage_left_rate", "weeklyUsageLeftRate"); ok {
		out["weekly_left_rate"] = f
	}
	if ms, ok := fieldI64(v, "weekly_usage_reset_time", "weeklyUsageResetTime"); ok {
		out["weekly_reset_at"] = ISOFromMs(ms)
	}
	if c := fieldSub(v, "plan_credit_rate_limit", "planCreditRateLimit"); c != nil {
		if f, ok := fieldF64(c, "subscription_credit_left_rate", "subscriptionCreditLeftRate", "subscription_Credit_left_rate"); ok {
			out["credit_left_rate"] = f
		}
		if ms, ok := fieldI64(c, "subscription_Credit_reset_time", "subscription_credit_reset_time", "subscriptionCreditResetTime"); ok {
			out["credit_reset_at"] = ISOFromMs(ms)
		}
	}
	return out
}

// RateLimit 5 小时 / 周 节流窗口。
func RateLimit(region Region, sess *Session) (map[string]any, *Fail) {
	v, f := Dashboard(region, sess, "QueryStepPlanRateLimit", map[string]any{})
	if f != nil {
		return nil, f
	}
	return RenderRateLimit(v), nil
}

// AccessKeys 该账户名下的全部 access key（控制台里那张表）。
// 这是「孤儿 key」检测的唯一来源：new-api 侧只能看到已被登记的 key，
// 看不到账户里还躺着几个没接进来的。
func AccessKeys(region Region, sess *Session) (map[string]any, *Fail) {
	v, f := Dashboard(region, sess, "ListAccessKeys", map[string]any{"filter": false})
	if f != nil {
		return nil, f
	}
	keys := []map[string]any{}
	for _, slot := range []string{"accessKeys", "access_keys"} {
		arr, ok := v[slot].([]any)
		if !ok {
			continue
		}
		for _, item := range arr {
			k, ok := item.(map[string]any)
			if !ok {
				continue
			}
			entry := map[string]any{
				"name":         nil,
				"key_id":       nil,
				"key_masked":   nil,
				"key_len":      nil,
				"created_at":   "",
				"last_used_at": "",
				"status":       Field(k, "status"),
				"deleted":      nil,
			}
			if s := fieldStr(k, "name"); s != "" {
				entry["name"] = s
			}
			if n, ok := fieldI64(k, "keyId", "key_id"); ok {
				entry["key_id"] = n
			}
			if s := fieldStr(k, "accessKey", "access_key"); s != "" {
				entry["key_masked"] = Mask(s)
				entry["key_len"] = len([]rune(s))
			}
			if ms, ok := fieldI64(k, "createdAt", "created_at"); ok {
				entry["created_at"] = ISOFromMs(ms)
			}
			if ms, ok := fieldI64(k, "lastUsedAt", "last_used_at"); ok {
				entry["last_used_at"] = ISOFromMs(ms)
			}
			if n, ok := fieldI64(k, "isDeleted", "is_deleted"); ok {
				entry["deleted"] = n
			}
			keys = append(keys, entry)
		}
	}
	return map[string]any{"count": len(keys), "keys": keys}, nil
}

// PlanModels plan 推理面：模型清单。id 数量本身就是订阅探针（无 plan=2，Plus=7/10），
// 而且是永久凭据，不需要 console 会话。
func PlanModels(region Region, accessKey string) ([]string, *Fail) {
	url := fmt.Sprintf("%s/step_plan/v1/models", region.API())
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	req.Header.Set("authorization", "Bearer "+accessKey)
	req.Header.Set("user-agent", UA)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, &Fail{Kind: FailTransport, Msg: err.Error()}
	}
	if resp.StatusCode >= 400 {
		return nil, classify(resp.StatusCode, string(raw))
	}
	var v struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return []string{}, nil
	}
	ids := make([]string, 0, len(v.Data))
	for _, m := range v.Data {
		if m.ID != "" {
			ids = append(ids, m.ID)
		}
	}
	return ids, nil
}

// ------------------------------------------------------------------ passport

// Tokens accessToken / refreshToken 解出来的形状（{raw, duration, mode}）
type Tokens struct {
	Access  string
	Refresh string
	// Duration access token 的存活秒数，实测恒为 7200
	Duration int64
	// OasisID JWT 里的 oasis_id：账户的稳定身份
	OasisID string
}

func parseTokens(v map[string]any) (*Tokens, *Fail) {
	at := fieldSub(v, "access_token", "accessToken")
	if at == nil {
		return nil, &Fail{Kind: FailHTTP, Msg: "响应里没有 access_token"}
	}
	access := fieldStr(at, "raw")
	if access == "" {
		return nil, &Fail{Kind: FailHTTP, Msg: "access_token.raw 为空"}
	}
	t := &Tokens{Access: access, OasisID: (&Session{Token: access}).UID()}
	if rt := fieldSub(v, "refresh_token", "refreshToken"); rt != nil {
		t.Refresh = fieldStr(rt, "raw")
	}
	if d, ok := fieldI64(at, "duration"); ok {
		t.Duration = d
	}
	return t, nil
}

// RegisterDevice 注册一个设备身份，拿到匿名 token（前端首屏就是这么干的，入参为空对象）。
// 用来给「还没登录的账户槽位」造一个稳定的 webid，不承载任何用户凭据。
func RegisterDevice(region Region, webid string) (*Tokens, *Fail) {
	v, f := call(region.Console()+"/passport", passportService, "RegisterDevice", region,
		&Session{Webid: webid}, map[string]any{})
	if f != nil {
		return nil, f
	}
	return parseTokens(v)
}

// RefreshToken 换一张新的 access token。实测结论：入参为空对象即可，
// 设备身份由 Oasis-Webid / Oasis-Did 头承载，journal_b64 / encoded_device_info 都不必填——
// 所以「~2 h 过期」不是服务端管理的障碍，只要在被注销前持续续期就能长期持有会话。
func RefreshToken(region Region, sess *Session) (*Tokens, *Fail) {
	v, f := call(region.Console()+"/passport", passportService, "RefreshToken", region, sess, map[string]any{})
	if f != nil {
		return nil, f
	}
	return parseTokens(v)
}

// ---------------------------------------------------------------- 会话录入

// grab 从 key=value / key: value 混排的文本里取一个头/cookie 值。
func grab(text, name string) string {
	lower := strings.ToLower(text)
	target := strings.ToLower(name)
	from := 0
	for {
		rel := strings.Index(lower[from:], target)
		if rel < 0 {
			return ""
		}
		i := from + rel + len(target)
		from = i + 1
		rest := strings.TrimLeft(text[i:], " \t")
		if rest == "" {
			continue
		}
		if c := rest[0]; c != '=' && c != ':' {
			continue
		}
		val := strings.TrimLeft(rest[1:], " \t")
		end := len(val)
		for idx, c := range val {
			if c == ';' || c == '\n' || c == '\r' || c == ' ' || c == '"' || c == ',' {
				end = idx
				break
			}
		}
		if v := strings.TrimSpace(val[:end]); v != "" {
			return v
		}
	}
}

// jwtRE 一个标准 3 段 JWT 的形状。
var jwtRE = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)

// jwtBlobRE 一整块只由 JWT 段和点拼出来的值。实测 .ai 的 Oasis-Token cookie 是
// 两段 JWT 拼接（8 段、中间夹空段），console 只认整值——单取任何一段都回
// `token is illegal`。所以这种值必须原样保留，不能截。
var jwtBlobRE = regexp.MustCompile(`^eyJ[A-Za-z0-9_.-]+$`)

// ParseSessionText 把用户从浏览器里复制来的任何东西解析成会话。三种输入都要吃得下：
// document.cookie 整串、DevTools 里抄的 Oasis-Token: … 头行、或者裸 JWT。
// webid 缺失时新生成一个并固定下来——续期只认头，所以只要我们自己复用同一个就行。
func ParseSessionText(raw string) (*Session, error) {
	text := strings.NewReplacer("%0A", "\n", "%0D", "\r").Replace(raw)
	token := grab(text, "Oasis-Token")
	if token == "" {
		for _, p := range strings.FieldsFunc(text, func(r rune) bool {
			return r == ';' || r == '\n' || r == '\r' || r == ' ' || r == ','
		}) {
			if p = strings.TrimSpace(p); strings.HasPrefix(p, "eyJ") {
				token = p
				break
			}
		}
	}
	if token == "" {
		return nil, fmt.Errorf("没找到 Oasis-Token（贴 document.cookie、Oasis-Token 头，或裸 JWT 都行）")
	}
	switch {
	case jwtBlobRE.MatchString(token):
		// JWT 块（含多段拼接）原样保留，服务端认的是整值
	case jwtRE.MatchString(token):
		// 值里混了别的内容，捞出第一个完整 JWT
		token = jwtRE.FindString(token)
	case len(strings.Split(token, ".")) != 3:
		return nil, fmt.Errorf("Oasis-Token 不是合法的 JWT 形状")
	}
	webid := grab(text, "Oasis-Webid")
	if webid == "" {
		webid = grab(text, "Oasis-Did")
	}
	if webid == "" {
		webid = NewWebid()
	}
	return &Session{
		Token:   token,
		Webid:   webid,
		Refresh: grab(text, "Oasis-Refresh"),
	}, nil
}

// SessionSummary 会话的可展示摘要（不含 token 值，只有长度 / 过期 / 身份）。
func SessionSummary(sess *Session) map[string]any {
	ttl, hasTTL := sess.TTL()
	exp, _ := sess.exp()
	out := map[string]any{
		"webid_mask": Mask(sess.Webid),
		"token_len":  len([]rune(sess.Token)),
		"uid":        sess.UID(),
		"exp":        ISOFromSecs(exp),
		"ttl_secs":   ttl,
		// 读不出 exp（token 形状不对）时按已过期处理，宁可让面板提示重新登录
		"expired":    !hasTTL || ttl <= 0,
		"has_refresh": sess.Refresh != "",
	}
	if mode, ok := sess.mode(); ok {
		out["mode"] = mode
	} else {
		out["mode"] = nil
	}
	return out
}
