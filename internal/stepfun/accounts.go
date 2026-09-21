package stepfun

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/limitcool/quota-mcp/internal/store"
)

// 一个「账户」= stepfun_accounts 表里的一行，两个密文字段：
//
//	access_key_enc      plan 推理 key（sk-…），永久有效
//	console_session_enc {token, webid, refresh} JSON，~2 h，可无限续
//
// 手机号注册的账户永远拿不到第二次登录（发验证码要过腾讯 TCaptcha），这类槽位只登记
// access_key + 邮箱，并在 identity 里带 sessionless: true；面板据此把「看不到额度」
// 读成设计态而不是掉线。
//
// 非机密的元数据走普通列：label = 标签，identity = 账号身份（oasis uid / key 掩码 / 邮箱），
// probe_data = 最近一次探测聚合。
//
// 两条鉴权面都要探：只有 plan key 是长期可信的，console 会话随时可能掉线。
// 「这个账户还能不能用」以 plan 面为准，「还剩多少额度 / 什么时候到期」只有 console 面知道。

// Account 内存中的账户视图（含解密的明文，绝不进任何响应体）。
type Account struct {
	Service     string
	Region      Region
	Label       string
	AccessKey   string // 明文，只在内存里
	Session     *Session
	Email       string
	Sessionless bool
	ProbeData   map[string]any
	UpdatedAt   string
}

// EnrolRequest 登记/更新一个账户的入参。
type EnrolRequest struct {
	// Service 账户槽位名，建议用 ai-<uid> / cn-<手机号后4位> 这类可读 slug
	Service string `json:"service"`
	// Region ai | com
	Region string `json:"region"`
	Label  string `json:"label"`
	// AccessKey plan 推理 key（sk-…）。可以只登记会话不登记 key，反之亦然。
	AccessKey string `json:"access_key"`
	// SessionText 用户自己从浏览器里复制的 cookie 串 / Oasis-Token 头 / 裸 JWT
	SessionText string `json:"session_text"`
	// Email 账户邮箱（非机密，写进 identity）
	Email string `json:"email"`
	// Sessionless 手机号注册、无法二次登录：只登记邮箱 + key，面板不按掉线处理
	Sessionless bool `json:"sessionless"`
}

func nowISO() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// ---------------------------------------------------------------- 存储层

// upsertSQL 局部更新语义：没给的密文字段传 NULL，COALESCE 保住旧值——
// 只贴了会话的登记不能把已有的 plan key 擦掉，反之亦然。
const upsertSQL = `INSERT INTO stepfun_accounts
	(service, region, label, access_key_enc, console_session_enc, updated_at)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(service) DO UPDATE SET
		region = excluded.region,
		label = COALESCE(NULLIF(excluded.label, ''), stepfun_accounts.label),
		access_key_enc = COALESCE(excluded.access_key_enc, stepfun_accounts.access_key_enc),
		console_session_enc = COALESCE(excluded.console_session_enc, stepfun_accounts.console_session_enc),
		updated_at = excluded.updated_at`

// registerSlotSQL 只写设备会话列，绝不为占位而碰 access_key / identity / probe_data。
const registerSlotSQL = `INSERT INTO stepfun_accounts
	(service, region, label, console_session_enc, updated_at)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(service) DO UPDATE SET
		region = excluded.region,
		label = excluded.label,
		console_session_enc = excluded.console_session_enc,
		updated_at = excluded.updated_at`

type nullStr struct {
	sql.NullString
}

func (n *nullStr) value() string {
	if n.Valid {
		return n.String
	}
	return ""
}

func decryptOrErr(enc string, what string) (string, error) {
	if enc == "" {
		return "", nil
	}
	plain := store.Decrypt(enc)
	if plain == nil {
		// 密文解不开：主密钥换过，或行被外部改坏。宁可直接报错，
		// 也不要让一个「看起来登记过」的空壳账户留在面板上。
		return "", fmt.Errorf("%s 解密失败（主密钥不匹配？）", what)
	}
	return *plain, nil
}

// load 读出某个账户槽位（解密密钥，因此需要主密钥）。
func load(service string) (*Account, error) {
	var (
		regionStr, label, identityJSON, probeJSON, updatedAt string
		accessEnc, sessionEnc                                nullStr
	)
	err := store.DB.QueryRow(`SELECT region, label, access_key_enc, console_session_enc,
		identity, probe_data, updated_at FROM stepfun_accounts WHERE service = ?`, service).
		Scan(&regionStr, &label, &accessEnc, &sessionEnc, &identityJSON, &probeJSON, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("没有登记过名为 %s 的账户", service)
	}
	if err != nil {
		return nil, err
	}
	region, ok := ParseRegion(regionStr)
	if !ok {
		region = RegionCom
	}
	acc := &Account{
		Service:   service,
		Region:    region,
		Label:     label,
		UpdatedAt: updatedAt,
	}
	// identity 列是 JSON 对象；历史数据可能是纯文本，读不了就当没有
	if strings.HasPrefix(strings.TrimSpace(identityJSON), "{") {
		var id struct {
			Email       string `json:"email"`
			Sessionless bool   `json:"sessionless"`
		}
		if json.Unmarshal([]byte(identityJSON), &id) == nil {
			acc.Email = id.Email
			acc.Sessionless = id.Sessionless
		}
	}
	if probeJSON != "" {
		_ = json.Unmarshal([]byte(probeJSON), &acc.ProbeData)
	}
	if acc.ProbeData == nil {
		acc.ProbeData = map[string]any{}
	}
	if acc.AccessKey, err = decryptOrErr(accessEnc.value(), "access_key"); err != nil {
		return nil, err
	}
	if blob, err := decryptOrErr(sessionEnc.value(), "console_session"); err != nil {
		return nil, err
	} else if blob != "" {
		var s struct {
			Token   string `json:"token"`
			Webid   string `json:"webid"`
			Refresh string `json:"refresh"`
		}
		if json.Unmarshal([]byte(blob), &s) == nil && s.Token != "" {
			acc.Session = &Session{Token: s.Token, Webid: s.Webid, Refresh: s.Refresh}
		}
	}
	return acc, nil
}

// Services 所有已登记的账户槽位。
func Services() ([]string, error) {
	rows, err := store.DB.Query(`SELECT service FROM stepfun_accounts ORDER BY service`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// List 列表视图：只出元数据 + 掩码，永不出密文明文。
func List() ([]map[string]any, error) {
	svcs, err := Services()
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(svcs))
	for _, s := range svcs {
		acc, err := load(s)
		if err != nil {
			return nil, err
		}
		out = append(out, view(acc, nil))
	}
	return out, nil
}

func view(acc *Account, live map[string]any) map[string]any {
	p := acc.ProbeData
	if live != nil {
		p = live
	}
	sess := map[string]any(nil)
	if acc.Session != nil {
		sess = SessionSummary(acc.Session)
	}
	return map[string]any{
		"service":         acc.Service,
		"region":          acc.Region.String(),
		"label":           acc.Label,
		"has_access_key":  acc.AccessKey != "",
		"access_key_mask": maskOrNil(acc.AccessKey),
		"email":           acc.Email,
		"sessionless":     acc.Sessionless,
		"session":         sess,
		"probed_at":       probeField(p, "probed_at"),
		"plan":            probeField(p, "plan"),
		"console":         probeField(p, "console"),
		"console_error":   probeField(p, "console_error"),
		"renewed":         probeFieldDefault(p, "renewed", false),
		"session_state":   probeField(p, "session_state"),
		"verdict":         probeField(p, "verdict"),
		"updated_at":      acc.UpdatedAt,
	}
}

func maskOrNil(key string) any {
	if key == "" {
		return nil
	}
	return Mask(key)
}

func probeField(p map[string]any, key string) any {
	if p == nil {
		return nil
	}
	return p[key]
}

func probeFieldDefault(p map[string]any, key string, def any) any {
	if v := probeField(p, key); v != nil {
		return v
	}
	return def
}

// numOf 本进程内构造的计数是 int，从 JSON 反解回来的是 float64，两种都要接住。
func numOf(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return 0, false
}

func setProbeData(service string, data map[string]any) error {
	_, err := store.DB.Exec(`UPDATE stepfun_accounts SET probe_data = ?, updated_at = ? WHERE service = ?`,
		mustJSON(data), nowISO(), service)
	return err
}

func setIdentity(service, identityJSON string) error {
	_, err := store.DB.Exec(`UPDATE stepfun_accounts SET identity = ? WHERE service = ?`,
		identityJSON, service)
	return err
}

// ---------------------------------------------------------------- 登记

// validate 只出结果、不写库的一次校验。登记前先确认这条凭据真能打开至少一条面，
// 免得「先落库再回滚」在中途失败时留下半条账户。
func validate(region Region, accessKey string, session *Session) (plan, console map[string]any) {
	if accessKey != "" {
		ids, f := PlanModels(region, accessKey)
		if f != nil {
			plan = map[string]any{"ok": false, "error": f.Error(), "kind": string(f.Kind)}
		} else {
			plan = map[string]any{"ok": true, "model_count": len(ids)}
		}
	} else {
		plan = map[string]any{"ok": false, "kind": "not_enrolled", "error": "没有给 access_key"}
	}
	if session != nil {
		console, _ = consoleProbe(region, session)
	} else {
		console = map[string]any{"ok": false, "kind": "not_enrolled", "error": "没有给 console 会话"}
	}
	return plan, console
}

// Enrol 登记或更新一个账户。至少要能通过一次探测，否则拒绝写入——
// 空壳账户留在面板上只会让人以为它在被监控。
func Enrol(req *EnrolRequest) (map[string]any, error) {
	service := strings.ToLower(strings.TrimSpace(req.Service))
	if service == "" || !validService(service) {
		return nil, fmt.Errorf("service 只能是字母/数字/-/_.（用于主键）")
	}
	region, ok := ParseRegion(req.Region)
	if !ok {
		return nil, fmt.Errorf("region 要是 ai 或 com")
	}
	accessKey := strings.TrimSpace(req.AccessKey)
	if accessKey != "" && !strings.HasPrefix(accessKey, "sk-") {
		return nil, fmt.Errorf("access_key 看起来不是 StepFun 的 sk- 开头 key")
	}
	var session *Session
	if text := strings.TrimSpace(req.SessionText); text != "" {
		s, err := ParseSessionText(text)
		if err != nil {
			return nil, fmt.Errorf("解析 console 会话失败: %w", err)
		}
		session = s
	}
	if accessKey == "" && session == nil {
		return nil, fmt.Errorf("access_key 和 session_text 至少要给一个")
	}
	email := strings.TrimSpace(req.Email)
	if email != "" && (strings.Count(email, "@") != 1 || strings.ContainsFunc(email, func(r rune) bool { return r == ' ' || r == '\t' })) {
		return nil, fmt.Errorf("email 看起来不像邮箱地址")
	}
	// 真给了会话就不算「拿不到二次登录」，两个声明互斥
	sessionless := req.Sessionless && session == nil

	plan, console := validate(region, accessKey, session)
	if plan["ok"] != true && console["ok"] != true {
		return nil, fmt.Errorf("两条面都没探通，未写入任何一行：plan=%s console=%s",
			probeErrText(plan), consoleFirstError(console))
	}

	now := nowISO()
	var accessEnc, sessionEnc string
	if accessKey != "" {
		accessEnc = encryptOrEmpty(accessKey)
	}
	if session != nil {
		sessionEnc = encryptOrEmpty(mustJSON(map[string]any{
			"token":       session.Token,
			"webid":       session.Webid,
			"refresh":     session.Refresh,
			"captured_at": now,
		}))
	}
	if _, err := store.DB.Exec(upsertSQL, service, region.String(), req.Label,
		nullIfEmpty(accessEnc), nullIfEmpty(sessionEnc), now); err != nil {
		return nil, err
	}

	// 运营者给的元数据（邮箱 / sessionless）先落 identity；探测回来后再合并 uid / key 掩码
	var seed map[string]any
	if email != "" || sessionless {
		seed = map[string]any{}
		if email != "" {
			seed["email"] = email
		}
		if sessionless {
			seed["sessionless"] = true
		}
		if err := setIdentity(service, mustJSON(seed)); err != nil {
			return nil, err
		}
	}

	out, err := Probe(service)
	if err != nil {
		return nil, err
	}
	saved := []string{}
	if accessKey != "" {
		saved = append(saved, "access_key")
	}
	if session != nil {
		saved = append(saved, "console_session")
	}
	out["saved"] = saved
	return out, nil
}

func encryptOrEmpty(plain string) string {
	enc := store.Encrypt(plain)
	if enc == nil {
		return ""
	}
	return *enc
}

func validService(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}

func probeErrText(p map[string]any) string {
	if e, ok := p["error"].(string); ok {
		return e
	}
	return "?"
}

func consoleFirstError(console map[string]any) string {
	for _, k := range []string{"status", "rate_limit", "access_keys"} {
		sub, ok := console[k].(map[string]any)
		if !ok {
			continue
		}
		if e, ok := sub["error"].(string); ok && e != "" {
			return e
		}
	}
	return "?"
}

// consoleProbe 用保存下来的会话逐条调用 console 数据面。每一项都是 best effort：
// console 少一个方法可用不应该让整块面板变灰。
func consoleProbe(region Region, sess *Session) (map[string]any, *Fail) {
	out := map[string]any{"ok": true}
	var firstFail *Fail
	one := func(name string, r map[string]any, f *Fail) {
		if f != nil {
			out[name] = map[string]any{"ok": false, "error": f.Error(), "kind": string(f.Kind)}
			if firstFail == nil {
				firstFail = f
			}
			return
		}
		out[name] = r
	}
	v, f := PlanStatus(region, sess)
	one("status", v, f)
	v, f = RateLimit(region, sess)
	one("rate_limit", v, f)
	v, f = AccessKeys(region, sess)
	one("access_keys", v, f)
	if firstFail != nil {
		out["ok"] = false
	}
	return out, firstFail
}

// isDegradedRenewal 续期降级检测。
// 实测：会话过期之后再调 RefreshToken，passport 发回的是**设备令牌**
// （mode 1、uid 变成设备号），console 数据面一律 token is illegal——
// 比不续更糟，因为它把「过期」伪装成「有效」。登录态（mode 2）续成非登录态
// 即判定降级，此时绝不能落库，要保留原会话并要求重新登录。
func isDegradedRenewal(old, next *Session) bool {
	oldMode, okOld := old.mode()
	newMode, okNew := next.mode()
	if okOld && okNew && oldMode == 2 && newMode != 2 {
		return true
	}
	// uid 变了同样可疑（设备令牌的 uid 是设备号，不是账户号）
	oldUID, newUID := old.UID(), next.UID()
	if oldUID != "" && newUID != "" && oldUID != newUID {
		return true
	}
	return false
}

// renewPersisted 续期并立即落库（新 token 不换 webid——设备身份就是那个头）。
// 第二个返回值表示服务端确实发了一张不同的 token。
func renewPersisted(acc *Account) (*Session, bool, error) {
	if acc.Session == nil {
		return nil, false, fmt.Errorf("该账户没有 console 会话可续（手机号注册的账户只登记邮箱 + key）")
	}
	t, f := RefreshToken(acc.Region, acc.Session)
	if f != nil {
		return nil, false, fmt.Errorf("RefreshToken 失败: %w", f)
	}
	next := &Session{Token: t.Access, Webid: acc.Session.Webid, Refresh: orStr(t.Refresh, acc.Session.Refresh)}
	if isDegradedRenewal(acc.Session, next) {
		// 保留库里的原会话不动：过期会话至少能让人看出「要重新登录」，
		// 被换成设备令牌后界面一切显示正常、实际早已打不开数据面。
		return nil, false, fmt.Errorf("续期返回了降级的设备令牌（mode/uid 已变），已保留原会话；请到浏览器重新登录后覆盖登记")
	}
	changed := t.Access != acc.Session.Token
	if acc.Session.Webid == "" {
		next.Webid = NewWebid()
	}
	enc := encryptOrEmpty(mustJSON(map[string]any{
		"token":      next.Token,
		"webid":      next.Webid,
		"refresh":    next.Refresh,
		"renewed_at": nowISO(),
	}))
	if _, err := store.DB.Exec(`UPDATE stepfun_accounts SET console_session_enc = ?, updated_at = ? WHERE service = ?`,
		nullIfEmpty(enc), nowISO(), acc.Service); err != nil {
		return nil, false, err
	}
	return next, changed, nil
}

func orStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Probe 探测一个账户：plan 面 + console 面，console 认证失败时自动续一次再重试。
func Probe(service string) (map[string]any, error) {
	acc, err := load(service)
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"service":     service,
		"region":      acc.Region.String(),
		"email":       acc.Email,
		"sessionless": acc.Sessionless,
		"probed_at":   nowISO(),
	}
	renewed := false

	if acc.AccessKey != "" {
		ids, f := PlanModels(acc.Region, acc.AccessKey)
		if f != nil {
			out["plan"] = map[string]any{"ok": false, "error": f.Error(), "kind": string(f.Kind)}
		} else {
			out["plan"] = map[string]any{"ok": true, "model_count": len(ids), "models": ids}
		}
	} else {
		out["plan"] = map[string]any{"ok": false, "kind": "not_enrolled", "error": "没有登记 access_key"}
	}

	if acc.Session != nil {
		v, fail := consoleProbe(acc.Region, acc.Session)
		switch {
		case fail == nil:
			out["console"] = v
		case fail.ShouldAttemptRenew():
			next, changed, rerr := renewPersisted(acc)
			if rerr != nil {
				out["console"] = v
				out["console_error"] = map[string]any{"error": rerr.Error(), "kind": string(fail.Kind)}
				out["session_state"] = "needs_relogin"
				break
			}
			v2, fail2 := consoleProbe(acc.Region, next)
			renewed = changed
			out["console"] = v2
			if fail2 != nil {
				out["console_error"] = map[string]any{"error": fail2.Error(), "kind": string(fail2.Kind)}
				out["session_state"] = "needs_relogin"
			}
		default:
			out["console"] = v
			out["console_error"] = map[string]any{"error": fail.Error(), "kind": string(fail.Kind)}
			if fail.NeedsRelogin() {
				out["session_state"] = "needs_relogin"
			}
		}
	} else if acc.Sessionless {
		// 手机号注册的账户本来就只登记邮箱 + key，看不到额度是设计如此
		out["session_state"] = "metadata_only"
	} else {
		out["session_state"] = "not_enrolled"
	}

	out["renewed"] = renewed
	out["verdict"] = verdict(acc, out)

	// 身份与聚合写回数据库（都是非机密字段）
	if err := setProbeData(service, out); err != nil {
		return nil, err
	}
	if id := identityOf(acc); id != "" {
		if err := setIdentity(service, id); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// verdict 面板上的一句话结论。顺序很重要：plan 面是永久凭据，它说了算；
// console 面只是「看不看得到额度」。
func verdict(acc *Account, out map[string]any) string {
	plan, _ := out["plan"].(map[string]any)
	if plan == nil {
		return "unknown"
	}
	switch plan["ok"] {
	case true:
		n, _ := numOf(plan["model_count"])
		console, _ := out["console"].(map[string]any)
		if acc.Session != nil && console != nil && console["ok"] == true {
			return "serving+quota"
		}
		switch {
		case int(n) >= 7:
			return "serving"
		case int(n) > 2:
			return "serving_partial"
		default:
			return "no_plan"
		}
	case false:
		kind, _ := plan["kind"].(string)
		switch kind {
		case "not_enrolled":
			return "key_not_enrolled"
		case "unreachable":
			return "unreachable"
		default:
			return "not_serving"
		}
	}
	return "unknown"
}

func identityOf(acc *Account) string {
	m := map[string]any{}
	if acc.Email != "" {
		m["email"] = acc.Email
	}
	if acc.Sessionless {
		m["sessionless"] = true
	}
	if acc.Session != nil {
		if uid := acc.Session.UID(); uid != "" {
			m["uid"] = uid
		}
	}
	if acc.AccessKey != "" {
		m["key_mask"] = Mask(acc.AccessKey)
	}
	if len(m) == 0 {
		return ""
	}
	return mustJSON(m)
}

// Renew 强制续期（运维手动触发；probe 已经会自动续，这里是给「已知快到期」用的）。
func Renew(service string) (map[string]any, error) {
	acc, err := load(service)
	if err != nil {
		return nil, err
	}
	next, changed, err := renewPersisted(acc)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"service":       service,
		"renewed_at":    nowISO(),
		"token_changed": changed,
		"session":       SessionSummary(next),
	}, nil
}

// Remove 删掉该槽位的全部密文。
func Remove(service string) (int64, error) {
	res, err := store.DB.Exec(`DELETE FROM stepfun_accounts WHERE service = ?`, service)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RegisterSlot 给一个槽位注册我们自己的匿名设备会话（不含任何用户凭据）。
// 用途有二：新账户先占位、以及在没有用户 cookie 的情况下自证续期链路是通的。
// 匿名设备 token 打不开 console 数据面（服务端回 token is illegal），
// 这是预期行为，不是失败——所以这里直接断言「能不能换到新 token」。
func RegisterSlot(service string, region Region) (map[string]any, error) {
	if !validService(service) {
		return nil, fmt.Errorf("service 只能是字母/数字/-/_.（用于主键）")
	}
	webid := NewWebid()
	t, f := RegisterDevice(region, webid)
	if f != nil {
		return nil, fmt.Errorf("RegisterDevice 失败: %w", f)
	}
	sess := &Session{Token: t.Access, Webid: webid, Refresh: t.Refresh}
	enc := encryptOrEmpty(mustJSON(map[string]any{
		"token":         sess.Token,
		"webid":         sess.Webid,
		"refresh":       sess.Refresh,
		"registered_at": nowISO(),
	}))
	label := "自注册设备会话（匿名，非用户凭据）"
	if _, err := store.DB.Exec(registerSlotSQL, service, region.String(), label, nullIfEmpty(enc), nowISO()); err != nil {
		return nil, err
	}

	// 立刻验证续期链路：调一次 RefreshToken 并落库。
	// 注意 .com 在同一秒内续期会拿回逐字节相同的 token（passport 按秒签发），
	// 所以「调用成功」和「token 变了」是两件事，分开报。
	renewal, rerr := Renew(service)
	ok := false
	if rerr == nil {
		changed, _ := renewal["token_changed"].(bool)
		tokenLen := 0.0
		if s, m := renewal["session"].(map[string]any); m {
			tokenLen, _ = numOf(s["token_len"])
		}
		ok = changed || tokenLen > 0
	} else {
		renewal = map[string]any{"ok": false, "error": rerr.Error()}
	}
	renewal["ok"] = ok

	exp, _ := (&Session{Token: t.Access}).exp()
	return map[string]any{
		"service": service,
		"region":  region.String(),
		"registered": map[string]any{
			"webid_mask":    Mask(webid),
			"oasis_id":      t.OasisID,
			"duration_secs": t.Duration,
			"token_len":     len([]rune(sess.Token)),
			"has_refresh":   t.Refresh != "",
			"exp":           ISOFromSecs(exp),
		},
		"renewal": renewal,
	}, nil
}
