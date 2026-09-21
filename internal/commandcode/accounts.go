package commandcode

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/limitcool/quota-mcp/internal/store"
)

// 一个「账户」= commandcode_accounts 表里的一行，两条鉴权面二选一或并存：
//
//	api_key_enc       /alpha 面永久 Bearer key（commandcode.ai/settings 获取）
//	session_token_enc /internal 面浏览器会话 cookie（__Secure-commandcode_prod_.session_token）
//
// api_key 永久有效、不会掉线，会话_token 会过期需要重抓。两者都给时优先用 api_key。
// 没有续期机制：会话过期了只能重新从 CookieCloud 同步。

// Account 内存中的账户视图（含解密的凭据明文，绝不进任何响应体）。
type Account struct {
	Service   string
	APIKey    string
	Session   string
	Label     string
	ProbeData map[string]any
	UpdatedAt string
}

// credential 组装一次探测用的凭据（api_key 优先）。
func (a *Account) credential() Credential {
	return Credential{Key: a.APIKey, Session: a.Session}
}

// EnrolRequest 登记一个账户的入参。
//
// 轮换语义：每次 Enrol 都写「本次请求提供的凭据」——未提供的面会被置 NULL。
// 例：只带 api_key 重新登记会清掉旧的 session_token_enc，反之亦然。
// 这样用户「换成 api_key 就当已轮换」的直觉与库内状态一致，不会残留旧 cookie 密文。
type EnrolRequest struct {
	Service string `json:"service"`
	// APIKey 永久 Bearer key（可选；与 session_text 至少给一个）
	APIKey string `json:"api_key"`
	// SessionText 用户从浏览器/CookieCloud 复制的会话串（整串 cookie / Cookie 头 / 裸 session_token）
	SessionText string `json:"session_text"`
	Label       string `json:"label"`
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

// upsertSQL 每次登记都整行覆盖凭据两面：未提供（NULL）的面会被清空，
// 而不是保留旧值。这是刻意的轮换语义——只给 api_key 重新登记会清掉旧 session，
// 只给 session_text 会清掉旧 key，避免「用户以为已轮换、旧密文却永久留库」的盲区。
const upsertSQL = `INSERT INTO commandcode_accounts
	(service, api_key_enc, session_token_enc, label, updated_at)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(service) DO UPDATE SET
		api_key_enc = excluded.api_key_enc,
		session_token_enc = excluded.session_token_enc,
		label = COALESCE(NULLIF(excluded.label, ''), commandcode_accounts.label),
		updated_at = excluded.updated_at`

func encryptOrEmpty(plain string) string {
	enc := store.Encrypt(plain)
	if enc == nil {
		return ""
	}
	return *enc
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func decryptOrErr(enc, what string) (string, error) {
	if enc == "" {
		return "", nil
	}
	plain := store.Decrypt(enc)
	if plain == nil {
		return "", fmt.Errorf("%s 解密失败（主密钥不匹配？）", what)
	}
	return *plain, nil
}

// load 读出某个账户槽位（解密凭据，因此需要主密钥）。
func load(service string) (*Account, error) {
	var label, probeJSON, updatedAt string
	var keyEnc, sessEnc sql.NullString
	err := store.DB.QueryRow(`SELECT api_key_enc, session_token_enc, label, probe_data, updated_at
		FROM commandcode_accounts WHERE service = ?`, service).
		Scan(&keyEnc, &sessEnc, &label, &probeJSON, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("没有登记过名为 %s 的账户", service)
	}
	if err != nil {
		return nil, err
	}
	acc := &Account{Service: service, Label: label, UpdatedAt: updatedAt}
	if probeJSON != "" {
		_ = json.Unmarshal([]byte(probeJSON), &acc.ProbeData)
	}
	if acc.ProbeData == nil {
		acc.ProbeData = map[string]any{}
	}
	if acc.APIKey, err = decryptOrErr(keyEnc.String, "api_key"); err != nil {
		return nil, err
	}
	if acc.Session, err = decryptOrErr(sessEnc.String, "session_token"); err != nil {
		return nil, err
	}
	return acc, nil
}

// Services 所有已登记的账户槽位。
func Services() ([]string, error) {
	rows, err := store.DB.Query(`SELECT service FROM commandcode_accounts ORDER BY service`)
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

// List 列表视图：只出元数据 + 掩码，永不出 key 明文。
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
	cred := acc.credential()
	var sess map[string]any
	if acc.Session != "" {
		sess = SessionSummary(acc.Session)
	}
	return map[string]any{
		"service":     acc.Service,
		"label":       acc.Label,
		"key_mask":    maskOrNil(acc.APIKey),
		"has_api_key": acc.APIKey != "",
		"has_session": acc.Session != "",
		"cred_source": cred.describe(),
		"session":     sess,
		"account":     probeField(p, "account"),
		"plan":        probeField(p, "plan"),
		"credits":     probeField(p, "credits"),
		"five_hour":   probeField(p, "five_hour"),
		"weekly":      probeField(p, "weekly"),
		"monthly":     probeField(p, "monthly"),
		"usage":       probeField(p, "usage"),
		"failures":    probeField(p, "failures"),
		"probed_at":   probeField(p, "probed_at"),
		"verdict":     probeFieldDefault(p, "verdict", "unknown"),
		"updated_at":  acc.UpdatedAt,
	}
}

func maskOrNil(key string) any {
	if key == "" {
		return nil
	}
	if len([]rune(key)) <= 12 {
		return "…"
	}
	r := []rune(key)
	return fmt.Sprintf("%s…%s", string(r[:4]), string(r[len(r)-4:]))
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

func setProbeData(service string, data map[string]any) error {
	_, err := store.DB.Exec(`UPDATE commandcode_accounts SET probe_data = ?, updated_at = ? WHERE service = ?`,
		mustJSON(data), nowISO(), service)
	return err
}

func setIdentity(service, identityJSON string) error {
	_, err := store.DB.Exec(`UPDATE commandcode_accounts SET identity = ? WHERE service = ?`,
		identityJSON, service)
	return err
}

// ---------------------------------------------------------------- 登记与探测

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

// validateCredential 只出结果、不写库地确认这条凭据真能打开数据面。
// api_key 面先打 whoami；会话面没有身份端点，用 billing/credits 验证。
func validateCredential(cred Credential) (who map[string]any, f *Fail) {
	if cred.Key != "" {
		return Whoami(cred)
	}
	// 会话面：credits 能返回即视为有效
	if _, f := Credits(cred); f != nil {
		return nil, f
	}
	return nil, nil
}

// Enrol 登记或更新一个账户。至少要能通过一次探测（api_key 的 whoami / 会话的 credits），
// 被拒就不落库——免得面板上留一个死账户。
func Enrol(req *EnrolRequest) (map[string]any, error) {
	service := strings.ToLower(strings.TrimSpace(req.Service))
	if !validService(service) {
		return nil, fmt.Errorf("service 只能是字母/数字/-/_.（用于主键）")
	}
	key := strings.TrimSpace(req.APIKey)
	var session string
	if text := strings.TrimSpace(req.SessionText); text != "" {
		s, err := ParseSessionText(text)
		if err != nil {
			return nil, fmt.Errorf("解析会话失败: %w", err)
		}
		session = s
	}
	if key == "" && session == "" {
		return nil, fmt.Errorf("api_key 和 session_text 至少要给一个")
	}
	// 校验：凭据无效就不落库
	if _, f := validateCredential(Credential{Key: key, Session: session}); f != nil {
		return nil, fmt.Errorf("凭据校验未通过: %w", f)
	}
	var keyEnc, sessEnc string
	saved := []string{}
	if key != "" {
		keyEnc = encryptOrEmpty(key)
		saved = append(saved, "api_key")
	}
	if session != "" {
		sessEnc = encryptOrEmpty(session)
		saved = append(saved, "session_token")
	}
	if _, err := store.DB.Exec(upsertSQL, service, nullIfEmpty(keyEnc), nullIfEmpty(sessEnc), req.Label, nowISO()); err != nil {
		return nil, err
	}
	out, err := Probe(service)
	if err != nil {
		return nil, err
	}
	out["saved"] = saved
	out["cred_source"] = Credential{Key: key, Session: session}.describe()
	return out, nil
}

// Probe 探测一个账户：四条数据面端点各打一遍，任一面失败只记 failures，不拖垮其他面。
// 凭据按「api_key 优先，会话兜底」选取。
func Probe(service string) (map[string]any, error) {
	acc, err := load(service)
	if err != nil {
		return nil, err
	}
	if acc.APIKey == "" && acc.Session == "" {
		return nil, fmt.Errorf("该账户没有登记 api_key 或 session_token")
	}
	cred := acc.credential()
	sessionMode := cred.sessionMode()
	out := map[string]any{
		"service":     service,
		"probed_at":   nowISO(),
		"cred_source": cred.describe(),
	}
	failures := []string{}

	// 1. whoami → 账户身份（+ orgId 供订阅端点）。仅 api_key 面有该端点。
	var orgID string
	if !sessionMode {
		who, f := Whoami(cred)
		if f != nil {
			failures = append(failures, "whoami: "+f.Error())
			if f.Kind == FailKeyRejected {
				// key 直接被拒：其余端点没有意义，直接出结论
				out["account"] = nil
				out["failures"] = failures
				out["verdict"] = "key_rejected"
				_ = setProbeData(service, out)
				return out, nil
			}
		} else {
			out["account"] = who
			orgID, _ = who["org_id"].(string)
		}
	} else {
		// 会话面没有 identity 端点，身份留空；凭据来源已由 cred_source 说明
		out["account"] = nil
	}

	// 2. billing/credits → 余额 + 5h/周窗口（会话面同样有该端点）
	cr, creditsFail := Credits(cred)
	if creditsFail != nil {
		failures = append(failures, "billing/credits: "+creditsFail.Error())
	} else {
		out["credits"] = cr
		out["five_hour"] = cr["five_hour"]
		out["weekly"] = cr["weekly"]
	}

	// 3. billing/subscriptions → 套餐与账期
	sub, f := Subscriptions(cred, orgID)
	if f != nil {
		failures = append(failures, "billing/subscriptions: "+f.Error())
		// credits 响应里可能带 planId，作兜底
		if cr != nil {
			if pid, _ := cr["plan_id"].(string); pid != "" {
				sub = map[string]any{"plan_id": pid, "status": ""}
			}
		}
	}
	if sub != nil {
		if info, ok := planInfo(strOf(sub["plan_id"])); ok {
			sub["plan_name"] = info.Name
			sub["monthly_credits_cap"] = info.MonthlyCredits
		}
		out["plan"] = sub
	}

	// 4. usage/summary → 账期累计统计
	us, f := UsageSummary(cred)
	if f != nil {
		failures = append(failures, "usage/summary: "+f.Error())
	} else {
		out["usage"] = us
	}

	// 会话面且首面就 401：说明 session_token 过期，报明确的「要重抓」状态。
	if sessionMode && creditsFail != nil && creditsFail.NeedsRefresh() {
		out["session_state"] = "needs_refresh"
	}
	// 月度窗口是推导值：cap 来自套餐映射，used = cap − 剩余，重置 = 账期结束
	out["monthly"] = deriveMonthly(out)
	if len(failures) > 0 {
		out["failures"] = failures
	}
	out["verdict"] = verdict(out)
	if id := identityOf(out); id != "" {
		if err := setIdentity(service, id); err != nil {
			log.Printf("commandcode: 写入 %s 的 identity 失败（面板可能显示旧身份）: %v", service, err)
		}
	}
	if err := setProbeData(service, out); err != nil {
		log.Printf("commandcode: 写入 %s 的 probe_data 失败（面板可能显示旧探测结果）: %v", service, err)
	}
	return out, nil
}

// deriveMonthly 月度用量窗口（社区面板同款推导，标注「额度按套餐估算」）。
func deriveMonthly(out map[string]any) map[string]any {
	plan, _ := out["plan"].(map[string]any)
	credits, _ := out["credits"].(map[string]any)
	if plan == nil {
		return nil
	}
	capVal, ok := plan["monthly_credits_cap"].(float64)
	if !ok || capVal <= 0 {
		// 未知套餐：推不出月度窗口，面板退回只显示余额
		return nil
	}
	remaining := 0.0
	if credits != nil {
		if m, ok := credits["monthly_credits"].(float64); ok {
			remaining = m
		}
	}
	used := capVal - remaining
	if used < 0 {
		used = 0
	}
	return map[string]any{
		"used":      used,
		"cap":       capVal,
		"exceeded":  used >= capVal,
		"reset_at":  strOf(plan["current_period_end"]),
		"estimated": true,
	}
}

// verdict 面板上的一句话结论。api_key 面靠 account 身份，会话面没有身份端点，
// 所以以「有没有拿到 credits/plan 数据」为准，而不是以 account 是否为空。
func verdict(out map[string]any) string {
	if out["verdict"] == "key_rejected" {
		return "key_rejected"
	}
	if s, _ := out["session_state"].(string); s == "needs_refresh" {
		return "session_expired"
	}
	// 完全没拿到数据面：账号身份也没有，就是打不通/凭据全废
	_, hasCredits := out["credits"].(map[string]any)
	_, hasPlan := out["plan"].(map[string]any)
	_, hasUsage := out["usage"].(map[string]any)
	if !hasCredits && !hasPlan && !hasUsage {
		return "unreachable"
	}
	// 整体限流状态优先：windowLimits.exceeded 直接指出是哪个窗口在拦
	for _, k := range []string{"five_hour", "weekly"} {
		if w, ok := out[k].(map[string]any); ok && w["exceeded"] == true {
			return "limited"
		}
	}
	if m, ok := out["monthly"].(map[string]any); ok && m["exceeded"] == true {
		return "limited"
	}
	return "serving"
}

func identityOf(out map[string]any) string {
	acc, _ := out["account"].(map[string]any)
	if acc == nil {
		return ""
	}
	m := map[string]any{}
	if v := strOf(acc["user_name"]); v != "" {
		m["user_name"] = v
	}
	if v := strOf(acc["name"]); v != "" {
		m["name"] = v
	}
	if v := strOf(acc["id"]); v != "" {
		m["user_id"] = v
	}
	if len(m) == 0 {
		return ""
	}
	return mustJSON(m)
}

// Remove 删掉该槽位的 key。
func Remove(service string) (int64, error) {
	res, err := store.DB.Exec(`DELETE FROM commandcode_accounts WHERE service = ?`, service)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
