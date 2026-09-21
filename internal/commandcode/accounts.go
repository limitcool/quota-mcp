package commandcode

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/limitcool/quota-mcp/internal/store"
)

// 一个「账户」= commandcode_accounts 表里的一行：一把 Bearer API key（密文）。
// Command Code 没有会话概念，key 即全部，所以不存在续期；探测就是把四个
// /alpha 端点各打一遍，任一面失败不影响其他面（面板按面各自显示）。

// Account 内存中的账户视图（含解密的 key 明文，绝不进任何响应体）。
type Account struct {
	Service   string
	APIKey    string
	Label     string
	ProbeData map[string]any
	UpdatedAt string
}

// EnrolRequest 登记一个账户的入参。
type EnrolRequest struct {
	Service string `json:"service"`
	APIKey  string `json:"api_key"`
	Label   string `json:"label"`
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

const upsertSQL = `INSERT INTO commandcode_accounts
	(service, api_key_enc, label, updated_at)
	VALUES (?, ?, ?, ?)
	ON CONFLICT(service) DO UPDATE SET
		api_key_enc = excluded.api_key_enc,
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

// load 读出某个账户槽位（解密 key，因此需要主密钥）。
func load(service string) (*Account, error) {
	var label, probeJSON, updatedAt string
	var keyEnc sql.NullString
	err := store.DB.QueryRow(`SELECT api_key_enc, label, probe_data, updated_at
		FROM commandcode_accounts WHERE service = ?`, service).
		Scan(&keyEnc, &label, &probeJSON, &updatedAt)
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
	return map[string]any{
		"service":    acc.Service,
		"label":      acc.Label,
		"key_mask":   maskOrNil(acc.APIKey),
		"account":    probeField(p, "account"),
		"plan":       probeField(p, "plan"),
		"credits":    probeField(p, "credits"),
		"five_hour":  probeField(p, "five_hour"),
		"weekly":     probeField(p, "weekly"),
		"monthly":    probeField(p, "monthly"),
		"usage":      probeField(p, "usage"),
		"failures":   probeField(p, "failures"),
		"probed_at":  probeField(p, "probed_at"),
		"verdict":    probeFieldDefault(p, "verdict", "unknown"),
		"updated_at": acc.UpdatedAt,
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

// Enrol 登记或更新一个账户。先打 whoami 验证 key，被拒就不落库。
func Enrol(req *EnrolRequest) (map[string]any, error) {
	service := strings.ToLower(strings.TrimSpace(req.Service))
	if !validService(service) {
		return nil, fmt.Errorf("service 只能是字母/数字/-/_.（用于主键）")
	}
	key := strings.TrimSpace(req.APIKey)
	if key == "" {
		return nil, fmt.Errorf("api_key 必填（commandcode.ai/settings 里获取）")
	}
	// key 无效在 whoami 就会暴露（401/403），没必要落一个死账户
	if _, f := Whoami(key); f != nil {
		return nil, fmt.Errorf("key 校验未通过: %w", f)
	}
	if _, err := store.DB.Exec(upsertSQL, service, encryptOrEmpty(key), req.Label, nowISO()); err != nil {
		return nil, err
	}
	out, err := Probe(service)
	if err != nil {
		return nil, err
	}
	out["saved"] = []string{"api_key"}
	return out, nil
}

// Probe 探测一个账户：四个端点各打一遍，任一面失败只记 failures，不拖垮其他面。
func Probe(service string) (map[string]any, error) {
	acc, err := load(service)
	if err != nil {
		return nil, err
	}
	if acc.APIKey == "" {
		return nil, fmt.Errorf("该账户没有登记 api_key")
	}
	key := acc.APIKey
	out := map[string]any{
		"service":   service,
		"probed_at": nowISO(),
	}
	failures := []string{}

	// 1. whoami → 账户身份（+ orgId 供订阅端点）
	var orgID string
	who, f := Whoami(key)
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

	// 2. billing/credits → 余额 + 5h/周窗口
	cr, f := Credits(key)
	if f != nil {
		failures = append(failures, "billing/credits: "+f.Error())
	} else {
		out["credits"] = cr
		out["five_hour"] = cr["five_hour"]
		out["weekly"] = cr["weekly"]
	}

	// 3. billing/subscriptions → 套餐与账期
	sub, f := Subscriptions(key, orgID)
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
	us, f := UsageSummary(key)
	if f != nil {
		failures = append(failures, "usage/summary: "+f.Error())
	} else {
		out["usage"] = us
	}

	// 月度窗口是推导值：cap 来自套餐映射，used = cap − 剩余，重置 = 账期结束
	out["monthly"] = deriveMonthly(out)
	if len(failures) > 0 {
		out["failures"] = failures
	}
	out["verdict"] = verdict(out)
	if id := identityOf(out); id != "" {
		_ = setIdentity(service, id)
	}
	_ = setProbeData(service, out)
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

// verdict 面板上的一句话结论。
func verdict(out map[string]any) string {
	if out["account"] == nil {
		if out["verdict"] == "key_rejected" {
			return "key_rejected"
		}
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
