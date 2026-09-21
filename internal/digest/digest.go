// Package digest 组装定时播报 payload。
//
// hermes 的 cron 每天 9:30 跑一个 turn：调 quota_report（或 GET /api/report），
// 把返回整理成消息发出去。这里只负责把两个 provider 的数据压成一份
// 人话友好、字段稳定的日报，不碰调度与投递——那是 hermes 的强项。
package digest

import (
	"time"

	"github.com/limitcool/quota-mcp/internal/alerts"
	"github.com/limitcool/quota-mcp/internal/commandcode"
	"github.com/limitcool/quota-mcp/internal/stepfun"
)

// Report 播报 payload。
func Report() (map[string]any, error) {
	sf, err := stepfun.List()
	if err != nil {
		return nil, err
	}
	cc, err := commandcode.List()
	if err != nil {
		return nil, err
	}
	firing, err := alerts.Firing()
	if err != nil {
		return nil, err
	}

	out := map[string]any{
		"generated_at": time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"stepfun":      stepfunLines(sf),
		"commandcode":  ccLines(cc),
		"alerts":       firing,
		"alert_count":  len(firing),
	}
	return out, nil
}

func stepfunLines(items []map[string]any) []map[string]any {
	lines := []map[string]any{}
	for _, a := range items {
		row := map[string]any{
			"service":       a["service"],
			"region":        a["region"],
			"label":         a["label"],
			"session_state": a["session_state"],
		}
		if s, ok := a["session"].(map[string]any); ok {
			row["session_ttl_secs"] = s["ttl_secs"]
			row["session_expired"] = s["expired"]
		}
		if c, ok := a["console"].(map[string]any); ok {
			if rl, ok := c["rate_limit"].(map[string]any); ok {
				row["credit_left_rate"] = rl["credit_left_rate"]
				row["credit_reset_at"] = rl["credit_reset_at"]
			}
			if st, ok := c["status"].(map[string]any); ok {
				row["plan_name"] = st["plan_name"]
				row["valid_until"] = st["valid_until"]
			}
		}
		lines = append(lines, row)
	}
	return lines
}

func ccLines(items []map[string]any) []map[string]any {
	lines := []map[string]any{}
	for _, a := range items {
		row := map[string]any{
			"service": a["service"],
			"label":   a["label"],
			"verdict": a["verdict"],
		}
		if p, ok := a["plan"].(map[string]any); ok {
			row["plan_name"] = p["plan_name"]
			row["current_period_end"] = p["current_period_end"]
		}
		if c, ok := a["credits"].(map[string]any); ok {
			row["monthly_credits"] = c["monthly_credits"]
		}
		for _, k := range []string{"five_hour", "weekly", "monthly"} {
			if w, ok := a[k].(map[string]any); ok {
				row[k] = map[string]any{"used": w["used"], "cap": w["cap"], "exceeded": w["exceeded"]}
			}
		}
		if u, ok := a["usage"].(map[string]any); ok {
			row["usage_total_count"] = u["total_count"]
			row["usage_success_rate"] = u["success_rate"]
		}
		lines = append(lines, row)
	}
	return lines
}
