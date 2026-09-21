package alerts

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/limitcool/quota-mcp/internal/store"
)

func nowISO() string { return time.Now().UTC().Format("2006-01-02T15:04:05Z") }

// EvaluateAll 汇总两个 provider 的当前条件。
func EvaluateAll(stepfunItems, ccItems []map[string]any, cfg Config) []Alert {
	out := []Alert{}
	for _, a := range stepfunItems {
		out = append(out, evalStepfun(a, cfg)...)
	}
	for _, a := range ccItems {
		out = append(out, evalCommandCode(a, cfg)...)
	}
	return out
}

// Reconcile 把当前条件同步进状态机，返回「新触发」和「刚恢复」的告警
// （只有这两类值得通知；持续 firing 的不会重复推）。
func Reconcile(current []Alert) (fired, resolved []Alert, err error) {
	tx, err := store.DB.Begin()
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()

	// 1. 当前条件 upsert；全新指纹 = 新触发
	seen := map[string]bool{}
	for _, a := range current {
		fp := a.fingerprint()
		seen[fp] = true
		var id int
		var state string
		err := tx.QueryRow(`SELECT id, state FROM alert_events WHERE fingerprint = ?`, fp).Scan(&id, &state)
		switch {
		case err == sql.ErrNoRows:
			if _, e := tx.Exec(`INSERT INTO alert_events
				(fingerprint, kind, provider, service, severity, title, detail, state, first_seen, last_seen)
				VALUES (?,?,?,?,?,?,?, 'firing', ?, ?)`,
				fp, a.Kind, a.Provider, a.Service, a.Severity, a.Title, a.Detail, nowISO(), nowISO()); e != nil {
				return nil, nil, e
			}
			fired = append(fired, a)
		case err != nil:
			return nil, nil, err
		default:
			// 已存在：刷新呈现（severity/detail 可能变）；此前恢复过的算再次触发
			if _, e := tx.Exec(`UPDATE alert_events SET severity = ?, title = ?, detail = ?, last_seen = ?, state = 'firing', resolved_at = NULL
				WHERE id = ?`, a.Severity, a.Title, a.Detail, nowISO(), id); e != nil {
				return nil, nil, e
			}
			if state != "firing" {
				fired = append(fired, a)
			}
		}
	}

	// 2. 库里 firing 但当前不在场的 → 标记恢复
	rows, err := tx.Query(`SELECT fingerprint, kind, provider, service, title FROM alert_events WHERE state = 'firing'`)
	if err != nil {
		return nil, nil, err
	}
	type row struct {
		fp, kind, provider, service, title string
	}
	var firing []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.fp, &r.kind, &r.provider, &r.service, &r.title); err != nil {
			rows.Close()
			return nil, nil, err
		}
		firing = append(firing, r)
	}
	rows.Close()
	for _, r := range firing {
		if seen[r.fp] {
			continue
		}
		if _, e := tx.Exec(`UPDATE alert_events SET state = 'resolved', resolved_at = ?, notified = 0 WHERE fingerprint = ?`, nowISO(), r.fp); e != nil {
			return nil, nil, e
		}
		resolved = append(resolved, Alert{
			Kind: r.kind, Provider: r.provider, Service: r.service,
			Severity: SevInfo, Title: r.title + "（已恢复）", Detail: "条件已解除",
		})
	}

	return fired, resolved, tx.Commit()
}

// Firing 当前触发中的告警（按 severity 降序）。
func Firing() ([]Alert, error) {
	rows, err := store.DB.Query(`SELECT kind, provider, service, severity, title, detail FROM alert_events
		WHERE state = 'firing' ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'warn' THEN 1 ELSE 2 END, first_seen`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var a Alert
		var sev string
		if err := rows.Scan(&a.Kind, &a.Provider, &a.Service, &sev, &a.Title, &a.Detail); err != nil {
			return nil, err
		}
		a.Severity = Severity(sev)
		out = append(out, a)
	}
	return out, rows.Err()
}

// History 最近 N 条（含已恢复），给面板/播报做上下文。
func History(limit int) ([]map[string]any, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := store.DB.Query(`SELECT kind, provider, service, severity, title, detail, state, first_seen, last_seen, resolved_at
		FROM alert_events ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var kind, provider, service, severity, title, detail, state, firstSeen, lastSeen string
		var resolvedAt sql.NullString
		if err := rows.Scan(&kind, &provider, &service, &severity, &title, &detail, &state, &firstSeen, &lastSeen, &resolvedAt); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"kind": kind, "provider": provider, "service": service, "severity": severity,
			"title": title, "detail": detail, "state": state,
			"first_seen": firstSeen, "last_seen": lastSeen, "resolved_at": resolvedAt.String,
		})
	}
	return out, rows.Err()
}

// NotifyWebhook 把跃迁事件推给 hermes 的 webhook 订阅（至少一次，notified 标记）。
func NotifyWebhook(url string, fired, resolved []Alert) error {
	if url == "" || (len(fired) == 0 && len(resolved) == 0) {
		return nil
	}
	payload := map[string]any{
		"source":   "quota-mcp",
		"at":       nowISO(),
		"fired":    fired,
		"resolved": resolved,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook 返回 HTTP %d", resp.StatusCode)
	}
	return markNotified(fired, resolved)
}

func markNotified(fired, resolved []Alert) error {
	for _, a := range append(append([]Alert{}, fired...), resolved...) {
		if _, err := store.DB.Exec(`UPDATE alert_events SET notified = 1 WHERE fingerprint = ?`, a.fingerprint()); err != nil {
			return err
		}
	}
	return nil
}
