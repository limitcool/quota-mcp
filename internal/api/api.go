// Package api 提供 quota-mcp 的 REST 管理接口（std net/http，无框架）。
//
// 所有响应只出掩码视图，绝不出密文。写入类接口（登记/续期/删除）建议只在
// 本机或内网暴露；对外查询用 MCP 工具面（internal/mcpsrv）。
package api

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/limitcool/quota-mcp/internal/alerts"
	"github.com/limitcool/quota-mcp/internal/commandcode"
	"github.com/limitcool/quota-mcp/internal/digest"
	"github.com/limitcool/quota-mcp/internal/stepfun"
)

// Handler 返回挂好全部路由的 ServeMux。
func Handler() *http.ServeMux {
	mux := http.NewServeMux()

	// StepFun
	mux.HandleFunc("/api/stepfun/accounts", stepfunAccounts)
	mux.HandleFunc("/api/stepfun/accounts/", stepfunAccount)
	mux.HandleFunc("/api/stepfun/probe", stepfunProbeAll)

	// Command Code
	mux.HandleFunc("/api/commandcode/accounts", commandcodeAccounts)
	mux.HandleFunc("/api/commandcode/accounts/", commandcodeAccount)
	mux.HandleFunc("/api/commandcode/probe", commandcodeProbeAll)

	// 告警与播报
	mux.HandleFunc("/api/alerts", handleAlerts)
	mux.HandleFunc("/api/report", handleReport)

	// 健康检查
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	return mux
}

// GET /api/alerts?history=20 — 触发中的告警（+ 可选历史）
func handleAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	firing, err := alerts.Firing()
	if err != nil {
		fail(w, err)
		return
	}
	out := map[string]any{"firing": firing, "firing_count": len(firing)}
	if n, err := strconv.Atoi(r.URL.Query().Get("history")); err == nil && n > 0 {
		h, err := alerts.History(n)
		if err != nil {
			fail(w, err)
			return
		}
		out["history"] = h
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/report — 定时播报 payload（hermes cron 每天 9:30 拉这个）
func handleReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	rep, err := digest.Report()
	if err != nil {
		fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// errText 错误文本只回显首行并截断——解析失败时错误里可能带用户贴入的原文。
func errText(err error) string {
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i >= 0 {
		msg = msg[:i]
	}
	if r := []rune(msg); len(r) > 200 {
		msg = string(r[:200])
	}
	log.Printf("api: %s", msg)
	return msg
}

func fail(w http.ResponseWriter, err error) {
	jsonError(w, errText(err), http.StatusBadRequest)
}

// ---------------------------------------------------------------- StepFun

func stepfunAccounts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := stepfun.List()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
	case http.MethodPost:
		var req stepfun.EnrolRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid json", http.StatusBadRequest)
			return
		}
		v, err := stepfun.Enrol(&req)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func stepfunAccount(w http.ResponseWriter, r *http.Request) {
	rawService, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/stepfun/accounts/"), "/")
	if rawService == "" {
		jsonError(w, "缺少账户槽位名", http.StatusBadRequest)
		return
	}
	switch {
	case action == "probe" && r.Method == http.MethodPost:
		v, err := stepfun.Probe(rawService)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	case action == "renew" && r.Method == http.MethodPost:
		v, err := stepfun.Renew(rawService)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	case action == "register" && r.Method == http.MethodPost:
		region, ok := stepfun.ParseRegion(r.URL.Query().Get("region"))
		if !ok {
			jsonError(w, "region 要是 ai 或 com", http.StatusBadRequest)
			return
		}
		v, err := stepfun.RegisterSlot(rawService, region)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	case action == "" && r.Method == http.MethodDelete:
		n, err := stepfun.Remove(rawService)
		if err != nil {
			fail(w, err)
			return
		}
		if n == 0 {
			jsonError(w, "没有这个账户槽位", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": n, "service": rawService})
	default:
		jsonError(w, "没有这个端点", http.StatusNotFound)
	}
}

func stepfunProbeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	svcs, err := stepfun.Services()
	if err != nil {
		fail(w, err)
		return
	}
	items := make([]map[string]any, 0, len(svcs))
	for _, s := range svcs {
		v, err := stepfun.Probe(s)
		if err != nil {
			items = append(items, map[string]any{"service": s, "error": err.Error()})
			continue
		}
		items = append(items, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// ---------------------------------------------------------------- Command Code

func commandcodeAccounts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		items, err := commandcode.List()
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
	case http.MethodPost:
		var req commandcode.EnrolRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid json", http.StatusBadRequest)
			return
		}
		v, err := commandcode.Enrol(&req)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	default:
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
	}
}

func commandcodeAccount(w http.ResponseWriter, r *http.Request) {
	rawService, action, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/api/commandcode/accounts/"), "/")
	if rawService == "" {
		jsonError(w, "缺少账户槽位名", http.StatusBadRequest)
		return
	}
	switch {
	case action == "probe" && r.Method == http.MethodPost:
		v, err := commandcode.Probe(rawService)
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, v)
	case action == "" && r.Method == http.MethodDelete:
		n, err := commandcode.Remove(rawService)
		if err != nil {
			fail(w, err)
			return
		}
		if n == 0 {
			jsonError(w, "没有这个账户槽位", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": n, "service": rawService})
	default:
		jsonError(w, "没有这个端点", http.StatusNotFound)
	}
}

func commandcodeProbeAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	svcs, err := commandcode.Services()
	if err != nil {
		fail(w, err)
		return
	}
	items := make([]map[string]any, 0, len(svcs))
	for _, s := range svcs {
		v, err := commandcode.Probe(s)
		if err != nil {
			items = append(items, map[string]any{"service": s, "error": err.Error()})
			continue
		}
		items = append(items, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}
