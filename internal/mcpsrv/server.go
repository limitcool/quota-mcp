// Package mcpsrv 把账户用量数据暴露成 MCP 工具面（官方 modelcontextprotocol/go-sdk，
// Streamable HTTP 传输，挂载在 /mcp）。
//
// 设计原则：**只读**。MCP 侧只提供查询（列表/探测/汇总），登记、续期、删除等
// 写操作走 REST（internal/api）——查询面可以放心暴露给 agent，写面留在本机。
package mcpsrv

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/limitcool/quota-mcp/internal/alerts"
	"github.com/limitcool/quota-mcp/internal/commandcode"
	"github.com/limitcool/quota-mcp/internal/digest"
	"github.com/limitcool/quota-mcp/internal/stepfun"
)

// NewServer 构造 MCP server（含全部工具）。
func NewServer() *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "quota-mcp",
		Version: "0.3.2",
	}, nil)

	// 1. 列出全部账户（掩码视图 + 最近一次探测结果）
	mcp.AddTool(server, &mcp.Tool{
		Name: "quota_list_accounts",
		Description: "列出全部已登记的 AI 订阅账户（StepFun / Command Code），返回掩码视图：" +
			"套餐、订阅到期、剩余额度（console 面的真实数据）、会话/密钥状态。provider 可传 stepfun / commandcode / all。",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct {
		Provider *string `json:"provider,omitempty" jsonschema:"stepfun|commandcode|all，默认 all"`
	}) (*mcp.CallToolResult, any, error) {
		out := map[string]any{}
		prov := ""
		if args.Provider != nil {
			prov = *args.Provider
		}
		if p := prov; p == "" || p == "all" || p == "stepfun" {
			items, err := stepfun.List()
			if err != nil {
				return toolErr(err)
			}
			out["stepfun"] = items
		}
		if prov == "" || prov == "all" || prov == "commandcode" {
			items, err := commandcode.List()
			if err != nil {
				return toolErr(err)
			}
			out["commandcode"] = items
		}
		return toolJSON(out)
	})

	// 2. 探测单个账户（实时打上游，console 会话认证失败会自动续一次）
	mcp.AddTool(server, &mcp.Tool{
		Name: "quota_probe_account",
		Description: "实时探测一个账户：打上游接口拉取最新用量/额度/会话状态。" +
			"StepFun 返回订阅、5 小时/周/订阅额度、名下 access key；Command Code 返回 5 小时/周/月度窗口与账期统计。",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct {
		Provider string `json:"provider" jsonschema:"stepfun 或 commandcode"`
		Service  string `json:"service" jsonschema:"账户槽位名，如 ai-412848664332275700"`
	}) (*mcp.CallToolResult, any, error) {
		if args.Service == "" {
			return toolErr(fmt.Errorf("service 必填"))
		}
		switch args.Provider {
		case "stepfun":
			v, err := stepfun.Probe(args.Service)
			if err != nil {
				return toolErr(err)
			}
			return toolJSON(v)
		case "commandcode":
			v, err := commandcode.Probe(args.Service)
			if err != nil {
				return toolErr(err)
			}
			return toolJSON(v)
		default:
			return toolErr(fmt.Errorf("provider 要是 stepfun 或 commandcode"))
		}
	})

	// 3. 全部探测一遍（慢：串行打所有上游接口）
	mcp.AddTool(server, &mcp.Tool{
		Name: "quota_probe_all",
		Description: "串行探测全部账户并刷新缓存。账户多或有网络黑洞时会比较慢（每个账户数秒）。" +
			"只看缓存数据用 quota_list_accounts 就够。",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct {
		Provider *string `json:"provider,omitempty" jsonschema:"stepfun|commandcode|all，默认 all"`
	}) (*mcp.CallToolResult, any, error) {
		out := map[string]any{}
		prov := ""
		if args.Provider != nil {
			prov = *args.Provider
		}
		if p := prov; p == "" || p == "all" || p == "stepfun" {
			svcs, err := stepfun.Services()
			if err != nil {
				return toolErr(err)
			}
			items := make([]map[string]any, 0, len(svcs))
			for _, s := range svcs {
				if v, err := stepfun.Probe(s); err == nil {
					items = append(items, v)
				} else {
					items = append(items, map[string]any{"service": s, "error": err.Error()})
				}
			}
			out["stepfun"] = items
		}
		if prov == "" || prov == "all" || prov == "commandcode" {
			svcs, err := commandcode.Services()
			if err != nil {
				return toolErr(err)
			}
			items := make([]map[string]any, 0, len(svcs))
			for _, s := range svcs {
				if v, err := commandcode.Probe(s); err == nil {
					items = append(items, v)
				} else {
					items = append(items, map[string]any{"service": s, "error": err.Error()})
				}
			}
			out["commandcode"] = items
		}
		return toolJSON(out)
	})

	// 4. 汇总状态（一眼看有多少账户、多少健康、多少要处理）
	mcp.AddTool(server, &mcp.Tool{
		Name: "quota_status",
		Description: "汇总：各 provider 账户数、服务中/被限流/key 失效/需重新登录的数量，" +
			"以及每个账户的一句话状态。适合被问「我的额度还剩多少」时直接回答。",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
		out := map[string]any{}
		sf, err := stepfun.List()
		if err != nil {
			return toolErr(err)
		}
		cc, err := commandcode.List()
		if err != nil {
			return toolErr(err)
		}
		out["stepfun"] = summarize(sf)
		out["commandcode"] = summarizeCC(cc)
		return toolJSON(out)
	})

	// 5. 当前触发的告警（阈值/过期/掉线/key 失效）——hermes 轮询这个做告警
	mcp.AddTool(server, &mcp.Tool{
		Name: "quota_check_alerts",
		Description: "当前触发中的告警：剩余额度低于阈值、订阅/账期即将到期、console 会话掉线需重新登录、" +
			"API key 失效、节流窗口超限。无告警时返回空列表。同一条告警不重复返回，恢复后会自动消失。",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct {
		History *int `json:"history,omitempty" jsonschema:"附带最近多少条历史（含已恢复），0 = 只要触发中的"`
	}) (*mcp.CallToolResult, any, error) {
		firing, err := alerts.Firing()
		if err != nil {
			return toolErr(err)
		}
		out := map[string]any{"firing": firing, "firing_count": len(firing)}
		historyN := 0
		if args.History != nil {
			historyN = *args.History
		}
		if historyN > 0 {
			h, err := alerts.History(historyN)
			if err != nil {
				return toolErr(err)
			}
			out["history"] = h
		}
		return toolJSON(out)
	})

	// 6. 定时播报 payload（hermes cron 每天 9:30 调它生成日报）
	mcp.AddTool(server, &mcp.Tool{
		Name: "quota_report",
		Description: "定时播报用的汇总 payload：两个平台全部账户的关键数字（套餐、到期、剩余额度、会话状态、" +
			"窗口用量、请求统计）+ 当前告警。适合 hermes cron 拉取后整理成消息投递。",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args struct{}) (*mcp.CallToolResult, any, error) {
		r, err := digest.Report()
		if err != nil {
			return toolErr(err)
		}
		return toolJSON(r)
	})

	return server
}

func summarize(items []map[string]any) map[string]any {
	total, healthy, attention := len(items), 0, 0
	lines := []string{}
	for _, a := range items {
		svc, _ := a["service"].(string)
		state, _ := a["session_state"].(string)
		plan, _ := a["plan"].(map[string]any)
		models := 0.0
		if plan != nil {
			models, _ = plan["model_count"].(float64)
		}
		ok := state != "needs_relogin"
		if ok {
			healthy++
		} else {
			attention++
		}
		lines = append(lines, fmt.Sprintf("%s: %s（%v 模型）", svc, or(state, "正常"), int(models)))
	}
	return map[string]any{
		"total": total, "healthy": healthy, "attention": attention, "accounts": lines,
	}
}

func summarizeCC(items []map[string]any) map[string]any {
	total, serving, limited, rejected := len(items), 0, 0, 0
	lines := []string{}
	for _, a := range items {
		svc, _ := a["service"].(string)
		verdict, _ := a["verdict"].(string)
		switch verdict {
		case "serving":
			serving++
		case "limited":
			limited++
		case "key_rejected":
			rejected++
		}
		plan, _ := a["plan"].(map[string]any)
		name := ""
		if plan != nil {
			name, _ = plan["plan_name"].(string)
		}
		lines = append(lines, fmt.Sprintf("%s: %s %s", svc, or(verdict, "unknown"), name))
	}
	return map[string]any{
		"total": total, "serving": serving, "limited": limited, "key_rejected": rejected, "accounts": lines,
	}
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func toolJSON(v any) (*mcp.CallToolResult, any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return toolErr(err)
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

func toolErr(err error) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "错误: " + err.Error()}},
		IsError: true,
	}, nil, nil
}

// HTTPHandler 返回挂在 /mcp 上的 Streamable HTTP handler。
func HTTPHandler() http.Handler {
	server := NewServer()
	return mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server {
		return server
	}, nil)
}
