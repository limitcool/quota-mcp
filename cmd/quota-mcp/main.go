// Command quota-mcp 是 AI 订阅账户的用量/额度追踪服务。
//
// 两种运行形态：
//
//	quota-mcp -db data/quota-mcp.db -listen 127.0.0.1:8780   # HTTP 服务（默认）
//	quota-mcp -stdio                                        # 标准输入输出上的 MCP（容器/本地客户端 spawn 用）
//
// HTTP 形态下同一个端口两个面：
//
//	/mcp                 MCP 工具面（Streamable HTTP）——给 agent / hermes 查询
//	/api/...             REST 管理面——登记 / 探测 / 续期 / 删除
//	/healthz             健康检查
//
// 环境变量：
//
//	QUOTA_MCP_MASTER_KEY  64 hex 字符主密钥（不设则按机器特征派生，换机读不出旧密文）
//	QUOTA_MCP_DB          SQLite 路径（默认 data/quota-mcp.db）
//	QUOTA_MCP_NO_RENEWER        置 1 时关闭 StepFun 后台续期 goroutine
//	QUOTA_MCP_ALERT_CREDIT_PCT  额度告警阈值：剩余占比低于它触发（默认 0.2）
//	QUOTA_MCP_ALERT_EXPIRY_DAYS 到期告警提前量（默认 7 天）
//	QUOTA_MCP_ALERT_WEBHOOK_URL 告警跃迁时 POST 的目标（hermes webhook 订阅地址），空则只记账不推送
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/limitcool/quota-mcp/internal/alerts"
	"github.com/limitcool/quota-mcp/internal/api"
	"github.com/limitcool/quota-mcp/internal/mcpsrv"
	"github.com/limitcool/quota-mcp/internal/stepfun"
	"github.com/limitcool/quota-mcp/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "SQLite 路径（默认 $QUOTA_MCP_DB 或 data/quota-mcp.db）")
	listen := flag.String("listen", "127.0.0.1:8780", "监听地址（HTTP 形态）")
	stdio := flag.Bool("stdio", false, "以 stdio 传输运行 MCP server（不启 HTTP/REST）")
	flag.Parse()

	if err := store.Init(*dbPath); err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer store.Close()

	if os.Getenv("QUOTA_MCP_NO_RENEWER") != "1" {
		// StepFun console 会话 ~2h（.com 只有 30min）过期，后台按 TTL 主动续
		stepfun.StartRenewer()
	}
	// 告警评估器：数据保鲜（探测超 5 分钟自动刷新）→ 规则评估 → 状态机 → 跃迁推 webhook
	alerts.StartEvaluator(alertConfigFromEnv(), os.Getenv("QUOTA_MCP_ALERT_WEBHOOK_URL"))

	if *stdio {
		// stdio 形态：JSON-RPC 走 stdin/stdout，日志一律去 stderr，绝不污染协议流
		log.SetOutput(os.Stderr)
		log.Printf("quota-mcp: stdio 模式启动")
		if err := mcpsrv.NewServer().Run(context.Background(), &mcp.StdioTransport{}); err != nil {
			log.Fatalf("stdio 服务退出: %v", err)
		}
		return
	}

	rest := api.Handler()
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpsrv.HTTPHandler())
	mux.Handle("/mcp/", mcpsrv.HTTPHandler())
	mux.Handle("/", rest)

	addr := *listen
	log.Printf("quota-mcp 启动: http://%s （MCP: /mcp，REST: /api，健康检查: /healthz）", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("服务退出: %v", err)
	}
}

// alertConfigFromEnv 读告警阈值（非法值回退默认）。
func alertConfigFromEnv() alerts.Config {
	cfg := alerts.DefaultConfig()
	if v := strings.TrimSpace(os.Getenv("QUOTA_MCP_ALERT_CREDIT_PCT")); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil && f > 0 && f < 1 {
			cfg.CreditLowPct = f
		}
	}
	if v := strings.TrimSpace(os.Getenv("QUOTA_MCP_ALERT_EXPIRY_DAYS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ExpiryDays = n
		}
	}
	return cfg
}
