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
//	QUOTA_MCP_NO_RENEWER  置 1 时关闭 StepFun 后台续期 goroutine
package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

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
