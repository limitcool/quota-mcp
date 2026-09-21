// Command quota-mcp 是 AI 订阅账户的用量/额度追踪服务。
//
// 用法：
//
//	quota-mcp -db data/quota-mcp.db -listen 127.0.0.1:8780
//
// 同一个端口上两个面：
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
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/limitcool/quota-mcp/internal/api"
	"github.com/limitcool/quota-mcp/internal/mcpsrv"
	"github.com/limitcool/quota-mcp/internal/stepfun"
	"github.com/limitcool/quota-mcp/internal/store"
)

func main() {
	dbPath := flag.String("db", "", "SQLite 路径（默认 $QUOTA_MCP_DB 或 data/quota-mcp.db）")
	listen := flag.String("listen", "127.0.0.1:8780", "监听地址")
	flag.Parse()

	if err := store.Init(*dbPath); err != nil {
		log.Fatalf("数据库初始化失败: %v", err)
	}
	defer store.Close()

	if os.Getenv("QUOTA_MCP_NO_RENEWER") != "1" {
		// StepFun console 会话 ~2h（.com 只有 30min）过期，后台按 TTL 主动续
		stepfun.StartRenewer()
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
