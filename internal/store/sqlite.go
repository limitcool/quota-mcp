package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

// DB 全局数据库句柄。单二进制服务，包级变量是最省事的接法；
// 库表结构见 Init。
var DB *sql.DB

// Init 打开（或创建）SQLite 库并建表。path 为空时用环境变量 QUOTA_MCP_DB，
// 再为空用 ./data/quota-mcp.db。
func Init(path string) error {
	if path == "" {
		path = os.Getenv("QUOTA_MCP_DB")
	}
	if path == "" {
		path = filepath.Join("data", "quota-mcp.db")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	var err error
	DB, err = sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return err
	}
	_, err = DB.Exec(schema)
	if err != nil {
		return err
	}
	return migrate()
}

// migrate 幂等地给旧库补新增列。CREATE TABLE IF NOT EXISTS 不会给已存在的表加列，
// 所以每加一个列都要在这里显式 ALTER 一次。
func migrate() error {
	// 依赖错误文本 "duplicate column" 判定既脆弱（措辞随驱动变）又难读；
	// 先用 PRAGMA 查列是否存在，缺才 ALTER。
	if err := ensureColumn("commandcode_accounts", "session_token_enc", "TEXT"); err != nil {
		return err
	}
	return nil
}

// ensureColumn 若 table 缺 column 就 ALTER 补上（幂等）。
func ensureColumn(table, column, typ string) error {
	rows, err := DB.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid       int
			name, ct  string
			notnull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &ct, &notnull, &dfltValue, &pk); err != nil {
			return err
		}
		if strings.EqualFold(name, column) {
			return nil // 列已存在
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	_, err = DB.Exec("ALTER TABLE " + table + " ADD COLUMN " + column + " " + typ)
	return err
}

// schema 三张表：
//
//	stepfun_accounts    —— 双鉴权面：plan key（永久）+ console 会话（~2h，可续）
//	commandcode_accounts —— 单把 Bearer key，无会话
//	alert_events        —— 告警状态机（fingerprint 去重，firing/resolved 生命周期）
//
// 密文列只存密文；identity 存非机密身份（uid/邮箱/key 掩码），probe_data 存最近一次探测聚合。
const schema = `
CREATE TABLE IF NOT EXISTS stepfun_accounts (
	service TEXT PRIMARY KEY,
	region TEXT NOT NULL DEFAULT 'com',
	label TEXT DEFAULT '',
	access_key_enc TEXT,
	console_session_enc TEXT,
	identity TEXT DEFAULT '',
	probe_data TEXT DEFAULT '',
	created_at TEXT DEFAULT (datetime('now')),
	updated_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS commandcode_accounts (
	service TEXT PRIMARY KEY,
	api_key_enc TEXT,
	session_token_enc TEXT,
	label TEXT DEFAULT '',
	identity TEXT DEFAULT '',
	probe_data TEXT DEFAULT '',
	created_at TEXT DEFAULT (datetime('now')),
	updated_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS alert_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	fingerprint TEXT NOT NULL UNIQUE,
	kind TEXT NOT NULL,
	provider TEXT NOT NULL,
	service TEXT NOT NULL,
	severity TEXT NOT NULL,
	title TEXT NOT NULL,
	detail TEXT NOT NULL,
	state TEXT NOT NULL DEFAULT 'firing',
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	resolved_at TEXT,
	notified INTEGER NOT NULL DEFAULT 0
);
`

func Close() error {
	if DB != nil {
		return DB.Close()
	}
	return nil
}
