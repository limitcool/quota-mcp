package commandcode

import (
	"path/filepath"
	"testing"

	"github.com/limitcool/quota-mcp/internal/store"
)

// TestUpsertRotationClearsUnprovidedPlane 验证凭据轮换语义：只带一面的 Enrol
// 会清掉另一面的旧密文，而不是用 COALESCE 永久保留。曾因 COALESCE(excluded.*)
// 出现「用户以为已轮换、旧 cookie 密文仍留库」的盲区。
func TestUpsertRotationClearsUnprovidedPlane(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "rot.db")
	if err := store.Init(dbPath); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	defer store.DB.Close()

	// 第一次：同时给两面
	if _, err := store.DB.Exec(upsertSQL, "cc-rot", "KEYENC", "SESSENC", "l1", nowISO()); err != nil {
		t.Fatalf("初次写入: %v", err)
	}
	var key, sess string
	if err := store.DB.QueryRow(
		`SELECT COALESCE(api_key_enc,''), COALESCE(session_token_enc,'') FROM commandcode_accounts WHERE service=?`,
		"cc-rot").Scan(&key, &sess); err != nil {
		t.Fatalf("读回: %v", err)
	}
	if key != "KEYENC" || sess != "SESSENC" {
		t.Fatalf("初次写入 = key %q sess %q", key, sess)
	}

	// 第二次：只给 api_key（session 面 NULL），旧 session 必须被清空
	if _, err := store.DB.Exec(upsertSQL, "cc-rot", "KEYENC2", nil, "", nowISO()); err != nil {
		t.Fatalf("轮换写入: %v", err)
	}
	if err := store.DB.QueryRow(
		`SELECT COALESCE(api_key_enc,''), COALESCE(session_token_enc,'') FROM commandcode_accounts WHERE service=?`,
		"cc-rot").Scan(&key, &sess); err != nil {
		t.Fatalf("轮换后读回: %v", err)
	}
	if key != "KEYENC2" {
		t.Fatalf("api_key 未更新: %q", key)
	}
	if sess != "" {
		t.Fatalf("旧 session 应被清空，实际残留: %q", sess)
	}

	// 第三次：只给 session（api_key NULL），旧 key 必须被清空
	if _, err := store.DB.Exec(upsertSQL, "cc-rot", nil, "SESSENC3", "", nowISO()); err != nil {
		t.Fatalf("反向轮换写入: %v", err)
	}
	if err := store.DB.QueryRow(
		`SELECT COALESCE(api_key_enc,''), COALESCE(session_token_enc,'') FROM commandcode_accounts WHERE service=?`,
		"cc-rot").Scan(&key, &sess); err != nil {
		t.Fatalf("反向轮换后读回: %v", err)
	}
	if key != "" {
		t.Fatalf("旧 api_key 应被清空，实际残留: %q", key)
	}
	if sess != "SESSENC3" {
		t.Fatalf("session 未更新: %q", sess)
	}
}
