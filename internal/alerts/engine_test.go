package alerts

import (
	"path/filepath"
	"testing"

	"github.com/limitcool/quota-mcp/internal/store"
)

// 状态机需要真库，用临时 SQLite 跑完整生命周期。

func setupDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := store.Init(filepath.Join(dir, "test.db")); err != nil {
		t.Fatalf("store.Init: %v", err)
	}
	t.Cleanup(func() { store.Close() })
}

func TestReconcileLifecycle(t *testing.T) {
	setupDB(t)

	low := Alert{Kind: KindCreditLow, Provider: "stepfun", Service: "ai-x", Severity: SevWarn, Title: "额度低", Detail: "剩 13%"}

	// 第一次出现 → 触发
	fired, resolved, err := Reconcile([]Alert{low})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 || len(resolved) != 0 {
		t.Fatalf("首次应触发 1 条：fired=%d resolved=%d", len(fired), len(resolved))
	}

	// 同样的条件再来 → 不重复触发（持续 firing）
	fired, _, err = Reconcile([]Alert{low})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 0 {
		t.Fatalf("持续 firing 不应重复触发，得到 %d", len(fired))
	}

	// 条件消失 → 恢复
	_, resolved, err = Reconcile(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(resolved) != 1 {
		t.Fatalf("条件消失应恢复 1 条，得到 %d", len(resolved))
	}
	firing, _ := Firing()
	if len(firing) != 0 {
		t.Fatalf("恢复后 firing 应为空，得到 %d", len(firing))
	}

	// 条件再来 → 算再次触发
	fired, _, err = Reconcile([]Alert{low})
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 1 {
		t.Fatalf("再次出现应算新触发，得到 %d", len(fired))
	}
}

func TestReconcileDedupesPerService(t *testing.T) {
	setupDB(t)
	cfg := Config{CreditLowPct: 0.2, ExpiryDays: 7}
	a := map[string]any{
		"service": "ai-1",
		"console": map[string]any{
			"ok":         true,
			"rate_limit": map[string]any{"credit_left_rate": 0.1},
			"status":     map[string]any{"ok": true, "valid_until": soon(30)},
		},
	}
	b := map[string]any{
		"service": "ai-2",
		"console": map[string]any{
			"ok":         true,
			"rate_limit": map[string]any{"credit_left_rate": 0.1},
			"status":     map[string]any{"ok": true, "valid_until": soon(30)},
		},
	}
	fired, _, err := Reconcile(EvaluateAll([]map[string]any{a, b}, nil, cfg))
	if err != nil {
		t.Fatal(err)
	}
	if len(fired) != 2 {
		t.Fatalf("两个账户应各触发一条（指纹按账户区分），得到 %d", len(fired))
	}
}
