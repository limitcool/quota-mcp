package alerts

import (
	"log"
	"time"

	"github.com/limitcool/quota-mcp/internal/commandcode"
	"github.com/limitcool/quota-mcp/internal/stepfun"
)

// 后台评估循环：保持数据新鲜（太旧就全量探测）→ 评估规则 → 状态机 reconcile
// → 跃迁瞬间推 webhook。没有跃迁就安静待命，不会刷屏。

const (
	evalTick         = 60 * time.Second
	probeIfOlderThan = 5 * time.Minute
)

// StartEvaluator 启动评估 goroutine（进程内单例，main 调用一次）。
// webhookURL 为空时只在库内记账，不做推送（pull 模式）。
func StartEvaluator(cfg Config, webhookURL string) {
	go func() {
		log.Printf("alerts: 评估器已启动（每 %s，探测数据超过 %s 自动刷新）", evalTick, probeIfOlderThan)
		for {
			tick(cfg, webhookURL)
			time.Sleep(evalTick)
		}
	}()
}

func tick(cfg Config, webhookURL string) {
	sfStale, ccStale := staleness()
	if sfStale {
		probeAll(stepfun.Services, stepfun.Probe)
	}
	if ccStale {
		probeAll(commandcode.Services, commandcode.Probe)
	}

	sf, err := stepfun.List()
	if err != nil {
		log.Printf("alerts: 读 stepfun 列表失败: %v", err)
		return
	}
	cc, err := commandcode.List()
	if err != nil {
		log.Printf("alerts: 读 commandcode 列表失败: %v", err)
		return
	}

	fired, resolved, err := Reconcile(EvaluateAll(sf, cc, cfg))
	if err != nil {
		log.Printf("alerts: reconcile 失败: %v", err)
		return
	}
	if len(fired) == 0 && len(resolved) == 0 {
		return
	}
	for _, a := range fired {
		log.Printf("alerts: [%s] %s/%s %s — %s", a.Severity, a.Provider, a.Service, a.Title, a.Detail)
	}
	if err := NotifyWebhook(webhookURL, fired, resolved); err != nil {
		// 推送失败不致命：库内已是 firing 态，下次跃迁/手动仍可再推
		log.Printf("alerts: webhook 推送失败（库内已记账）: %v", err)
	}
}

// staleness 两个 provider 的探测数据是否陈旧（任一行探过就当新鲜）。
func staleness() (stepfunStale, ccStale bool) {
	sf, err := stepfun.List()
	if err != nil || len(sf) == 0 {
		stepfunStale = len(sf) == 0 && err == nil
	} else {
		stepfunStale = oldestProbe(sf)
	}
	cc, err := commandcode.List()
	if err != nil || len(cc) == 0 {
		ccStale = len(cc) == 0 && err == nil
	} else {
		ccStale = oldestProbe(cc)
	}
	return
}

func oldestProbe(items []map[string]any) bool {
	cutoff := time.Now().Add(-probeIfOlderThan)
	for _, a := range items {
		ts, _ := a["probed_at"].(string)
		if ts == "" {
			return true
		}
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil || t.Before(cutoff) {
			return true
		}
	}
	return false
}

func probeAll(list func() ([]string, error), probe func(string) (map[string]any, error)) {
	svcs, err := list()
	if err != nil {
		return
	}
	for _, s := range svcs {
		if _, err := probe(s); err != nil {
			log.Printf("alerts: 保鲜探测 %s 失败: %v", s, err)
		}
	}
}
