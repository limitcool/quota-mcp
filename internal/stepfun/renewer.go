package stepfun

import (
	"log"
	"time"
)

// 后台会话续期器。
//
// 为什么需要它：console 会话会过期（.ai ~2 h，.com 实测只有 30 min），而内置的
// 自动续期只在「探测时认证失败」触发一次——没人探测就没人续，会话会静静死掉。
// 实测 .com 过期之后再续，passport 发回的是设备令牌（mode 1，console 数据面
// 一律 token is illegal），那个账户只能重新登录导入。所以必须在过期前主动续。
//
// 策略：每隔 renewTick 把所有 TTL 低于 renewThreshold 的账户续一遍；
// 网络类失败（TLS 握手超时、connect 超时——这个域名的 CDN 边缘节点会黑洞）
// 只记日志，下个 tick 重试，不判定会话死亡。

const (
	renewTick      = 60 * time.Second
	renewThreshold = 20 * time.Minute
)

// StartRenewer 启动后台续期 goroutine（进程内单例，由 main 调用一次）。
func StartRenewer() {
	go func() {
		log.Printf("stepfun: %s", "会话续期器已启动（每 60s 检查，TTL < 20min 自动续期）")
		for {
			renewDue()
			time.Sleep(renewTick)
		}
	}()
}

func renewDue() {
	svcs, err := Services()
	if err != nil {
		log.Printf("stepfun WARN: %s", "续期器读取账户列表失败: "+err.Error())
		return
	}
	for _, svc := range svcs {
		acc, err := load(svc)
		if err != nil {
			log.Printf("stepfun WARN: %s", "续期器加载账户 "+svc+" 失败: "+err.Error())
			continue
		}
		if acc.Session == nil {
			continue
		}
		ttl, ok := acc.Session.TTL()
		if ok && ttl >= int64(renewThreshold.Seconds()) {
			continue
		}
		next, changed, rerr := renewPersisted(acc)
		if rerr != nil {
			// 网络类失败下个 tick 会重试；这里只记下来，不动库里的会话
			log.Printf("stepfun WARN: %s", "续期 "+svc+" 失败: "+rerr.Error())
			continue
		}
		log.Printf("stepfun: 已续期 %s (token_changed=%v uid=%s)", svc, changed, next.UID())
	}
}
