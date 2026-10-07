package main

import (
	"fmt"
	"net"
	"sync"
	"testing"
)

// ---------- connCtx（连接级日志上下文） ----------

// prefix 前缀格式：域名未知时为 "[#ID -]"，setHost 更新后为 "[#ID 域名]"，空串 setHost 不生效
func TestConnCtx_PrefixAndSetHost(t *testing.T) {
	c := newConnCtx("1.2.3.4:5555")
	if c.id <= 0 {
		t.Fatalf("连接 ID 应为正数(从 1 开始), got %d", c.id)
	}
	if c.srcAddr != "1.2.3.4:5555" {
		t.Fatalf("srcAddr 应保留创建时的来源地址, got %q", c.srcAddr)
	}
	if c.host != "-" {
		t.Fatalf("域名未知时应为 \"-\" 占位, got %q", c.host)
	}
	if got, want := c.prefix(), fmt.Sprintf("[#%d -]", c.id); got != want {
		t.Fatalf("域名未知时前缀 = %q, 期望 %q", got, want)
	}

	c.setHost("www.example.com")
	if c.host != "www.example.com" {
		t.Fatalf("setHost 应更新域名, got %q", c.host)
	}
	if got, want := c.prefix(), fmt.Sprintf("[#%d www.example.com]", c.id); got != want {
		t.Fatalf("setHost 后前缀 = %q, 期望 %q", got, want)
	}

	c.setHost("") // 空串应被忽略，不覆盖已有域名
	if c.host != "www.example.com" {
		t.Fatalf("setHost(\"\") 不应覆盖已有域名, got %q", c.host)
	}
}

// newConnCtx 分配的连接 ID 应严格单调递增，且并发调用时不重复（atomic 保证）
func TestNewConnCtx_IDUniqueAndIncreasing(t *testing.T) {
	prev := newConnCtx("a:1").id
	for i := 0; i < 100; i++ {
		id := newConnCtx("a:1").id
		if id <= prev {
			t.Fatalf("连接 ID 应严格单调递增, prev=%d, got %d", prev, id)
		}
		prev = id
	}

	const goroutines, perG = 20, 50
	ids := make(chan int64, goroutines*perG)
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				ids <- newConnCtx("b:2").id
			}
		}()
	}
	wg.Wait()
	close(ids)

	seen := make(map[int64]bool, goroutines*perG)
	for id := range ids {
		if seen[id] {
			t.Fatalf("并发分配的连接 ID 出现重复: %d", id)
		}
		seen[id] = true
	}
	if len(seen) != goroutines*perG {
		t.Fatalf("并发应产生 %d 个互不重复的 ID, got %d", goroutines*perG, len(seen))
	}
}

// ---------- matchForwardRules（白名单命中判定） ----------

// matchForwardRules 按子串匹配规则表：命中(含子域名/子串)、未命中、空规则表
func TestMatchForwardRules(t *testing.T) {
	saveCfg(t) // matchForwardRules 读全局 cfg.ForwardRules，测试内临时设置、测完恢复

	cfg.ForwardRules = []string{"aa.com", "bb.net"}
	cases := []struct {
		host string
		want bool
	}{
		{"aa.com", true},            // 与规则完全相同
		{"www.aa.com", true},        // 子域名包含规则串 -> 命中
		{"aa.com.cn", true},         // 规则串是 host 的子串 -> 命中
		{"x.bb.net.evil.com", true}, // 子串匹配对 host 中任意位置生效
		{"cc.com", false},           // 不含任何规则串 -> 未命中
		{"aab.com", false},          // 相似但不含规则串 -> 未命中
	}
	for _, c := range cases {
		if got := matchForwardRules(c.host); got != c.want {
			t.Fatalf("matchForwardRules(%q) = %v, 期望 %v", c.host, got, c.want)
		}
	}

	cfg.ForwardRules = nil // 规则表为空：任何域名都不命中
	if matchForwardRules("aa.com") {
		t.Fatal("规则表为空时不应命中任何域名")
	}
}

// ---------- backendResult.backendDesc（字节日志中的后端描述） ----------

// backendDesc 格式："后端[ip:port 候选N/M]"，IPv6 地址需加方括号
func TestBackendResult_BackendDesc(t *testing.T) {
	v4 := &backendResult{ip: net.ParseIP("1.2.3.4"), index: 2, total: 4}
	if got, want := v4.backendDesc("443"), "后端[1.2.3.4:443 候选2/4]"; got != want {
		t.Fatalf("IPv4 描述 = %q, 期望 %q", got, want)
	}

	v6 := &backendResult{ip: net.ParseIP("2001:db8::1"), index: 1, total: 2}
	if got, want := v6.backendDesc("443"), "后端[[2001:db8::1]:443 候选1/2]"; got != want {
		t.Fatalf("IPv6 描述(地址应加方括号) = %q, 期望 %q", got, want)
	}

	v4b := &backendResult{ip: net.ParseIP("1.2.3.4"), index: 1, total: 1}
	if got, want := v4b.backendDesc("8443"), "后端[1.2.3.4:8443 候选1/1]"; got != want {
		t.Fatalf("非默认端口描述 = %q, 期望 %q", got, want)
	}
}
