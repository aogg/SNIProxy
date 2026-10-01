package main

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestDedupeIPs(t *testing.T) {
	in := []net.IP{
		net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), net.ParseIP("1.1.1.1"),
		net.ParseIP("3.3.3.3"), net.ParseIP("2.2.2.2"),
	}
	got := dedupeIPs(in)
	if len(got) != 3 || !got[0].Equal(net.ParseIP("1.1.1.1")) || !got[1].Equal(net.ParseIP("2.2.2.2")) || !got[2].Equal(net.ParseIP("3.3.3.3")) {
		t.Fatalf("去重结果不符合预期, got %v", got)
	}
}

func TestOrderIPs_NoHistory(t *testing.T) {
	c := &dnsRetryCache{stats: make(map[string]map[string]*ipStat)}
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), net.ParseIP("3.3.3.3")}
	got := c.orderIPs("a.com", ips)
	if len(got) != 3 || !got[0].Equal(ips[0]) || !got[1].Equal(ips[1]) || !got[2].Equal(ips[2]) {
		t.Fatalf("无历史记录时应保持 DNS 原始顺序, got %v", got)
	}
}

func TestOrderIPs_SuccessFirstFailLast(t *testing.T) {
	c := &dnsRetryCache{stats: make(map[string]map[string]*ipStat)}
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), net.ParseIP("3.3.3.3")}
	c.reportResult("a.com", "1.1.1.1", false) // 首个 IP 失败
	c.reportResult("a.com", "3.3.3.3", true)  // 最后一个 IP 成功
	got := c.orderIPs("a.com", ips)
	// 期望：成功的(3.3.3.3) -> 未尝试过的(2.2.2.2) -> 失败的(1.1.1.1)
	if !got[0].Equal(net.ParseIP("3.3.3.3")) || !got[1].Equal(net.ParseIP("2.2.2.2")) || !got[2].Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("排序结果不符合预期, got %v", got)
	}
}

func TestOrderIPs_MostRecentSuccessFirst(t *testing.T) {
	c := &dnsRetryCache{stats: make(map[string]map[string]*ipStat)}
	ips := []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2")}
	c.reportResult("a.com", "1.1.1.1", true)
	time.Sleep(10 * time.Millisecond)
	c.reportResult("a.com", "2.2.2.2", true) // 更近的成功
	got := c.orderIPs("a.com", ips)
	if !got[0].Equal(net.ParseIP("2.2.2.2")) || !got[1].Equal(net.ParseIP("1.1.1.1")) {
		t.Fatalf("最近成功的 IP 应排在最前, got %v", got)
	}
}

func TestOrderIPs_PruneStaleIPs(t *testing.T) {
	c := &dnsRetryCache{stats: make(map[string]map[string]*ipStat)}
	c.reportResult("a.com", "9.9.9.9", true) // 该 IP 已不在本次 DNS 结果中
	ips := []net.IP{net.ParseIP("1.1.1.1")}
	c.orderIPs("a.com", ips) // 触发清理
	if _, ok := c.stats["a.com"]["9.9.9.9"]; ok {
		t.Fatal("已不在 DNS 结果中的旧 IP 应被清理")
	}
}

func TestReportResult_Concurrent(t *testing.T) {
	c := &dnsRetryCache{stats: make(map[string]map[string]*ipStat)}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.reportResult("a.com", "1.1.1.1", i%2 == 0)
		}(i)
	}
	wg.Wait()
	st := c.stats["a.com"]["1.1.1.1"]
	if st.success+st.fail != 100 {
		t.Fatalf("并发记录结果丢失: success=%d fail=%d", st.success, st.fail)
	}
}

func TestCleanup(t *testing.T) {
	c := &dnsRetryCache{stats: make(map[string]map[string]*ipStat)}
	c.reportResult("old.com", "1.1.1.1", true)
	c.reportResult("new.com", "2.2.2.2", true)
	// 把 old.com 的记录时间改到 2 小时前
	c.mu.Lock()
	c.stats["old.com"]["1.1.1.1"].lastSuccess = time.Now().Add(-2 * time.Hour)
	c.mu.Unlock()

	c.cleanup(time.Hour)

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.stats["old.com"]; ok {
		t.Fatal("过期的域名记录应被清理")
	}
	if _, ok := c.stats["new.com"]["2.2.2.2"]; !ok {
		t.Fatal("未过期的记录不应被清理")
	}
}

// 起一个假后端：接受连接后把收到的数据读出来，再回写一段响应
func fakeBackend(t *testing.T, ln net.Listener, response string) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	buf := make([]byte, 1024)
	conn.Read(buf)
	if response != "" {
		conn.Write([]byte(response))
		// 保持连接不断开，模拟正常后端
		time.Sleep(500 * time.Millisecond)
	}
}

func TestDialBackendRetry_Failover(t *testing.T) {
	cfg.DialTimeout = 2
	cfg.FirstByteTimeout = 2

	// 在 127.0.0.1 上起一个可用的假后端，127.0.0.2 同端口无人监听（连接会被拒绝）
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go fakeBackend(t, ln, "HELLO")
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	host := "test.example.com"
	dead := net.ParseIP("127.0.0.2")
	alive := net.ParseIP("127.0.0.1")

	// 故意把“坏 IP”排在前面，验证会自动重试到“好 IP”
	backend, first := dialBackendRetry(host, port, []net.IP{dead, alive}, []byte("data"))
	if backend == nil {
		t.Fatal("应自动重试并连接到可用的 IP")
	}
	defer backend.Close()
	if string(first) != "HELLO" {
		t.Fatalf("应返回提前读到的后端首字节响应, got %q", first)
	}

	// 重试结果应已存储：失败 IP 排到最后、成功 IP 排到最前
	ordered := dnsRetryCacheInstance.orderIPs(host, []net.IP{dead, alive})
	if !ordered[0].Equal(alive) || !ordered[1].Equal(dead) {
		t.Fatalf("下次转发应根据上次结果排序(成功 IP 优先), got %v", ordered)
	}
	st := dnsRetryCacheInstance.stats[host]["127.0.0.2"]
	if st == nil || st.fail != 1 {
		t.Fatal("坏 IP 的失败结果应被记录")
	}
	st = dnsRetryCacheInstance.stats[host]["127.0.0.1"]
	if st == nil || st.success != 1 {
		t.Fatal("好 IP 的成功结果应被记录")
	}
}

func TestDialBackendRetry_AllFail(t *testing.T) {
	cfg.DialTimeout = 2
	cfg.FirstByteTimeout = 2

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	ln.Close() // 两个 IP 的该端口都无人监听，拨号会被直接拒绝

	backend, _ := dialBackendRetry("allfail.example.com", port, []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("127.0.0.2")}, []byte("data"))
	if backend != nil {
		backend.Close()
		t.Fatal("所有 IP 均失败时应返回 nil")
	}
}

func TestDialBackendRetry_DeadBackendNoResponse(t *testing.T) {
	cfg.DialTimeout = 2
	cfg.FirstByteTimeout = 1

	// 起一个“连接成功但收不到任何响应”的假死后端
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go fakeBackend(t, ln, "") // 不写任何响应
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	backend, first := dialBackendRetry("dead.example.com", port, []net.IP{net.ParseIP("127.0.0.1")}, []byte("data"))
	if backend != nil {
		backend.Close()
		t.Fatal("后端假死(无响应)时应视为失败并返回 nil")
	}
	if first != nil {
		t.Fatal("假死后端不应有首字节响应")
	}
	st := dnsRetryCacheInstance.stats["dead.example.com"]["127.0.0.1"]
	if st == nil || st.fail != 1 {
		t.Fatal("假死后端的失败结果应被记录")
	}
}
