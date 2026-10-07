package main

import (
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- 公共小工具 ----------

// boolPtr 返回 bool 指针，便于构造 cfg.VerifyTLS 的取值
func boolPtr(b bool) *bool { return &b }

// saveCfg 保存全局配置 cfg 并在测试结束时恢复，避免用例间相互影响
// （cfg 是全局变量，isVerifyTLSEnabled / verifyProbeTimeout / dialBackendRetry 都直接读它）
func saveCfg(t *testing.T) {
	t.Helper()
	old := cfg
	t.Cleanup(func() { cfg = old })
}

// buildServerHello 手工构造一条合法的 TLS ServerHello 记录（纯字节、不依赖网络）：
// 记录头 5 字节(0x16 + 版本2字节 + 负载长度2字节) + 握手消息头 4 字节(类型2 + 长度3字节) + 消息体
func buildServerHello() []byte {
	body := []byte{
		0x03, 0x03, // ServerHello 版本 TLS1.2
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Random（示意值）
		0x00, // Session ID 长度 = 0
	}
	msg := append([]byte{typeServerHello, 0x00, 0x00, byte(len(body))}, body...) // 握手消息头 + 消息体
	rec := append([]byte{byte(recordTypeHandshake), 0x03, 0x03, byte(len(msg) >> 8), byte(len(msg))}, msg...)
	return rec
}

// ---------- isValidServerHello ----------

func TestIsValidServerHello(t *testing.T) {
	valid := buildServerHello()

	alert := []byte{byte(recordTypeAlert), 0x03, 0x03, 0x00, 0x02, 0x50, 0x00} // TLS alert(0x15) 记录

	badVersion := append([]byte(nil), valid...)
	badVersion[1] = 0x04 // 版本首字节非 3

	notServerHello := append([]byte(nil), valid...)
	notServerHello[5] = typeClientHello // 首条握手消息不是 ServerHello

	shortPayload := append([]byte(nil), valid...)
	shortPayload[3], shortPayload[4] = 0x00, 0x03 // 记录负载长度 < 4（连 4 字节握手头都放不下）

	zeroPayload := append([]byte(nil), valid...)
	zeroPayload[3], zeroPayload[4] = 0x00, 0x00 // 记录负载长度为 0

	cases := []struct {
		name string
		data []byte
		want bool
	}{
		{"合法的ServerHello", valid, true},
		{"TLS alert记录(0x15)", alert, false},
		{"明文HTTP响应", []byte("HTTP/1.1 400 Bad Request\r\n\r\n"), false},
		{"数据不足9字节", valid[:8], false},
		{"仅记录头5字节", valid[:5], false},
		{"空数据", nil, false},
		{"版本首字节非3", badVersion, false},
		{"首条握手消息非ServerHello", notServerHello, false},
		{"记录负载长度小于4", shortPayload, false},
		{"记录负载长度为0", zeroPayload, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isValidServerHello(c.data); got != c.want {
				t.Fatalf("isValidServerHello(长度%d) = %v, 期望 %v", len(c.data), got, c.want)
			}
		})
	}
}

// ---------- verifyBackend ----------

// 说明：verifyBackend 的“成功路径”（真实 TLS 握手成功且证书校验通过）需要一张被系统信任的
// 证书（verifyBackend 固定用系统证书池做完整校验，且不允许为测试修改源码），
// 单元测试环境无法本地模拟，故此处仅覆盖三类失败路径与 timeoutSec<=0 的兜底行为。
// 假后端全部用进程内 net.Listener 监听在 127.0.0.1 上，不启动 SNIProxy 服务、不访问外网。

// 纯 TCP 后端（端口通但不是 TLS 服务）：应报“TLS握手失败”
func TestVerifyBackend_PlainTCPBackend(t *testing.T) {
	saveCfg(t)
	cfg.EnableSocks = false // 直连，避免受遗留 SOCKS5 配置影响

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		conn.Read(buf)                                         // 读走客户端发来的 ClientHello
		conn.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")) // 回明文，模拟“非 TLS 服务”
		time.Sleep(500 * time.Millisecond)
	}()

	err = verifyBackend(ln.Addr().String(), "plain.invalid", 2)
	if err == nil {
		t.Fatal("纯 TCP 后端(无 TLS)应验证失败")
	}
	if !strings.Contains(err.Error(), "TLS握手失败") {
		t.Fatalf("应报 TLS握手失败, got: %v", err)
	}
}

// 连接拒绝端口（无人监听）：应报“拨号失败”
func TestVerifyBackend_ConnectionRefused(t *testing.T) {
	saveCfg(t)
	cfg.EnableSocks = false

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // 先拿到端口再关闭，该端口无人监听，拨号会被直接拒绝

	err = verifyBackend(addr, "refused.invalid", 2)
	if err == nil {
		t.Fatal("连接拒绝端口应验证失败")
	}
	if !strings.Contains(err.Error(), "拨号失败") {
		t.Fatalf("应报 拨号失败, got: %v", err)
	}
}

// 接受连接后不响应（假死后端）：应在总超时内握手失败
func TestVerifyBackend_SilentBackendTimeout(t *testing.T) {
	saveCfg(t)
	cfg.EnableSocks = false

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		time.Sleep(2 * time.Second) // 接受连接后不读不写，模拟假死后端
		conn.Close()
	}()

	err = verifyBackend(ln.Addr().String(), "silent.invalid", 1) // 1 秒总超时
	if err == nil {
		t.Fatal("接受连接后不响应的后端应验证失败(超时)")
	}
	if !strings.Contains(err.Error(), "TLS握手失败") {
		t.Fatalf("应报 TLS握手失败(超时), got: %v", err)
	}
}

// timeoutSec <= 0 时不探测、直接放行（兜底行为，不发起任何连接）
func TestVerifyBackend_TimeoutZero(t *testing.T) {
	if err := verifyBackend("127.0.0.1:1", "skip.invalid", 0); err != nil {
		t.Fatalf("timeoutSec=0 应视为通过(不探测), got: %v", err)
	}
}

// ---------- setVerifyResult / getVerifyResult ----------

func TestVerifyResultCache_SuccessTTL(t *testing.T) {
	c := &dnsRetryCache{verify: make(map[string]map[string]*verifyResult)}

	c.setVerifyResult("succ.invalid", "10.0.0.1", true, "")
	r, hit := c.getVerifyResult("succ.invalid", "10.0.0.1")
	if !hit || r == nil || !r.ok {
		t.Fatalf("刚写入的成功结果应命中, hit=%v, r=%+v", hit, r)
	}

	// 同包测试直接改 r.at 模拟时间流逝：超过成功 TTL(10 分钟)后应未命中
	c.mu.Lock()
	c.verify["succ.invalid"]["10.0.0.1"].at = time.Now().Add(-verifySuccessTTL - time.Second)
	c.mu.Unlock()
	if _, hit := c.getVerifyResult("succ.invalid", "10.0.0.1"); hit {
		t.Fatal("成功结果超过成功 TTL 后应返回未命中")
	}
	if _, ok := c.verify["succ.invalid"]; ok {
		t.Fatal("过期条目应被顺带删除(连同清空的 host 桶)")
	}
}

func TestVerifyResultCache_FailTTL(t *testing.T) {
	c := &dnsRetryCache{verify: make(map[string]map[string]*verifyResult)}

	c.setVerifyResult("fail.invalid", "10.0.0.2", false, "TLS握手失败: 测试原因")
	r, hit := c.getVerifyResult("fail.invalid", "10.0.0.2")
	if !hit || r == nil || r.ok || r.reason == "" {
		t.Fatalf("刚写入的失败结果应命中且带原因, hit=%v, r=%+v", hit, r)
	}

	// 失败 TTL(60 秒)比成功 TTL 短：把 at 拨到失败 TTL 之外后应未命中
	c.mu.Lock()
	c.verify["fail.invalid"]["10.0.0.2"].at = time.Now().Add(-verifyFailTTL - time.Second)
	c.mu.Unlock()
	if _, hit := c.getVerifyResult("fail.invalid", "10.0.0.2"); hit {
		t.Fatal("失败结果超过失败 TTL 后应返回未命中")
	}
	if _, ok := c.verify["fail.invalid"]["10.0.0.2"]; ok {
		t.Fatal("过期条目应被顺带删除")
	}
}

func TestVerifyResultCache_MissAndIsolation(t *testing.T) {
	c := &dnsRetryCache{verify: make(map[string]map[string]*verifyResult)}

	// 未写入过 -> 未命中
	if _, hit := c.getVerifyResult("none.invalid", "10.0.0.3"); hit {
		t.Fatal("未写入过的 域名+IP 应未命中")
	}

	c.setVerifyResult("h1.invalid", "10.0.0.3", true, "")
	// 域名或 IP 任一不同 -> 未命中
	if _, hit := c.getVerifyResult("h1.invalid", "10.0.0.4"); hit {
		t.Fatal("同域名不同 IP 应未命中")
	}
	if _, hit := c.getVerifyResult("h2.invalid", "10.0.0.3"); hit {
		t.Fatal("同 IP 不同域名应未命中")
	}

	// TTL 未到（仍在成功 TTL 之内）-> 命中
	c.mu.Lock()
	c.verify["h1.invalid"]["10.0.0.3"].at = time.Now().Add(-verifySuccessTTL + 10*time.Second)
	c.mu.Unlock()
	if r, hit := c.getVerifyResult("h1.invalid", "10.0.0.3"); !hit || r == nil || !r.ok {
		t.Fatalf("TTL 内的结果应命中, hit=%v, r=%+v", hit, r)
	}
}

func TestVerifyResultCache_Concurrent(t *testing.T) {
	c := &dnsRetryCache{verify: make(map[string]map[string]*verifyResult)}
	host, ip1, ip2 := "cc.invalid", "10.0.1.1", "10.0.1.2"
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func(i int) { defer wg.Done(); c.setVerifyResult(host, ip1, i%2 == 0, "") }(i)
		go func() { defer wg.Done(); c.getVerifyResult(host, ip1) }()
		go func(i int) { defer wg.Done(); c.setVerifyResult(host, ip2, i%3 == 0, "") }(i)
	}
	wg.Wait()
	// 并发 set/get 后记录不丢失：两个 IP 各保留一条记录
	if _, hit := c.getVerifyResult(host, ip1); !hit {
		t.Fatal("并发写入后 ip1 应仍有缓存记录")
	}
	if _, hit := c.getVerifyResult(host, ip2); !hit {
		t.Fatal("并发写入后 ip2 应仍有缓存记录")
	}
}

// ---------- isVerifyTLSEnabled / verifyProbeTimeout ----------

func TestVerifyTLSConfig(t *testing.T) {
	cases := []struct {
		name        string
		verifyTLS   *bool
		firstByte   int
		wantEnabled bool
		wantProbe   int
	}{
		{"未配置(nil)默认开启", nil, 5, true, 5},
		{"显式开启", boolPtr(true), 5, true, 5},
		{"显式关闭", boolPtr(false), 5, false, 0},
		{"未配置且FirstByteTimeout为0", nil, 0, true, 0},
		{"开启但FirstByteTimeout为0", boolPtr(true), 0, true, 0},
		{"开启但FirstByteTimeout为负", boolPtr(true), -1, true, 0},
		{"关闭且FirstByteTimeout为0", boolPtr(false), 0, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			saveCfg(t) // 测完恢复 cfg，避免影响其他用例
			cfg.VerifyTLS = c.verifyTLS
			cfg.FirstByteTimeout = c.firstByte
			if got := isVerifyTLSEnabled(); got != c.wantEnabled {
				t.Fatalf("isVerifyTLSEnabled() = %v, 期望 %v", got, c.wantEnabled)
			}
			if got := verifyProbeTimeout(); got != c.wantProbe {
				t.Fatalf("verifyProbeTimeout() = %v, 期望 %v", got, c.wantProbe)
			}
		})
	}
}

// ---------- dialBackendRetry 与 TLS 验证的联动（进程内 listener，不启动服务） ----------

// 开启 verify_tls 时，回明文的假后端应在“后端真实 TLS 验证”阶段被拒绝，最终返回 nil，
// 且验证失败结果应写入缓存（60 秒内不再重复探测该 IP）
func TestDialBackendRetry_VerifyRejectsPlainBackend(t *testing.T) {
	saveCfg(t)
	cfg.EnableSocks = false
	cfg.DialTimeout = 2
	cfg.FirstByteTimeout = 2
	cfg.VerifyTLS = boolPtr(true)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Write([]byte("HELLO")) // 回明文，TLS 握手必失败
		time.Sleep(500 * time.Millisecond)
	}()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	host := "verify-reject.invalid"
	res := dialBackendRetry(newConnCtx("127.0.0.1:1234"), host, port, []net.IP{net.ParseIP("127.0.0.1")}, []byte("data"))
	if res != nil {
		res.conn.Close()
		t.Fatal("开启 verify_tls 时明文后端应被 TLS 验证拒绝")
	}
	if r := dnsRetryCacheInstance.verify[host]["127.0.0.1"]; r == nil || r.ok {
		t.Fatalf("验证失败结果应写入缓存, got %+v", r)
	}
}
