package main

import (
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- 测试内全局状态保护 ----------

// saveEnvHTTPProxy 保存全局 envHTTPProxy 并在测试结束时恢复，避免用例间相互影响
// （envHTTPProxy 是全局变量，dialBackendRetry 的第 2 轮代理轮询直接读它）
func saveEnvHTTPProxy(t *testing.T) {
	t.Helper()
	old := envHTTPProxy
	t.Cleanup(func() { envHTTPProxy = old })
}

// setEnvProxyLookup 把 envProxyLookup 替换为按给定 map 查询的注入实现，测完恢复原值（默认 os.LookupEnv）
func setEnvProxyLookup(t *testing.T, envs map[string]string) {
	t.Helper()
	old := envProxyLookup
	envProxyLookup = func(name string) (string, bool) {
		v, ok := envs[name]
		return v, ok
	}
	t.Cleanup(func() { envProxyLookup = old })
}

// ---------- 进程内假 HTTP 代理（net.Listener 假服务，不启动完整 SNIProxy、不访问外网） ----------

// fakeHTTPProxy 记录假 HTTP 代理收到的各连接 CONNECT 请求信息（目标地址与认证头）
type fakeHTTPProxy struct {
	ln net.Listener

	mu      sync.Mutex
	targets []string // 各连接 CONNECT 请求行的目标地址（host:port），按到达顺序
	auths   []string // 各连接的 Proxy-Authorization 头值（未携带时为 ""），按到达顺序
}

// readHTTPRequestHead 读取一份完整的 HTTP 报文头（读到空行 "\r\n\r\n" 为止），供假代理解析 CONNECT 请求
func readHTTPRequestHead(conn net.Conn) (string, error) {
	var head []byte
	buf := make([]byte, 1)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			head = append(head, buf[0])
			if len(head) >= 4 && string(head[len(head)-4:]) == "\r\n\r\n" {
				return string(head), nil
			}
		}
		if err != nil {
			return "", err
		}
	}
}

// parseConnectHead 从 CONNECT 请求头里提取请求行目标地址与 Proxy-Authorization 头
func parseConnectHead(head string) (target, auth string) {
	for i, line := range strings.Split(head, "\r\n") {
		if i == 0 { // 请求行：CONNECT host:port HTTP/1.1
			if fields := strings.Fields(line); len(fields) >= 2 {
				target = fields[1]
			}
			continue
		}
		if v := strings.TrimPrefix(line, "Proxy-Authorization: "); v != line {
			auth = v
		}
	}
	return target, auth
}

// startFakeHTTPProxy 起一个进程内假 HTTP 代理（监听 127.0.0.1 随机端口，测试结束时自动关闭）：
// 每接受一个连接先读完整 CONNECT 请求头并记录，再调用 respond（参数为第几个连接，从 1 开始）完成应答；
// respond 为 nil 时收到请求后不做任何应答（模拟假死代理，供 ctx deadline 超时用例使用）
func startFakeHTTPProxy(t *testing.T, respond func(n int, conn net.Conn)) *fakeHTTPProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &fakeHTTPProxy{ln: ln}
	go func() {
		n := 0
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			n++
			go p.handleConn(conn, n, respond)
		}
	}()
	return p
}

// handleConn 处理假代理的单个连接：读 CONNECT 请求 -> 记录目标与认证头 -> 交给 respond 应答
func (p *fakeHTTPProxy) handleConn(conn net.Conn, n int, respond func(int, net.Conn)) {
	defer conn.Close()
	head, err := readHTTPRequestHead(conn)
	if err != nil {
		return
	}
	target, auth := parseConnectHead(head)
	p.mu.Lock()
	p.targets = append(p.targets, target)
	p.auths = append(p.auths, auth)
	p.mu.Unlock()

	if respond != nil {
		respond(n, conn)
		time.Sleep(300 * time.Millisecond) // 应答后保持连接片刻，模拟正常代理不立刻断开隧道
		return
	}
	time.Sleep(5 * time.Second) // 不应答：保持连接打开（不给任何响应），让客户端的 deadline 先超时
}

// port 返回假代理监听端口的字符串形式（供构造 host:port 与候选 IP 列表使用）
func (p *fakeHTTPProxy) port() string {
	return strconv.Itoa(p.ln.Addr().(*net.TCPAddr).Port)
}

// connectTargets 返回已收到的 CONNECT 目标地址列表（按到达顺序的副本）
func (p *fakeHTTPProxy) connectTargets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.targets...)
}

// connectCount 返回已收到的 CONNECT 请求个数
func (p *fakeHTTPProxy) connectCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.targets)
}

// connectAuth 返回第 n 个连接（从 1 开始）携带的 Proxy-Authorization 头值
func (p *fakeHTTPProxy) connectAuth(n int) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.auths[n-1]
}

// ---------- env 代理解析（parseEnvHTTPProxy） ----------

// parseEnvHTTPProxy 按优先级取第一个非空值：HTTPS_PROXY → https_proxy → HTTP_PROXY → http_proxy → ALL_PROXY → all_proxy；
// 空白值视为未设置继续往下；无 scheme 视为 http:// 且 port 缺省 80；非 http scheme 或解析失败时返回 nil（等效未配置）
func TestParseEnvHTTPProxy(t *testing.T) {
	cases := []struct {
		name string
		envs map[string]string
		want *httpProxyAddr
	}{
		{"优先级取HTTPS_PROXY", map[string]string{
			"HTTPS_PROXY": "10.0.0.1:8843", "https_proxy": "10.0.0.2:8843",
			"HTTP_PROXY": "10.0.0.3:8843", "ALL_PROXY": "10.0.0.5:8843",
		}, &httpProxyAddr{Name: "HTTPS_PROXY", Host: "10.0.0.1", Port: "8843"}},
		{"次级取https_proxy", map[string]string{
			"https_proxy": "10.0.0.2:8843", "HTTP_PROXY": "10.0.0.3:8843",
		}, &httpProxyAddr{Name: "https_proxy", Host: "10.0.0.2", Port: "8843"}},
		{"空白值视为未设置继续往下", map[string]string{
			"HTTPS_PROXY": "", "https_proxy": "   ", "HTTP_PROXY": "10.0.0.3:8843",
		}, &httpProxyAddr{Name: "HTTP_PROXY", Host: "10.0.0.3", Port: "8843"}},
		{"小写all_proxy兜底", map[string]string{"all_proxy": "10.0.0.6:8843"},
			&httpProxyAddr{Name: "all_proxy", Host: "10.0.0.6", Port: "8843"}},
		{"无scheme缺省端口80", map[string]string{"HTTP_PROXY": "1.2.3.4"},
			&httpProxyAddr{Name: "HTTP_PROXY", Host: "1.2.3.4", Port: "80"}},
		{"无scheme带userinfo缺省端口80", map[string]string{"HTTP_PROXY": "user:pass@1.2.3.4"},
			&httpProxyAddr{Name: "HTTP_PROXY", Host: "1.2.3.4", Port: "80", User: "user", Pass: "pass"}},
		{"scheme大小写不敏感", map[string]string{"HTTP_PROXY": "HTTP://user:pass@1.2.3.4:8080"},
			&httpProxyAddr{Name: "HTTP_PROXY", Host: "1.2.3.4", Port: "8080", User: "user", Pass: "pass"}},
		{"全部未设置返回nil", map[string]string{}, nil},
		{"非http scheme返回nil且不再尝试低优先级", map[string]string{
			"HTTPS_PROXY": "socks5://10.0.0.1:1080", "HTTP_PROXY": "10.0.0.9:80",
		}, nil},
		{"缺少主机地址返回nil", map[string]string{"HTTP_PROXY": "http://"}, nil},
		{"端口非法解析失败返回nil", map[string]string{"HTTP_PROXY": "http://1.2.3.4:abc"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setEnvProxyLookup(t, c.envs)
			got := parseEnvHTTPProxy()
			if (c.want == nil) != (got == nil) {
				t.Fatalf("解析结果 = %v, 期望 %v", got, c.want)
			}
			if got != nil && *got != *c.want {
				t.Fatalf("解析结果 = %+v, 期望 %+v", *got, *c.want)
			}
		})
	}
}

// maskedURL 打码格式：userinfo 的密码以 *** 代替（http://user:***@host:port），无 userinfo 时原样
func TestHTTPProxyAddr_MaskedURL(t *testing.T) {
	authed := &httpProxyAddr{Name: "HTTPS_PROXY", Host: "127.0.0.1", Port: "8080", User: "user", Pass: "pass"}
	if got, want := authed.maskedURL(), "http://user:***@127.0.0.1:8080"; got != want {
		t.Fatalf("带认证的打码地址 = %q, 期望 %q", got, want)
	}
	plain := &httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: "80"}
	if got, want := plain.maskedURL(), "http://127.0.0.1:80"; got != want {
		t.Fatalf("无认证的打码地址 = %q, 期望 %q", got, want)
	}
}

// maskProxyRaw 尽力打码原始值中的 userinfo（仅用于无法解析时的 warn 日志展示）
func TestMaskProxyRaw(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"带scheme的userinfo", "http://user:pass@10.0.0.1:8080", "http://***@10.0.0.1:8080"},
		{"无scheme的userinfo", "user:pass@10.0.0.1:8080", "***@10.0.0.1:8080"},
		{"无userinfo原样返回", "http://10.0.0.1:8080", "http://10.0.0.1:8080"},
		{"无scheme无userinfo原样返回", "10.0.0.1:8080", "10.0.0.1:8080"},
		{"其他scheme照常打码", "socks5://u:p@10.0.0.1:1080", "socks5://***@10.0.0.1:1080"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := maskProxyRaw(c.in); got != c.want {
				t.Fatalf("maskProxyRaw(%q) = %q, 期望 %q", c.in, got, c.want)
			}
		})
	}
}

// ---------- httpProxyDialer（CONNECT 拨号器，对进程内假代理发请求） ----------

// 代理回 200：请求行目标地址正确；无 userinfo 时必须不带 Proxy-Authorization 头；隧道内双向读写数据一致
func TestHTTPProxyDialer_ConnectOKNoAuth(t *testing.T) {
	fp := startFakeHTTPProxy(t, func(n int, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		buf := make([]byte, 1024)
		if num, err := conn.Read(buf); err == nil && num > 0 {
			conn.Write(buf[:num]) // 隧道对端：原样回显，验证双向数据一致
		}
	})
	d := newHTTPProxyDialer(&httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: fp.port()})

	conn, err := d.DialContext(context.Background(), "tcp", "5.6.7.8:443")
	if err != nil {
		t.Fatalf("代理回 200 时应建立隧道, got: %v", err)
	}
	defer conn.Close()

	if targets := fp.connectTargets(); len(targets) != 1 || targets[0] != "5.6.7.8:443" {
		t.Fatalf("CONNECT 请求行目标地址应为 5.6.7.8:443, got %v", targets)
	}
	if auth := fp.connectAuth(1); auth != "" {
		t.Fatalf("无 userinfo 时不应携带 Proxy-Authorization 头, got %q", auth)
	}

	if _, err := conn.Write([]byte("HELLO")); err != nil {
		t.Fatalf("隧道内写入失败: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	num, err := conn.Read(buf)
	if err != nil || string(buf[:num]) != "HELLO" {
		t.Fatalf("隧道内应能双向读写且数据一致, got %q, err: %v", buf[:num], err)
	}
}

// 带 userinfo 的代理：CONNECT 必须携带 Proxy-Authorization: Basic 头（值为 user:pass 的 Base64）
func TestHTTPProxyDialer_ConnectWithAuth(t *testing.T) {
	fp := startFakeHTTPProxy(t, func(n int, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	})
	d := newHTTPProxyDialer(&httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: fp.port(), User: "user", Pass: "pass"})

	conn, err := d.DialContext(context.Background(), "tcp", "5.6.7.8:443")
	if err != nil {
		t.Fatalf("带认证的 CONNECT 应成功, got: %v", err)
	}
	defer conn.Close()

	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass"))
	if auth := fp.connectAuth(1); auth != wantAuth {
		t.Fatalf("Proxy-Authorization = %q, 期望 %q", auth, wantAuth)
	}
}

// 代理回非 200（403）：应报错（含状态码），隧道不建立
func TestHTTPProxyDialer_ProxyForbidden(t *testing.T) {
	fp := startFakeHTTPProxy(t, func(n int, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	})
	d := newHTTPProxyDialer(&httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: fp.port()})

	conn, err := d.DialContext(context.Background(), "tcp", "5.6.7.8:443")
	if err == nil {
		conn.Close()
		t.Fatal("代理回 403 时应报错")
	}
	if !strings.Contains(err.Error(), "代理CONNECT失败") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("错误应包含 代理CONNECT失败 与 403, got: %v", err)
	}
}

// 应答头分多次写入（逐字节到达）也应能正确解析出 200 并建立隧道
func TestHTTPProxyDialer_FragmentedResponseHead(t *testing.T) {
	fp := startFakeHTTPProxy(t, func(n int, conn net.Conn) {
		for _, b := range []byte("HTTP/1.1 200 Connection established\r\n\r\n") {
			conn.Write([]byte{b}) // 逐字节写入应答头，模拟分片到达
		}
		buf := make([]byte, 1024)
		if num, err := conn.Read(buf); err == nil && num > 0 {
			conn.Write(buf[:num]) // 隧道对端：原样回显，验证隧道可用
		}
	})
	d := newHTTPProxyDialer(&httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: fp.port()})

	conn, err := d.DialContext(context.Background(), "tcp", "5.6.7.8:443")
	if err != nil {
		t.Fatalf("分片到达的应答头也应能正确解析, got: %v", err)
	}
	defer conn.Close()

	if targets := fp.connectTargets(); len(targets) != 1 || targets[0] != "5.6.7.8:443" {
		t.Fatalf("CONNECT 请求行目标地址应为 5.6.7.8:443, got %v", targets)
	}
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatalf("隧道内写入失败: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	num, err := conn.Read(buf)
	if err != nil || string(buf[:num]) != "PING" {
		t.Fatalf("隧道内应能双向读写且数据一致, got %q, err: %v", buf[:num], err)
	}
}

// 应答头之后紧随的业务数据不被吞（逐字节读头的关键回归点）：
// 应答头与 "HELLO" 在同一个包里到达，DialContext 返回后读到的第一个字节必须是 'H'
func TestHTTPProxyDialer_TunnelDataAfterHeadNotSwallowed(t *testing.T) {
	fp := startFakeHTTPProxy(t, func(n int, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 OK\r\n\r\nHELLO")) // 应答头与隧道内业务数据一次性写入
	})
	d := newHTTPProxyDialer(&httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: fp.port()})

	conn, err := d.DialContext(context.Background(), "tcp", "5.6.7.8:443")
	if err != nil {
		t.Fatalf("应建立隧道, got: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 32)
	num, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("应答头之后的隧道数据应可读, err: %v", err)
	}
	if buf[0] != 'H' || string(buf[:num]) != "HELLO" {
		t.Fatalf("应答头之后的业务数据不应被吞, got %q (第一个字节 %q)", buf[:num], buf[0])
	}
}

// ctx 带 deadline 时超时生效：假代理 accept 后不发任何回应，deadline 到应报错（而不是永久阻塞）
func TestHTTPProxyDialer_DeadlineTimeout(t *testing.T) {
	fp := startFakeHTTPProxy(t, nil) // 不应答，模拟假死代理
	d := newHTTPProxyDialer(&httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: fp.port()})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", "5.6.7.8:443")
	elapsed := time.Since(start)
	if err == nil {
		conn.Close()
		t.Fatal("假死代理上 ctx deadline 到期时应报错")
	}
	if elapsed < 400*time.Millisecond || elapsed > 5*time.Second {
		t.Fatalf("应在 ctx deadline(500ms) 到期时及时报错, 实际耗时 %v", elapsed)
	}
}

// 仅支持 tcp 网络：其他网络类型应直接报错（不发起任何连接）
func TestHTTPProxyDialer_UnsupportedNetwork(t *testing.T) {
	d := newHTTPProxyDialer(&httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: "80"})
	if _, err := d.Dial("udp", "5.6.7.8:443"); err == nil {
		t.Fatal("非 tcp 网络类型应报错")
	}
}

// ---------- dialBackendRetry 两轮回退（第 1 轮直连/Socks5，第 2 轮 env 代理轮询） ----------
// 注意：dialBackendRetry 读写全局 envHTTPProxy 与 dnsRetryCacheInstance，以下用例禁止 t.Parallel，
// 且每个用例前后都保存/恢复全局状态（cfg 与 envHTTPProxy），host 均用独立域名避免缓存串扰。

// 代理轮询收 CONNECT 后自己扮演后端的标准应答：回 200 建立隧道，读走客户端发来的握手数据后回 "HELLO"
// （读到才回数据，隐式验证隧道双向可通）
func respondConnectOKPlayBackend(n int, conn net.Conn) {
	conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	buf := make([]byte, 1024)
	conn.Read(buf)
	conn.Write([]byte("HELLO"))
}

// 场景 A：直连轮询全败 + envHTTPProxy 已设置 -> 第 2 轮经代理对同一候选列表再轮询并连接成功
func TestDialBackendRetry_EnvProxyFallbackWhenDirectAllFail(t *testing.T) {
	saveCfg(t) // 测完恢复 cfg，避免影响其他用例
	cfg.EnableSocks = false
	cfg.VerifyTLS = boolPtr(false) // 关闭 verify 探测，假代理扮演的后端回明文即可通过首字节检查
	cfg.DialTimeout = 2
	cfg.FirstByteTimeout = 2

	// 假 HTTP 代理只监听在 127.0.0.1 上：候选 IP(127.0.0.2/127.0.0.3) 的同端口无人监听，第 1 轮直连全部失败
	fp := startFakeHTTPProxy(t, respondConnectOKPlayBackend)
	saveEnvHTTPProxy(t) // 测完恢复全局 envHTTPProxy
	port := fp.port()
	envHTTPProxy = &httpProxyAddr{Name: "HTTPS_PROXY", Host: "127.0.0.1", Port: port}

	host := "envproxy-fallback.example.com"
	ips := []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.3")}

	res := dialBackendRetry(newConnCtx("127.0.0.1:1234"), host, port, ips, []byte("data"))
	if res == nil {
		t.Fatal("直连全败且配置了 env 代理时，第 2 轮代理轮询应连接成功")
	}
	defer res.conn.Close()
	if !res.viaProxy {
		t.Fatal("经代理轮询连上时应标记 viaProxy=true")
	}
	if res.index != 1 || res.total != 2 {
		t.Fatalf("代理轮询的候选序号应基于同一候选列表(候选1/2), got 候选%d/%d", res.index, res.total)
	}
	if !res.ip.Equal(net.ParseIP("127.0.0.2")) {
		t.Fatalf("代理轮询应按顺序连上第 1 个候选 IP, got %s", res.ip)
	}
	if string(res.first) != "HELLO" {
		t.Fatalf("应返回经代理读到的后端首字节响应, got %q", res.first)
	}
	if targets := fp.connectTargets(); len(targets) != 1 || targets[0] != "127.0.0.2:"+port {
		t.Fatalf("代理应只收到第 1 个候选的 CONNECT, got %v", targets)
	}
}

// 场景 B（顺序关键断言）：候选列表 ≥3 个，前两个候选代理拒绝(403)、最后一个回 200，
// 代理轮询的 CONNECT 尝试顺序应与传入的同一候选列表顺序完全一致（同序、不重排）
func TestDialBackendRetry_EnvProxyKeepsCandidateOrder(t *testing.T) {
	saveCfg(t)
	cfg.EnableSocks = false
	cfg.VerifyTLS = boolPtr(false)
	cfg.DialTimeout = 2
	cfg.FirstByteTimeout = 2

	fp := startFakeHTTPProxy(t, func(n int, conn net.Conn) {
		if n < 3 { // 前两个候选代理拒绝，逼出对第 3 个候选的尝试
			conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
		respondConnectOKPlayBackend(n, conn)
	})
	saveEnvHTTPProxy(t)
	port := fp.port()
	envHTTPProxy = &httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: port}

	host := "envproxy-order.example.com"
	ips := []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.3"), net.ParseIP("127.0.0.4")}

	res := dialBackendRetry(newConnCtx("127.0.0.1:1234"), host, port, ips, []byte("data"))
	if res == nil {
		t.Fatal("前两个候选被代理拒绝后应继续轮询到第 3 个候选")
	}
	defer res.conn.Close()

	want := []string{"127.0.0.2:" + port, "127.0.0.3:" + port, "127.0.0.4:" + port}
	if got := fp.connectTargets(); len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("代理 CONNECT 尝试顺序应与候选列表完全一致(同序不重排), got %v, 期望 %v", got, want)
	}
	if !res.ip.Equal(net.ParseIP("127.0.0.4")) || res.index != 3 || res.total != 3 || !res.viaProxy {
		t.Fatalf("应连上第 3 个候选(候选3/3)且 viaProxy=true, got ip=%s 候选%d/%d viaProxy=%v", res.ip, res.index, res.total, res.viaProxy)
	}
}

// 场景 C（缓存不污染）：代理轮询的一切结果不写入 dnsRetryCache ——
// stats 只保留第 1 轮直连失败的记录（代理成功的 IP 不得记 success），verify 缓存也无该 host 条目
func TestDialBackendRetry_EnvProxyNotPolluteCache(t *testing.T) {
	saveCfg(t)
	cfg.EnableSocks = false
	cfg.VerifyTLS = boolPtr(false)
	cfg.DialTimeout = 2
	cfg.FirstByteTimeout = 2

	fp := startFakeHTTPProxy(t, respondConnectOKPlayBackend)
	saveEnvHTTPProxy(t)
	port := fp.port()
	envHTTPProxy = &httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: port}

	host := "envproxy-cache.example.com"
	dead1, dead2 := net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.3")

	// 前置快照：该 host 在 stats/verify 缓存中均无记录
	if _, ok := dnsRetryCacheInstance.stats[host]; ok {
		t.Fatalf("前置条件不成立: %s 不应有历史 stats", host)
	}
	if _, ok := dnsRetryCacheInstance.verify[host]; ok {
		t.Fatalf("前置条件不成立: %s 不应有历史 verify 记录", host)
	}

	res := dialBackendRetry(newConnCtx("127.0.0.1:1234"), host, port, []net.IP{dead1, dead2}, []byte("data"))
	if res == nil || !res.viaProxy {
		t.Fatal("代理轮询应连接成功(否则本用例没有真正走到代理路径)")
	}
	defer res.conn.Close()

	for _, ip := range []string{"127.0.0.2", "127.0.0.3"} {
		st := dnsRetryCacheInstance.stats[host][ip]
		if st == nil || st.fail != 1 || st.success != 0 || st.consecFail != 1 {
			t.Fatalf("代理轮询不应污染 %s 的 stats(应只有第 1 轮的 1 次失败), got %+v", ip, st)
		}
	}
	if _, ok := dnsRetryCacheInstance.verify[host]; ok {
		t.Fatal("代理轮询不应写 verify 缓存(该 host 应无条目)")
	}
}

// 场景 D：envHTTPProxy 已设置但第 1 轮直连成功 -> 绝不进代理轮询，假代理一次 CONNECT 都不该收到
func TestDialBackendRetry_FirstRoundSuccessSkipsProxy(t *testing.T) {
	saveCfg(t)
	cfg.EnableSocks = false
	cfg.VerifyTLS = boolPtr(false)
	cfg.DialTimeout = 2
	cfg.FirstByteTimeout = 2

	// 在 127.0.0.1 上起一个直连可用的假后端（复用 retry_test.go 的 fakeBackend）
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听 127.0.0.1: %v", err)
	}
	defer ln.Close()
	go fakeBackend(t, ln, "HELLO")
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	// env 代理虽已配置，但第 1 轮存在可用 IP 时不应被使用
	fp := startFakeHTTPProxy(t, func(n int, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	})
	saveEnvHTTPProxy(t)
	envHTTPProxy = &httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: fp.port()}

	host := "envproxy-skip.example.com"
	res := dialBackendRetry(newConnCtx("127.0.0.1:1234"), host, port, []net.IP{net.ParseIP("127.0.0.2"), net.ParseIP("127.0.0.1")}, []byte("data"))
	if res == nil {
		t.Fatal("第 1 轮存在可用 IP 时应直连成功")
	}
	defer res.conn.Close()
	if res.viaProxy {
		t.Fatal("直连成功时不应标记 viaProxy")
	}
	if res.index != 2 || res.total != 2 {
		t.Fatalf("直连成功的应是第 2 个候选(候选2/2), got 候选%d/%d", res.index, res.total)
	}
	if string(res.first) != "HELLO" {
		t.Fatalf("应返回直连读到的后端首字节响应, got %q", res.first)
	}
	if got := fp.connectCount(); got != 0 {
		t.Fatalf("第 1 轮成功时不应发起代理轮询(代理应收到 0 次 CONNECT), got %d", got)
	}
}

// ---------- verifyBackendWithDialer（探测拨号器可注入，代理轮询的探测握手经代理拨号） ----------

// 负面路径：传假代理拨号器探测时，代理回 403 -> 探测失败返回错误
func TestVerifyBackendWithDialer_ProxyForbidden(t *testing.T) {
	fp := startFakeHTTPProxy(t, func(n int, conn net.Conn) {
		conn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
	})
	d := newHTTPProxyDialer(&httpProxyAddr{Name: "HTTP_PROXY", Host: "127.0.0.1", Port: fp.port()})

	err := verifyBackendWithDialer(d, "5.6.7.8:443", "verify-proxy.invalid", 2)
	if err == nil {
		t.Fatal("代理拒绝 CONNECT 时探测应失败")
	}
	if !strings.Contains(err.Error(), "代理CONNECT失败") {
		t.Fatalf("应报 代理CONNECT失败, got: %v", err)
	}
}
