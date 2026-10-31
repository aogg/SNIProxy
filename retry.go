package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// TLS 验证结果的缓存时长
const (
	verifySuccessTTL = 10 * time.Minute // 验证通过：10 分钟内直接复用结果，不再重复探测
	verifyFailTTL    = 60 * time.Second // 验证失败：60 秒内不再探测、直接跳过该 IP，之后允许重新验证
)

// ipStat 记录某个后端 IP 的历史连接结果，用于下次按“上次结果”排序转发
type ipStat struct {
	success     int       // 累计成功次数
	fail        int       // 累计失败次数
	consecFail  int       // 连续失败次数
	lastSuccess time.Time // 最近一次成功时间
	lastFail    time.Time // 最近一次失败时间
}

// verifyResult 记录某个 域名+IP 的真实 TLS 验证结果
type verifyResult struct {
	ok     bool      // 是否验证通过（真实 TLS 握手成功且证书校验通过）
	at     time.Time // 验证时间（用于判断缓存是否过期）
	reason string    // 失败原因（仅用于日志输出）
}

// dnsRetryCache 按“域名 -> IP -> 连接结果”存储 DNS 多 IP 自动重试的结果
// 这样下次连接同一域名时，可以优先使用上次成功过的 IP，把上次失败的 IP 排到最后
// 说明：结果只保存在内存中，重启后清零（DNS 记录本身会变化，持久化反而容易用到已失效的旧 IP）
type dnsRetryCache struct {
	mu     sync.Mutex
	stats  map[string]map[string]*ipStat       // 域名 -> IP -> 连接结果
	verify map[string]map[string]*verifyResult // 域名 -> IP -> 真实 TLS 验证结果
}

// dnsRetryCache 全局唯一实例
var dnsRetryCacheInstance = &dnsRetryCache{
	stats:  make(map[string]map[string]*ipStat),
	verify: make(map[string]map[string]*verifyResult),
}

// reportResult 记录一次后端 IP 的连接结果（成功/失败），并发安全
func (c *dnsRetryCache) reportResult(host, ip string, success bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	m := c.stats[host]
	if m == nil {
		m = make(map[string]*ipStat)
		c.stats[host] = m
	}
	st := m[ip]
	if st == nil {
		st = &ipStat{}
		m[ip] = st
	}
	now := time.Now()
	if success {
		st.success++
		st.consecFail = 0
		st.lastSuccess = now
	} else {
		st.fail++
		st.consecFail++
		st.lastFail = now
	}
}

// getVerifyResult 查询 域名+IP 的真实 TLS 验证结果缓存（并发安全）
// 命中且未过期时返回 (结果, true)；未缓存或已过期时返回 (nil, false)（过期条目会被顺带删除）
func (c *dnsRetryCache) getVerifyResult(host, ip string) (*verifyResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	r, ok := c.verify[host][ip]
	if !ok {
		return nil, false
	}
	ttl := verifyFailTTL
	if r.ok {
		ttl = verifySuccessTTL
	}
	if time.Since(r.at) > ttl { // 已过期，视为未验证过
		delete(c.verify[host], ip)
		if len(c.verify[host]) == 0 {
			delete(c.verify, host)
		}
		return nil, false
	}
	return r, true
}

// setVerifyResult 写入 域名+IP 的真实 TLS 验证结果缓存（并发安全）
func (c *dnsRetryCache) setVerifyResult(host, ip string, ok bool, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.verify == nil { // 兼容直接构造的空缓存（未初始化 verify 的场景）
		c.verify = make(map[string]map[string]*verifyResult)
	}
	m := c.verify[host]
	if m == nil {
		m = make(map[string]*verifyResult)
		c.verify[host] = m
	}
	m[ip] = &verifyResult{ok: ok, at: time.Now(), reason: reason}
}

// orderIPs 根据历史连接结果，对本次 DNS 返回的候选 IP 列表排序，排序规则如下：
//  1. 上次连接成功过的 IP 排最前（按最近成功时间倒序，越新越优先）
//  2. 从未尝试过的 IP 排中间（保持 DNS 返回的原始顺序）
//  3. 只有失败记录的 IP 排最后（按最近失败时间正序，失败越久越靠前，留一点“改过自新”的机会）
//
// 同时会清理缓存中已不在本次 DNS 结果里的旧 IP（例如该域名的 DNS 记录已变化）
func (c *dnsRetryCache) orderIPs(host string, ips []net.IP) []net.IP {
	c.mu.Lock()
	defer c.mu.Unlock()

	m := c.stats[host]
	if m == nil {
		return ips // 该域名没有历史记录，直接按 DNS 返回顺序
	}

	// 以本次 DNS 结果为准，清理已消失的旧 IP 记录
	alive := make(map[string]bool, len(ips))
	for _, ip := range ips {
		alive[ip.String()] = true
	}
	for k := range m {
		if !alive[k] {
			delete(m, k)
		}
	}

	if len(ips) <= 1 || len(m) == 0 {
		return ips // 只有一个候选 IP 或没有相关历史记录时无需排序
	}

	type timedIP struct {
		ip net.IP
		t  time.Time
	}
	var good, bad []timedIP
	var unknown []net.IP
	for _, ip := range ips {
		st, ok := m[ip.String()]
		if !ok {
			unknown = append(unknown, ip) // 没尝试过的，保持原顺序
			continue
		}
		if st.lastSuccess.After(st.lastFail) {
			good = append(good, timedIP{ip, st.lastSuccess}) // 成功过的排最前
		} else {
			bad = append(bad, timedIP{ip, st.lastFail}) // 失败过的排最后
		}
	}
	sort.SliceStable(good, func(i, j int) bool { return good[i].t.After(good[j].t) })
	sort.SliceStable(bad, func(i, j int) bool { return bad[i].t.Before(bad[j].t) })

	ordered := make([]net.IP, 0, len(ips))
	for _, x := range good {
		ordered = append(ordered, x.ip)
	}
	ordered = append(ordered, unknown...)
	for _, x := range bad {
		ordered = append(ordered, x.ip)
	}
	return ordered
}

// cleanup 清理长时间没有连接记录的域名/IP，以及已过期的 TLS 验证结果缓存
// （内存兜底，防止 allow_all_hosts 时无限增长）
func (c *dnsRetryCache) cleanup(maxIdle time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for host, m := range c.stats {
		for k, st := range m {
			last := st.lastSuccess
			if st.lastFail.After(last) {
				last = st.lastFail
			}
			if now.Sub(last) > maxIdle {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(c.stats, host)
		}
	}
	// 按成功/失败各自的 TTL 清理 TLS 验证结果缓存
	for host, m := range c.verify {
		for k, r := range m {
			ttl := verifyFailTTL
			if r.ok {
				ttl = verifySuccessTTL
			}
			if now.Sub(r.at) > ttl {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(c.verify, host)
		}
	}
}

// startJanitor 启动后台协程，定期清理过期的连接结果
func (c *dnsRetryCache) startJanitor(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.cleanup(time.Hour)
			}
		}
	}()
}

// joinIPs 将 IP 列表拼成 "1.1.1.1, 2.2.2.2" 形式，仅用于日志输出
func joinIPs(ips []net.IP) string {
	strs := make([]string, 0, len(ips))
	for _, ip := range ips {
		strs = append(strs, ip.String())
	}
	return strings.Join(strs, ", ")
}

// dialWithDialer 使用指定拨号器带超时拨号（单位：秒），超时通过 ContextDialer 的 context deadline 实现
// （第 1 轮传直连/SOCKS5 拨号器，代理轮询传 httpProxyDialer）
func dialWithDialer(d proxy.Dialer, network, addr string, timeoutSec int) (net.Conn, error) {
	if timeoutSec > 0 {
		if cd, ok := d.(proxy.ContextDialer); ok { // 直连(*net.Dialer)、SOCKS5 与 HTTP 代理拨号器都实现了 DialContext
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
			defer cancel()
			return cd.DialContext(ctx, network, addr)
		}
	}
	return d.Dial(network, addr)
}

// dialWithTimeout 带超时的拨号（直连、Socks5 前置代理均支持），单位：秒
func dialWithTimeout(network, addr string, timeoutSec int) (net.Conn, error) {
	return dialWithDialer(GetDialer(cfg.EnableSocks), network, addr, timeoutSec)
}

// isVerifyTLSEnabled 返回是否启用后端真实 TLS 验证（verify_tls 未配置时默认开启）
func isVerifyTLSEnabled() bool {
	return cfg.VerifyTLS == nil || *cfg.VerifyTLS
}

// verifyProbeTimeout 返回探测握手的超时时间（秒）：复用 first_byte_timeout；
// verify_tls 关闭或 first_byte_timeout 为 0/负数时返回 0（表示不探测，完全保持旧行为）
func verifyProbeTimeout() int {
	if !isVerifyTLSEnabled() || cfg.FirstByteTimeout <= 0 {
		return 0
	}
	return cfg.FirstByteTimeout
}

// verifyBackend 通过一次真实的 TLS 客户端握手来验证候选 IP 是否真的可用：
// 先拨号到 addr（复用 dialWithTimeout，保证 SOCKS5 前置代理可用），
// 再以 ServerName=host 发起完整证书校验（InsecureSkipVerify=false）的 TLS 握手，
// 握手成功（含证书校验通过）才认为该 IP 可用，返回 nil；否则返回具体失败原因。
// 整个探测（拨号 + 握手）受 timeoutSec 秒的总超时限制，超时同样视为验证失败。
func verifyBackend(addr, host string, timeoutSec int) error {
	return verifyBackendWithDialer(GetDialer(cfg.EnableSocks), addr, host, timeoutSec)
}

// verifyBackendWithDialer 与 verifyBackend 相同的探测逻辑，但使用指定的拨号器
// （代理轮询时传 httpProxyDialer，探测握手也经代理拨号，探测总超时同样受 timeoutSec 秒约束）。
func verifyBackendWithDialer(d proxy.Dialer, addr, host string, timeoutSec int) error {
	if timeoutSec <= 0 {
		return nil // 配置为不探测（调用方不会以 0 调用，此处仅兜底，视为通过）
	}
	deadline := time.Now().Add(time.Duration(timeoutSec) * time.Second)

	backend, err := dialWithDialer(d, "tcp", addr, timeoutSec)
	if err != nil {
		return fmt.Errorf("拨号失败: %v", err)
	}
	defer backend.Close() // 探测连接用完即关，真实转发由后续正常流程重新建立连接

	if err := backend.SetDeadline(deadline); err != nil { // 让整个 TLS 握手也受同一超时限制
		return fmt.Errorf("设置超时失败: %v", err)
	}

	conn := tls.Client(backend, &tls.Config{
		ServerName:         host,  // 以目标域名做 SNI 与证书匹配
		InsecureSkipVerify: false, // 显式启用完整证书校验（证书不匹配/过期/自签名都算失败）
	})
	defer conn.Close()
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("TLS握手失败: %v", err)
	}
	return nil
}

// peekFirstByte 在超时时间内等待后端返回第一个响应字节，用于识别
// “TCP 连接成功、数据也发出去了，但后端服务其实已经假死/无响应”的情况，
// 避免把客户端交给一个看着连上了、实际不通的后端。
// 返回提前读到的响应数据；超时或出错则 ok 为 false（该 IP 视为连接失败）
func peekFirstByte(backend net.Conn, timeoutSec int) (first []byte, ok bool) {
	if timeoutSec <= 0 {
		return nil, true // 配置为不检测
	}
	if err := backend.SetReadDeadline(time.Now().Add(time.Duration(timeoutSec) * time.Second)); err != nil {
		return nil, true // 该连接不支持设置超时，就不检测了，保持旧行为
	}
	defer backend.SetReadDeadline(time.Time{}) // 无论成败都要清除超时，避免影响后续转发
	buf := make([]byte, 4096)
	n, err := backend.Read(buf)
	if n > 0 {
		return buf[:n], true // 只要收到了数据就说明后端是活的
	}
	if err != nil {
		return nil, false
	}
	return nil, true // n=0 且无错误（很少见），视为后端可用
}

// isValidServerHello 校验 peekFirstByte 读到的首个响应是不是合法的 TLS 握手记录：
// 记录类型必须为 handshake(0x16)，且第一条握手消息类型必须为 ServerHello(2)；
// alert(0x15)、明文 "HTTP/"（如被劫持后返回的错误页）、数据长度不足等情况都视为失败。
// 纯内存判断（不含任何 IO），方便单元测试。
func isValidServerHello(first []byte) bool {
	// 需要至少：TLS 记录头 5 字节（类型1 + 版本2 + 长度2）+ 握手消息头 4 字节（类型1 + 长度3）
	if len(first) < 9 {
		return false // 数据长度不足，无法构成合法的 TLS 握手记录
	}
	if recordType(first[0]) != recordTypeHandshake {
		return false // 不是 handshake 记录（如 0x15=alert、明文 "HTTP/" 等）
	}
	if first[1] != 3 {
		return false // TLS 主要版本必须为 3（与 getSNIServerName 的判断保持一致）
	}
	if first[5] != typeServerHello {
		return false // 第一条握手消息不是 ServerHello
	}
	length := int(first[3])<<8 | int(first[4])
	return length >= 4 // 记录负载至少要容纳 4 字节的握手消息头，否则也是异常响应
}

// 出口路径日志标签：从“出口路径确定”起的每条日志（拨号尝试与 [已连] 阶段）都携带，
// 用于区分该连接实际走的出口（AGAIN_PROXY 命名与启动日志 “AGAIN_PROXY: 开启” 保持一致）
const (
	pathTagDirect     = "(直连)"        // 第 1 轮：直连出口（cfg.EnableSocks=false）
	pathTagSocks5     = "(socks5)"      // 第 1 轮：Socks5 前置代理出口（cfg.EnableSocks=true，不误标成直连）
	pathTagAgainProxy = "(AGAIN_PROXY)" // 第 2 轮：AGAIN_PROXY 代理回退出口
)

// round1Tag 返回第 1 轮的出口路径标签：cfg.EnableSocks 开启时第 1 轮实为 Socks5 前置，标签用 (socks5)，否则为 (直连)
func round1Tag() string {
	if cfg.EnableSocks {
		return pathTagSocks5
	}
	return pathTagDirect
}

// backendResult dialBackendRetry 的连接结果：
// 除后端连接与提前读到的首包数据外，还携带“实际连接的后端 IP 及其序号”，
// 供调用方（forward/ioReflector）在 [已连] 阶段的字节日志中展示实际后端信息
type backendResult struct {
	conn     net.Conn // 已建立的后端连接（dialBackendRetry 全部失败时返回 nil 结果）
	first    []byte   // 等待首字节时提前读到的后端响应（由调用方转发给客户端）
	ip       net.IP   // 实际连接成功的后端 IP
	index    int      // 该 IP 在去重排序后候选列表中的位置（1-based，即拨号尝试顺序中的第几个）
	total    int      // 去重排序后的候选 IP 总数
	viaProxy bool     // 是否经 AGAIN_PROXY 代理轮询连上（配合 cfg.EnableSocks 推导出口路径标签，见 pathTag）
}

// pathTag 返回该连接实际出口路径的日志标签（出口路径标签的单一来源）：
// 经第 2 轮 AGAIN_PROXY 代理连上时为 (AGAIN_PROXY)，否则按 cfg.EnableSocks 区分 (socks5)/(直连)。
// [已连] 阶段日志（首包回写客户端、双向字节数等）统一从这里取标签，与拨号阶段的 roundTag 同源一致
func (r *backendResult) pathTag() string {
	if r.viaProxy {
		return pathTagAgainProxy
	}
	return round1Tag()
}

// backendDesc 生成字节日志中使用的后端描述：后端[185.199.110.133:443 候选2/4](直连)
// （出口路径标签由 pathTag 提供，追加在方括号之后）
func (r *backendResult) backendDesc(port string) string {
	return fmt.Sprintf("后端[%s 候选%d/%d]%s", net.JoinHostPort(r.ip.String(), port), r.index, r.total, r.pathTag())
}

// dialBackendRetry 按“上次连接结果”排序后依次尝试连接 host 的所有候选 IP：
//
//	1.（TLS 验证开启时）先用真实 TLS 握手验证该 IP（结果缓存：成功 10 分钟、失败 60 秒）
//	   -> 验证失败（含证书校验失败）或 60 秒内验证失败过的 IP，自动换下一个 IP
//	2. 连接某个 IP 失败（连接被拒/超时等）-> 自动重试下一个 IP
//	3. 连接成功但发送握手数据失败     -> 自动重试下一个 IP
//	4. 连接成功但等待后端响应超时     -> 自动重试下一个 IP
//	5. 连接成功但首个响应不是合法的 TLS ServerHello 记录 -> 按连接失败处理，自动重试下一个 IP
//
// 上述单 IP 尝试会轮询两轮（对客户端完全透明，此时还没有任何数据发给客户端）：
//   - 第 1 轮：现有行为（直连或 Socks5 前置），每个 IP 的结果都会记录到 dnsRetryCache；
//   - 第 2 轮（仅当第 1 轮全部失败且配置了 AGAIN_PROXY 代理时）：对同一个排序后的候选列表
//     按同一顺序经代理再完整轮询一轮（探测握手也经代理拨号），
//     该轮的一切结果都不写入 dnsRetryCache，避免污染直连排序语义。
//
// 过程中的所有日志都通过连接上下文 c 输出（带 [#ID 域名] 前缀与 [连前]/[已连] 阶段标记），
// 且每条日志都带出口路径标签：第 1 轮为 “(直连)”/“(socks5)”（按 cfg.EnableSocks），第 2 轮为 “(AGAIN_PROXY)”。
// 两轮全部失败时返回 nil。
func dialBackendRetry(c *connCtx, host, port string, ips []net.IP, data []byte) *backendResult {
	// 排序后再对最终候选列表做一次防御性去重，保证 “第 N 个候选” 的编号与 IP 一一对应、无重复
	ordered := dedupeIPs(dnsRetryCacheInstance.orderIPs(host, ips))
	c.logf(stagePreConnect, 36, true, "候选IP顺序(共%d): %s", len(ordered), joinIPs(ordered))

	probeTimeout := verifyProbeTimeout() // 为 0 时表示不探测（verify_tls=false 等），完全保持旧行为

	// 第 1 轮：直连或 Socks5 前置（GetDialer(cfg.EnableSocks)），结果写入 dnsRetryCache（出口路径标签按 cfg.EnableSocks 取 直连/socks5）
	if res := dialBackendRound(c, host, port, ordered, data, GetDialer(cfg.EnableSocks), probeTimeout, round1Tag(), true); res != nil {
		return res
	}

	// 未配置 AGAIN_PROXY 代理时到此为止（保持原有失败路径，零改动行为）
	if envHTTPProxy == nil {
		return nil
	}

	// 第 2 轮：AGAIN_PROXY 代理回退轮询。
	// 必须复用第 1 轮最终的 ordered 列表的同一顺序（不得重新排序、去重或打乱），候选序号 (i/N) 按同一列表
	c.logf(stagePreConnect, 33, false, "直连轮询全部失败(共%d个), 开始 AGAIN_PROXY 代理轮询", len(ordered))
	proxyDialer := newHTTPProxyDialer(envHTTPProxy) // 连代理本身是直连 TCP（cfg.EnableSocks 只影响第 1 轮）
	return dialBackendRound(c, host, port, ordered, data, proxyDialer, probeTimeout, pathTagAgainProxy, false)
}

// dialBackendRound dialBackendRetry 的单轮实现：按给定顺序对候选列表完整轮询一轮，
// 每个 IP 的尝试步骤（TLS 验证探测 -> 拨号 -> 写握手数据 -> 等首字节 -> ServerHello 校验）保持一致，
// 任一步失败自动尝试下一个 IP，全部失败返回 nil。
//
//	d          本轮使用的拨号器（第 1 轮为 GetDialer(cfg.EnableSocks)，代理轮询为 httpProxyDialer）
//	roundTag   出口路径日志标签（第 1 轮为 "(直连)"/"(socks5)"，第 2 轮为 "(AGAIN_PROXY)"，插入在日志内容与候选序号之间以区分出口路径）
//	report     是否把每个 IP 的结果写入 dnsRetryCache（代理轮询必须传 false，避免污染直连排序语义）
func dialBackendRound(c *connCtx, host, port string, ordered []net.IP, data []byte, d proxy.Dialer, probeTimeout int, roundTag string, report bool) *backendResult {
	// 结果记录统一入口：代理轮询（report=false）不写缓存，stats 与 verify 缓存都不受影响
	record := func(ip net.IP, success bool) {
		if report {
			dnsRetryCacheInstance.reportResult(host, ip.String(), success)
		}
	}

	for i, ip := range ordered {
		addr := net.JoinHostPort(ip.String(), port)
		attempt := fmt.Sprintf("(%d/%d)", i+1, len(ordered))

		// 后端真实 TLS 验证：候选 IP 必须通过一次真实 TLS 握手（含完整证书校验）才算可用
		if probeTimeout > 0 {
			if report { // 第 1 轮：探测结果读写缓存（成功 10 分钟内复用、失败 60 秒内直接跳过）
				if r, hit := dnsRetryCacheInstance.getVerifyResult(host, ip.String()); !hit {
					// 未验证过（或缓存已过期）：先探测再连接
					if err := verifyBackendWithDialer(d, addr, host, probeTimeout); err != nil {
						// 验证失败按连接失败处理：记 fail、缓存失败结果，60 秒内不再探测该 IP
						dnsRetryCacheInstance.setVerifyResult(host, ip.String(), false, err.Error())
						record(ip, false)
						c.logf(stagePreConnect, 31, false, "后端验证失败%s%s: [%s], %v", roundTag, attempt, addr, err)
						continue
					}
					dnsRetryCacheInstance.setVerifyResult(host, ip.String(), true, "")
					c.logf(stagePreConnect, 32, false, "后端验证通过%s%s: [%s]", roundTag, attempt, addr)
				} else if !r.ok {
					// 60 秒内验证失败过的 IP 直接跳过，不再探测
					c.logf(stagePreConnect, 31, true, "后端验证失败(缓存)%s%s: [%s], %s, 跳过", roundTag, attempt, addr, r.reason)
					continue
				}
				// 验证通过（含 10 分钟内缓存命中），继续走下面的正常连接流程
			} else { // 代理轮询：探测握手经代理拨号，结果不读写验证缓存（代理链路的可用性与直连无关）
				if err := verifyBackendWithDialer(d, addr, host, probeTimeout); err != nil {
					c.logf(stagePreConnect, 31, false, "后端验证失败%s%s: [%s], %v", roundTag, attempt, addr, err)
					continue
				}
				c.logf(stagePreConnect, 32, false, "后端验证通过%s%s: [%s]", roundTag, attempt, addr)
			}
		}

		backend, err := dialWithDialer(d, "tcp", addr, cfg.DialTimeout)
		if err != nil { // 连接失败，记录结果并自动重试下一个 IP
			record(ip, false)
			c.logf(stagePreConnect, 31, false, "连接后端失败%s%s: [%s], %v", roundTag, attempt, addr, err)
			continue
		}

		if _, err := backend.Write(data); err != nil { // 发送握手数据失败，同样自动重试下一个 IP
			backend.Close()
			record(ip, false)
			c.logf(stagePreConnect, 31, false, "无法传输到后端%s%s: [%s], %v", roundTag, attempt, addr, err)
			continue
		}

		// 等待后端返回第一个响应字节（识别假死后端），提前读到的数据由调用方转发给客户端
		first, ok := peekFirstByte(backend, cfg.FirstByteTimeout)
		if !ok {
			backend.Close()
			record(ip, false)
			c.logf(stagePreConnect, 31, false, "后端无响应%s%s: [%s]", roundTag, attempt, addr)
			continue
		}

		// 校验首个响应是不是合法的 TLS 握手记录（识别“回了数据但不是正常 TLS 服务”的坏 IP）
		if probeTimeout > 0 && !isValidServerHello(first) {
			backend.Close()
			record(ip, false)
			c.logf(stagePreConnect, 31, false, "后端响应异常%s%s: [%s], 不是合法的 TLS ServerHello 记录", roundTag, attempt, addr)
			continue
		}

		// 连接成功，记录结果，下次优先使用该 IP（连接成功及之后的日志进入 [已连] 阶段）
		record(ip, true)
		c.logf(stageConnected, 32, false, "连接后端成功%s%s: [%s]", roundTag, attempt, addr)
		return &backendResult{conn: backend, first: first, ip: ip, index: i + 1, total: len(ordered), viaProxy: roundTag == pathTagAgainProxy}
	}
	return nil
}
