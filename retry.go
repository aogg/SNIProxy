package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ipStat 记录某个后端 IP 的历史连接结果，用于下次按“上次结果”排序转发
type ipStat struct {
	success     int       // 累计成功次数
	fail        int       // 累计失败次数
	consecFail  int       // 连续失败次数
	lastSuccess time.Time // 最近一次成功时间
	lastFail    time.Time // 最近一次失败时间
}

// dnsRetryCache 按“域名 -> IP -> 连接结果”存储 DNS 多 IP 自动重试的结果
// 这样下次连接同一域名时，可以优先使用上次成功过的 IP，把上次失败的 IP 排到最后
// 说明：结果只保存在内存中，重启后清零（DNS 记录本身会变化，持久化反而容易用到已失效的旧 IP）
type dnsRetryCache struct {
	mu    sync.Mutex
	stats map[string]map[string]*ipStat
}

// dnsRetryCache 全局唯一实例
var dnsRetryCacheInstance = &dnsRetryCache{stats: make(map[string]map[string]*ipStat)}

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

// cleanup 清理长时间没有连接记录的域名/IP（内存兜底，防止 allow_all_hosts 时无限增长）
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

// dialWithTimeout 带超时的拨号（直连、Socks5 前置代理均支持），单位：秒
func dialWithTimeout(network, addr string, timeoutSec int) (net.Conn, error) {
	d := GetDialer(cfg.EnableSocks)
	if timeoutSec > 0 {
		if cd, ok := d.(proxy.ContextDialer); ok { // 直连(*net.Dialer)和 SOCKS5 拨号器都实现了 DialContext
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
			defer cancel()
			return cd.DialContext(ctx, network, addr)
		}
	}
	return d.Dial(network, addr)
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

// dialBackendRetry 按“上次连接结果”排序后依次尝试连接 host 的所有候选 IP：
//  1. 连接某个 IP 失败（连接被拒/超时等）-> 自动重试下一个 IP
//  2. 连接成功但发送握手数据失败     -> 自动重试下一个 IP
//  3. 连接成功但等待后端响应超时     -> 自动重试下一个 IP
//
// 整个重试过程都在 SNIProxy 内部完成，对客户端完全透明（此时还没有任何数据发给客户端）。
// 每次尝试的结果都会记录到 dnsRetryCache，下次连接同一域名时按上次结果排序转发。
// 全部 IP 都失败时返回 nil。
func dialBackendRetry(host, port string, ips []net.IP, data []byte) (net.Conn, []byte) {
	ordered := dnsRetryCacheInstance.orderIPs(host, ips)
	serviceLogger(fmt.Sprintf("候选IP顺序: %s -> [%s]", host, joinIPs(ordered)), 36, true)

	for i, ip := range ordered {
		addr := net.JoinHostPort(ip.String(), port)
		attempt := fmt.Sprintf("(%d/%d)", i+1, len(ordered))

		backend, err := dialWithTimeout("tcp", addr, cfg.DialTimeout)
		if err != nil { // 连接失败，记录结果并自动重试下一个 IP
			dnsRetryCacheInstance.reportResult(host, ip.String(), false)
			serviceLogger(fmt.Sprintf("连接后端失败%s: [%s], %v", attempt, addr, err), 31, false)
			continue
		}

		if _, err := backend.Write(data); err != nil { // 发送握手数据失败，同样自动重试下一个 IP
			backend.Close()
			dnsRetryCacheInstance.reportResult(host, ip.String(), false)
			serviceLogger(fmt.Sprintf("无法传输到后端%s: [%s], %v", attempt, addr, err), 31, false)
			continue
		}

		// 等待后端返回第一个响应字节（识别假死后端），提前读到的数据由调用方转发给客户端
		first, ok := peekFirstByte(backend, cfg.FirstByteTimeout)
		if !ok {
			backend.Close()
			dnsRetryCacheInstance.reportResult(host, ip.String(), false)
			serviceLogger(fmt.Sprintf("后端无响应%s: [%s]", attempt, addr), 31, false)
			continue
		}

		// 连接成功，记录结果，下次优先使用该 IP
		dnsRetryCacheInstance.reportResult(host, ip.String(), true)
		serviceLogger(fmt.Sprintf("连接后端成功%s: [%s]", attempt, addr), 32, false)
		return backend, first
	}
	return nil, nil
}
