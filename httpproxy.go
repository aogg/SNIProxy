package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// 环境变量 HTTP 代理（仅作为“直连轮询全部失败后”的回退出口）：
//   1. 启动时按优先级取第一个非空的代理环境变量（HTTPS_PROXY → https_proxy → HTTP_PROXY → http_proxy → ALL_PROXY → all_proxy）；
//   2. 值仅接受 http:// 或无 scheme（无 scheme 视为 http://），支持 user:pass@host[:port]（CONNECT 时加 Proxy-Authorization: Basic），port 缺省 80；
//   3. 其他 scheme（如 socks5://）或解析失败：启动日志 warn 一条后忽略（等同无 env 代理），不影响正常运行；
//   4. 代理轮询对“第一轮排序后的同一个候选列表”按同一顺序再完整轮询一轮，结果不写入 dnsRetryCache。
// 说明：不做 NO_PROXY 支持；cfg.EnableSocks（Socks5 前置）只影响第一轮，连 HTTP 代理本身始终是直连 TCP。

// envProxyNames 依次探测的代理环境变量（按优先级从高到低，取第一个非空值）
var envProxyNames = []string{
	"HTTPS_PROXY", "https_proxy",
	"HTTP_PROXY", "http_proxy",
	"ALL_PROXY", "all_proxy",
}

// envProxyLookup 可注入的环境变量查询函数（默认 os.LookupEnv，便于将来单元测试）
var envProxyLookup = os.LookupEnv

// envHTTPProxy 启动时解析到的环境变量 HTTP 代理（未检测到、或值非法被忽略时为 nil）
var envHTTPProxy *httpProxyAddr

// httpProxyAddr 解析后的环境变量 HTTP 代理地址
type httpProxyAddr struct {
	Name string // 实际命中的环境变量名（如 HTTPS_PROXY，用于启动日志）
	Host string // 代理主机
	Port string // 代理端口（未填写时缺省 80）
	User string // 认证用户名（可空）
	Pass string // 认证密码（可空）
}

// addr 返回代理的 host:port 形式地址
func (p *httpProxyAddr) addr() string {
	return net.JoinHostPort(p.Host, p.Port)
}

// maskedURL 生成打码后的展示地址（userinfo 中的密码以 *** 代替，避免泄漏到日志），
// 如：http://user:***@127.0.0.1:8080
func (p *httpProxyAddr) maskedURL() string {
	s := "http://"
	if p.User != "" || p.Pass != "" {
		s += p.User + ":***@"
	}
	return s + p.addr()
}

// parseEnvHTTPProxy 按优先级取第一个非空的代理环境变量并解析，返回 nil 表示“无可用代理”。
// 取值为首个非空的变量（不再继续尝试低优先级变量），其 scheme 不支持或解析失败时
// warn 一条后按“未检测到”处理（等同无 env 代理），不影响正常运行。
func parseEnvHTTPProxy() *httpProxyAddr {
	for _, name := range envProxyNames {
		val, ok := envProxyLookup(name)
		if !ok || strings.TrimSpace(val) == "" {
			continue
		}
		p, err := parseHTTPProxyValue(name, strings.TrimSpace(val))
		if err != nil {
			serviceLogger(fmt.Sprintf("环境变量代理: %s=%s 的值无法使用(%v), 已忽略, 等同未配置", name, maskProxyRaw(val), err), 33, false)
			return nil
		}
		return p
	}
	return nil
}

// parseHTTPProxyValue 解析单个环境变量的值：仅接受 http:// 或无 scheme（无 scheme 视为 http://），
// 支持 user:pass@host[:port]（port 缺省 80）；其他 scheme 或格式非法时返回错误。
func parseHTTPProxyValue(name, raw string) (*httpProxyAddr, error) {
	val := raw
	if !strings.Contains(strings.ToLower(val), "://") {
		val = "http://" + val // 无 scheme 视为 http://
	}
	u, err := url.Parse(val)
	if err != nil {
		return nil, fmt.Errorf("无法解析: %v", err)
	}
	if strings.ToLower(u.Scheme) != "http" {
		return nil, fmt.Errorf("不支持的 scheme %q (仅支持 http 代理)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("缺少代理主机地址")
	}
	port := u.Port()
	if port == "" {
		port = "80" // port 缺省 80
	}
	p := &httpProxyAddr{Name: name, Host: host, Port: port}
	if u.User != nil {
		p.User = u.User.Username()
		p.Pass, _ = u.User.Password()
	}
	return p, nil
}

// maskProxyRaw 尽力打码原始值中的 userinfo（仅用于无法解析时的 warn 日志展示），
// 如 "http://user:pass@host:port" -> "http://***@host:port"
func maskProxyRaw(val string) string {
	rest := val
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		return val[:len(val)-len(rest)] + "***@" + rest[i+1:]
	}
	return val
}

// 编译期检查：httpProxyDialer 同时实现 proxy.Dialer 与 proxy.ContextDialer
var (
	_ proxy.Dialer        = (*httpProxyDialer)(nil)
	_ proxy.ContextDialer = (*httpProxyDialer)(nil)
)

// httpProxyDialer 通过环境变量指定的 HTTP 代理建立 CONNECT 隧道的拨号器
// （手写 HTTP CONNECT，不引入新依赖；连代理本身始终是直连 TCP，不受 Socks5 前置影响）
type httpProxyDialer struct {
	addr string // 代理地址 host:port
	auth string // Base64 编码的 Proxy-Authorization 值（无认证信息时为空）
}

// newHTTPProxyDialer 根据解析后的环境变量代理构造拨号器
func newHTTPProxyDialer(p *httpProxyAddr) *httpProxyDialer {
	d := &httpProxyDialer{addr: p.addr()}
	if p.User != "" || p.Pass != "" { // 支持账号密码认证（CONNECT 时加 Proxy-Authorization 头）
		d.auth = base64.StdEncoding.EncodeToString([]byte(p.User + ":" + p.Pass))
	}
	return d
}

// Dial 实现 proxy.Dialer（无超时控制，实际调用方均走 DialContext）
func (d *httpProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext 实现 proxy.ContextDialer：
// “TCP 连代理 + 发 CONNECT + 收完应答头”整体受 ctx 的 deadline 约束（调用方按 dial_timeout 设置），
// 隧道建立成功后清除该 deadline，后续读写交由调用方的首字节超时与转发逻辑控制。
func (d *httpProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("HTTP 代理不支持的网络类型: %s", network)
	}
	// 直连 TCP 到代理本身
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, fmt.Errorf("连接代理失败: %v", err)
	}
	// 让整个 CONNECT 阶段（含读应答头）受同一 deadline 约束
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			conn.Close()
			return nil, fmt.Errorf("设置超时失败: %v", err)
		}
	}

	// 组装并发送 CONNECT 请求
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if d.auth != "" {
		req += "Proxy-Authorization: Basic " + d.auth + "\r\n"
	}
	req += "\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("发送 CONNECT 请求失败: %v", err)
	}

	// 逐字节读取代理应答头（读到 "\r\n\r\n" 为止）：逐字节是为了避免 bufio 预读
	// 把隧道里紧随应答头的后端 TLS 数据一并缓冲走（那部分数据必须留给调用方）
	head, err := readProxyResponseHead(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("读取代理应答失败: %v", err)
	}

	// 应答头读取完毕，清除整体 deadline
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("清除超时失败: %v", err)
	}

	// 校验状态行（如 "HTTP/1.1 200 Connection established"），非 200 视为隧道建立失败
	statusLine := head
	if idx := strings.IndexByte(head, '\n'); idx >= 0 {
		statusLine = strings.TrimRight(head[:idx], "\r")
	}
	fields := strings.Fields(statusLine)
	if len(fields) < 2 || fields[1] != "200" {
		conn.Close()
		return nil, fmt.Errorf("代理CONNECT失败: %s", statusLine)
	}
	return conn, nil
}

// readProxyResponseHead 从连接中读取一份完整的 HTTP 应答头（含结尾的空行 "\r\n\r\n"）
func readProxyResponseHead(conn net.Conn) (string, error) {
	const maxHeadSize = 8 * 1024 // 应答头大小上限（防御代理异常返回超大内容）
	var head []byte
	buf := make([]byte, 1)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			head = append(head, buf[0])
			if len(head) > maxHeadSize {
				return "", fmt.Errorf("代理应答头超过 %d 字节", maxHeadSize)
			}
			if len(head) >= 4 && string(head[len(head)-4:]) == "\r\n\r\n" {
				return string(head), nil
			}
		}
		if err != nil {
			return "", err
		}
	}
}
