package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	version string // 编译时写入版本号

	ConfigFilePath string // 配置文件
	LogFilePath    string // 日志文件
	EnableDebug    bool   // 调试模式（详细日志）
	printVersion   bool   // 程序版本

	ForwardPort = 443       // 要转发至的目标端口
	cfg         configModel // 配置文件结构
)

// 连接级日志的阶段标记：区分日志发生在“连接后端成功前”还是“成功后”
const (
	stagePreConnect = "连前"   // 尚未与后端建立可用连接的阶段（连接来自/握手/SNI/白名单/DNS/安全拒绝/TLS验证/连接重试等）
	stageConnected  = "已连"   // 已成功连接后端及之后的阶段（连接后端成功/首包回写客户端/双向转发字节数等）
	stageTransfer   = "传输"   // 双向转发阶段的传输监视日志（进度/停滞检测）
	stageClose      = "结束"   // 连接结束总结日志（结束原因/总时长/双向字节）
	stageSniffFail  = "嗅探失败" // 嗅探失败/无域名连接的关闭日志（非TLS数据、无SNI等，非 debug 必出）
)

// connIDSeq 全局连接 ID 计数器（Accept 到连接时原子自增，从 1 开始）
var connIDSeq int64

// connCtx 连接上下文：在 Accept 到连接时创建，贯穿该连接整个生命周期，
// 用于给所有连接级日志统一加上 “连接 ID + 域名 + 阶段” 前缀，方便区分是哪个连接、哪个域名发出的请求
type connCtx struct {
	id      int64     // 连接 ID（全局唯一，从 1 开始递增，日志中显示为 #<id>）
	srcAddr string    // 客户端来源地址（host:port）
	host    string    // 域名（解析出 SNI/Host 之前为 "-" 占位）
	start   time.Time // 连接开始时间（Accept 时赋值，用于各阶段耗时与结束总结的总时长）
}

// newConnCtx 创建连接上下文（在 Accept 到连接时调用，为连接分配全局唯一 ID）
func newConnCtx(srcAddr string) *connCtx {
	return &connCtx{
		id:      atomic.AddInt64(&connIDSeq, 1),
		srcAddr: srcAddr,
		host:    "-",
		start:   time.Now(),
	}
}

// setHost 更新域名（解析出 SNI/Host 之后调用，仅在该连接的转发协程内更新）
func (c *connCtx) setHost(host string) {
	if host != "" {
		c.host = host
	}
}

// prefix 生成连接级日志前缀：[#42 域名]（域名未知时为 [#42 -]）
func (c *connCtx) prefix() string {
	return fmt.Sprintf("[#%d %s]", c.id, c.host)
}

// logf 输出一条连接级日志："[#42 域名] [阶段] 内容"
// 颜色/debug/写文件逻辑复用 serviceLogger，各日志行的级别与颜色语义保持不变
func (c *connCtx) logf(stage string, color int, isDebug bool, format string, v ...interface{}) {
	serviceLogger(c.prefix()+" ["+stage+"] "+fmt.Sprintf(format, v...), color, isDebug)
}

// logSniffFail 输出嗅探失败/无域名连接的关闭日志（非 debug 必出）：关闭原因 + 首字节安全预览 + 关闭动作，
// 让 "SSH-2.0-..." 这类非 TLS 流量在生产日志里一眼可辨（此前这些关闭点大多仅 debug 可见，线上表现为“悄无声息”）
func logSniffFail(c *connCtx, reason string, data []byte) {
	c.logf(stageSniffFail, 31, false, "%s 首字节:%s → 关闭连接", reason, safePreview(data, 64))
}

// safePreview 生成首字节的安全预览：可打印 ASCII 原样显示，控制字符/非 ASCII 转义为 \xHH，
// 最多取前 max 字节（超出以 " ..." 结尾），末尾附前 32 字节的 hex，便于辨认 SSH 等非 TLS 协议
func safePreview(data []byte, max int) string {
	// ////////////////  校验参数  start  ////////////////////////////////////////////////
	if len(data) == 0 {
		return `"" (空)`
	}
	preview := data
	if len(preview) > max {
		preview = preview[:max]
	}
	// ////////////////  校验参数  end ////////////////////////////////////////////////
	// ////////////////  核心逻辑  start  ////////////////////////////////////////////////
	var text strings.Builder
	for _, by := range preview {
		if by >= 0x20 && by <= 0x7E { // 可打印 ASCII 原样显示
			text.WriteByte(by)
		} else { // 控制字符等转义为 \xHH
			fmt.Fprintf(&text, "\\x%02X", by)
		}
	}
	if len(preview) < len(data) {
		text.WriteString(" ...")
	}
	hexPart := preview
	if len(hexPart) > 32 { // hex 摘要最多取前 32 字节，避免日志过长
		hexPart = hexPart[:32]
	}
	// ////////////////  核心逻辑  end ////////////////////////////////////////////////
	// ////////////////  返回  start  ////////////////////////////////////////////////
	return fmt.Sprintf("\"%s\" (hex: %s)", text.String(), hex.EncodeToString(hexPart))
	// ////////////////  返回  end ////////////////////////////////////////////////
}

// isTLSRecordHeader 判断数据开头是否符合 TLS 记录层特征（记录类型 20-23 且主版本号为 3），
// 用于在等待完整握手前快速辨认 SSH 等永远解析不出 SNI 的非 TLS 流量
func isTLSRecordHeader(data []byte) bool {
	return len(data) >= 2 && data[0] >= 20 && data[0] <= 23 && data[1] == 3
}

// 配置文件结构
type configModel struct {
	ForwardRules     []string `yaml:"rules,omitempty"`
	ListenAddr       string   `yaml:"listen_addr,omitempty"`
	ListenAddrHTTP   string   `yaml:"listen_addr_http,omitempty"`
	EnableSocks      bool     `yaml:"enable_socks5,omitempty"`
	SocksAddr        string   `yaml:"socks_addr,omitempty"`
	SocksUsername    string   `yaml:"socks_username,omitempty"`
	SocksPassword    string   `yaml:"socks_password,omitempty"`
	AllowAllHosts    bool     `yaml:"allow_all_hosts,omitempty"`
	DialTimeout      int      `yaml:"dial_timeout,omitempty"`       // 连接单个后端 IP 的超时时间（秒）
	FirstByteTimeout int      `yaml:"first_byte_timeout,omitempty"` // 等待后端响应第一个字节的超时时间（秒）
	VerifyTLS        *bool    `yaml:"verify_tls,omitempty"`         // 连接前是否用真实 TLS 握手验证候选 IP（指针是为了区分“未配置”，未配置时默认开启）
	AgainProxy       string   `yaml:"again_proxy,omitempty"`        // AGAIN_PROXY HTTP 回退代理（环境变量 AGAIN_PROXY 未设置或值非法时使用，值格式同环境变量）
	ProgressInterval *int     `yaml:"progress_interval,omitempty"`  // 传输进度日志间隔秒（指针是为了区分“未配置”，未配置时默认 10；显式 0=关闭进度日志）
	StallTimeout     *int     `yaml:"stall_timeout,omitempty"`      // 停滞判定秒（指针是为了区分“未配置”，未配置时默认 30；显式 0=关闭停滞检测）
}

func init() {
	var help = `
SNIProxy ` + version + `
https://github.com/XIU2/SNIProxy

参数：
    -c config.yaml
        配置文件 (默认 config.yaml)
    -l sni.log
        日志文件 (默认 无)
    -d
        调试模式 (默认 关)
    -v
        程序版本
    -h
        帮助说明
`
	flag.StringVar(&ConfigFilePath, "c", "config.yaml", "配置文件")
	flag.StringVar(&LogFilePath, "l", "", "日志文件")
	flag.BoolVar(&EnableDebug, "d", false, "调试模式")
	flag.BoolVar(&printVersion, "v", false, "程序版本")
	flag.Usage = func() { fmt.Print(help) }
}

// parseFlags 解析命令行参数（单独放出来、不放在 init() 里是为了能正常跑单元测试）
func parseFlags() {
	flag.Parse()
	if printVersion {
		fmt.Printf("XIU2/SNIProxy %s\n", version)
		os.Exit(0)
	}
}

func main() {
	parseFlags()

	data, err := os.ReadFile(ConfigFilePath) // 读取配置文件
	if err != nil {
		serviceLogger(fmt.Sprintf("配置文件读取失败: %v", err), 31, false)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		serviceLogger(fmt.Sprintf("配置文件解析失败: %v", err), 31, false)
		os.Exit(1)
	}
	if len(cfg.ForwardRules) <= 0 && !cfg.AllowAllHosts { // 如果 rules 为空且 allow_all_hosts 不等于 true
		serviceLogger("配置文件中 rules 不能为空（除非 allow_all_hosts 等于 true）!", 31, false)
		os.Exit(1)
	}
	if len(cfg.ListenAddr) <= 0 {
		cfg.ListenAddr = ":443" // 如果没有指定 listen_addr 则默认监听 443 端口
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 // 连接单个后端 IP 的默认超时时间（秒）
	}
	if cfg.FirstByteTimeout <= 0 {
		cfg.FirstByteTimeout = 5 // 等待后端响应第一个字节的默认超时时间（秒）
	}
	for _, rule := range cfg.ForwardRules { // 输出规则中的所有域名
		serviceLogger(fmt.Sprintf("加载规则: %v", rule), 32, false)
	}
	serviceLogger(fmt.Sprintf("调试模式: %v", EnableDebug), 32, false)
	serviceLogger(fmt.Sprintf("前置代理: %v", cfg.EnableSocks), 32, false)
	serviceLogger(fmt.Sprintf("任意域名: %v", cfg.AllowAllHosts), 32, false)
	verifyState := "关闭"
	if isVerifyTLSEnabled() && cfg.FirstByteTimeout > 0 {
		verifyState = fmt.Sprintf("开启, 探测超时: %d秒", cfg.FirstByteTimeout)
	}
	serviceLogger(fmt.Sprintf("DNS重试: 开启 (连接超时: %d秒, 首字节超时: %d秒, TLS验证: %s)", cfg.DialTimeout, cfg.FirstByteTimeout, verifyState), 32, false)

	// 传输进度/停滞检测：未配置时填充默认值（显式 0=关闭，负数与 0 同义按关闭处理）
	cfg.ProgressInterval = normalizeTransferInterval(cfg.ProgressInterval, defaultProgressInterval)
	cfg.StallTimeout = normalizeTransferInterval(cfg.StallTimeout, defaultStallTimeout)
	if *cfg.ProgressInterval <= 0 && *cfg.StallTimeout <= 0 {
		serviceLogger("传输日志: 已关闭 (↑=客户端→后端, ↓=后端→客户端)", 32, false)
	} else {
		serviceLogger(fmt.Sprintf("传输日志: 进度间隔 %ds, 停滞判定 %ds (↑=客户端→后端, ↓=后端→客户端)", *cfg.ProgressInterval, *cfg.StallTimeout), 32, false)
	}

	// AGAIN_PROXY HTTP 代理：启动时解析一次（环境变量 AGAIN_PROXY/again_proxy 优先，未设置或值非法时再用 config.yaml 的 again_proxy），
	// 仅作为“直连轮询全部失败后”的回退出口（解析规则与回退行为详见 httpproxy.go）
	envHTTPProxy = resolveAgainProxy(cfg.AgainProxy)
	if envHTTPProxy == nil {
		serviceLogger("AGAIN_PROXY: 未检测到", 32, false)
	} else if envHTTPProxy.Name == configAgainProxyName {
		serviceLogger(fmt.Sprintf("AGAIN_PROXY: 开启 (来源: config.yaml again_proxy, %s)", envHTTPProxy.maskedURL()), 32, false)
	} else {
		serviceLogger(fmt.Sprintf("AGAIN_PROXY: 开启 (来源: 环境变量 %s, %s)", envHTTPProxy.Name, envHTTPProxy.maskedURL()), 32, false)
	}

	startSniProxy() // 启动 SNI Proxy
}

// 启动 SNI Proxy
func startSniProxy() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dnsRetryCacheInstance.startJanitor(ctx) // 定期清理过期的 DNS 重试结果

	// 如果配置了 listen_addr_http，则启动 HTTP 监听（用于 301 重定向至 HTTPS）
	if cfg.ListenAddrHTTP != "" {
		listenerHTTP, err := net.Listen("tcp", cfg.ListenAddrHTTP)
		if err != nil {
			serviceLogger(fmt.Sprintf("监听失败(HTTP): %s -> %v", cfg.ListenAddrHTTP, err), 31, false)
			os.Exit(1)
		}
		serviceLogger(fmt.Sprintf("开始监听: %v", listenerHTTP.Addr()), 0, false)

		go func(listenerHTTP net.Listener) {
			defer listenerHTTP.Close()
			for {
				conn, err := listenerHTTP.Accept()
				if err != nil {
					serviceLogger(fmt.Sprintf("接受连接请求时出错(HTTP): %v", err), 31, false)
					continue
				}
				raddr := conn.RemoteAddr().(*net.TCPAddr)
				c := newConnCtx(raddr.String()) // 为连接分配全局唯一 ID
				c.logf(stagePreConnect, 32, false, "连接来自: [%s] 监听端口: [%d]", c.srcAddr, conn.LocalAddr().(*net.TCPAddr).Port)
				go handleHTTPRedirect(conn, c) // 有新连接进来，启动一个新线程处理
			}
		}(listenerHTTP)
	}

	// 启动 HTTPS 监听
	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		serviceLogger(fmt.Sprintf("监听失败(HTTPS): %s -> %v", cfg.ListenAddrHTTP, err), 31, false)
		os.Exit(1)
	}
	serviceLogger(fmt.Sprintf("开始监听: %v", listener.Addr()), 0, false)

	go func(listener net.Listener) {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				serviceLogger(fmt.Sprintf("接受连接请求时出错(HTTPS): %v", err), 31, false)
				continue
			}
			raddr := conn.RemoteAddr().(*net.TCPAddr)
			c := newConnCtx(raddr.String()) // 为连接分配全局唯一 ID
			c.logf(stagePreConnect, 32, false, "连接来自: [%s] 监听端口: [%d]", c.srcAddr, conn.LocalAddr().(*net.TCPAddr).Port)
			go serve(conn, c) // 有新连接进来，启动一个新线程处理
		}
	}(listener)

	// 收到终止信号时退出
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	s := <-ch
	cancel()
	fmt.Printf("\n接收到信号 %s, 退出.\n", s)
}

// 处理 HTTP 重定向至 HTTPS
func handleHTTPRedirect(conn net.Conn, c *connCtx) {
	defer conn.Close()
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		c.logf(stagePreConnect, 31, false, "读取连接请求时出错(HTTP): %v", err)
		return
	}
	data := string(buf[:n])
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		logSniffFail(c, "非HTTP数据(空请求)", buf[:n])
		return
	}
	// 解析请求行，获得路径
	reqLine := strings.Fields(lines[0])
	if len(reqLine) < 2 {
		logSniffFail(c, "HTTP请求行解析失败", buf[:n])
		return
	}
	path := reqLine[1]
	// 解析 Host，获得域名
	var host string
	for _, line := range lines[1:] {
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[5:])
			break
		}
	}
	// 如果没有 Host 或者 Host 为空，则不进行重定向，直接断开连接
	if host == "" {
		logSniffFail(c, "HTTP请求中未找到Host域名", buf[:n])
		return
	}
	c.setHost(host) // 域名已知，后续日志前缀带上域名

	if cfg.AllowAllHosts { // 如果 allow_all_hosts 为 true 则代表无需判断 http 域名
		sendHTTPRedirect(conn, c, host, path)
		return
	}
	// 白名单判定：先得出最终结果，未命中时每个连接只打一条日志（避免逐条规则重复打“忽略”）
	if !matchForwardRules(host) {
		c.logf(stagePreConnect, 31, false, "域名 %s 不在允许域名列表中, 忽略(http)...", host)
		return
	}
	sendHTTPRedirect(conn, c, host, path)
}

// 发送 301 跳转响应的函数
func sendHTTPRedirect(conn net.Conn, c *connCtx, host, path string) {
	// 生成 301 重定向响应
	location := "https://" + host + path
	resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nLocation: %s\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", location)
	c.logf(stagePreConnect, 34, false, "重定向至: %s", location)
	// 发送响应
	_, err := conn.Write([]byte(resp))
	if err != nil {
		c.logf(stagePreConnect, 31, false, "无法传输到后端(HTTP), %v", err)
	}
}

// matchForwardRules 判断域名是否命中转发规则白名单
// （例如 www.aa.com 中包含规则 aa.com 则命中）
func matchForwardRules(host string) bool {
	for _, rule := range cfg.ForwardRules {
		if strings.Contains(host, rule) {
			return true
		}
	}
	return false
}

// 处理 HTTPS 新连接
func serve(conn net.Conn, c *connCtx) {
	defer conn.Close()

	buf := make([]byte, 2048)
	var fullHeader []byte
	const maxAttempts = 2
	attempts := 0

	for {
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			c.logf(stagePreConnect, 31, false, "读取连接请求时出错(HTTPS): %v", err)
			return
		}
		fullHeader = append(fullHeader, buf[:n]...)

		// 首字节快速嗅探：不符合 TLS 记录特征的流量（如 SSH-2.0- 的 SSH 协议、明文 HTTP）永远解析不出 SNI，
		// 首次收到数据时立即输出一条嗅探失败日志便于辨认（仅判定一次；不改变原有等待/关闭行为，只补可观测性）
		if attempts == 0 && len(fullHeader) >= 2 && !isTLSRecordHeader(fullHeader) {
			c.logf(stageSniffFail, 31, false, "非TLS数据 首字节:%s (解析不出SNI, 继续等待)", safePreview(fullHeader, 64))
		}

		if len(fullHeader) < 5 { // 判断是不是 TLS 握手消息
			logSniffFail(c, "非TLS数据(不足5字节)", fullHeader)
			return
		} else if IsCompleteHandshake(fullHeader) { // 检查是否已经接收到完整的 TLS 握手消息
			break // 如果已经完整，那么退出循环
		}

		attempts++
		if attempts >= maxAttempts {
			logSniffFail(c, "接收握手消息超时(始终未收到完整TLS握手)", fullHeader)
			return // 如果超过最大等待次数，退出函数
		}
	}
	if attempts > 0 { // 如果等于 0 说明第一次就接收到了完整握手消息，如果大于 0 说明握手消息丢包或分段了
		c.logf(stagePreConnect, 32, true, "已接收到完整握手消息...")
	}

	ServerName := getSNIServerName(fullHeader, c) // 获取 SNI 域名

	if ServerName == "" {
		logSniffFail(c, "TLS握手中未找到SNI域名", fullHeader)
		return
	}
	c.setHost(ServerName) // 域名已知，后续日志前缀带上域名

	if !cfg.AllowAllHosts && !matchForwardRules(ServerName) {
		// 白名单判定：先得出最终结果，未命中时每个连接只打一条日志（避免逐条规则重复打“忽略”）
		c.logf(stagePreConnect, 31, false, "域名 %s 不在允许域名列表中, 忽略(https)...", ServerName)
		return
	}
	c.logf(stagePreConnect, 32, false, "转发目标: %s:%d", ServerName, ForwardPort)
	forward(conn, c, fullHeader, fmt.Sprintf("%s:%d", ServerName, ForwardPort))
}

// 判断握手消息是否完整
func IsCompleteHandshake(header []byte) bool {
	Length := binary.BigEndian.Uint16(header[3:5])
	return len(header) >= int(Length)+5
}

// 获取 SNI 域名
func getSNIServerName(buf []byte, c *connCtx) string {
	n := len(buf)
	if n < 5 {
		logSniffFail(c, "非TLS数据(不足5字节)", buf)
		return ""
	}

	// TLS 记录类型
	if recordType(buf[0]) != recordTypeHandshake {
		logSniffFail(c, fmt.Sprintf("非TLS数据(记录类型: %d)", buf[0]), buf)
		return ""
	}

	// TLS 主要版本
	if buf[1] != 3 {
		logSniffFail(c, fmt.Sprintf("不支持TLS版本<3(主版本: %d)", buf[1]), buf)
		return ""
	}

	// payload 长度
	//l := int(buf[3])<<16 + int(buf[4])
	//log.Printf("length: %d, got: %d", l, n)

	// 握手消息类型
	if buf[5] != typeClientHello {
		logSniffFail(c, fmt.Sprintf("不是ClientHello消息(握手类型: %d)", buf[5]), buf)
		return ""
	}

	// 以下开始解析 Client Hello 消息
	msg := &clientHelloMsg{}
	// Client Hello 不包含 TLS 标头, 5 字节
	ret := msg.unmarshal(buf[5:n])
	if !ret {
		logSniffFail(c, "解析ClientHello消息失败", buf)
		return ""
	}
	return msg.serverName
}

// forward 函数接收一个 net.Conn 类型的连接对象 conn、连接上下文 c、一个 []byte 类型的数据 data 和一个目标地址 dst
// 该函数先解析 dst 得到全部候选 IP（DNS 对同一域名可能返回多个 A/AAAA 记录），
// 再由 dialBackendRetry 按“上次连接结果”排序后依次尝试连接（开启 verify_tls 时会先用真实 TLS 握手验证候选 IP，
// 验证失败/连接失败会在内部自动重试下一个 IP，对客户端透明，
// 且每次结果都会记录下来，下次连接同一域名时优先使用上次成功的 IP），
// 连接成功后将 data 写入 backend，然后使用 ioReflector 函数将 backend 和 conn 连接起来，以便将数据从一个连接转发到另一个连接
// 字节转发日志会带上实际连接的后端 IP、该 IP 在候选列表中的序号与出口路径标签（由 dialBackendRetry 返回的 backendResult 提供）
func forward(conn net.Conn, c *connCtx, data []byte, dst string) {
	// 从 host:port 中提取 host，后续用于 DNS 解析与 IP 比较
	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		c.logf(stagePreConnect, 31, false, "目标地址格式错误(HTTPS): \"%s\", %v", dst, err)
		return
	}

	// 解析目标 host，拿到所有候选 IP（支持直接 IP 或域名）
	dnsStart := time.Now()
	ips, err := resolveHostIPs(host)
	if err != nil {
		c.logf(stagePreConnect, 31, false, "解析目标地址失败(HTTPS): \"%s\", %v", host, err)
		return
	}
	c.logf(stagePreConnect, 32, false, "DNS解析完成: %d 个IP, 耗时 %v", len(ips), time.Since(dnsStart))

	// 建立后端连接前先做安全检查，避免把流量再次传回本机导致死循环
	if blocked, reason := shouldBlockForwardIPs(ips, c.srcAddr); blocked {
		c.logf(stagePreConnect, 31, false, "拒绝转发(HTTPS): \"%s\", 目标: [%s], 来源: [%s]", reason, dst, c.srcAddr)
		return
	}

	// 按历史结果排序后依次尝试连接所有候选 IP（内部自动重试）
	res := dialBackendRetry(c, host, port, ips, data)
	if res == nil {
		c.logf(stagePreConnect, 31, false, "所有后端 IP 连接失败(HTTPS): [%s], 共尝试 %d 个", dst, len(ips))
		return
	}
	backend := res.conn
	defer backend.Close()

	// 连接后端已成功，后续日志进入 [已连] 阶段
	ts := newTransferStats()      // 双向字节计数与最后活动时间（传输监视与结束总结共用）
	closeInfo := &transferClose{} // 先结束方向的结束原因（仅第一次保存生效）

	if len(res.first) > 0 { // 把等待首字节时提前读到的后端响应，先发回给客户端
		if _, err := conn.Write(res.first); err != nil {
			c.logf(stageConnected, 31, false, "无法传输到客户端(HTTPS), %v", err)
			return
		}
		ts.addDown(int64(len(res.first))) // 首包回写的字节数手动计入 ↓ 后端→客户端 计数器
		c.logf(stageConnected, 33, true, "首包回写客户端%s: %d bytes, 距连接开始 %v", res.pathTag(), len(res.first), time.Since(c.start))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backendDesc := res.backendDesc(port) // 字节日志中展示实际后端 IP 与候选序号
	conChk := make(chan struct{})
	go ioReflector(ctx, backend, conn, false, conChk, c, backendDesc, ts, closeInfo)
	go ioReflector(ctx, conn, backend, true, conChk, c, backendDesc, ts, closeInfo)
	startTransferWatcher(ctx, c, backendDesc, ts, c.start) // 传输监视：进度/停滞日志，随 ctx 退出
	<-conChk
	// 取消上下文，通知另一个 ioReflector 退出
	cancel()

	// 连接结束总结（非 debug 必出）：先结束方向的原因 + 总时长 + 双向累计字节（正常断开绿色 32，带 error 红色 31）
	reason := closeInfo.get()
	color := 32 // 正常断开：绿色
	if reason.isError {
		color = 31 // 异常结束（带 error）：红色
	}
	c.logf(stageClose, color, false, "%s: 总时长 %v, ↑%s ↓%s, %s",
		reason.text, time.Since(c.start).Truncate(time.Second), humanBytes(ts.up()), humanBytes(ts.down()), backendDesc)
}

// shouldBlockForwardIPs 在建立后端连接前判断目标 IP 列表是否有问题（DNS 解析由调用方完成，避免重复解析）
func shouldBlockForwardIPs(targetIPs []net.IP, raddr string) (bool, string) {
	// 将来源地址转换为 IP，便于判断“目标 IP 和来源 IP 相同”的场景
	srcIP := extractIPFromAddr(raddr)

	// 获取本机所有网卡 IP（含回环），用于识别“目标是否本机”
	localIPs, err := collectLocalIPs()
	if err != nil {
		return true, fmt.Sprintf("获取本机地址失败: %v", err)
	}

	for _, targetIP := range targetIPs {
		// 命中回环/未指定地址（0.0.0.0、::）也视为会导致回流，直接拒绝
		if targetIP.IsLoopback() || targetIP.IsUnspecified() {
			return true, fmt.Sprintf("目标IP是本地保留地址: [%s]", targetIP.String())
		}

		// 如果目标IP属于本机任一网卡地址，说明会转发到自己，直接拒绝
		if isIPInList(targetIP, localIPs) {
			return true, fmt.Sprintf("目标IP是本机地址: [%s]", targetIP.String())
		}

		// 如果目标IP和来源IP相同，说明请求很可能会回流到发起端路径，直接拒绝
		if srcIP != nil && targetIP.Equal(srcIP) {
			return true, fmt.Sprintf("目标IP与来源IP相同: [%s]", targetIP.String())
		}
	}

	// 未命中风险规则时允许继续建立连接
	return false, ""
}

// resolveHostIPs 将 host 解析为 IP 列表；若 host 本身是 IP 则直接返回
func resolveHostIPs(host string) ([]net.IP, error) {
	// 目标是字面量 IP 时无需 DNS 查询
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	// 目标是域名时查询 A/AAAA 记录
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	ips = dedupeIPs(ips) // 去重（系统解析器可能将同一 IP 重复返回多次）
	if len(ips) == 0 {
		return nil, fmt.Errorf("未解析到任何IP")
	}
	return ips, nil
}

// dedupeIPs 对 IP 列表去重，保持首次出现的顺序
func dedupeIPs(ips []net.IP) []net.IP {
	seen := make(map[string]bool, len(ips))
	unique := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		key := ip.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, ip)
		}
	}
	return unique
}

// collectLocalIPs 收集本机网卡地址，供“目标是否本机IP”判断使用
func collectLocalIPs() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	// 使用 map 去重，避免同一 IP 在不同表示下重复比较
	ipSet := make(map[string]net.IP)
	for _, addr := range addrs {
		switch v := addr.(type) {
		case *net.IPNet:
			if v.IP != nil {
				ipSet[v.IP.String()] = v.IP
			}
		case *net.IPAddr:
			if v.IP != nil {
				ipSet[v.IP.String()] = v.IP
			}
		}
	}

	localIPs := make([]net.IP, 0, len(ipSet))
	for _, ip := range ipSet {
		localIPs = append(localIPs, ip)
	}
	//serviceLogger(fmt.Sprintf("本机网卡IP列表: %v", localIPs), 36, true)
	return localIPs, nil
}

// extractIPFromAddr 从 host:port 中提取 IP；无法解析时返回 nil
func extractIPFromAddr(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	return net.ParseIP(host)
}

// isIPInList 判断目标 IP 是否出现在给定 IP 列表中
func isIPInList(target net.IP, list []net.IP) bool {
	for _, ip := range list {
		if target.Equal(ip) {
			return true
		}
	}
	return false
}

// ioReflector 函数接收一个 io.WriteCloser 类型的写入对象 dst、一个 io.Reader 类型的读取对象 src、一个 bool 类型的 isToClient、
// 一个 chan struct{} 类型的 conChk、连接上下文 c、字节日志中使用的后端描述 backendDesc、
// 双向字节计数器 ts 与先结束方向的结束原因记录 closeInfo
// 该函数将 src 中读取到的数据流复制到 dst 中（手写拷贝循环 reflectorCopy，用于区分读/写错误并统计双向字节），
// 然后将结束原因保存到 closeInfo（仅先结束的方向生效），最后关闭 dst 连接，并向 conChk 通道发送一个信号以表示连接已关闭。
func ioReflector(ctx context.Context, dst io.WriteCloser, src io.Reader, isToClient bool, conChk chan struct{}, c *connCtx, backendDesc string, ts *transferStats, closeInfo *transferClose) {
	// 将 IO 流反映到另一个
	defer onDisconnect(dst, conChk)

	done := make(chan struct{})
	go func() {
		// 手写拷贝循环：分别记录读/写错误并统计双向字节
		written, reason := reflectorCopy(dst, src, ts, isToClient)
		// 保存结束原因（仅先结束的方向生效）
		closeInfo.save(reason)
		if isToClient {
			c.logf(stageConnected, 33, true, "%s -> [%s] %d bytes", backendDesc, c.srcAddr, written)
		} else {
			c.logf(stageConnected, 33, true, "[%s] -> %s %d bytes", c.srcAddr, backendDesc, written)
		}
		close(done)
	}()

	select {
	case <-ctx.Done():
		// 上下文取消，退出
	case <-done:
		// 复制完成，退出
	}
}

// onDisconnect 函数接收一个 io.WriteCloser 类型的写入对象 dst 和一个 chan struct{} 类型的 conChk
// 该函数在 dst 连接关闭时被调用，并向 conChk 通道发送一个信号以表示连接已关闭
func onDisconnect(dst io.WriteCloser, conChk chan struct{}) {
	// 关闭时 -> 强制断开另一对连接
	dst.Close()
	select {
	case conChk <- struct{}{}:
	default:
	}
}

// 解析 Client Hello 消息
func (m *clientHelloMsg) unmarshal(data []byte) bool {
	if len(data) < 42 {
		return false
	}
	m.raw = data
	m.vers = uint16(data[4])<<8 | uint16(data[5])
	m.random = data[6:38]
	sessionIDLen := int(data[38])
	if sessionIDLen > 32 || len(data) < 39+sessionIDLen {
		return false
	}
	m.sessionID = data[39 : 39+sessionIDLen]
	data = data[39+sessionIDLen:]
	if len(data) < 2 {
		return false
	}
	// cipherSuiteLen 是密码套件编号的字节数。由于是 uint16，因此数字必须是偶数
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if cipherSuiteLen%2 == 1 || len(data) < 2+cipherSuiteLen {
		return false
	}
	numCipherSuites := cipherSuiteLen / 2
	m.cipherSuites = make([]uint16, numCipherSuites)
	for i := 0; i < numCipherSuites; i++ {
		m.cipherSuites[i] = uint16(data[2+2*i])<<8 | uint16(data[3+2*i])
		if m.cipherSuites[i] == scsvRenegotiation {
			m.secureRenegotiationSupported = true
		}
	}
	data = data[2+cipherSuiteLen:]
	if len(data) < 1 {
		return false
	}
	compressionMethodsLen := int(data[0])
	if len(data) < 1+compressionMethodsLen {
		return false
	}
	m.compressionMethods = data[1 : 1+compressionMethodsLen]

	data = data[1+compressionMethodsLen:]

	m.nextProtoNeg = false
	m.serverName = ""
	m.ocspStapling = false
	m.ticketSupported = false
	m.sessionTicket = nil
	m.signatureAndHashes = nil
	m.alpnProtocols = nil
	m.scts = false

	if len(data) == 0 {
		// ClientHello 后面可选地跟着扩展数据
		return true
	}
	if len(data) < 2 {
		return false
	}

	extensionsLength := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if extensionsLength != len(data) {
		return false
	}

	for len(data) != 0 {
		if len(data) < 4 {
			return false
		}
		extension := uint16(data[0])<<8 | uint16(data[1])
		length := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < length {
			return false
		}

		switch extension {
		case extensionServerName:
			d := data[:length]
			if len(d) < 2 {
				return false
			}
			namesLen := int(d[0])<<8 | int(d[1])
			d = d[2:]
			if len(d) != namesLen {
				return false
			}
			for len(d) > 0 {
				if len(d) < 3 {
					return false
				}
				nameType := d[0]
				nameLen := int(d[1])<<8 | int(d[2])
				d = d[3:]
				if len(d) < nameLen {
					return false
				}
				if nameType == 0 {
					m.serverName = string(d[:nameLen])
					// SNI 值末尾不能有点
					if strings.HasSuffix(m.serverName, ".") {
						return false
					}
					break
				}
				d = d[nameLen:]
			}
		case extensionNextProtoNeg:
			if length > 0 {
				return false
			}
			m.nextProtoNeg = true
		case extensionStatusRequest:
			m.ocspStapling = length > 0 && data[0] == statusTypeOCSP
		case extensionSupportedCurves:
			// http://tools.ietf.org/html/rfc4492#section-5.5.1
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l%2 == 1 || length != l+2 {
				return false
			}
			numCurves := l / 2
			m.supportedCurves = make([]CurveID, numCurves)
			d := data[2:]
			for i := 0; i < numCurves; i++ {
				m.supportedCurves[i] = CurveID(d[0])<<8 | CurveID(d[1])
				d = d[2:]
			}
		case extensionSupportedPoints:
			// http://tools.ietf.org/html/rfc4492#section-5.5.2
			if length < 1 {
				return false
			}
			l := int(data[0])
			if length != l+1 {
				return false
			}
			m.supportedPoints = make([]uint8, l)
			copy(m.supportedPoints, data[1:])
		case extensionSessionTicket:
			// http://tools.ietf.org/html/rfc5077#section-3.2
			m.ticketSupported = true
			m.sessionTicket = data[:length]
		case extensionSignatureAlgorithms:
			// https://tools.ietf.org/html/rfc5246#section-7.4.1.4.1
			if length < 2 || length&1 != 0 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			n := l / 2
			d := data[2:]
			m.signatureAndHashes = make([]signatureAndHash, n)
			for i := range m.signatureAndHashes {
				m.signatureAndHashes[i].hash = d[0]
				m.signatureAndHashes[i].signature = d[1]
				d = d[2:]
			}
		case extensionRenegotiationInfo:
			if length == 0 {
				return false
			}
			d := data[:length]
			l := int(d[0])
			d = d[1:]
			if l != len(d) {
				return false
			}

			m.secureRenegotiation = d
			m.secureRenegotiationSupported = true
		case extensionALPN:
			if length < 2 {
				return false
			}
			l := int(data[0])<<8 | int(data[1])
			if l != length-2 {
				return false
			}
			d := data[2:length]
			for len(d) != 0 {
				stringLen := int(d[0])
				d = d[1:]
				if stringLen == 0 || stringLen > len(d) {
					return false
				}
				m.alpnProtocols = append(m.alpnProtocols, string(d[:stringLen]))
				d = d[stringLen:]
			}
		case extensionSCT:
			m.scts = true
			if length != 0 {
				return false
			}
		}
		data = data[length:]
	}

	return true
}

// 输出日志
func serviceLogger(log string, color int, isDebug bool) {
	if isDebug && !EnableDebug {
		return
	}
	log = strings.Replace(log, "\n", "", -1)
	log = strings.Join([]string{time.Now().Format("2006/01/02 15:04:05"), " ", log}, "")
	if color == 0 {
		fmt.Printf("%s\n", log)
	} else {
		fmt.Printf("%c[1;0;%dm%s%c[0m\n", 0x1B, color, log, 0x1B)
	}
	if LogFilePath != "" {
		fd, _ := os.OpenFile(LogFilePath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		fdContent := strings.Join([]string{log, "\n"}, "")
		buf := []byte(fdContent)
		fd.Write(buf)
		fd.Close()
	}
}
