package main

import (
	"context"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// 传输日志配置默认值（config.yaml 未配置时使用）
const (
	defaultProgressInterval = 10 // 进度日志默认间隔（秒）
	defaultStallTimeout     = 30 // 停滞检测默认时长（秒）
	defaultStuckTimeout     = 3  // 卡顿检测默认时长（秒）
)

// downloadBytesThreshold 疑似下载的 ↓ 累计字节阈值（1MB）：
// ↓ 后端→客户端 累计达到该值视为客户端可能在下载大文件，卡顿日志降级为黄色提示（而非红色告警）
const downloadBytesThreshold int64 = 1 << 20

// transferStats 连接双向字节计数
// （int64 + sync/atomic 包函数实现并发安全，兼容 go1.18，不使用 go1.19+ 才有的 atomic 类型）
type transferStats struct {
	upBytes    int64 // ↑ 客户端→后端 累计成功写出的字节数
	downBytes  int64 // ↓ 后端→客户端 累计成功写出的字节数
	upActive   int64 // ↑ 方向最后活动时间（UnixNano，读或写成功都算该方向活动）
	downActive int64 // ↓ 方向最后活动时间（UnixNano）
}

// newTransferStats 创建双向计数器（两个方向的最后活动时间初始化为当前时间，作为停滞检测的起点）
func newTransferStats() *transferStats {
	now := time.Now().UnixNano()
	return &transferStats{upActive: now, downActive: now}
}

// addUp 记录 ↑ 方向成功写出的字节数并刷新该方向的最后活动时间（并发安全）
func (t *transferStats) addUp(n int64) {
	atomic.AddInt64(&t.upBytes, n)
	atomic.StoreInt64(&t.upActive, time.Now().UnixNano())
}

// addDown 记录 ↓ 方向成功写出的字节数并刷新该方向的最后活动时间（并发安全）
func (t *transferStats) addDown(n int64) {
	atomic.AddInt64(&t.downBytes, n)
	atomic.StoreInt64(&t.downActive, time.Now().UnixNano())
}

// up 返回 ↑ 方向累计字节数
func (t *transferStats) up() int64 {
	return atomic.LoadInt64(&t.upBytes)
}

// down 返回 ↓ 方向累计字节数
func (t *transferStats) down() int64 {
	return atomic.LoadInt64(&t.downBytes)
}

// upLastActive 返回 ↑ 方向最后活动时间
func (t *transferStats) upLastActive() time.Time {
	return time.Unix(0, atomic.LoadInt64(&t.upActive))
}

// downLastActive 返回 ↓ 方向最后活动时间
func (t *transferStats) downLastActive() time.Time {
	return time.Unix(0, atomic.LoadInt64(&t.downActive))
}

// lastActive 返回两个方向中较晚的最后活动时间（即“最后数据”时间）
func (t *transferStats) lastActive() time.Time {
	u, d := t.upLastActive(), t.downLastActive()
	if d.After(u) {
		return d
	}
	return u
}

// transferCloseReason 连接结束原因
type transferCloseReason struct {
	text    string // 结束原因文案（如 客户端断开 / 读取后端失败: xxx）
	isError bool   // 是否异常结束（true=带 error 用红色日志，false=正常断开用绿色日志）
}

// transferClose 保存先结束方向的结束原因
type transferClose struct {
	mu     sync.Mutex
	reason transferCloseReason // 先结束方向的结束原因
	saved  bool                // 是否已保存（仅第一次保存生效）
}

// save 保存结束原因（并发安全，仅第一次保存生效，保证结束总结记录的是先结束的方向）
func (t *transferClose) save(reason transferCloseReason) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.saved {
		return
	}
	t.saved = true
	t.reason = reason
}

// get 读取结束原因（尚未保存过时返回兜底文案）
func (t *transferClose) get() transferCloseReason {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.saved {
		return transferCloseReason{text: "连接关闭"}
	}
	return t.reason
}

// normalizeTransferInterval 规范化传输日志间隔配置：未配置(nil)填默认值，负数归为 0（关闭）
func normalizeTransferInterval(v *int, def int) *int {
	// ////////////////  核心逻辑  start  ////////////////////////////////////////////////
	if v == nil {
		return &def
	}
	if *v < 0 {
		zero := 0
		return &zero
	}
	return v
	// ////////////////  核心逻辑  end ////////////////////////////////////////////////
}

// humanBytes 字节数人性化：B/KB/MB/GB，一位小数（如 1412B、89.2MB）
func humanBytes(n int64) string {
	// ////////////////  核心逻辑  start  ////////////////////////////////////////////////
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	value := float64(n)
	for _, suffix := range [...]string{"KB", "MB", "GB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	// ////////////////  核心逻辑  end ////////////////////////////////////////////////
	return fmt.Sprintf("%.1fTB", value/unit) // 超过 GB 继续按 TB 展示
}

// isLikeDownload 判断该连接是否疑似下载：↓ 后端→客户端 累计字节达到 downloadBytesThreshold(1MB) 即视为疑似下载
func isLikeDownload(down int64) bool {
	return down >= downloadBytesThreshold
}

// stuckClientAbandonCloseReason 判断连接结束是否属于“客户端在停滞期间放弃等待”：
// 改写条件（全部满足才改写）：卡顿检测开启(stuckTimeout>0)、结束原因是不带 error 的“客户端断开”（精确匹配）、
// 结束时距最后数据（lastActive）已停滞 ≥ stuck_timeout、且 ↓ 累计未达疑似下载阈值（下载中的客户端断开是正常行为）。
// 命中时把结束原因改写为带实际停滞时长与 ↓ 累计量的异常文案（isError=true，结束总结随之变红），
// 便于在生产日志里区分“客户端正常用完断开”与“连接卡死后客户端放弃”。
// 纯函数（不含 IO），返回改写后的原因与是否改写（未命中时原样返回），方便单元测试
func stuckClientAbandonCloseReason(reason transferCloseReason, ts *transferStats, stuckTimeout time.Duration, now time.Time) (transferCloseReason, bool) {
	// ////////////////  校验参数  start  ////////////////////////////////////////////////
	if stuckTimeout <= 0 || reason.isError || reason.text != "客户端断开" {
		return reason, false // 检测关闭 / 异常结束（读写出错等）/ 非客户端断开（如 后端断开），保持原样
	}
	// ////////////////  校验参数  end ////////////////////////////////////////////////
	// ////////////////  核心逻辑  start  ////////////////////////////////////////////////
	stallFor := now.Sub(ts.lastActive()) // 结束时的实际停滞时长（距最后任一方向活动）
	if stallFor < stuckTimeout {
		return reason, false // 停滞不足卡顿判定时长，视为客户端正常断开
	}
	down := ts.down()
	if down >= downloadBytesThreshold {
		return reason, false // 疑似下载中的客户端断开（下载完成/用户取消）不改写
	}
	// ////////////////  核心逻辑  end ////////////////////////////////////////////////
	// ////////////////  返回  start  ////////////////////////////////////////////////
	return transferCloseReason{
		text:    fmt.Sprintf("客户端断开(停滞 %v 期间客户端放弃, ↓%s)", stallFor.Truncate(time.Second), humanBytes(down)),
		isError: true, // 结束总结随之变红
	}, true
	// ////////////////  返回  end ////////////////////////////////////////////////
}

// startTransferWatcher 启动传输监视 goroutine（进度/停滞/卡顿日志），三项检测都关闭时不启动
func startTransferWatcher(ctx context.Context, c *connCtx, backendDesc string, ts *transferStats, start time.Time) {
	// ////////////////  校验参数  start  ////////////////////////////////////////////////
	progressInterval := time.Duration(*cfg.ProgressInterval) * time.Second // 进度日志间隔（main 已填充默认值，0=关闭）
	stallTimeout := time.Duration(*cfg.StallTimeout) * time.Second         // 停滞判定时长（tier2，main 已填充默认值，0=关闭）
	stuckTimeout := time.Duration(*cfg.StuckTimeout) * time.Second         // 卡顿判定时长（tier1，main 已填充默认值，0=关闭）
	if progressInterval <= 0 && stallTimeout <= 0 && stuckTimeout <= 0 {
		return // 进度、停滞与卡顿检测均已关闭，不启动监视
	}
	// ////////////////  校验参数  end ////////////////////////////////////////////////
	go transferWatcher(ctx, c, backendDesc, ts, start, progressInterval, stallTimeout, stuckTimeout)
}

// transferWatcher 传输监视循环：每秒 tick 一次，按配置输出进度日志（青色 36）、
// 卡顿日志（tier1：红色 31，疑似下载改黄色 33，stuck_timeout=0 时本层整体关闭）与停滞日志（tier2：黄色 33），
// 卡顿/停滞恢复时输出对应的解除日志，随 ctx.Done 退出
func transferWatcher(ctx context.Context, c *connCtx, backendDesc string, ts *transferStats, start time.Time, progressInterval, stallTimeout, stuckTimeout time.Duration) {
	// ////////////////  准备数据  start  ////////////////////////////////////////////////
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var (
		lastUp, lastDown int64     // 上次进度日志时的双向累计字节（用于计算窗口速率与新增字节判定）
		lastProgress     time.Time // 上次进度日志时间（零值时以连接开始时间为基准）
		stalling         bool      // 是否处于停滞状态（tier2，停滞期间不再输出进度日志）
		lastStallLog     time.Time // 上次停滞日志时间（用于每隔 stall_timeout 重复输出一次）
		stucking         bool      // 是否处于卡顿状态（tier1，独立于停滞 tier2 的状态机）
		lastStuckLog     time.Time // 上次卡顿日志时间（用于每隔 stuck_timeout 重复输出一次）
		stuckStart       time.Time // 本次卡顿的数据停止时刻（首次触发时记录，卡顿解除时用于计算实际停滞时长）
	)

	// logProgress 输出一条进度日志并推进进度窗口基准（累计量、相对上次进度日志的窗口速率、距连接开始时长）
	logProgress := func(now time.Time, up, down int64) {
		window := now.Sub(lastProgress).Seconds()
		if window <= 0 {
			window = 1 // 防御同一时刻重复输出时除零
		}
		c.logf(stageTransfer, 36, false, "进度 ↑%s ↓%s (速率 ↑%s/s ↓%s/s) 已运行 %v %s",
			humanBytes(up), humanBytes(down),
			humanBytes(int64(float64(up-lastUp)/window)), humanBytes(int64(float64(down-lastDown)/window)),
			time.Since(start).Truncate(time.Second), backendDesc)
		lastUp, lastDown, lastProgress = up, down, now
	}

	// logStuck 输出一条卡顿日志（tier1，非 debug 必出）：非疑似下载红色 31 告警、疑似下载黄色 33 提示，
	// noData 为日志展示的“无数据时长”（首次触发传配置的 stuck_timeout，重复时传实际 stallFor，对齐停滞日志重复模式）
	logStuck := func(noData time.Duration, up, down int64) {
		if isLikeDownload(down) {
			c.logf(stageTransfer, 33, false, "卡顿 %v 无数据: ↑%s ↓%s, 最后数据 %s, 疑似下载:是(↓%s), 已运行 %v, %s",
				noData, humanBytes(up), humanBytes(down), ts.lastActive().Format("15:04:05"), humanBytes(ts.down()),
				time.Since(start).Truncate(time.Second), backendDesc)
			return
		}
		c.logf(stageTransfer, 31, false, "卡顿 %v 无数据: ↑%s ↓%s, 最后数据 %s, 疑似下载:否, 已运行 %v, %s",
			noData, humanBytes(up), humanBytes(down), ts.lastActive().Format("15:04:05"),
			time.Since(start).Truncate(time.Second), backendDesc)
	}
	// ////////////////  准备数据  end ////////////////////////////////////////////////

	for {
		select {
		case <-ctx.Done():
			// 上下文取消（连接已结束），监视退出
			return
		case <-ticker.C:
		}

		// ////////////////  核心逻辑  start  ////////////////////////////////////////////////
		up, down := ts.up(), ts.down()
		now := time.Now()

		// 停滞时长 = 距最后任一方向活动（两方向距最后活动均 ≥ stall_timeout 等价于它 ≥ stall_timeout）
		stallFor := now.Sub(ts.lastActive())

		// 停滞检测：两个方向连续无数据达到 stall_timeout
		if stallTimeout > 0 && stallFor >= stallTimeout {
			if !stalling { // 首次停滞：输出一条（展示配置的判定时长），之后每隔 stall_timeout 重复
				stalling = true
				lastStallLog = now
				c.logf(stageTransfer, 33, false, "停滞 %v 无数据: ↑%s ↓%s, 最后数据 %s, %s",
					stallTimeout, humanBytes(up), humanBytes(down), ts.lastActive().Format("15:04:05"), backendDesc)
				// 重置进度窗口基准：恢复后的进度日志只统计恢复后的新增数据
				lastUp, lastDown, lastProgress = up, down, now
			} else if now.Sub(lastStallLog) >= stallTimeout { // 重复停滞日志：把判定时长换成实际持续时长
				lastStallLog = now
				c.logf(stageTransfer, 33, false, "停滞 %v 无数据: ↑%s ↓%s, 最后数据 %s, %s",
					stallFor.Truncate(time.Second), humanBytes(up), humanBytes(down), ts.lastActive().Format("15:04:05"), backendDesc)
			}
			continue // 停滞期间不再输出进度日志
		}

		// 卡顿检测（tier1）：两个方向连续无数据达到 stuck_timeout（先判停滞 tier2，tier2 未命中才轮到本层；
		// stuck_timeout=0 时本层整体关闭，行为与无卡顿检测时完全一致）
		if stuckTimeout > 0 && stallFor >= stuckTimeout {
			if !stucking { // 首次卡顿：输出一条（展示配置的判定时长），之后每隔 stuck_timeout 重复一次
				stucking = true
				lastStuckLog = now
				stuckStart = ts.lastActive() // 记录数据停止时刻，卡顿解除时据此计算实际停滞时长
				logStuck(stuckTimeout, up, down)
			} else if now.Sub(lastStuckLog) >= stuckTimeout { // 重复卡顿日志：把判定时长换成实际持续时长
				lastStuckLog = now
				logStuck(stallFor.Truncate(time.Second), up, down)
			}
			continue // 卡顿期间不再输出进度日志
		}

		// 卡顿恢复：卡顿日志输出过、之后有新数据到达（stallFor < stuck_timeout），
		// 输出一条解除日志（带实际停滞时长）后不 continue，正常走进度日志逻辑（与停滞恢复衔接）
		if stucking {
			stucking = false
			c.logf(stageTransfer, 32, false, "卡顿解除: 停滞 %v 后恢复数据流", now.Sub(stuckStart).Truncate(time.Second))
		}

		// 停滞恢复：停滞中有新数据到达，停滞状态解除，可再输出一条进度日志表示恢复
		if stalling {
			stalling = false
			if progressInterval > 0 && (up > lastUp || down > lastDown) {
				logProgress(now, up, down)
			}
			continue
		}

		// 进度日志：距上次进度日志 ≥ 间隔 且期间任一方向有新增字节
		if progressInterval > 0 {
			ref := lastProgress
			if ref.IsZero() {
				ref = start
			}
			if now.Sub(ref) >= progressInterval && (up > lastUp || down > lastDown) {
				logProgress(now, up, down)
			}
		}
		// ////////////////  核心逻辑  end ////////////////////////////////////////////////
	}
}

// reflectorCopy 手写拷贝循环（替代 io.Copy）：src.Read -> dst.Write，
// 成功写出的字节数计入对应方向的计数器并刷新该方向的最后活动时间，
// 读/写错误分别生成对应方向的结束原因（src 读到 io.EOF 视为对端正常断开）；
// 返回成功写出的字节数与结束原因
func reflectorCopy(dst io.Writer, src io.Reader, ts *transferStats, isToClient bool) (int64, transferCloseReason) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		// 读取一端
		n, rerr := src.Read(buf)
		if n > 0 {
			// 写给另一端
			wn, werr := dst.Write(buf[:n])
			if wn > 0 {
				written += int64(wn)
				if isToClient {
					ts.addDown(int64(wn)) // ↓ 后端→客户端
				} else {
					ts.addUp(int64(wn)) // ↑ 客户端→后端
				}
			}
			// 写错误 / 短写入：按方向生成结束原因
			if werr != nil {
				if isToClient {
					return written, transferCloseReason{fmt.Sprintf("写回客户端失败: %v", werr), true}
				}
				return written, transferCloseReason{fmt.Sprintf("写入后端失败: %v", werr), true}
			}
			if wn != n {
				if isToClient {
					return written, transferCloseReason{text: "写回客户端失败: 短写入", isError: true}
				}
				return written, transferCloseReason{text: "写入后端失败: 短写入", isError: true}
			}
		}
		// 读错误：EOF 视为对端正常断开，其余读错误按方向生成结束原因
		if rerr != nil {
			if rerr == io.EOF {
				if isToClient {
					return written, transferCloseReason{text: "后端断开"}
				}
				return written, transferCloseReason{text: "客户端断开"}
			}
			if isToClient {
				return written, transferCloseReason{fmt.Sprintf("读取后端失败: %v", rerr), true}
			}
			return written, transferCloseReason{fmt.Sprintf("读取客户端失败: %v", rerr), true}
		}
	}
}
