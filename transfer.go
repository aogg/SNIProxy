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
)

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

// startTransferWatcher 启动传输监视 goroutine（进度/停滞日志），两项检测都关闭时不启动
func startTransferWatcher(ctx context.Context, c *connCtx, backendDesc string, ts *transferStats, start time.Time) {
	// ////////////////  校验参数  start  ////////////////////////////////////////////////
	progressInterval := time.Duration(*cfg.ProgressInterval) * time.Second // 进度日志间隔（main 已填充默认值，0=关闭）
	stallTimeout := time.Duration(*cfg.StallTimeout) * time.Second         // 停滞判定时长（main 已填充默认值，0=关闭）
	if progressInterval <= 0 && stallTimeout <= 0 {
		return // 进度与停滞检测均已关闭，不启动监视
	}
	// ////////////////  校验参数  end ////////////////////////////////////////////////
	go transferWatcher(ctx, c, backendDesc, ts, start, progressInterval, stallTimeout)
}

// transferWatcher 传输监视循环：每秒 tick 一次，按配置输出进度日志（青色 36）与停滞日志（黄色 33），随 ctx.Done 退出
func transferWatcher(ctx context.Context, c *connCtx, backendDesc string, ts *transferStats, start time.Time, progressInterval, stallTimeout time.Duration) {
	// ////////////////  准备数据  start  ////////////////////////////////////////////////
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	var (
		lastUp, lastDown int64     // 上次进度日志时的双向累计字节（用于计算窗口速率与新增字节判定）
		lastProgress     time.Time // 上次进度日志时间（零值时以连接开始时间为基准）
		stalling         bool      // 是否处于停滞状态（停滞期间不再输出进度日志）
		lastStallLog     time.Time // 上次停滞日志时间（用于每隔 stall_timeout 重复输出一次）
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
