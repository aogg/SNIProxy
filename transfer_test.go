package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- isLikeDownload（疑似下载判定） ----------

// isLikeDownload 以 ↓累计 ≥ 1MB(downloadBytesThreshold) 判定疑似下载：边界值（差1字节/恰好1MB）、0、大值
func TestIsLikeDownload(t *testing.T) {
	cases := []struct {
		down int64
		want bool
	}{
		{0, false},
		{1, false},
		{downloadBytesThreshold - 1, false}, // 边界：差 1 字节不算疑似下载
		{downloadBytesThreshold, true},      // 边界：恰好 1MB 即算疑似下载
		{downloadBytesThreshold + 1, true},
		{10 << 20, true}, // 10MB 大响应
	}
	for _, c := range cases {
		if got := isLikeDownload(c.down); got != c.want {
			t.Fatalf("isLikeDownload(%d) = %v, 期望 %v", c.down, got, c.want)
		}
	}
}

// ---------- stuckClientAbandonCloseReason（客户端停滞期间放弃的结束原因改写） ----------

// makeStallStats 构造一个“最后活动在 stall 前、↓累计 down 字节”的传输计数器（纯内存，不依赖真实计时等待）
func makeStallStats(now time.Time, stall time.Duration, down int64) *transferStats {
	past := now.Add(-stall)
	return &transferStats{
		upBytes: 100, downBytes: down,
		upActive:   past.UnixNano(),
		downActive: past.UnixNano(),
	}
}

// 命中改写：正常“客户端断开” + 停滞达卡顿判定时长 + ↓未达疑似下载阈值 → 改写为带实际停滞时长的红色异常文案
func TestStuckClientAbandonCloseReason_Hit(t *testing.T) {
	now := time.Now()
	reason := transferCloseReason{text: "客户端断开"}

	got, ok := stuckClientAbandonCloseReason(reason, makeStallStats(now, 5*time.Second, 50), 3*time.Second, now)
	if !ok {
		t.Fatal("停滞 5s(≥3s) 且 ↓未达阈值的客户端断开应改写结束原因")
	}
	if !got.isError {
		t.Fatal("改写后的结束原因应为异常(isError=true)，结束总结变红")
	}
	if want := "客户端断开(停滞 5s 期间客户端放弃, ↓50B)"; got.text != want {
		t.Fatalf("改写文案 = %q, 期望 %q", got.text, want)
	}

	// 边界：停滞恰好等于卡顿判定时长（>= 判定）也应命中
	if _, ok := stuckClientAbandonCloseReason(reason, makeStallStats(now, 3*time.Second, 0), 3*time.Second, now); !ok {
		t.Fatal("停滞恰好等于卡顿判定时长也应命中改写")
	}
}

// 未命中保持原样：停滞不足 / 疑似下载 / 异常结束 / 非客户端断开 / 检测关闭 / 文案非精确匹配
func TestStuckClientAbandonCloseReason_Keep(t *testing.T) {
	now := time.Now()
	keep := transferCloseReason{text: "客户端断开"}

	cases := []struct {
		name         string
		reason       transferCloseReason
		stall        time.Duration
		down         int64
		stuckTimeout time.Duration
	}{
		{"停滞未达判定时长", keep, 2 * time.Second, 0, 3 * time.Second},
		{"疑似下载中的客户端断开不改写", keep, 5 * time.Second, downloadBytesThreshold, 3 * time.Second},
		{"异常结束(读写出错)不改写", transferCloseReason{text: "读取客户端失败: xx", isError: true}, 5 * time.Second, 0, 3 * time.Second},
		{"后端断开不改写", transferCloseReason{text: "后端断开"}, 5 * time.Second, 0, 3 * time.Second},
		{"卡顿检测关闭(0)不改写", keep, 5 * time.Second, 0, 0},
		{"文案非精确匹配不改写", transferCloseReason{text: "客户端断开(短写入)"}, 5 * time.Second, 0, 3 * time.Second},
	}
	for _, c := range cases {
		got, ok := stuckClientAbandonCloseReason(c.reason, makeStallStats(now, c.stall, c.down), c.stuckTimeout, now)
		if ok {
			t.Fatalf("%s: 不应改写结束原因, got %q", c.name, got.text)
		}
		if got != c.reason {
			t.Fatalf("%s: 未命中时原因应原样返回, got %+v, 期望 %+v", c.name, got, c.reason)
		}
	}
}

// ---------- transferWatcher（tier1 卡顿 / tier2 停滞，进程内测试） ----------

// captureLog 把全局 LogFilePath 指到测试临时文件并返回路径，
// serviceLogger 每条日志都会追加写入该文件，用于断言 watcher 的输出内容（测完自动恢复）
func captureLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "watcher.log")
	old := LogFilePath
	LogFilePath = path
	t.Cleanup(func() { LogFilePath = old })
	return path
}

// logFileContains 判断测试日志文件里是否已出现指定子串
func logFileContains(t *testing.T, path, substr string) bool {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取测试日志文件失败: %v", err)
	}
	return strings.Contains(string(data), substr)
}

// logMustRead 读取测试日志文件全文（断言用）
func logMustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取测试日志文件失败: %v", err)
	}
	return string(data)
}

// startTestWatcher 启动 transferWatcher 并返回退出信号 chan；
// 测试结束前须 cancel 后等待该 chan 关闭，确保 watcher 完全退出后再由 t.Cleanup 恢复 LogFilePath
// （否则恢复写入会与 watcher 内 serviceLogger 对 LogFilePath 的读取构成数据竞争，-race 下会报）
func startTestWatcher(t *testing.T, ts *transferStats, src string, progressInterval, stallTimeout, stuckTimeout time.Duration) (context.CancelFunc, <-chan struct{}) {
	t.Helper()
	c := newConnCtx(src)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		transferWatcher(ctx, c, "后端[测试]", ts, time.Now(), progressInterval, stallTimeout, stuckTimeout)
		close(done)
	}()
	return cancel, done
}

// tier1 卡顿与 tier2 停滞的先后接管 + 恢复数据流后的“卡顿解除”：
// 卡顿(1s)先出、停滞(2s)接管后卡顿不再重复、恢复数据流输出卡顿解除
func TestTransferWatcher_StuckThenStallThenRecovery(t *testing.T) {
	logPath := captureLog(t)
	ts := newTransferStats() // 最后活动时间=现在，作为停滞/卡顿计时起点
	cancel, done := startTestWatcher(t, ts, "127.0.0.1:1", 0, 2*time.Second, 1*time.Second)
	defer cancel()

	time.Sleep(1300 * time.Millisecond) // ≈1s tick：首次卡顿（红色，疑似下载:否）
	if !logFileContains(t, logPath, "卡顿 1s 无数据") {
		t.Fatal("停滞 1s 后应输出首次卡顿日志")
	}
	if !logFileContains(t, logPath, "疑似下载:否") {
		t.Fatal("↓为 0 时卡顿日志应标注 疑似下载:否")
	}

	time.Sleep(1000 * time.Millisecond) // ≈2s tick：tier2 停滞接管（卡顿不再重复输出）
	if !logFileContains(t, logPath, "停滞 2s 无数据") {
		t.Fatal("停滞 2s 后应输出 tier2 停滞日志")
	}
	if strings.Contains(logMustRead(t, logPath), "卡顿 2s 无数据") {
		t.Fatal("tier2 停滞接管后 tier1 卡顿不应再重复输出")
	}

	ts.addDown(1024) // 恢复数据流
	time.Sleep(1200 * time.Millisecond)
	if !logFileContains(t, logPath, "卡顿解除: 停滞") {
		t.Fatal("恢复数据流后应输出卡顿解除日志")
	}
	cancel()
	<-done // 等 watcher 退出，避免其日志写入与 LogFilePath 恢复竞争
}

// tier1 卡顿的重复输出：停滞未达 tier2 时，卡顿日志每隔 stuck_timeout 重复一次，
// 首个 %v 从配置的判定时长(1s)换成实际持续时长(2s)；↓ 达到疑似下载阈值时改黄色提示文案
func TestTransferWatcher_StuckRepeatAndLikeDownload(t *testing.T) {
	logPath := captureLog(t)
	now := time.Now()
	ts := &transferStats{
		upBytes: 100, downBytes: downloadBytesThreshold + 512, // ↓已超 1MB：疑似下载
		upActive: now.UnixNano(), downActive: now.UnixNano(),
	}
	cancel, done := startTestWatcher(t, ts, "127.0.0.1:2", 0, 100*time.Second, 1*time.Second)
	defer cancel()

	time.Sleep(2300 * time.Millisecond) // ≈1s 首次卡顿(黄)，≈2s 重复卡顿(实际 2s)
	content := logMustRead(t, logPath)
	if !strings.Contains(content, "卡顿 1s 无数据") {
		t.Fatal("首次卡顿日志未输出")
	}
	if !strings.Contains(content, "疑似下载:是(↓1.0MB)") {
		t.Fatal("↓超 1MB 时卡顿日志应标注 疑似下载:是(↓1.0MB)")
	}
	if !strings.Contains(content, "卡顿 2s 无数据") {
		t.Fatal("卡顿日志应每隔 stuck_timeout 重复一次且展示实际持续时长 2s")
	}
	cancel()
	<-done // 等 watcher 退出，避免其日志写入与 LogFilePath 恢复竞争
}

// 回归底线：stuck_timeout=0 时卡顿层整体关闭，输出与旧版完全一致（只有停滞日志，无任何卡顿字样）
func TestTransferWatcher_StuckDisabledKeepsLegacyOutput(t *testing.T) {
	logPath := captureLog(t)
	ts := newTransferStats()
	cancel, done := startTestWatcher(t, ts, "127.0.0.1:3", 0, 1*time.Second, 0)
	defer cancel()

	time.Sleep(1500 * time.Millisecond) // ≈1s tick：停滞日志
	if !logFileContains(t, logPath, "停滞 1s 无数据") {
		t.Fatal("stuck_timeout=0 时停滞日志应保持原有输出")
	}
	if strings.Contains(logMustRead(t, logPath), "卡顿") {
		t.Fatal("stuck_timeout=0 时不应输出任何卡顿日志")
	}
	cancel()
	<-done // 等 watcher 退出，避免其日志写入与 LogFilePath 恢复竞争
}
