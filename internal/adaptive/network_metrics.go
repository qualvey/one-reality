package adaptive

import (
	"sync"
	"time"
)

// ProbeSample 单次探测采样明细
type ProbeSample struct {
	Duration  time.Duration
	IsTimeout bool
	IsSuccess bool
}

// NetworkSnapshot 网络延迟与拥塞滑动窗口快照
type NetworkSnapshot struct {
	TotalSamples int           `json:"total_samples"`
	SuccessCount int           `json:"success_count"`
	TimeoutCount int           `json:"timeout_count"`
	TimeoutRate  float64       `json:"timeout_rate"` // 0.0 ~ 1.0
	MinRTT       time.Duration `json:"min_rtt"`
	AvgRTT       time.Duration `json:"avg_rtt"`
	BloatRatio   float64       `json:"bloat_ratio"` // AvgRTT / MinRTT (>= 1.0)
}

// NetworkTracker 基于环形缓冲区的滑动窗口网络探测延迟与拥塞指标追踪器
type NetworkTracker struct {
	mu       sync.RWMutex
	capacity int
	samples  []ProbeSample
	cursor   int
	count    int
}

// NewNetworkTracker 创建网络延迟滑动窗口追踪器 (默认容量如 100 条)
func NewNetworkTracker(capacity int) *NetworkTracker {
	if capacity <= 0 {
		capacity = 100
	}
	return &NetworkTracker{
		capacity: capacity,
		samples:  make([]ProbeSample, capacity),
	}
}

// Record 记录一次单 IP 探测指标
func (t *NetworkTracker) Record(duration time.Duration, isTimeout bool, isSuccess bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.samples[t.cursor] = ProbeSample{
		Duration:  duration,
		IsTimeout: isTimeout,
		IsSuccess: isSuccess,
	}

	t.cursor = (t.cursor + 1) % t.capacity
	if t.count < t.capacity {
		t.count++
	}
}

// Snapshot 计算并获取当前窗口的统计快照
func (t *NetworkTracker) Snapshot() NetworkSnapshot {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.count == 0 {
		return NetworkSnapshot{
			BloatRatio: 1.0,
		}
	}

	var sumRTT time.Duration
	var minRTT time.Duration = 0
	var successCount int
	var timeoutCount int

	for i := 0; i < t.count; i++ {
		sample := t.samples[i]
		if sample.IsTimeout {
			timeoutCount++
		}
		if sample.IsSuccess && sample.Duration > 0 {
			successCount++
			sumRTT += sample.Duration
			if minRTT == 0 || sample.Duration < minRTT {
				minRTT = sample.Duration
			}
		}
	}

	var avgRTT time.Duration
	var bloatRatio float64 = 1.0

	if successCount > 0 {
		avgRTT = sumRTT / time.Duration(successCount)
		baseRTT := minRTT
		if baseRTT < 40*time.Millisecond {
			baseRTT = 40 * time.Millisecond // 稳健基准保底，防止个别离群极速握手拉爆膨胀比
		}
		if baseRTT > 0 {
			bloatRatio = float64(avgRTT) / float64(baseRTT)
		}
	}

	timeoutRate := float64(timeoutCount) / float64(t.count)

	return NetworkSnapshot{
		TotalSamples: t.count,
		SuccessCount: successCount,
		TimeoutCount: timeoutCount,
		TimeoutRate:  timeoutRate,
		MinRTT:       minRTT,
		AvgRTT:       avgRTT,
		BloatRatio:   bloatRatio,
	}
}

// Reset 清空当前窗口数据
func (t *NetworkTracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cursor = 0
	t.count = 0
}
