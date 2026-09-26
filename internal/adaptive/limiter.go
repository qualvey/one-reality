package adaptive

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AdjustmentAction 自适应调节动作枚举
type AdjustmentAction string

const (
	ActionHold             AdjustmentAction = "HOLD"
	ActionRampUp           AdjustmentAction = "RAMP_UP"
	ActionNetworkThrottle  AdjustmentAction = "NET_THROTTLE"
	ActionSystemThrottle   AdjustmentAction = "SYS_THROTTLE"
)

// LimiterStats 自适应限流中枢实时运行状态快照
type LimiterStats struct {
	CurrentConcurrency int              `json:"current_concurrency"`
	MinConcurrency     int              `json:"min_concurrency"`
	MaxConcurrency     int              `json:"max_concurrency"`
	SystemLoad1        float64          `json:"system_load_1"`
	SystemCPUPercent   float64          `json:"system_cpu_percent"`
	NetworkAvgRTT      time.Duration    `json:"network_avg_rtt"`
	NetworkBloatRatio  float64          `json:"network_bloat_ratio"`
	NetworkTimeoutRate float64          `json:"network_timeout_rate"`
	LastAction         AdjustmentAction `json:"last_action"`
	LastActionReason   string           `json:"last_action_reason"`
}

// RateLimiter 扫描器消费的抽象自适应流控接口
type RateLimiter interface {
	Acquire(ctx context.Context) error
	Release()
	ReportProbe(duration time.Duration, isTimeout bool, isSuccess bool)
	CurrentConcurrency() int
	Stats() LimiterStats
	Stop()
}

// dynamicSemaphore 动态可伸缩的高性能并发信号量
type dynamicSemaphore struct {
	mu      sync.Mutex
	cond    *sync.Cond
	current int
	limit   int
	closed  bool
}

func newDynamicSemaphore(initialLimit int) *dynamicSemaphore {
	s := &dynamicSemaphore{
		limit: initialLimit,
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *dynamicSemaphore) Acquire(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for s.current >= s.limit && !s.closed {
		// 配合 Context 唤醒支持
		done := ctx.Done()
		if done == nil {
			s.cond.Wait()
			continue
		}

		// 创建通道联动支持非阻塞取消
		waitChan := make(chan struct{})
		go func() {
			s.mu.Lock()
			for s.current >= s.limit && !s.closed && ctx.Err() == nil {
				s.cond.Wait()
			}
			s.mu.Unlock()
			close(waitChan)
		}()

		s.mu.Unlock()
		select {
		case <-ctx.Done():
			s.mu.Lock()
			s.cond.Broadcast()
			return ctx.Err()
		case <-waitChan:
			s.mu.Lock()
		}
	}

	if s.closed {
		return fmt.Errorf("limiter closed")
	}

	s.current++
	return nil
}

func (s *dynamicSemaphore) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current > 0 {
		s.current--
	}
	s.cond.Signal()
}

func (s *dynamicSemaphore) SetLimit(newLimit int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.limit = newLimit
	s.cond.Broadcast()
}

func (s *dynamicSemaphore) GetLimit() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.limit
}

func (s *dynamicSemaphore) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.cond.Broadcast()
}

// AdaptiveLimiter 硬件感知 + 宿主系统守护 + 网络拥塞调谐自适应限流控制器
type AdaptiveLimiter struct {
	profile    HardwareProfile
	sem        *dynamicSemaphore
	sysMon     SystemMonitor
	netTracker *NetworkTracker

	mu               sync.RWMutex
	lastAction       AdjustmentAction
	lastActionReason string
	stopChan         chan struct{}
	stopOnce         sync.Once
}

// NewAdaptiveLimiter 创建自适应流控控制器
func NewAdaptiveLimiter(profile HardwareProfile, sysMon SystemMonitor) *AdaptiveLimiter {
	if sysMon == nil {
		sysMon = NewSystemMonitor()
	}

	sem := newDynamicSemaphore(profile.InitialConcurrency)
	tracker := NewNetworkTracker(100)

	l := &AdaptiveLimiter{
		profile:          profile,
		sem:              sem,
		sysMon:           sysMon,
		netTracker:       tracker,
		lastAction:       ActionHold,
		lastActionReason: "初始硬件基准预估就绪",
		stopChan:         make(chan struct{}),
	}

	go l.adjustLoop()

	return l
}

func (l *AdaptiveLimiter) Acquire(ctx context.Context) error {
	return l.sem.Acquire(ctx)
}

func (l *AdaptiveLimiter) Release() {
	l.sem.Release()
}

func (l *AdaptiveLimiter) ReportProbe(duration time.Duration, isTimeout bool, isSuccess bool) {
	l.netTracker.Record(duration, isTimeout, isSuccess)
}

func (l *AdaptiveLimiter) CurrentConcurrency() int {
	return l.sem.GetLimit()
}

func (l *AdaptiveLimiter) Stats() LimiterStats {
	l.mu.RLock()
	defer l.mu.RUnlock()

	sys := l.sysMon.Sample()
	netSnap := l.netTracker.Snapshot()

	return LimiterStats{
		CurrentConcurrency: l.sem.GetLimit(),
		MinConcurrency:     l.profile.MinConcurrency,
		MaxConcurrency:     l.profile.MaxConcurrency,
		SystemLoad1:        sys.Load1,
		SystemCPUPercent:   sys.CPUPercent,
		NetworkAvgRTT:      netSnap.AvgRTT,
		NetworkBloatRatio:  netSnap.BloatRatio,
		NetworkTimeoutRate: netSnap.TimeoutRate,
		LastAction:         l.lastAction,
		LastActionReason:   l.lastActionReason,
	}
}

func (l *AdaptiveLimiter) Stop() {
	l.stopOnce.Do(func() {
		close(l.stopChan)
		l.sem.Close()
	})
}

// adjustLoop 周期性触发自适应调谐
func (l *AdaptiveLimiter) adjustLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-l.stopChan:
			return
		case <-ticker.C:
			l.performAdjustment()
		}
	}
}

// performAdjustment 执行单轮双轨仲裁决策
func (l *AdaptiveLimiter) performAdjustment() {
	sys := l.sysMon.Sample()
	netSnap := l.netTracker.Snapshot()
	current := l.sem.GetLimit()

	l.mu.Lock()
	defer l.mu.Unlock()

	// 1. 最高优先级：系统级安全红线守门 (Guardrail)
	targetLoadMax := float64(l.profile.NumCPU) * l.profile.TargetLoadRatio
	isLoadOverloaded := sys.Available && sys.Load1 > 0 && sys.Load1 > targetLoadMax
	isCPUOverloaded := sys.Available && sys.CPUPercent > 0 && sys.CPUPercent > l.profile.TargetCPUPercent

	if isLoadOverloaded || isCPUOverloaded {
		// 触发系统级惩罚性急刹车 (乘法削减 35%)
		newLimit := int(float64(current) * 0.65)
		if newLimit < l.profile.MinConcurrency {
			newLimit = l.profile.MinConcurrency
		}
		l.sem.SetLimit(newLimit)
		l.lastAction = ActionSystemThrottle
		if isLoadOverloaded {
			l.lastActionReason = fmt.Sprintf("系统负载过高 (Load1=%.2f > 目标%.2f)，自适应紧急收缩并发: %d -> %d",
				sys.Load1, targetLoadMax, current, newLimit)
		} else {
			l.lastActionReason = fmt.Sprintf("CPU利用率过高 (CPU=%.1f%% > 目标%.1f%%)，自适应紧急收缩并发: %d -> %d",
				sys.CPUPercent, l.profile.TargetCPUPercent, current, newLimit)
		}
		l.netTracker.Reset()
		return
	}

	// 2. 次高优先级：网络延迟膨胀与拥塞调谐 (需累积至少 10 个样本)
	if netSnap.TotalSamples >= 10 {
		isBloated := netSnap.BloatRatio > 2.2
		isHighTimeout := netSnap.TimeoutRate > 0.15

		if isBloated || isHighTimeout {
			// 网络或调度积压，温和收缩 (乘法削减 15%)
			newLimit := int(float64(current) * 0.85)
			if newLimit < l.profile.MinConcurrency {
				newLimit = l.profile.MinConcurrency
			}
			l.sem.SetLimit(newLimit)
			l.lastAction = ActionNetworkThrottle
			if isBloated {
				l.lastActionReason = fmt.Sprintf("探测延迟发生膨胀 (膨胀比=%.2f > 2.2)，自适应收敛并发: %d -> %d",
					netSnap.BloatRatio, current, newLimit)
			} else {
				l.lastActionReason = fmt.Sprintf("探测超时率过高 (超时率=%.1f%% > 15%%)，自适应收敛并发: %d -> %d",
					netSnap.TimeoutRate*100, current, newLimit)
			}
			return
		}

		// 3. 网络与系统均健康：加法探索性爬升 (Additive Increase)
		if netSnap.TimeoutRate < 0.05 && netSnap.BloatRatio < 1.3 && current < l.profile.MaxConcurrency {
			step := 3
			if l.profile.NumCPU >= 8 {
				step = 8
			}
			newLimit := current + step
			if newLimit > l.profile.MaxConcurrency {
				newLimit = l.profile.MaxConcurrency
			}
			l.sem.SetLimit(newLimit)
			l.lastAction = ActionRampUp
			l.lastActionReason = fmt.Sprintf("网络与系统状态优良，自适应爬坡提升吞吐: %d -> %d", current, newLimit)
			return
		}
	}

	l.lastAction = ActionHold
	l.lastActionReason = fmt.Sprintf("状态稳定保持当前并发: %d (Load=%.2f, RTT=%v)",
		current, sys.Load1, netSnap.AvgRTT.Round(time.Millisecond))
}
