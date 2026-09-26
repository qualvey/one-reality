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

	// 平滑控制状态
	smoothedLoad1    float64
	smoothedCPU      float64
	hasSmoothedInit  bool
	cooldownUntil    time.Time
	cooldownDuration time.Duration // 调节后的观察静息期 (默认 5 秒)
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
		cooldownDuration: 5 * time.Second,
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

// performAdjustment 执行单轮双轨仲裁决策（采用 EWMA 滤波、死区维持与渐进微调）
func (l *AdaptiveLimiter) performAdjustment() {
	sys := l.sysMon.Sample()
	netSnap := l.netTracker.Snapshot()
	current := l.sem.GetLimit()

	l.mu.Lock()
	defer l.mu.Unlock()

	// 0. 更新 EWMA 指数平滑指标，滤除瞬时毛刺
	if sys.Available {
		if !l.hasSmoothedInit {
			l.smoothedLoad1 = sys.Load1
			l.smoothedCPU = sys.CPUPercent
			l.hasSmoothedInit = true
		} else {
			l.smoothedLoad1 = l.smoothedLoad1*0.65 + sys.Load1*0.35
			l.smoothedCPU = l.smoothedCPU*0.65 + sys.CPUPercent*0.35
		}
	}

	// 1. 冷却期检查：前一次调谐动作生效需要系统反应时间，在冷却期内保持观察不反复折腾
	now := time.Now()
	if now.Before(l.cooldownUntil) {
		l.lastAction = ActionHold
		l.lastActionReason = fmt.Sprintf("处于调整后平息冷却期，保持并发稳定: %d (平滑Load=%.2f, 平滑CPU=%.1f%%)",
			current, l.smoothedLoad1, l.smoothedCPU)
		return
	}

	targetLoad := float64(l.profile.NumCPU) * l.profile.TargetLoadRatio
	deadbandMin := targetLoad * 0.75 // 死区下限 (例如 4核 为 2.25)
	deadbandMax := targetLoad * 1.05 // 死区上限 (例如 4核 为 3.15)
	criticalLoad := targetLoad * 1.35 // 严重超载红线 (例如 4核 为 4.05)

	// 2. 第一优先级：极端严重过载紧急制动
	isCriticalLoad := sys.Available && l.smoothedLoad1 > criticalLoad
	isCriticalCPU := sys.Available && l.smoothedCPU > 88.0

	if isCriticalLoad || isCriticalCPU {
		// 快速避险：温和削减 20%
		newLimit := int(float64(current) * 0.80)
		if newLimit < l.profile.MinConcurrency {
			newLimit = l.profile.MinConcurrency
		}
		l.sem.SetLimit(newLimit)
		l.cooldownUntil = now.Add(6 * time.Second)
		l.lastAction = ActionSystemThrottle
		l.netTracker.Reset()
		if isCriticalLoad {
			l.lastActionReason = fmt.Sprintf("系统负载严重超标 (平滑Load=%.2f > 极限%.2f)，自适应快速避险: %d -> %d",
				l.smoothedLoad1, criticalLoad, current, newLimit)
		} else {
			l.lastActionReason = fmt.Sprintf("CPU利用率严重超标 (平滑CPU=%.1f%% > 88%%)，自适应快速避险: %d -> %d",
				l.smoothedCPU, current, newLimit)
		}
		return
	}

	// 3. 第二优先级：轻度超出死区上限（采用微步梯度递减，杜绝断崖式暴跌）
	isSoftOverLoad := sys.Available && l.smoothedLoad1 > deadbandMax
	isSoftOverCPU := sys.Available && l.smoothedCPU > l.profile.TargetCPUPercent

	if isSoftOverLoad || isSoftOverCPU {
		step := int(float64(current) * 0.08)
		if step < 2 {
			step = 2
		}
		newLimit := current - step
		if newLimit < l.profile.MinConcurrency {
			newLimit = l.profile.MinConcurrency
		}
		l.sem.SetLimit(newLimit)
		l.cooldownUntil = now.Add(5 * time.Second)
		l.lastAction = ActionSystemThrottle
		if isSoftOverLoad {
			l.lastActionReason = fmt.Sprintf("系统负载轻微偏离死区 (平滑Load=%.2f > 上限%.2f)，自适应微调收敛: %d -> %d",
				l.smoothedLoad1, deadbandMax, current, newLimit)
		} else {
			l.lastActionReason = fmt.Sprintf("CPU利用率略高 (平滑CPU=%.1f%% > 目标%.1f%%)，自适应微调收敛: %d -> %d",
				l.smoothedCPU, l.profile.TargetCPUPercent, current, newLimit)
		}
		return
	}

	// 4. 第三优先级：网络延迟膨胀与超时调谐 (结合绝对延迟与超时率，防异构目标物理RTT差异误判)
	if netSnap.TotalSamples >= 15 {
		// 真实网络拥塞条件：
		// a) 膨胀比严重且平均延迟显著恶化 (>300ms)
		// b) 膨胀比偏高且出现丢包超时 (>3%)
		// c) 超时率偏高 (>12%)
		isBloated := (netSnap.BloatRatio > 3.0 && netSnap.AvgRTT > 300*time.Millisecond) ||
			(netSnap.BloatRatio > 2.2 && netSnap.TimeoutRate > 0.03)
		isHighTimeout := netSnap.TimeoutRate > 0.12

		if isBloated || isHighTimeout {
			step := int(float64(current) * 0.08)
			if step < 2 {
				step = 2
			}
			newLimit := current - step
			if newLimit < l.profile.MinConcurrency {
				newLimit = l.profile.MinConcurrency
			}
			l.sem.SetLimit(newLimit)
			l.cooldownUntil = now.Add(4 * time.Second)
			l.lastAction = ActionNetworkThrottle
			if isBloated {
				l.lastActionReason = fmt.Sprintf("探测网络发生延迟膨胀 (膨胀比=%.2f, 平均RTT=%v, 超时率=%.1f%%)，自适应微调收敛: %d -> %d",
					netSnap.BloatRatio, netSnap.AvgRTT.Round(time.Millisecond), netSnap.TimeoutRate*100, current, newLimit)
			} else {
				l.lastActionReason = fmt.Sprintf("探测超时率过高 (超时率=%.1f%% > 12%%)，自适应微调收敛: %d -> %d",
					netSnap.TimeoutRate*100, current, newLimit)
			}
			return
		}
	}

	// 5. 第四优先级：处于黄金死区内部（锁定平衡点，定速巡航，绝对不折腾）
	isInDeadband := sys.Available && l.smoothedLoad1 >= deadbandMin && l.smoothedLoad1 <= deadbandMax
	if isInDeadband {
		l.lastAction = ActionHold
		l.lastActionReason = fmt.Sprintf("处于系统健康死区内，锁定平衡点: %d (平滑Load=%.2f在[%.2f, %.2f], CPU=%.1f%%)",
			current, l.smoothedLoad1, deadbandMin, deadbandMax, l.smoothedCPU)
		return
	}

	// 6. 第五优先级：明显欠载时的加法探索性平稳爬升
	isUnderloaded := (!sys.Available || (l.smoothedLoad1 < deadbandMin && l.smoothedCPU < 40.0))
	if isUnderloaded && netSnap.TimeoutRate < 0.03 && current < l.profile.MaxConcurrency {
		step := 3
		if l.profile.NumCPU >= 8 {
			step = 6
		}
		newLimit := current + step
		if newLimit > l.profile.MaxConcurrency {
			newLimit = l.profile.MaxConcurrency
		}
		l.sem.SetLimit(newLimit)
		l.cooldownUntil = now.Add(4 * time.Second)
		l.lastAction = ActionRampUp
		l.lastActionReason = fmt.Sprintf("系统负载充裕且网络通畅，自适应渐进爬坡: %d -> %d", current, newLimit)
		return
	}

	l.lastAction = ActionHold
	l.lastActionReason = fmt.Sprintf("状态稳定保持当前并发: %d (平滑Load=%.2f, RTT=%v)",
		current, l.smoothedLoad1, netSnap.AvgRTT.Round(time.Millisecond))
}
