package adaptive

import (
	"context"
	"testing"
	"time"
)

type mockSystemMonitor struct {
	metrics SystemMetrics
}

func (m *mockSystemMonitor) Sample() SystemMetrics {
	return m.metrics
}

func TestDynamicSemaphore_AcquireRelease(t *testing.T) {
	sem := newDynamicSemaphore(2)

	ctx := context.Background()
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := sem.Acquire(ctx); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 此时已达到上限 2，带超时的 context 应该阻塞超时
	ctxTimeout, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if err := sem.Acquire(ctxTimeout); err != context.DeadlineExceeded {
		t.Errorf("expected DeadlineExceeded, got %v", err)
	}

	// 释放一个
	sem.Release()

	// 现在应该可以再次获取
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := sem.Acquire(ctx2); err != nil {
		t.Errorf("expected success after release, got %v", err)
	}

	// 动态扩容至 5
	sem.SetLimit(5)
	if sem.GetLimit() != 5 {
		t.Errorf("expected limit 5, got %d", sem.GetLimit())
	}
}

func TestAdaptiveLimiter_SystemThrottle(t *testing.T) {
	profile := CalculateProfile(4, "arm64", 2000) // 4核 ARM 2GB, Init=60, TargetLoad=4*0.75=3.0
	mockSys := &mockSystemMonitor{
		metrics: SystemMetrics{
			Load1:      6.5, // 严重超载 (大于 3.0)
			Available:  true,
			SampleTime: time.Now(),
		},
	}

	limiter := NewAdaptiveLimiter(profile, mockSys)
	defer limiter.Stop()

	initLimit := limiter.CurrentConcurrency()
	if initLimit != 60 {
		t.Fatalf("expected initial concurrency 60, got %d", initLimit)
	}

	// 执行调谐判断
	limiter.performAdjustment()

	newLimit := limiter.CurrentConcurrency()
	// 期望乘法急刹车 60 * 0.65 = 39
	if newLimit >= initLimit {
		t.Errorf("expected concurrency to shrink under high load, got %d (was %d)", newLimit, initLimit)
	}

	stats := limiter.Stats()
	if stats.LastAction != ActionSystemThrottle {
		t.Errorf("expected action %s, got %s", ActionSystemThrottle, stats.LastAction)
	}
}

func TestAdaptiveLimiter_NetworkThrottleAndRampUp(t *testing.T) {
	profile := CalculateProfile(4, "amd64", 8000) // 4核 x86, Init=120, Min=20, Max=240
	mockSys := &mockSystemMonitor{
		metrics: SystemMetrics{
			Load1:      1.0, // 系统完全健康
			CPUPercent: 30.0,
			Available:  true,
			SampleTime: time.Now(),
		},
	}

	limiter := NewAdaptiveLimiter(profile, mockSys)
	defer limiter.Stop()

	// 1. 模拟网络延迟膨胀 (10 个 100ms 成功，10 个 500ms 成功，Bloat > 2.2)
	limiter.netTracker.Record(100*time.Millisecond, false, true)
	for i := 0; i < 15; i++ {
		limiter.netTracker.Record(400*time.Millisecond, false, true)
	}

	limiter.performAdjustment()
	stats := limiter.Stats()
	if stats.LastAction != ActionNetworkThrottle {
		t.Errorf("expected action %s on network bloat, got %s", ActionNetworkThrottle, stats.LastAction)
	}

	// 2. 清空并模拟网络与系统极度健康状态 (均快、超时率 0%)
	limiter.netTracker.Reset()
	for i := 0; i < 20; i++ {
		limiter.netTracker.Record(80*time.Millisecond, false, true)
	}

	curr := limiter.CurrentConcurrency()
	limiter.performAdjustment()
	stats = limiter.Stats()
	if stats.LastAction != ActionRampUp {
		t.Errorf("expected action %s on healthy network, got %s", ActionRampUp, stats.LastAction)
	}
	if limiter.CurrentConcurrency() <= curr {
		t.Errorf("expected concurrency to increase from %d, got %d", curr, limiter.CurrentConcurrency())
	}
}
