package adaptive

import (
	"testing"
	"time"
)

func TestNetworkTracker_Snapshot(t *testing.T) {
	tracker := NewNetworkTracker(5)

	// 初始状态
	snap := tracker.Snapshot()
	if snap.TotalSamples != 0 || snap.BloatRatio != 1.0 {
		t.Errorf("unexpected initial snapshot: %+v", snap)
	}

	// 记录样本: 3 个成功 (100ms, 200ms, 300ms), 2 个超时
	tracker.Record(100*time.Millisecond, false, true)
	tracker.Record(200*time.Millisecond, false, true)
	tracker.Record(300*time.Millisecond, false, true)
	tracker.Record(3000*time.Millisecond, true, false)
	tracker.Record(3000*time.Millisecond, true, false)

	snap = tracker.Snapshot()
	if snap.TotalSamples != 5 {
		t.Errorf("expected 5 samples, got %d", snap.TotalSamples)
	}
	if snap.SuccessCount != 3 {
		t.Errorf("expected 3 success, got %d", snap.SuccessCount)
	}
	if snap.TimeoutCount != 2 {
		t.Errorf("expected 2 timeout, got %d", snap.TimeoutCount)
	}
	if snap.TimeoutRate != 0.4 {
		t.Errorf("expected timeout rate 0.4, got %f", snap.TimeoutRate)
	}
	if snap.MinRTT != 100*time.Millisecond {
		t.Errorf("expected MinRTT 100ms, got %v", snap.MinRTT)
	}
	if snap.AvgRTT != 200*time.Millisecond {
		t.Errorf("expected AvgRTT 200ms, got %v", snap.AvgRTT)
	}
	// BloatRatio = 200 / 100 = 2.0
	if snap.BloatRatio != 2.0 {
		t.Errorf("expected BloatRatio 2.0, got %f", snap.BloatRatio)
	}

	// 环形覆盖测试 (继续写入 2 个 50ms)
	tracker.Record(50*time.Millisecond, false, true)
	tracker.Record(50*time.Millisecond, false, true)

	snap2 := tracker.Snapshot()
	if snap2.TotalSamples != 5 {
		t.Errorf("expected count capped at capacity 5, got %d", snap2.TotalSamples)
	}
	if snap2.MinRTT != 50*time.Millisecond {
		t.Errorf("expected new MinRTT 50ms, got %v", snap2.MinRTT)
	}
}
