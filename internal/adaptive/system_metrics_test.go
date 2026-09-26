package adaptive

import (
	"testing"
)

func TestSystemMonitor_Sample(t *testing.T) {
	mon := NewSystemMonitor()
	metrics := mon.Sample()

	if metrics.SampleTime.IsZero() {
		t.Errorf("expected non-zero sample time")
	}
	if metrics.Load1 < 0 {
		t.Errorf("expected Load1 >= 0, got %f", metrics.Load1)
	}
	if metrics.CPUPercent < 0 || metrics.CPUPercent > 100 {
		t.Errorf("expected CPUPercent in [0, 100], got %f", metrics.CPUPercent)
	}
}
