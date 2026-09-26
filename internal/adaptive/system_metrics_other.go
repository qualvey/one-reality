//go:build !linux

package adaptive

import "time"

type fallbackSystemMonitor struct{}

func newPlatformSystemMonitor() SystemMonitor {
	return &fallbackSystemMonitor{}
}

func (m *fallbackSystemMonitor) Sample() SystemMetrics {
	// 非 Linux 平台 (如 Windows 开发机/macOS) 默认返回可用占位
	return SystemMetrics{
		Load1:      0,
		Load5:      0,
		CPUPercent: 0,
		SampleTime: time.Now(),
		Available:  false,
	}
}
