package adaptive

import "time"

// SystemMetrics 宿主机系统关键健康指标
type SystemMetrics struct {
	Load1      float64   `json:"load_1"`
	Load5      float64   `json:"load_5"`
	CPUPercent float64   `json:"cpu_percent"`
	SampleTime time.Time `json:"sample_time"`
	Available  bool      `json:"available"`
}

// SystemMonitor 系统健康采样器接口
type SystemMonitor interface {
	Sample() SystemMetrics
}

// NewSystemMonitor 创建与宿主操作系统相适配的系统健康采集器
func NewSystemMonitor() SystemMonitor {
	return newPlatformSystemMonitor()
}
