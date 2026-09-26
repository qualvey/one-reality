package adaptive

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// HardwareProfile 宿主机硬件算力画像与并发基线
type HardwareProfile struct {
	NumCPU             int     `json:"num_cpu"`
	Arch               string  `json:"arch"`
	TotalMemoryMB      int     `json:"total_memory_mb"`
	IsLowPowerARM      bool    `json:"is_low_power_arm"`
	InitialConcurrency int     `json:"initial_concurrency"`
	MinConcurrency     int     `json:"min_concurrency"`
	MaxConcurrency     int     `json:"max_concurrency"`
	TargetLoadRatio    float64 `json:"target_load_ratio"`  // 目标负载比例 (Load1 / NumCPU)
	TargetCPUPercent   float64 `json:"target_cpu_percent"` // 目标 CPU 使用百分比
}

// DetectHardwareProfile 探测宿主机硬件特征并计算自适应基线
func DetectHardwareProfile() HardwareProfile {
	numCPU := runtime.NumCPU()
	if numCPU <= 0 {
		numCPU = 1
	}
	arch := runtime.GOARCH
	memMB := readLinuxTotalMemoryMB()

	return CalculateProfile(numCPU, arch, memMB)
}

// CalculateProfile 纯逻辑计算硬件基线 profile，方便单元测试覆盖各种规格
func CalculateProfile(numCPU int, arch string, totalMemMB int) HardwareProfile {
	isARM := arch == "arm" || arch == "arm64" || arch == "mips" || arch == "mipsle"
	// 4核以下或内存<=2.5G的ARM平台视为典型低功耗单板机/嵌入式设备
	isLowPowerARM := isARM && (numCPU <= 4 || (totalMemMB > 0 && totalMemMB <= 2500))

	var initC, minC, maxC int
	var targetLoadRatio, targetCPU float64

	switch {
	case isLowPowerARM:
		// 弱算力 ARM (如树莓派/全志H6/RK3328等，单核密码学运算较弱)
		initC = numCPU * 15 // 4核对应 60
		minC = 10
		maxC = numCPU * 30 // 4核封顶 120
		targetLoadRatio = 0.75
		targetCPU = 70.0

	case isARM:
		// 高性能 ARM (如 RK3588, Apple M系列, 8核以上云主机)
		initC = numCPU * 25
		minC = 30
		maxC = numCPU * 50
		targetLoadRatio = 0.85
		targetCPU = 80.0

	case numCPU <= 4:
		// 2~4核低功耗 x86 (如 J4125/N5105/小云主机)
		initC = numCPU * 30 // 4核对应 120
		minC = 20
		maxC = numCPU * 60 // 4核对应 240
		targetLoadRatio = 0.85
		targetCPU = 80.0

	default:
		// 8核及以上桌面 PC / 高性能服务器
		initC = numCPU * 40
		minC = 50
		maxC = numCPU * 80
		targetLoadRatio = 0.90
		targetCPU = 85.0
	}

	// 整体上下限安全收口
	if initC < minC {
		initC = minC
	}
	if initC > maxC {
		initC = maxC
	}
	if maxC > 1000 {
		maxC = 1000
	}

	return HardwareProfile{
		NumCPU:             numCPU,
		Arch:               arch,
		TotalMemoryMB:      totalMemMB,
		IsLowPowerARM:      isLowPowerARM,
		InitialConcurrency: initC,
		MinConcurrency:     minC,
		MaxConcurrency:     maxC,
		TargetLoadRatio:    targetLoadRatio,
		TargetCPUPercent:   targetCPU,
	}
}

// readLinuxTotalMemoryMB 尝试从 /proc/meminfo 读取物理内存总量 (MB)
func readLinuxTotalMemoryMB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if kb, err := strconv.Atoi(fields[1]); err == nil {
					return kb / 1024
				}
			}
			break
		}
	}
	return 0
}
