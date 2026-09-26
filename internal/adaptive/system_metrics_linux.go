//go:build linux

package adaptive

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type linuxSystemMonitor struct {
	mu           sync.Mutex
	lastUser     uint64
	lastNice     uint64
	lastSystem   uint64
	lastIdle     uint64
	lastIOWait   uint64
	lastIRQ      uint64
	lastSoftIRQ  uint64
	hasPrevStats bool
}

func newPlatformSystemMonitor() SystemMonitor {
	m := &linuxSystemMonitor{}
	_ = m.sampleCPU() // 预热初始 tick
	return m
}

func (m *linuxSystemMonitor) Sample() SystemMetrics {
	m.mu.Lock()
	defer m.mu.Unlock()

	load1, load5 := m.sampleLoad()
	cpuPercent := m.sampleCPU()

	return SystemMetrics{
		Load1:      load1,
		Load5:      load5,
		CPUPercent: cpuPercent,
		SampleTime: time.Now(),
		Available:  true,
	}
}

func (m *linuxSystemMonitor) sampleLoad() (float64, float64) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, 0
	}
	l1, _ := strconv.ParseFloat(fields[0], 64)
	l5, _ := strconv.ParseFloat(fields[1], 64)
	return l1, l5
}

func (m *linuxSystemMonitor) sampleCPU() float64 {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "cpu ") {
			fields := strings.Fields(line)
			if len(fields) < 8 {
				return 0
			}
			user, _ := strconv.ParseUint(fields[1], 10, 64)
			nice, _ := strconv.ParseUint(fields[2], 10, 64)
			system, _ := strconv.ParseUint(fields[3], 10, 64)
			idle, _ := strconv.ParseUint(fields[4], 10, 64)
			iowait, _ := strconv.ParseUint(fields[5], 10, 64)
			irq, _ := strconv.ParseUint(fields[6], 10, 64)
			softirq, _ := strconv.ParseUint(fields[7], 10, 64)

			if !m.hasPrevStats {
				m.lastUser = user
				m.lastNice = nice
				m.lastSystem = system
				m.lastIdle = idle
				m.lastIOWait = iowait
				m.lastIRQ = irq
				m.lastSoftIRQ = softirq
				m.hasPrevStats = true
				return 0
			}

			prevIdle := m.lastIdle + m.lastIOWait
			idleTime := idle + iowait

			prevNonIdle := m.lastUser + m.lastNice + m.lastSystem + m.lastIRQ + m.lastSoftIRQ
			nonIdleTime := user + nice + system + irq + softirq

			prevTotal := prevIdle + prevNonIdle
			total := idleTime + nonIdleTime

			totalDiff := total - prevTotal
			idleDiff := idleTime - prevIdle

			m.lastUser = user
			m.lastNice = nice
			m.lastSystem = system
			m.lastIdle = idle
			m.lastIOWait = iowait
			m.lastIRQ = irq
			m.lastSoftIRQ = softirq

			if totalDiff == 0 {
				return 0
			}

			usage := float64(totalDiff-idleDiff) / float64(totalDiff) * 100.0
			if usage < 0 {
				usage = 0
			}
			if usage > 100 {
				usage = 100
			}
			return usage
		}
	}
	return 0
}
