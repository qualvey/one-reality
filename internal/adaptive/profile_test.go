package adaptive

import (
	"testing"
)

func TestCalculateProfile(t *testing.T) {
	tests := []struct {
		name         string
		numCPU       int
		arch         string
		totalMemMB   int
		wantLowPower bool
		wantInitC    int
		wantMaxC     int
	}{
		{
			name:         "4-core ARM64 2GB (Armbian SBC like RK3328/H6)",
			numCPU:       4,
			arch:         "arm64",
			totalMemMB:   1980,
			wantLowPower: true,
			wantInitC:    60,
			wantMaxC:     120,
		},
		{
			name:         "8-core ARM64 8GB (High performance RK3588/M1)",
			numCPU:       8,
			arch:         "arm64",
			totalMemMB:   8000,
			wantLowPower: false,
			wantInitC:    200,
			wantMaxC:     400,
		},
		{
			name:         "4-core amd64 4GB (J4125 soft-router)",
			numCPU:       4,
			arch:         "amd64",
			totalMemMB:   4000,
			wantLowPower: false,
			wantInitC:    120,
			wantMaxC:     240,
		},
		{
			name:         "16-core amd64 32GB (High end server)",
			numCPU:       16,
			arch:         "amd64",
			totalMemMB:   32000,
			wantLowPower: false,
			wantInitC:    640,
			wantMaxC:     1000, // Capped at 1000
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := CalculateProfile(tt.numCPU, tt.arch, tt.totalMemMB)
			if profile.IsLowPowerARM != tt.wantLowPower {
				t.Errorf("IsLowPowerARM = %v, want %v", profile.IsLowPowerARM, tt.wantLowPower)
			}
			if profile.InitialConcurrency != tt.wantInitC {
				t.Errorf("InitialConcurrency = %d, want %d", profile.InitialConcurrency, tt.wantInitC)
			}
			if profile.MaxConcurrency != tt.wantMaxC {
				t.Errorf("MaxConcurrency = %d, want %d", profile.MaxConcurrency, tt.wantMaxC)
			}
		})
	}
}

func TestDetectHardwareProfile(t *testing.T) {
	profile := DetectHardwareProfile()
	if profile.NumCPU <= 0 {
		t.Errorf("expected NumCPU > 0, got %d", profile.NumCPU)
	}
	if profile.InitialConcurrency <= 0 {
		t.Errorf("expected InitialConcurrency > 0, got %d", profile.InitialConcurrency)
	}
	if profile.InitialConcurrency < profile.MinConcurrency || profile.InitialConcurrency > profile.MaxConcurrency {
		t.Errorf("InitialConcurrency %d out of bounds [%d, %d]", profile.InitialConcurrency, profile.MinConcurrency, profile.MaxConcurrency)
	}
}
