//go:build !windows

package cmd

import (
	"syscall"
)

func init() {
	var rLimit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit); err == nil {
		if rLimit.Cur < 65535 {
			rLimit.Cur = 65535
			if rLimit.Max < 65535 {
				rLimit.Cur = rLimit.Max
			}
			_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rLimit)
		}
	}
}
