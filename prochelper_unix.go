// File: prochelper_unix.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-05-03
// Description: 
// License: MIT

//go:build !windows

package main

import (
	"fmt"
	"time"
)

func unixSec(secs int64) time.Time {
	return time.Unix(secs, 0)
}

// fmtStartTimeMS on Linux uses millisecond precision too for consistency.
func fmtStartTimeMS(ms int64) string {
	secs := ms / 1000
	millis := ms % 1000
	t := time.Unix(secs, 0)
	return fmt.Sprintf("%s:%03d", t.Format("06/01/02 15:04:05"), millis)
}

// getCmdlineCwd on Linux - gopsutil reads /proc directly and always has full
// data, so no fallback needed.
func getCmdlineCwd(pid int32, gopsutilCmd, gopsutilCwd, exe string) (string, string) {
	return gopsutilCmd, gopsutilCwd
}
