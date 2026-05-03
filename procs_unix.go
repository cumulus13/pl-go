// File: procs_unix.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-05-03
// Description: 
// License: MIT

//go:build !windows

package main

import "github.com/shirou/gopsutil/v3/process"

// getAllProcesses returns all running processes.
// On Linux/Mac, gopsutil reads /proc directly — no WMI.
func getAllProcesses() ([]*process.Process, error) {
	return process.Processes()
}
