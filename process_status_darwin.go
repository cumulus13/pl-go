//go:build darwin

package main

import (
	"github.com/shirou/gopsutil/v3/process"
)

func getProcessStatus(pid int32) string {
	p, err := process.NewProcess(pid)
	if err != nil {
		return "stopped"
	}

	status, err := p.Status()
	if err == nil && len(status) > 0 {

		switch status[0] {

		case "R":
			return "running"

		case "S":
			return "sleeping"

		case "T":
			return "stopped"

		case "Z":
			return "zombie"

		default:
			return status[0]
		}
	}

	running, err := p.IsRunning()
	if err != nil || !running {
		return "stopped"
	}

	return "running"
}