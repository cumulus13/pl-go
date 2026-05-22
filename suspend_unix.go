// File: suspend_unix.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// License: MIT

//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// suspendProcess sends SIGSTOP to the process, freezing it in place.
func suspendProcess(pid int32) error {
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := p.Signal(syscall.SIGSTOP); err != nil {
		return fmt.Errorf("SIGSTOP pid %d: %w", pid, err)
	}
	return nil
}

// resumeProcess sends SIGCONT to the process, unfreezing it.
func resumeProcess(pid int32) error {
	p, err := os.FindProcess(int(pid))
	if err != nil {
		return fmt.Errorf("find process %d: %w", pid, err)
	}
	if err := p.Signal(syscall.SIGCONT); err != nil {
		return fmt.Errorf("SIGCONT pid %d: %w", pid, err)
	}
	return nil
}
