// File: suspend_windows.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// License: MIT

//go:build windows

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

var (
	modNtdllSusp          = syscall.NewLazyDLL("ntdll.dll")
	procNtSuspendProcess  = modNtdllSusp.NewProc("NtSuspendProcess")
	procNtResumeProcess   = modNtdllSusp.NewProc("NtResumeProcess")
)

// suspendProcess suspends all threads in a Windows process via NtSuspendProcess.
// This is the same mechanism used by Process Explorer and Task Manager's "Suspend".
// No WMI involved — pure ntdll call.
func suspendProcess(pid int32) error {
	handle, err := windows.OpenProcess(
		windows.PROCESS_SUSPEND_RESUME,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	ret, _, _ := procNtSuspendProcess.Call(uintptr(handle))
	if ret != 0 {
		return fmt.Errorf("NtSuspendProcess pid %d: NTSTATUS 0x%X", pid, ret)
	}
	return nil
}

// resumeProcess resumes a previously suspended Windows process via NtResumeProcess.
func resumeProcess(pid int32) error {
	handle, err := windows.OpenProcess(
		windows.PROCESS_SUSPEND_RESUME,
		false,
		uint32(pid),
	)
	if err != nil {
		return fmt.Errorf("OpenProcess pid %d: %w", pid, err)
	}
	defer windows.CloseHandle(handle)

	ret, _, _ := procNtResumeProcess.Call(uintptr(handle))
	if ret != 0 {
		return fmt.Errorf("NtResumeProcess pid %d: NTSTATUS 0x%X", pid, ret)
	}
	return nil
}
