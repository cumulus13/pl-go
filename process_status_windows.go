//go:build windows

package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
	"github.com/shirou/gopsutil/v3/process"
)

const (
	TH32CS_SNAPTHREAD     = 0x00000004
	THREAD_SUSPEND_RESUME = 0x0002
)

var (
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procCreateToolhelp32Snapshot = modkernel32.NewProc("CreateToolhelp32Snapshot")
	procThread32First            = modkernel32.NewProc("Thread32First")
	procThread32Next             = modkernel32.NewProc("Thread32Next")

	procSuspendThread = modkernel32.NewProc("SuspendThread")
	procResumeThread  = modkernel32.NewProc("ResumeThread")
)

type THREADENTRY32 struct {
	Size           uint32
	Usage          uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

func suspendThread(h windows.Handle) (uint32, error) {
	ret, _, err := procSuspendThread.Call(uintptr(h))

	if ret == 0xFFFFFFFF {
		return 0, err
	}

	return uint32(ret), nil
}

func resumeThread(h windows.Handle) (uint32, error) {
	ret, _, err := procResumeThread.Call(uintptr(h))

	if ret == 0xFFFFFFFF {
		return 0, err
	}

	return uint32(ret), nil
}

func isProcessSuspended(pid uint32) (bool, error) {
	snapshot, _, err := procCreateToolhelp32Snapshot.Call(
		uintptr(TH32CS_SNAPTHREAD),
		0,
	)

	if snapshot == uintptr(windows.InvalidHandle) {
		return false, err
	}

	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry THREADENTRY32
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procThread32First.Call(
		snapshot,
		uintptr(unsafe.Pointer(&entry)),
	)

	if ret == 0 {
		return false, fmt.Errorf("Thread32First failed")
	}

	found := false

	for {
		if entry.OwnerProcessID == pid {
			found = true

			hThread, err := windows.OpenThread(
				THREAD_SUSPEND_RESUME,
				false,
				entry.ThreadID,
			)

			if err == nil {
				prev, err := suspendThread(hThread)

				if err == nil {
					// restore original state
					_, _ = resumeThread(hThread)

					// prev == 0 means thread WAS NOT suspended
					if prev == 0 {
						windows.CloseHandle(hThread)
						return false, nil
					}
				}

				windows.CloseHandle(hThread)
			}
		}

		ret, _, _ = procThread32Next.Call(
			snapshot,
			uintptr(unsafe.Pointer(&entry)),
		)

		if ret == 0 {
			break
		}
	}

	if !found {
		return false, fmt.Errorf("no threads found")
	}

	return true, nil
}

// func getProcessStatus(pid int32) string {
// 	suspended, err := isProcessSuspended(uint32(pid))
// 	if err == nil && suspended {
// 		return "suspended"
// 	}

// 	return "running"
// }

func getProcessStatus(pid int32) string {
	suspended, err := isProcessSuspended(uint32(pid))
	if err == nil && suspended {
		return "suspended"
	}

	p, err := process.NewProcess(pid)
	if err != nil {
		return "stopped"
	}

	running, err := p.IsRunning()
	if err != nil || !running {
		return "stopped"
	}

	return "running"
}