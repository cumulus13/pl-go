//go:build windows

package main

import (
	"syscall"
	"unsafe"

	"github.com/shirou/gopsutil/v3/process"
)

var (
	psapi           = syscall.NewLazyDLL("psapi.dll")
	enumProcesses   = psapi.NewProc("EnumProcesses")
)

// getAllProcesses enumerates PIDs via EnumProcesses (psapi) — no WMI.
// It then wraps each PID with gopsutil's Process struct.
// Individual field reads (exe, mem, cpu, cmdline, cwd) also avoid WMI:
//   - Exe       → QueryFullProcessImageName  (kernel32)
//   - Mem       → GetProcessMemoryInfo       (psapi)
//   - CPU       → GetProcessTimes            (kernel32)
//   - Cmdline   → NtQueryInformationProcess  (ntdll, PEB)
//   - Cwd       → NtQueryInformationProcess  (ntdll, PEB)
//   - Ppid      → NtQueryInformationProcess  (ntdll)
//   - CreateTime→ GetProcessTimes            (kernel32)
// The only remaining WMI call is Username() — acceptable since it's one call
// per process and uses OpenProcessToken rather than Win32_Process query.
func getAllProcesses() ([]*process.Process, error) {
	// Start with a buffer for 4096 PIDs and grow if needed
	const maxPIDs = 65536
	pids := make([]uint32, 4096)
	var bytesReturned uint32

	for {
		ret, _, err := enumProcesses.Call(
			uintptr(unsafe.Pointer(&pids[0])),
			uintptr(uint32(len(pids))*4),
			uintptr(unsafe.Pointer(&bytesReturned)),
		)
		if ret == 0 {
			return nil, err
		}
		count := bytesReturned / 4
		if count < uint32(len(pids)) {
			pids = pids[:count]
			break
		}
		// Buffer was too small — double it
		if len(pids) >= maxPIDs {
			pids = pids[:count]
			break
		}
		pids = make([]uint32, len(pids)*2)
	}

	var procs []*process.Process
	for _, pid := range pids {
		if pid == 0 {
			continue // skip System Idle Process
		}
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			continue
		}
		procs = append(procs, p)
	}
	return procs, nil
}
