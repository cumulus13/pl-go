// File: prochelper_windows.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-05-03
// Description: 
// License: MIT

//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── Win32 types ──────────────────────────────────────────────────────────────

var (
	modNtdll                     = syscall.NewLazyDLL("ntdll.dll")
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
	procIsWow64Process            = modKernel32.NewProc("IsWow64Process")
)

const (
	processBasicInformation    = 0
	processPebAddress32        = 26 // ProcessWow64Information — gives 32-bit PEB addr
)

type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// UNICODE_STRING (native 64-bit layout)
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte // alignment padding
	Buffer        uintptr
}

// UNICODE_STRING32 — for 32-bit PEB when read from a WoW64 process
type unicodeString32 struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uint32
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// isWow64 returns true if the process is a 32-bit process running on 64-bit Windows
func isWow64(handle windows.Handle) bool {
	var wow64 uint32
	ret, _, _ := procIsWow64Process.Call(uintptr(handle), uintptr(unsafe.Pointer(&wow64)))
	return ret != 0 && wow64 != 0
}

func readRemoteBytes(handle windows.Handle, addr uintptr, size uintptr) ([]byte, error) {
	if addr == 0 || size == 0 {
		return nil, fmt.Errorf("invalid addr/size")
	}
	buf := make([]byte, size)
	var read uintptr
	err := windows.ReadProcessMemory(handle, addr, &buf[0], size, &read)
	if err != nil {
		return nil, err
	}
	return buf[:read], nil
}

func readRemoteUTF16(handle windows.Handle, addr uintptr, length uint16) (string, error) {
	if addr == 0 || length == 0 {
		return "", nil
	}
	buf, err := readRemoteBytes(handle, addr, uintptr(length))
	if err != nil {
		return "", err
	}
	u16 := make([]uint16, len(buf)/2)
	for i := range u16 {
		u16[i] = uint16(buf[i*2]) | uint16(buf[i*2+1])<<8
	}
	return string(utf16.Decode(u16)), nil
}

func readPtr64(handle windows.Handle, addr uintptr) (uintptr, error) {
	buf, err := readRemoteBytes(handle, addr, 8)
	if err != nil {
		return 0, err
	}
	v := uintptr(buf[0]) | uintptr(buf[1])<<8 | uintptr(buf[2])<<16 | uintptr(buf[3])<<24 |
		uintptr(buf[4])<<32 | uintptr(buf[5])<<40 | uintptr(buf[6])<<48 | uintptr(buf[7])<<56
	return v, nil
}

func readPtr32(handle windows.Handle, addr uintptr) (uintptr, error) {
	buf, err := readRemoteBytes(handle, addr, 4)
	if err != nil {
		return 0, err
	}
	return uintptr(buf[0]) | uintptr(buf[1])<<8 | uintptr(buf[2])<<16 | uintptr(buf[3])<<24, nil
}

// ─── 64-bit PEB reading ───────────────────────────────────────────────────────

// getPEBStrings64 reads CMD and CWD from a native 64-bit process PEB.
func getPEBStrings64(handle windows.Handle) (cmdline, cwd string) {
	var pbi processBasicInfo
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(handle),
		processBasicInformation,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 || pbi.PebBaseAddress == 0 {
		return
	}

	// RTL_USER_PROCESS_PARAMETERS pointer is at PEB+0x20 (64-bit)
	ppAddr, err := readPtr64(handle, pbi.PebBaseAddress+0x20)
	if err != nil || ppAddr == 0 {
		return
	}

	// CurrentDirectory.DosPath UNICODE_STRING at RTL_USER_PROCESS_PARAMETERS+0x38
	cwdBuf, err := readRemoteBytes(handle, ppAddr+0x38, unsafe.Sizeof(unicodeString{}))
	if err == nil {
		us := (*unicodeString)(unsafe.Pointer(&cwdBuf[0]))
		if us.Buffer != 0 && us.Length > 0 {
			cwd, _ = readRemoteUTF16(handle, us.Buffer, us.Length)
			cwd = filepath.Clean(cwd)
		}
	}

	// CommandLine UNICODE_STRING at RTL_USER_PROCESS_PARAMETERS+0x70
	cmdBuf, err := readRemoteBytes(handle, ppAddr+0x70, unsafe.Sizeof(unicodeString{}))
	if err == nil {
		us := (*unicodeString)(unsafe.Pointer(&cmdBuf[0]))
		if us.Buffer != 0 && us.Length > 0 {
			cmdline, _ = readRemoteUTF16(handle, us.Buffer, us.Length)
		}
	}
	return
}

// ─── 32-bit PEB reading (WoW64) ───────────────────────────────────────────────

// getPEBStrings32 reads CMD and CWD from a 32-bit WoW64 process PEB.
// We use ProcessWow64Information to get the 32-bit PEB address, then read
// the 32-bit RTL_USER_PROCESS_PARAMETERS layout.
func getPEBStrings32(handle windows.Handle) (cmdline, cwd string) {
	// Get the 32-bit PEB address via ProcessWow64Information
	var peb32Addr uint32
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(handle),
		processPebAddress32,
		uintptr(unsafe.Pointer(&peb32Addr)),
		4,
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 || peb32Addr == 0 {
		return
	}

	// RTL_USER_PROCESS_PARAMETERS pointer is at PEB32+0x10
	ppAddr32, err := readPtr32(handle, uintptr(peb32Addr)+0x10)
	if err != nil || ppAddr32 == 0 {
		return
	}
	pp := uintptr(ppAddr32)

	// 32-bit offsets:
	//   CurrentDirectory.DosPath UNICODE_STRING32 at RTL_USER_PROCESS_PARAMETERS32+0x24
	//   CommandLine UNICODE_STRING32 at RTL_USER_PROCESS_PARAMETERS32+0x40
	cwdBuf, err := readRemoteBytes(handle, pp+0x24, unsafe.Sizeof(unicodeString32{}))
	if err == nil {
		us := (*unicodeString32)(unsafe.Pointer(&cwdBuf[0]))
		if us.Buffer != 0 && us.Length > 0 {
			cwd, _ = readRemoteUTF16(handle, uintptr(us.Buffer), us.Length)
			cwd = filepath.Clean(cwd)
		}
	}

	cmdBuf, err := readRemoteBytes(handle, pp+0x40, unsafe.Sizeof(unicodeString32{}))
	if err == nil {
		us := (*unicodeString32)(unsafe.Pointer(&cmdBuf[0]))
		if us.Buffer != 0 && us.Length > 0 {
			cmdline, _ = readRemoteUTF16(handle, uintptr(us.Buffer), us.Length)
		}
	}
	return
}

// ─── main entry point ─────────────────────────────────────────────────────────

// getPEBStrings opens the process with the MINIMUM access needed and reads
// CMD + CWD from the PEB, handling both native 64-bit and WoW64 32-bit targets.
//
// Key insight: PROCESS_QUERY_LIMITED_INFORMATION is sufficient for
// NtQueryInformationProcess(ProcessBasicInformation) and for IsWow64Process.
// Combined with PROCESS_VM_READ it lets us read the PEB from sandboxed
// processes that run as the same user (e.g. Chrome renderers).
func getPEBStrings(pid int32) (cmdline, cwd string) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
		false, uint32(pid),
	)
	if err != nil {
		// Try with full QUERY permission as fallback (needed for some system processes)
		handle, err = windows.OpenProcess(
			windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
			false, uint32(pid),
		)
		if err != nil {
			return
		}
	}
	defer windows.CloseHandle(handle)

	if isWow64(handle) {
		// Target is a 32-bit process running under WoW64
		return getPEBStrings32(handle)
	}
	// Target is a native 64-bit process
	return getPEBStrings64(handle)
}

// getCmdlineCwd wraps getPEBStrings with gopsutil fallback and exe-dir fallback.
// On Windows, this gives us CMD for sandboxed processes that gopsutil can't reach.
// CWD fallback to dirname(exe) is NOT applied — empty CWD matches Python behavior.
func getCmdlineCwd(pid int32, gopsutilCmd, gopsutilCwd, exe string) (string, string) {
	cmd := gopsutilCmd
	cwd := gopsutilCwd

	// If gopsutil got nothing, try direct PEB read
	if cmd == "" || cwd == "" {
		pebCmd, pebCwd := getPEBStrings(pid)
		if cmd == "" {
			cmd = pebCmd
		}
		if cwd == "" {
			cwd = pebCwd
		}
	}

	// Do NOT fall back to dirname(exe) for CWD — Python shows empty for
	// sandboxed processes where CWD is truly inaccessible, and we match that.

	return cmd, cwd
}

// fmtStartTimeMS formats millisecond epoch as YY/MM/DD HH:MM:SS:mmm
func fmtStartTimeMS(ms int64) string {
	secs := ms / 1000
	millis := ms % 1000
	t := unixSec(secs)
	return fmt.Sprintf("%s:%03d", t.Format("06/01/02 15:04:05"), millis)
}

// unixSec converts Unix seconds to time.Time
func unixSec(secs int64) time.Time {
	return time.Unix(secs, 0)
}