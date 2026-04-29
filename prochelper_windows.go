//go:build windows

package main

import (
	"time"
	"fmt"
	"path/filepath"
	"syscall"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ─── Win32 types ─────────────────────────────────────────────────────────────

var (
	modNtdll                    = syscall.NewLazyDLL("ntdll.dll")
	procNtQueryInformationProcess = modNtdll.NewProc("NtQueryInformationProcess")
)

const (
	processBasicInformation = 0
)

type processBasicInfo struct {
	ExitStatus                   uintptr
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 uintptr
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// unicodeString mirrors UNICODE_STRING from ntdll (32/64-bit safe via uintptr)
type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte // padding on 64-bit to align Buffer
	Buffer        uintptr
}

// readRemoteUTF16 reads a UTF-16LE string from another process's memory.
func readRemoteUTF16(handle windows.Handle, addr uintptr, length uint16) (string, error) {
	if addr == 0 || length == 0 {
		return "", nil
	}
	buf := make([]byte, length)
	var read uintptr
	err := windows.ReadProcessMemory(handle, addr, &buf[0], uintptr(length), &read)
	if err != nil {
		return "", err
	}
	// convert UTF-16LE bytes to runes
	u16 := make([]uint16, read/2)
	for i := range u16 {
		u16[i] = uint16(buf[i*2]) | uint16(buf[i*2+1])<<8
	}
	return string(utf16.Decode(u16)), nil
}

// readPtr reads one pointer-sized value from remote process memory.
func readPtr(handle windows.Handle, addr uintptr) (uintptr, error) {
	var val uintptr
	var read uintptr
	err := windows.ReadProcessMemory(handle, addr, (*byte)(unsafe.Pointer(&val)), unsafe.Sizeof(val), &read)
	if err != nil {
		return 0, err
	}
	return val, nil
}

// readUnicodeString reads a UNICODE_STRING struct from remote memory.
func readUnicodeString(handle windows.Handle, addr uintptr) (unicodeString, error) {
	var us unicodeString
	var read uintptr
	err := windows.ReadProcessMemory(handle, addr, (*byte)(unsafe.Pointer(&us)), unsafe.Sizeof(us), &read)
	return us, err
}

// getPEBStrings opens the process, walks its PEB and RTL_USER_PROCESS_PARAMETERS
// to extract CommandLine and CurrentDirectory.
// This works even for sandboxed processes where NtQueryInformationProcess
// returns STATUS_ACCESS_DENIED for ProcessParameters — because we only need
// PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, not full access.
func getPEBStrings(pid int32) (cmdline, cwd string) {
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false, uint32(pid),
	)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(handle)

	// Step 1: get PEB address via NtQueryInformationProcess
	var pbi processBasicInfo
	var retLen uint32
	status, _, _ := procNtQueryInformationProcess.Call(
		uintptr(handle),
		processBasicInformation,
		uintptr(unsafe.Pointer(&pbi)),
		unsafe.Sizeof(pbi),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if status != 0 {
		return "", ""
	}

	pebBase := pbi.PebBaseAddress
	if pebBase == 0 {
		return "", ""
	}

	// Step 2: read ProcessParameters pointer from PEB
	// PEB layout (64-bit): ProcessParameters is at offset 0x20
	// PEB layout (32-bit): ProcessParameters is at offset 0x10
	// We detect by pointer size (unsafe.Sizeof(uintptr(0)))
	var ppOffset uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		ppOffset = 0x20
	} else {
		ppOffset = 0x10
	}

	ppAddr, err := readPtr(handle, pebBase+ppOffset)
	if err != nil || ppAddr == 0 {
		return "", ""
	}

	// Step 3: read CommandLine and CurrentDirectory from RTL_USER_PROCESS_PARAMETERS
	// Offsets (64-bit):
	//   CurrentDirectory.DosPath  UNICODE_STRING at 0x38  (size 16 bytes)
	//   CommandLine               UNICODE_STRING at 0x70
	// Offsets (32-bit):
	//   CurrentDirectory.DosPath  at 0x24
	//   CommandLine               at 0x40
	var cwdOffset, cmdOffset uintptr
	if unsafe.Sizeof(uintptr(0)) == 8 {
		cwdOffset = 0x38
		cmdOffset = 0x70
	} else {
		cwdOffset = 0x24
		cmdOffset = 0x40
	}

	cwdUS, err := readUnicodeString(handle, ppAddr+cwdOffset)
	if err == nil && cwdUS.Buffer != 0 && cwdUS.Length > 0 {
		cwd, _ = readRemoteUTF16(handle, cwdUS.Buffer, cwdUS.Length)
		// trim trailing backslash to match Python output
		cwd = filepath.Clean(cwd)
	}

	cmdUS, err := readUnicodeString(handle, ppAddr+cmdOffset)
	if err == nil && cmdUS.Buffer != 0 && cmdUS.Length > 0 {
		cmdline, _ = readRemoteUTF16(handle, cmdUS.Buffer, cmdUS.Length)
	}

	return cmdline, cwd
}

// getCmdlineCwd wraps getPEBStrings and falls back gracefully:
//   - If cmdline is empty from gopsutil, try PEB read
//   - If cwd is still empty after PEB, fall back to dirname(exe)
func getCmdlineCwd(pid int32, gopsutilCmd, gopsutilCwd, exe string) (string, string) {
	cmd := gopsutilCmd
	cwd := gopsutilCwd

	if cmd == "" || cwd == "" {
		pebCmd, pebCwd := getPEBStrings(pid)
		if cmd == "" {
			cmd = pebCmd
		}
		if cwd == "" {
			cwd = pebCwd
		}
	}

	// Last resort for cwd: use exe directory
	if cwd == "" && exe != "" {
		cwd = filepath.Dir(exe)
	}

	return cmd, cwd
}

// fmtStartTimeMS formats a millisecond epoch with sub-second precision,
// matching Python's  YY/MM/DD HH:MM:SS:mmm  format.
func fmtStartTimeMS(ms int64) string {
	secs := ms / 1000
	millis := ms % 1000
	t := unixSec(secs)
	return fmt.Sprintf("%s:%03d", t.Format("06/01/02 15:04:05"), millis)
}

// unixSec converts Unix seconds to time.Time (used by fmtStartTimeMS).
func unixSec(secs int64) time.Time {
	return time.Unix(secs, 0)
}
