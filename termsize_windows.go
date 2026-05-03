// File: termsize_windows.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-05-03
// Description: 
// License: MIT

//go:build windows

package main

import (
	"golang.org/x/sys/windows"
	"unsafe"
)

func termWidth() int {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	getConsoleScreenBufferInfo := kernel32.NewProc("GetConsoleScreenBufferInfo")

	type coord struct{ X, Y int16 }
	type smallRect struct{ Left, Top, Right, Bottom int16 }
	type consoleScreenBufferInfo struct {
		Size              coord
		CursorPosition    coord
		Attributes        uint16
		Window            smallRect
		MaximumWindowSize coord
	}

	var csbi consoleScreenBufferInfo
	stdout := windows.Handle(windows.Stdout)
	ret, _, _ := getConsoleScreenBufferInfo.Call(
		uintptr(stdout),
		uintptr(unsafe.Pointer(&csbi)),
	)
	if ret == 0 {
		return 120
	}
	w := int(csbi.Window.Right-csbi.Window.Left) + 1
	if w <= 0 {
		return 120
	}
	return w
}
