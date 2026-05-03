// File: termsize_unix.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-05-03
// Description: 
// License: MIT

//go:build !windows

package main

import (
	"golang.org/x/sys/unix"
	"os"
)

func termWidth() int {
	ws, err := unix.IoctlGetWinsize(int(os.Stdout.Fd()), unix.TIOCGWINSZ)
	if err != nil || ws.Col == 0 {
		return 120
	}
	return int(ws.Col)
}
