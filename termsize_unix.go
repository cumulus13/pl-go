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
