//go:build !windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func hexToIPv4(h string) string {
	n, _ := strconv.ParseUint(h, 16, 32)
	return fmt.Sprintf("%d.%d.%d.%d", n&0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>24)&0xff)
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
	"04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
	"07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
	"0A": "LISTEN", "0B": "CLOSING", "00": "NONE",
}

func getConnections(pid int32) []NetConn {
	// Map socket inodes → fd numbers for this pid
	inodeToFd := map[string]string{}
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	if entries, err := os.ReadDir(fdDir); err == nil {
		for _, e := range entries {
			link, err := os.Readlink(filepath.Join(fdDir, e.Name()))
			if err == nil && strings.HasPrefix(link, "socket:[") {
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				inodeToFd[inode] = e.Name()
			}
		}
	}

	var results []NetConn
	for _, proto := range []string{"tcp", "udp", "tcp6", "udp6"} {
		f, err := os.Open(fmt.Sprintf("/proc/net/%s", proto))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		scanner.Scan() // skip header
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 {
				continue
			}
			inode := fields[9]
			fd, ok := inodeToFd[inode]
			if !ok {
				continue // not owned by this pid
			}
			lp := strings.Split(fields[1], ":")
			rp := strings.Split(fields[2], ":")
			if len(lp) < 2 || len(rp) < 2 {
				continue
			}
			state := strings.ToUpper(fields[3])
			stateStr, ok2 := tcpStates[state]
			if !ok2 {
				stateStr = state
			}
			family := "AF_INET"
			if strings.HasSuffix(proto, "6") {
				family = "AF_INET6"
			}
			connType := "TCP"
			if strings.HasPrefix(proto, "udp") {
				connType = "UDP"
			}
			lPort, _ := strconv.ParseUint(lp[1], 16, 32)
			rPort, _ := strconv.ParseUint(rp[1], 16, 32)
			results = append(results, NetConn{
				Fd:     fd,
				Family: family,
				Type:   connType,
				Laddr:  hexToIPv4(lp[0]),
				Lport:  int(lPort),
				Raddr:  hexToIPv4(rp[0]),
				Rport:  int(rPort),
				Status: stateStr,
			})
		}
		f.Close()
	}
	return results
}