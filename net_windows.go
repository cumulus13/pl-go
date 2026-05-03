// File: net_windows.go
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-05-03
// Description: 
// License: MIT

//go:build windows

package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// Uses GetExtendedTcpTable / GetExtendedUdpTable from iphlpapi.dll.
// Zero WMI. Same low-level API that netstat.exe uses.

var (
	iphlpapi                = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1 // UDP_TABLE_OWNER_PID
	afInet              = 2
	afInet6             = 23
)

type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32 // network byte order, only low 16 bits used
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// winPort converts the Windows port field (network byte order uint32, only
// low 2 bytes meaningful) to a host-order int.
// Windows: port stored as big-endian in bytes [0..1], bytes [2..3] are zero.
// So: port = (byte0 << 8) | byte1
func winPort(v uint32) int {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	// b[0] and b[1] hold the big-endian port
	return int(b[0])<<8 | int(b[1])
}

func u32ToIP(v uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IP(b).String()
}

var tcpStateNames = map[uint32]string{
	1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECV",
	5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT",
	9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

func getTableBytes(proc *syscall.LazyProc, tableClass, family uint32) ([]byte, error) {
	var size uint32
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(tableClass), 0)
	if size == 0 {
		size = 65536
	}
	buf := make([]byte, size)
	ret, _, err := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		uintptr(family),
		uintptr(tableClass),
		0,
	)
	if ret != 0 {
		return nil, fmt.Errorf("iphlpapi: %v", err)
	}
	return buf, nil
}

// connKey is used to deduplicate UDP entries (same port/addr binding on
// multiple interfaces — e.g. Chrome's mDNS port 5353 appears once per NIC).
type connKey struct {
	connType string
	family   string
	laddr    string
	lport    int
	raddr    string
	rport    int
	status   string
}

func getConnections(pid int32) []NetConn {
	var results []NetConn
	seen := map[connKey]bool{}

	addConn := func(c NetConn) {
		k := connKey{c.Type, c.Family, c.Laddr, c.Lport, c.Raddr, c.Rport, c.Status}
		if !seen[k] {
			seen[k] = true
			results = append(results, c)
		}
	}

	// ── TCP IPv4 ──────────────────────────────────────────────────────────────
	if buf, err := getTableBytes(procGetExtendedTcpTable, tcpTableOwnerPidAll, afInet); err == nil {
		count := binary.LittleEndian.Uint32(buf[0:4])
		rowSize := uint32(unsafe.Sizeof(mibTCPRowOwnerPID{}))
		for i := uint32(0); i < count; i++ {
			offset := 4 + i*rowSize
			if int(offset+rowSize) > len(buf) {
				break
			}
			row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[offset]))
			if int32(row.OwningPID) != pid {
				continue
			}
			stateName := tcpStateNames[row.State]
			if stateName == "" {
				stateName = fmt.Sprintf("STATE_%d", row.State)
			}
			raddr := u32ToIP(row.RemoteAddr)
			rport := winPort(row.RemotePort)
			// For LISTEN state, remote is meaningless — show N/A like Python
			if stateName == "LISTEN" || (raddr == "0.0.0.0" && rport == 0) {
				raddr = "N/A"
				rport = -1
			}
			addConn(NetConn{
				Fd:     "-1",
				Family: "AF_INET",
				Type:   "TCP",
				Laddr:  u32ToIP(row.LocalAddr),
				Lport:  winPort(row.LocalPort),
				Raddr:  raddr,
				Rport:  rport,
				Status: stateName,
			})
		}
	}

	// ── UDP IPv4 ──────────────────────────────────────────────────────────────
	if buf, err := getTableBytes(procGetExtendedUdpTable, udpTableOwnerPid, afInet); err == nil {
		count := binary.LittleEndian.Uint32(buf[0:4])
		rowSize := uint32(unsafe.Sizeof(mibUDPRowOwnerPID{}))
		for i := uint32(0); i < count; i++ {
			offset := 4 + i*rowSize
			if int(offset+rowSize) > len(buf) {
				break
			}
			row := (*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[offset]))
			if int32(row.OwningPID) != pid {
				continue
			}
			// UDP has no remote addr — show N/A to match Python psutil output
			addConn(NetConn{
				Fd:     "-1",
				Family: "AF_INET",
				Type:   "UDP",
				Laddr:  u32ToIP(row.LocalAddr),
				Lport:  winPort(row.LocalPort),
				Raddr:  "N/A",
				Rport:  -1,
				Status: "NONE",
			})
		}
	}

	// ── TCP IPv6 ──────────────────────────────────────────────────────────────
	// MIB_TCP6ROW_OWNER_PID layout
	type mibTCP6RowOwnerPID struct {
		LocalAddr     [16]byte
		LocalScopeId  uint32
		LocalPort     uint32
		RemoteAddr    [16]byte
		RemoteScopeId uint32
		RemotePort    uint32
		State         uint32
		OwningPID     uint32
	}
	if buf, err := getTableBytes(procGetExtendedTcpTable, tcpTableOwnerPidAll, afInet6); err == nil {
		count := binary.LittleEndian.Uint32(buf[0:4])
		rowSize := uint32(unsafe.Sizeof(mibTCP6RowOwnerPID{}))
		for i := uint32(0); i < count; i++ {
			offset := 4 + i*rowSize
			if int(offset+rowSize) > len(buf) {
				break
			}
			row := (*mibTCP6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
			if int32(row.OwningPID) != pid {
				continue
			}
			stateName := tcpStateNames[row.State]
			if stateName == "" {
				stateName = fmt.Sprintf("STATE_%d", row.State)
			}
			lIP := net.IP(row.LocalAddr[:]).String()
			rIP := net.IP(row.RemoteAddr[:]).String()
			rport := winPort(row.RemotePort)
			if stateName == "LISTEN" || rport == 0 {
				rIP = "N/A"
				rport = -1
			}
			addConn(NetConn{
				Fd:     "-1",
				Family: "AF_INET6",
				Type:   "TCP",
				Laddr:  lIP,
				Lport:  winPort(row.LocalPort),
				Raddr:  rIP,
				Rport:  rport,
				Status: stateName,
			})
		}
	}

	// ── UDP IPv6 ──────────────────────────────────────────────────────────────
	type mibUDP6RowOwnerPID struct {
		LocalAddr    [16]byte
		LocalScopeId uint32
		LocalPort    uint32
		OwningPID    uint32
	}
	if buf, err := getTableBytes(procGetExtendedUdpTable, udpTableOwnerPid, afInet6); err == nil {
		count := binary.LittleEndian.Uint32(buf[0:4])
		rowSize := uint32(unsafe.Sizeof(mibUDP6RowOwnerPID{}))
		for i := uint32(0); i < count; i++ {
			offset := 4 + i*rowSize
			if int(offset+rowSize) > len(buf) {
				break
			}
			row := (*mibUDP6RowOwnerPID)(unsafe.Pointer(&buf[offset]))
			if int32(row.OwningPID) != pid {
				continue
			}
			lIP := net.IP(row.LocalAddr[:]).String()
			addConn(NetConn{
				Fd:     "-1",
				Family: "AF_INET6",
				Type:   "UDP",
				Laddr:  lIP,
				Lport:  winPort(row.LocalPort),
				Raddr:  "N/A",
				Rport:  -1,
				Status: "NONE",
			})
		}
	}

	return results
}
