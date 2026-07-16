//go:build windows

// Package procnet maps local TCP/UDP ports to the owning process (via the IP Helper API) and resolves process names, so both the per-app interceptor and the proxy can tell which process a connection belongs to.
package procnet

import (
	"encoding/binary"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
	procSetTcpEntry         = iphlpapi.NewProc("SetTcpEntry")
)

const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
	afInet              = 2
	tcpRowSize          = 24 // MIB_TCPROW_OWNER_PID
	udpRowSize          = 12 // MIB_UDPROW_OWNER_PID

	mibTCPStateEstablished = 5
	mibTCPStateDeleteTCB   = 12
)

// ProcName returns the exe base name for a PID ("" if unknown).
func ProcName(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 260)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	full := windows.UTF16ToString(buf[:n])
	if i := strings.LastIndexByte(full, '\\'); i >= 0 {
		return full[i+1:]
	}
	return full
}

func tcpTable() []byte {
	var size uint32
	procGetExtendedTcpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ := procGetExtendedTcpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, tcpTableOwnerPidAll, 0)
	if r != 0 {
		return nil
	}
	return buf
}

func udpTable() []byte {
	var size uint32
	procGetExtendedUdpTable.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPid, 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ := procGetExtendedUdpTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPid, 0)
	if r != 0 {
		return nil
	}
	return buf
}

// TCPPortPID snapshots local-TCP-port → owning-PID.
func TCPPortPID() map[uint16]uint32 { return parseTCPPortPID(tcpTable()) }

func parseTCPPortPID(buf []byte) map[uint16]uint32 {
	if len(buf) < 4 {
		return nil
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	m := make(map[uint16]uint32, num)
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*tcpRowSize
		if off+tcpRowSize > len(buf) {
			break
		}
		port := binary.BigEndian.Uint16(buf[off+8 : off+10])
		m[port] = *(*uint32)(unsafe.Pointer(&buf[off+20]))
	}
	return m
}

// UDPPortPID snapshots local-UDP-port → owning-PID.
func UDPPortPID() map[uint16]uint32 { return parseUDPPortPID(udpTable()) }

func parseUDPPortPID(buf []byte) map[uint16]uint32 {
	if len(buf) < 4 {
		return nil
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	m := make(map[uint16]uint32, num)
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*udpRowSize
		if off+udpRowSize > len(buf) {
			break
		}
		port := binary.BigEndian.Uint16(buf[off+4 : off+6])
		m[port] = *(*uint32)(unsafe.Pointer(&buf[off+8]))
	}
	return m
}

// RunningTCPApps returns the distinct lowercase exe names of processes holding IPv4 TCP connections — the useful candidates to route.
func RunningTCPApps() []string {
	buf := tcpTable()
	if buf == nil {
		return nil
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	names := map[string]bool{}
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*tcpRowSize
		if off+tcpRowSize > len(buf) {
			break
		}
		pid := *(*uint32)(unsafe.Pointer(&buf[off+20]))
		if n := ProcName(pid); n != "" {
			names[strings.ToLower(n)] = true
		}
	}
	out := make([]string, 0, len(names))
	for n := range names {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ResetAppTCP force-closes (DeleteTCB) the established TCP connections owned by the named processes so they reconnect and the interceptor captures them; returns how many were reset. Needs admin.
func ResetAppTCP(names map[string]bool) int {
	buf := tcpTable()
	if buf == nil {
		return 0
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	reset := 0
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*tcpRowSize
		if off+tcpRowSize > len(buf) {
			break
		}
		if *(*uint32)(unsafe.Pointer(&buf[off])) != mibTCPStateEstablished {
			continue
		}
		pid := *(*uint32)(unsafe.Pointer(&buf[off+20]))
		if !names[strings.ToLower(ProcName(pid))] {
			continue
		}
		// MIB_TCPROW: state, localAddr, localPort, remoteAddr, remotePort.
		row := [5]uint32{
			mibTCPStateDeleteTCB,
			*(*uint32)(unsafe.Pointer(&buf[off+4])),
			*(*uint32)(unsafe.Pointer(&buf[off+8])),
			*(*uint32)(unsafe.Pointer(&buf[off+12])),
			*(*uint32)(unsafe.Pointer(&buf[off+16])),
		}
		if r, _, _ := procSetTcpEntry.Call(uintptr(unsafe.Pointer(&row[0]))); r == 0 {
			reset++
		}
	}
	return reset
}
