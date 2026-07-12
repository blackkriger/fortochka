//go:build windows

package apptunnel

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
	procSetTcpEntry         = iphlpapi.NewProc("SetTcpEntry")
)

const (
	tcpTableOwnerPidAll = 5
	afInet              = 2
	tcpRowSize          = 24

	mibTCPStateEstablished = 5
	mibTCPStateDeleteTCB   = 12
)

// resetAppConnections force-closes the given apps' current TCP connections so they reconnect and the interceptor (which only sees new SYNs) captures them; needs admin (the service is LocalSystem).
func (e *Engine) resetAppConnections(names map[string]bool) {
	buf := tcpTable()
	if buf == nil {
		return
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
		if !names[strings.ToLower(procName(pid))] {
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
	if reset > 0 {
		e.logf("apptunnel: reset %d existing connection(s) to re-route through the tunnel", reset)
	}
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

// tcpPortPIDMap returns a snapshot of local-TCP-port → owning-PID, built off the hot path (a periodic refresh) so the packet loop never blocks on the syscall.
func tcpPortPIDMap() map[uint16]uint32 {
	buf := tcpTable()
	if buf == nil {
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

// RunningNetApps returns the distinct lowercase exe names of processes currently holding IPv4 TCP connections — the useful candidates to route.
func RunningNetApps() []string {
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
		if n := procName(pid); n != "" {
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
