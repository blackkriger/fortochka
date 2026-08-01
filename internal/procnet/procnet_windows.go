//go:build windows

// Package procnet maps local TCP/UDP ports to the owning process (via the IP Helper API) and resolves process names, so both the per-app interceptor and the proxy can tell which process a connection belongs to.
package procnet

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
	procSetTcpEntry         = iphlpapi.NewProc("SetTcpEntry")

	versiondll                 = windows.NewLazySystemDLL("version.dll")
	procGetFileVersionInfoSize = versiondll.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = versiondll.NewProc("GetFileVersionInfoW")
	procVerQueryValue          = versiondll.NewProc("VerQueryValueW")
)

const (
	tcpTableOwnerPidAll = 5
	udpTableOwnerPid    = 1
	afInet              = 2
	afInet6             = 23
	tcpRowSize          = 24 // MIB_TCPROW_OWNER_PID
	udpRowSize          = 12 // MIB_UDPROW_OWNER_PID
	tcp6RowSize         = 56 // MIB_TCP6ROW_OWNER_PID
	udp6RowSize         = 28 // MIB_UDP6ROW_OWNER_PID

	mibTCPStateEstablished = 5
	mibTCPStateDeleteTCB   = 12
)

// ProcName returns the exe base name for a PID ("" if unknown).
func ProcName(pid uint32) string {
	name, _ := procNameAndPath(pid)
	return name
}

// procNameAndPath returns the exe base name and full path for a PID ("" if unknown).
func procNameAndPath(pid uint32) (name, path string) {
	if pid == 0 {
		return "", ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return "", ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 260)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", ""
	}
	full := windows.UTF16ToString(buf[:n])
	name = full
	if i := strings.LastIndexByte(full, '\\'); i >= 0 {
		name = full[i+1:]
	}
	return name, full
}

// extendedTable sizes then fetches a connection table, retrying when the table grew in between — returning nil there would make callers treat a connection as unowned and route it wrong.
func extendedTable(proc *windows.LazyProc, family, tableClass uintptr) []byte {
	var size uint32
	for attempt := 0; attempt < 4; attempt++ {
		proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, family, tableClass, 0)
		if size == 0 {
			return nil
		}
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, family, tableClass, 0)
		if r == 0 {
			return buf
		}
		if r != uintptr(windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil
		}
	}
	return nil
}

func tcpTable() []byte { return extendedTable(procGetExtendedTcpTable, afInet, tcpTableOwnerPidAll) }

func udpTable() []byte { return extendedTable(procGetExtendedUdpTable, afInet, udpTableOwnerPid) }

// portPID walks a table whose rows carry the local port and owning PID at fixed offsets.
func portPID(buf []byte, rowSize, portOff, pidOff int) map[uint16]uint32 {
	if len(buf) < 4 {
		return nil
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	m := make(map[uint16]uint32, num)
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*rowSize
		if off+rowSize > len(buf) {
			break
		}
		port := binary.BigEndian.Uint16(buf[off+portOff : off+portOff+2])
		if pid := *(*uint32)(unsafe.Pointer(&buf[off+pidOff])); pid != 0 { // an unowned row (TIME_WAIT reports PID 0) must not erase the live owner of the same port
			m[port] = pid
		}
	}
	return m
}

// TCP6PortPID snapshots local-IPv6-TCP-port → owning-PID.
func TCP6PortPID() map[uint16]uint32 {
	return portPID(extendedTable(procGetExtendedTcpTable, afInet6, tcpTableOwnerPidAll), tcp6RowSize, 20, 52)
}

// UDP6PortPID snapshots local-IPv6-UDP-port → owning-PID.
func UDP6PortPID() map[uint16]uint32 {
	return portPID(extendedTable(procGetExtendedUdpTable, afInet6, udpTableOwnerPid), udp6RowSize, 20, 24)
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
		if pid := *(*uint32)(unsafe.Pointer(&buf[off+20])); pid != 0 { // an unowned row (TIME_WAIT reports PID 0) must not erase the live owner of the same port
			m[port] = pid
		}
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
		if pid := *(*uint32)(unsafe.Pointer(&buf[off+8])); pid != 0 {
			m[port] = pid
		}
	}
	return m
}

// RunningTCPApps returns the distinct lowercase exe names of processes holding IPv4 TCP connections — the useful candidates to route.
func RunningTCPApps() []string {
	buf := tcpTable()
	if len(buf) < 4 {
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

var (
	displayMu    sync.Mutex
	displayCache = map[string]string{} // full exe path -> display name
)

// RunningTCPAppsNamed maps each running TCP app's lowercase exe base name to a display name (the exe's FileDescription, else a prettified base name).
func RunningTCPAppsNamed() map[string]string {
	buf := tcpTable()
	if len(buf) < 4 {
		return nil
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	out := map[string]string{}
	seen := map[uint32]bool{} // many rows share a PID; resolving each one would cost an OpenProcess per row
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*tcpRowSize
		if off+tcpRowSize > len(buf) {
			break
		}
		pid := *(*uint32)(unsafe.Pointer(&buf[off+20]))
		if pid == 0 || seen[pid] {
			continue
		}
		seen[pid] = true
		name, path := procNameAndPath(pid)
		if name == "" {
			continue
		}
		low := strings.ToLower(name)
		if _, ok := out[low]; !ok {
			out[low] = displayName(path, low)
		}
	}
	return out
}

// displayName resolves a friendly name for an exe, cached by path since it never changes.
func displayName(path, exe string) string {
	if path == "" {
		return prettyName(exe)
	}
	displayMu.Lock()
	v, ok := displayCache[path]
	displayMu.Unlock()
	if ok {
		return v
	}
	d := fileDescription(path) // resolved outside the lock: it reads the exe, which can stall on a network or removable path
	if d == "" {
		d = prettyName(exe)
	}
	displayMu.Lock()
	if len(displayCache) >= 1024 { // bound memory: versioned/temp exe paths would otherwise accumulate forever
		displayCache = map[string]string{}
	}
	displayCache[path] = d
	displayMu.Unlock()
	return d
}

// prettyName turns "discord.exe" into "Discord" when no FileDescription is available.
func prettyName(exe string) string {
	n := strings.TrimSuffix(exe, ".exe")
	if n == "" {
		return exe
	}
	r := []rune(n)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

// fileDescription reads the FileDescription string from an exe's version resource ("" if absent).
func fileDescription(path string) string {
	if path == "" {
		return ""
	}
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	size, _, _ := procGetFileVersionInfoSize.Call(uintptr(unsafe.Pointer(p16)), 0)
	if size == 0 {
		return ""
	}
	buf := make([]byte, size)
	if r, _, _ := procGetFileVersionInfo.Call(uintptr(unsafe.Pointer(p16)), 0, size, uintptr(unsafe.Pointer(&buf[0]))); r == 0 {
		return ""
	}
	var block unsafe.Pointer
	var blockLen uint32
	trans16, _ := windows.UTF16PtrFromString(`\VarFileInfo\Translation`)
	if r, _, _ := procVerQueryValue.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(trans16)), uintptr(unsafe.Pointer(&block)), uintptr(unsafe.Pointer(&blockLen))); r == 0 || blockLen < 4 {
		return ""
	}
	lang := *(*uint16)(block)
	cp := *(*uint16)(unsafe.Add(block, 2))
	query, _ := windows.UTF16PtrFromString(fmt.Sprintf(`\StringFileInfo\%04x%04x\FileDescription`, lang, cp))
	var val unsafe.Pointer
	var valLen uint32
	r, _, _ := procVerQueryValue.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(query)), uintptr(unsafe.Pointer(&val)), uintptr(unsafe.Pointer(&valLen)))
	if r == 0 || valLen == 0 {
		return ""
	}
	s := windows.UTF16ToString(unsafe.Slice((*uint16)(val), valLen))
	runtime.KeepAlive(buf)
	return strings.TrimSpace(s)
}

// ResetAppTCP force-closes (DeleteTCB) the established TCP connections owned by the named processes so they reconnect and the interceptor captures them; returns how many were reset. Needs admin.
func ResetAppTCP(names map[string]bool) int {
	buf := tcpTable()
	if len(buf) < 4 {
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
