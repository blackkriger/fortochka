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
	tcpRowSize          = 24 // MIB_TCPROW_OWNER_PID
	udpRowSize          = 12 // MIB_UDPROW_OWNER_PID

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

var displayCache sync.Map // full exe path -> display name

// RunningTCPAppsNamed maps each running TCP app's lowercase exe base name to a display name (the exe's FileDescription, else a prettified base name).
func RunningTCPAppsNamed() map[string]string {
	buf := tcpTable()
	if buf == nil {
		return nil
	}
	num := *(*uint32)(unsafe.Pointer(&buf[0]))
	out := map[string]string{}
	for i := uint32(0); i < num; i++ {
		off := 4 + int(i)*tcpRowSize
		if off+tcpRowSize > len(buf) {
			break
		}
		pid := *(*uint32)(unsafe.Pointer(&buf[off+20]))
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
	if path != "" {
		if v, ok := displayCache.Load(path); ok {
			return v.(string)
		}
	}
	d := fileDescription(path)
	if d == "" {
		d = prettyName(exe)
	}
	if path != "" {
		displayCache.Store(path, d)
	}
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
