//go:build windows

// Package windivert is a minimal binding to the WinDivert user-mode API (github.com/basil00/WinDivert); needs WinDivert.dll + WinDivert64.sys next to the executable and admin rights (the driver loads on first Open).
package windivert

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	LayerNetwork = 0
	LayerFlow    = 2
	LayerSocket  = 3

	FlagSniff    = 0x0001
	FlagRecvOnly = 0x0004

	EventNetworkPacket   = 0
	EventFlowEstablished = 1
	EventFlowDeleted     = 2
	EventSocketConnect   = 4
	EventSocketClose     = 7
)

var (
	dll               = windows.NewLazyDLL("WinDivert.dll")
	procOpen          = dll.NewProc("WinDivertOpen")
	procRecv          = dll.NewProc("WinDivertRecv")
	procSend          = dll.NewProc("WinDivertSend")
	procClose         = dll.NewProc("WinDivertClose")
	procCalcChecksums = dll.NewProc("WinDivertHelperCalcChecksums")
)

// Address is WINDIVERT_ADDRESS (80 bytes): timestamp + packed flags + reserved + a 64-byte union whose meaning depends on the layer.
type Address struct {
	Timestamp int64
	packed    uint32
	Reserved2 uint32
	Union     [64]byte
}

func (a *Address) Layer() uint8   { return uint8(a.packed & 0xFF) }
func (a *Address) Event() uint8   { return uint8((a.packed >> 8) & 0xFF) }
func (a *Address) Outbound() bool { return (a.packed>>17)&1 == 1 }
func (a *Address) Loopback() bool { return (a.packed>>18)&1 == 1 }

func (a *Address) SetOutbound(v bool) {
	if v {
		a.packed |= 1 << 17
	} else {
		a.packed &^= 1 << 17
	}
}

// ClearChecksums marks the IP/TCP/UDP checksums invalid so a following CalcChecksums recomputes them (needed after editing addresses).
func (a *Address) ClearChecksums() {
	a.packed &^= (1<<21 | 1<<22 | 1<<23)
}

// Socket is the union view for the SOCKET layer (same layout as FlowData).
func (a *Address) Socket() *FlowData {
	return (*FlowData)(unsafe.Pointer(&a.Union[0]))
}

// FlowData is WINDIVERT_DATA_FLOW (union view for the FLOW layer).
type FlowData struct {
	EndpointID       uint64
	ParentEndpointID uint64
	ProcessID        uint32
	LocalAddr        [4]uint32
	RemoteAddr       [4]uint32
	LocalPort        uint16
	RemotePort       uint16
	Protocol         uint8
	_                [7]uint8
}

func (a *Address) Flow() *FlowData {
	return (*FlowData)(unsafe.Pointer(&a.Union[0]))
}

type Handle uintptr

const invalidHandle = ^uintptr(0)

// Open wraps WinDivertOpen. For the FLOW layer use flags Sniff|RecvOnly.
func Open(filter string, layer int, priority int16, flags uint64) (Handle, error) {
	f, err := windows.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	r, _, e := procOpen.Call(
		uintptr(unsafe.Pointer(f)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r == invalidHandle {
		return 0, fmt.Errorf("WinDivertOpen: %w", e)
	}
	return Handle(r), nil
}

// Recv reads one event. For the FLOW layer pass a nil packet buffer.
func (h Handle) Recv(packet []byte) (n uint, addr Address, err error) {
	var recvLen uint32
	var p uintptr
	if len(packet) > 0 {
		p = uintptr(unsafe.Pointer(&packet[0]))
	}
	r, _, e := procRecv.Call(
		uintptr(h),
		p,
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r == 0 {
		return 0, addr, fmt.Errorf("WinDivertRecv: %w", e)
	}
	return uint(recvLen), addr, nil
}

// Send re-injects a packet (NETWORK layer).
func (h Handle) Send(packet []byte, addr *Address) (uint, error) {
	var sendLen uint32
	var p uintptr
	if len(packet) > 0 {
		p = uintptr(unsafe.Pointer(&packet[0]))
	}
	r, _, e := procSend.Call(
		uintptr(h),
		p,
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r == 0 {
		return 0, fmt.Errorf("WinDivertSend: %w", e)
	}
	return uint(sendLen), nil
}

// CalcChecksums recomputes IP/TCP/UDP checksums after editing a packet.
func (h Handle) CalcChecksums(packet []byte, addr *Address, flags uint64) {
	if len(packet) == 0 {
		return
	}
	procCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(addr)),
		uintptr(flags),
	)
}

func (h Handle) Close() error {
	r, _, e := procClose.Call(uintptr(h))
	if r == 0 {
		return e
	}
	return nil
}
