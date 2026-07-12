//go:build windows

// Package apptunnel transparently forces chosen processes' TCP through a Dialer (the VPN tunnel) via WinDivert: a network-layer handle captures outbound TCP, and on a target's SYN the flow is redirected to a local listener that dials the real destination through the tunnel. Needs admin.
package apptunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"fortochka/internal/windivert"
)

const redirPort = 1083

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type mapping struct {
	appIP   netip.Addr
	dstIP   netip.Addr
	dstPort uint16
}

type Engine struct {
	dial Dialer
	logf func(string, ...any)

	opMu sync.Mutex // serializes SetApps start/stop so transitions can't interleave

	mu      sync.Mutex
	apps    map[string]bool
	running bool
	netH    windivert.Handle
	ln      net.Listener

	trackMu sync.Mutex
	tracked map[uint16]mapping // target local ports -> destination
	seen    map[uint16]bool    // ports already evaluated (target or not)

	portPID atomic.Pointer[map[uint16]uint32] // port→pid snapshot, refreshed off the hot path
}

func New(dial Dialer, logf func(string, ...any)) *Engine {
	return &Engine{dial: dial, logf: logf, apps: map[string]bool{}}
}

// SetApps replaces the target set (lowercase exe base names) and starts/stops interception to match; opMu serializes the transition so concurrent callers can't double-start or invert it.
func (e *Engine) SetApps(names []string) {
	e.opMu.Lock()
	defer e.opMu.Unlock()

	e.mu.Lock()
	old := e.apps
	e.apps = map[string]bool{}
	added := map[string]bool{}
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			e.apps[n] = true
			if !old[n] {
				added[n] = true
			}
		}
	}
	want := len(e.apps) > 0
	running := e.running
	e.mu.Unlock()

	switch {
	case want && !running:
		if err := e.start(); err != nil {
			e.logf("apptunnel: start failed (need admin?): %v", err)
		}
	case !want && running:
		e.Stop()
	}
	e.mu.Lock()
	active := e.running
	e.mu.Unlock()
	if active && len(added) > 0 {
		go e.resetAppConnections(added) // pull the newly-added apps into the tunnel
	}
}

func (e *Engine) targetApp(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.apps[name]
}

func (e *Engine) start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", redirPort))
	if err != nil {
		return fmt.Errorf("redirect listener: %w", err)
	}
	netH, err := windivert.Open("outbound and tcp", windivert.LayerNetwork, 0, 0)
	if err != nil {
		ln.Close()
		return fmt.Errorf("network layer: %w", err)
	}
	firewallRule(true) // allow the redirected (inbound-looking) SYNs to reach us

	e.trackMu.Lock()
	e.tracked = map[uint16]mapping{}
	e.seen = map[uint16]bool{}
	e.trackMu.Unlock()

	e.mu.Lock()
	e.ln, e.netH, e.running = ln, netH, true
	e.mu.Unlock()

	initial := tcpPortPIDMap()
	e.portPID.Store(&initial)

	go e.refreshPorts()
	go e.serveRedirect(ln)
	go e.divertPackets(netH)
	e.logf("apptunnel: interception active (redirect :%d)", redirPort)
	return nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	ln, netH := e.ln, e.netH
	e.ln, e.netH = nil, 0
	e.mu.Unlock()

	if netH != 0 {
		netH.Close() // closing returns captured traffic to the system
	}
	if ln != nil {
		ln.Close()
	}
	firewallRule(false)
	e.logf("apptunnel: interception stopped")
}

func firewallRule(add bool) {
	args := []string{"advfirewall", "firewall", "add", "rule", "name=fortochka-redirect",
		"dir=in", "action=allow", "protocol=TCP", "localport=1083"}
	if !add {
		args = []string{"advfirewall", "firewall", "delete", "rule", "name=fortochka-redirect"}
	}
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	cmd.Run()
}

func (e *Engine) divertPackets(h windivert.Handle) {
	defer func() {
		if r := recover(); r != nil {
			e.logf("apptunnel: packet loop panic: %v", r)
		}
	}()
	buf := make([]byte, 65535)
	total := 0
	for {
		n, addr, err := h.Recv(buf)
		if err != nil {
			e.logf("apptunnel: packet loop ended after %d packets: %v", total, err)
			return
		}
		total++
		p := buf[:n]
		e.handlePacket(p, &addr)
		if _, err := h.Send(p, &addr); err != nil {
			e.logf("apptunnel: reinject: %v", err)
		}
	}
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

func (e *Engine) handlePacket(p []byte, addr *windivert.Address) {
	if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 { // IPv4 TCP only
		return
	}
	ihl := int(p[0]&0x0f) * 4
	if len(p) < ihl+14 {
		return
	}
	srcPort := binary.BigEndian.Uint16(p[ihl:])
	dstPort := binary.BigEndian.Uint16(p[ihl+2:])
	flags := p[ihl+13]
	srcIP := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]})
	dstIP := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})

	// Case B: redirect listener -> app.
	if srcPort == redirPort {
		e.trackMu.Lock()
		m, ok := e.tracked[dstPort]
		e.trackMu.Unlock()
		if !ok {
			return
		}
		e.logf("apptunnel: [B] reply -> app port %d", dstPort)
		setIP(p, 12, m.dstIP)
		binary.BigEndian.PutUint16(p[ihl:], m.dstPort)
		setIP(p, 16, m.appIP)
		finish(e, p, addr)
		return
	}

	e.trackMu.Lock()
	m, isTarget := e.tracked[srcPort]
	wasSeen := e.seen[srcPort]
	e.trackMu.Unlock()

	// Case A: known target flow.
	if isTarget {
		if flags&(tcpFIN|tcpRST) != 0 {
			e.trackMu.Lock()
			delete(e.tracked, srcPort)
			delete(e.seen, srcPort)
			e.trackMu.Unlock()
		}
		e.logf("apptunnel: [A] sp=%d -> %s:%d", srcPort, m.dstIP, m.dstPort)
		setIP(p, 12, m.dstIP)
		setIP(p, 16, m.appIP)
		binary.BigEndian.PutUint16(p[ihl+2:], redirPort)
		finish(e, p, addr)
		return
	}

	if wasSeen {
		if flags&(tcpFIN|tcpRST) != 0 {
			e.trackMu.Lock()
			delete(e.seen, srcPort)
			e.trackMu.Unlock()
		}
		return // already decided as direct
	}
	if flags&tcpSYN == 0 || flags&tcpACK != 0 || dstIP.IsLoopback() {
		return // only decide on a fresh SYN to a real destination
	}

	var pid uint32
	if m := e.portPID.Load(); m != nil {
		pid = (*m)[srcPort]
	}
	if pid == 0 {
		if m := tcpPortPIDMap(); m != nil { // refresh now so a brand-new port isn't leaked direct
			e.portPID.Store(&m)
			pid = m[srcPort]
		}
	}
	if pid == 0 {
		return
	}
	name := strings.ToLower(procName(pid))
	target := name != "" && e.targetApp(name)

	e.trackMu.Lock()
	e.seen[srcPort] = true
	if target {
		e.tracked[srcPort] = mapping{appIP: srcIP, dstIP: dstIP, dstPort: dstPort}
	}
	e.trackMu.Unlock()

	if target {
		e.logf("apptunnel: %s owns :%d -> %s:%d (redirect)", name, srcPort, dstIP, dstPort)
		setIP(p, 12, dstIP)
		setIP(p, 16, srcIP)
		binary.BigEndian.PutUint16(p[ihl+2:], redirPort)
		finish(e, p, addr)
	}
}

func finish(e *Engine, p []byte, addr *windivert.Address) {
	addr.SetOutbound(false) // inject as inbound so the local stack receives it
	addr.ClearChecksums()
	e.netH.CalcChecksums(p, addr, 0)
}

func setIP(p []byte, off int, ip netip.Addr) {
	a := ip.As4()
	copy(p[off:off+4], a[:])
}

func (e *Engine) serveRedirect(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go e.handleRedirect(c)
	}
}

func (e *Engine) handleRedirect(c net.Conn) {
	defer c.Close()
	e.logf("apptunnel: ACCEPTED redirect from %s", c.RemoteAddr())
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	appPort := uint16(ra.Port)
	e.trackMu.Lock()
	m, found := e.tracked[appPort]
	e.trackMu.Unlock()
	if !found {
		e.logf("apptunnel: redirect from :%d has no mapping", appPort)
		return
	}
	target := net.JoinHostPort(m.dstIP.String(), fmt.Sprint(m.dstPort))
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	up, err := e.dial.DialContext(ctx, "tcp", target)
	if err != nil {
		e.logf("apptunnel: dial %s via tunnel: %v", target, err)
		return
	}
	defer up.Close()
	e.logf("apptunnel: %s -> tunnel", target)
	done := make(chan struct{}, 2)
	go func() { io.Copy(up, c); done <- struct{}{} }()
	go func() { io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func (e *Engine) refreshPorts() {
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		e.mu.Lock()
		running := e.running
		e.mu.Unlock()
		if !running {
			return
		}
		m := tcpPortPIDMap()
		e.portPID.Store(&m)
	}
}

func procName(pid uint32) string {
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
