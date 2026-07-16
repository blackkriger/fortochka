//go:build windows

// Package apptunnel transparently forces chosen processes' traffic through a Dialer (the VPN tunnel) via WinDivert, using two network-layer handles. TCP is captured broadly ("outbound and tcp") — safe because the WG tunnel is UDP, so its packets are never touched — and a target's TCP is redirected to a local listener that dials through the tunnel. UDP is captured narrowly, only on the target apps' own source ports (so the tunnel's own UDP is never captured, which would starve the handshake), and NAT-ed through a netstack UDP socket with replies injected back. Needs admin.
package apptunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"fortochka/internal/procnet"
	"fortochka/internal/windivert"
)

const redirPort = 1083

// udpIdleTimeout evicts a UDP flow (and its tunnel socket) after this long with no traffic in either direction, since UDP has no close signal.
const udpIdleTimeout = 120 * time.Second

// maxUDPPorts caps how many UDP source ports the narrow filter lists; voice/games need only a handful, and a huge set would bloat the filter.
const maxUDPPorts = 40

// lowest WinDivert priority + "not impostor": a co-running DPI-bypass tool (zapret) crafts and re-injects first, and we never re-divert its fakes (re-diverting would decrement their TTL and break the bypass). -30000 is the WinDivert floor, so we sit below zapret whatever priority it picks.
const tcpFilter = "outbound and tcp and not impostor"
const tcpPriority int16 = -30000

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type mapping struct {
	appIP   netip.Addr
	dstIP   netip.Addr
	dstPort uint16
}

type udpKey struct {
	appPort uint16
	dstIP   netip.Addr
	dstPort uint16
}

type udpFlow struct {
	appIP    netip.Addr
	appPort  uint16
	dstIP    netip.Addr
	dstPort  uint16
	conn     net.Conn
	injAddr  atomic.Pointer[windivert.Address] // refreshed per outbound packet so replies use the current interface
	lastSeen atomic.Int64
}

type Engine struct {
	dial Dialer
	logf func(string, ...any)

	opMu sync.Mutex // serializes SetApps start/stop so transitions can't interleave

	mu      sync.Mutex
	apps    map[string]bool
	running bool
	ln      net.Listener
	tcpH    windivert.Handle // static broad TCP capture

	udpH atomic.Uintptr // narrow UDP capture handle (target apps' ports only); managed by udpSupervisor

	trackMu sync.Mutex
	tracked map[uint16]mapping
	seen    map[uint16]bool

	portPID    atomic.Pointer[map[uint16]uint32]
	udpPortPID atomic.Pointer[map[uint16]uint32]

	nameMu    sync.Mutex
	nameCache map[uint32]string

	udpMu      sync.Mutex
	udpStopped bool
	udpFlows   map[udpKey]*udpFlow
	udpDirect  map[udpKey]int64
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
	tcpH, err := windivert.Open(tcpFilter, windivert.LayerNetwork, tcpPriority, 0)
	if err != nil {
		ln.Close()
		return fmt.Errorf("tcp capture (need admin / WinDivert?): %w", err)
	}
	firewallRule(true) // allow the redirected (inbound-looking) SYNs to reach us

	e.trackMu.Lock()
	e.tracked = map[uint16]mapping{}
	e.seen = map[uint16]bool{}
	e.trackMu.Unlock()

	e.udpMu.Lock()
	e.udpFlows = map[udpKey]*udpFlow{}
	e.udpDirect = map[udpKey]int64{}
	e.udpStopped = false
	e.udpMu.Unlock()

	tcpInit := procnet.TCPPortPID()
	e.portPID.Store(&tcpInit)
	udpInit := procnet.UDPPortPID()
	e.udpPortPID.Store(&udpInit)

	e.mu.Lock()
	e.ln, e.tcpH, e.running = ln, tcpH, true
	e.mu.Unlock()

	go e.refreshPorts()
	go e.udpSweeper()
	go e.serveRedirect(ln)
	go e.divertPackets(tcpH)
	go e.udpSupervisor()
	e.logf("apptunnel: interception active (redirect :%d; tcp %q pri %d; narrow udp)", redirPort, tcpFilter, tcpPriority)
	return nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	ln, tcpH := e.ln, e.tcpH
	e.ln, e.tcpH = nil, 0
	e.mu.Unlock()

	if tcpH != 0 {
		tcpH.Close()
	}
	if h := windivert.Handle(e.udpH.Swap(0)); h != 0 {
		h.Close()
	}
	if ln != nil {
		ln.Close()
	}

	e.udpMu.Lock()
	e.udpStopped = true
	for k, fl := range e.udpFlows {
		fl.conn.Close()
		delete(e.udpFlows, k)
	}
	e.udpMu.Unlock()

	firewallRule(false)
	e.logf("apptunnel: interception stopped")
}

// RunningNetApps lists processes currently holding TCP connections — the useful candidates to route.
func RunningNetApps() []string { return procnet.RunningTCPApps() }

func (e *Engine) resetAppConnections(names map[string]bool) {
	if n := procnet.ResetAppTCP(names); n > 0 {
		e.logf("apptunnel: reset %d existing connection(s) to re-route through the tunnel", n)
	}
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

// --- narrow UDP capture: a handle scoped to the target apps' UDP source ports, reopened (debounced) when that set changes ---

func (e *Engine) udpSupervisor() {
	t := time.NewTicker(time.Second) // debounce reopens; short enough to pick up a new voice/video port quickly
	defer t.Stop()
	cur := ""
	for {
		e.mu.Lock()
		running := e.running
		e.mu.Unlock()
		if !running {
			if h := windivert.Handle(e.udpH.Swap(0)); h != 0 {
				h.Close()
			}
			return
		}
		if want := e.udpFilter(); want != cur {
			e.reopenUDP(want)
			cur = want
		}
		<-t.C
	}
}

// udpFilter returns a filter matching only the target apps' current UDP source ports, or "" when there are none (no UDP handle).
func (e *Engine) udpFilter() string {
	ports := e.targetUDPPorts()
	if len(ports) == 0 {
		return ""
	}
	terms := make([]string, 0, len(ports))
	for _, p := range ports {
		terms = append(terms, fmt.Sprintf("udp.SrcPort == %d", p))
	}
	return "outbound and udp and (" + strings.Join(terms, " or ") + ")"
}

func (e *Engine) targetUDPPorts() []uint16 {
	snap := e.udpPortPID.Load()
	if snap == nil {
		return nil
	}
	decided := map[uint32]bool{}
	var ports []uint16
	for port, pid := range *snap {
		t, ok := decided[pid]
		if !ok {
			t = pid != 0 && e.targetApp(e.pidName(pid))
			decided[pid] = t
		}
		if t {
			ports = append(ports, port)
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	if len(ports) > maxUDPPorts {
		ports = ports[:maxUDPPorts]
	}
	return ports
}

// reopenUDP swaps the UDP handle to one using filter (or none if filter is ""); the old handle's loop exits when it's closed.
func (e *Engine) reopenUDP(filter string) {
	if h := windivert.Handle(e.udpH.Swap(0)); h != 0 {
		h.Close()
	}
	if filter == "" {
		return
	}
	nh, err := windivert.Open(filter, windivert.LayerNetwork, 0, 0)
	if err != nil {
		e.logf("apptunnel: udp capture open failed (%v)", err)
		return
	}
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		nh.Close()
		return
	}
	e.udpH.Store(uintptr(nh))
	e.mu.Unlock()
	go e.divertPackets(nh)
}

func (e *Engine) pidName(pid uint32) string {
	e.nameMu.Lock()
	defer e.nameMu.Unlock()
	if e.nameCache == nil {
		e.nameCache = map[uint32]string{}
	}
	if n, ok := e.nameCache[pid]; ok {
		return n
	}
	if len(e.nameCache) > 1024 { // bound memory / staleness from PID reuse
		e.nameCache = map[uint32]string{}
	}
	n := strings.ToLower(procnet.ProcName(pid))
	e.nameCache[pid] = n
	return n
}

func (e *Engine) divertPackets(h windivert.Handle) {
	defer func() {
		if r := recover(); r != nil {
			e.logf("apptunnel: packet loop panic: %v", r)
		}
	}()
	buf := make([]byte, 65535)
	var sendErrs int
	var lastErrLog time.Time
	for {
		n, addr, err := h.Recv(buf)
		if err != nil {
			e.logf("apptunnel: packet loop ended: %v", err)
			return // handle closed (reopen or stop)
		}
		p := buf[:n]
		if e.handlePacket(h, p, &addr) {
			if _, err := h.Send(p, &addr); err != nil {
				sendErrs++
				if time.Since(lastErrLog) > 2*time.Second {
					e.logf("apptunnel: reinject failed x%d (last: %v)", sendErrs, err)
					lastErrLog = time.Now()
					sendErrs = 0
				}
			}
		}
	}
}

const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpACK = 0x10
)

// handlePacket decides one captured outbound packet; the returned bool says whether to reinject it (false = drop, because it was consumed into the tunnel).
func (e *Engine) handlePacket(h windivert.Handle, p []byte, addr *windivert.Address) bool {
	if len(p) < 20 || p[0]>>4 != 4 { // IPv4 only
		return true
	}
	proto := p[9]
	if proto != 6 && proto != 17 { // TCP or UDP
		return true
	}
	ihl := int(p[0]&0x0f) * 4
	if len(p) < ihl+8 {
		return true
	}
	srcPort := binary.BigEndian.Uint16(p[ihl:])
	dstPort := binary.BigEndian.Uint16(p[ihl+2:])
	srcIP := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]})
	dstIP := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]})

	if proto == 17 {
		return e.handleUDP(p, addr, ihl, srcIP, srcPort, dstIP, dstPort)
	}
	return e.handleTCP(h, p, addr, ihl, srcIP, srcPort, dstIP, dstPort)
}

func (e *Engine) handleTCP(h windivert.Handle, p []byte, addr *windivert.Address, ihl int, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) bool {
	if len(p) < ihl+14 {
		return true
	}
	flags := p[ihl+13]

	// Case B: redirect listener -> app.
	if srcPort == redirPort {
		e.trackMu.Lock()
		m, ok := e.tracked[dstPort]
		e.trackMu.Unlock()
		if !ok {
			return true
		}
		setIP(p, 12, m.dstIP)
		binary.BigEndian.PutUint16(p[ihl:], m.dstPort)
		setIP(p, 16, m.appIP)
		finish(h, p, addr)
		return true
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
		setIP(p, 12, m.dstIP)
		setIP(p, 16, m.appIP)
		binary.BigEndian.PutUint16(p[ihl+2:], redirPort)
		finish(h, p, addr)
		return true
	}

	if wasSeen {
		if flags&(tcpFIN|tcpRST) != 0 {
			e.trackMu.Lock()
			delete(e.seen, srcPort)
			e.trackMu.Unlock()
		}
		return true // already decided as direct
	}
	if flags&tcpSYN == 0 || flags&tcpACK != 0 || dstIP.IsLoopback() {
		return true // only decide on a fresh SYN to a real destination
	}

	var pid uint32
	if m := e.portPID.Load(); m != nil {
		pid = (*m)[srcPort]
	}
	if pid == 0 {
		if m := procnet.TCPPortPID(); m != nil { // refresh now so a brand-new port isn't leaked direct
			e.portPID.Store(&m)
			pid = m[srcPort]
		}
	}
	target := pid != 0 && e.targetApp(e.pidName(pid))

	e.trackMu.Lock()
	e.seen[srcPort] = true
	if target {
		e.tracked[srcPort] = mapping{appIP: srcIP, dstIP: dstIP, dstPort: dstPort}
	}
	e.trackMu.Unlock()

	if target {
		e.logf("apptunnel: %s owns :%d -> %s:%d (redirect)", e.pidName(pid), srcPort, dstIP, dstPort)
		setIP(p, 12, dstIP)
		setIP(p, 16, srcIP)
		binary.BigEndian.PutUint16(p[ihl+2:], redirPort)
		finish(h, p, addr)
	}
	return true
}

// handleUDP tunnels a target app's UDP by feeding the payload into a per-flow netstack UDP socket (replies come back via udpReader), dropping the original. The narrow UDP filter already limits capture to target ports; the ownership check guards against a port being reused by another process before the filter catches up. On a tunnel write failure the flow is torn down and the datagram is sent direct so the app isn't silently blackholed.
func (e *Engine) handleUDP(p []byte, addr *windivert.Address, ihl int, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) bool {
	if dstIP.IsLoopback() {
		return true // leave loopback (local proxy, local DNS) alone
	}
	key := udpKey{srcPort, dstIP, dstPort}
	now := time.Now().UnixNano()
	payload := p[ihl+8:]

	e.udpMu.Lock()
	fl, ok := e.udpFlows[key]
	_, direct := e.udpDirect[key]
	if ok {
		e.udpMu.Unlock()
		fl.lastSeen.Store(now)
		ac := *addr
		fl.injAddr.Store(&ac)
		if err := nbWrite(fl.conn, payload); err != nil {
			if isTimeout(err) {
				return false // send buffer full: drop this datagram (video is lossy), keep the flow
			}
			e.evictUDP(key, fl)
			return true
		}
		return false
	}
	if direct {
		e.udpDirect[key] = now
		e.udpMu.Unlock()
		return true
	}
	e.udpMu.Unlock()

	pid := e.udpPID(srcPort)
	if pid == 0 || !e.targetApp(e.pidName(pid)) {
		e.udpMu.Lock()
		e.udpDirect[key] = now
		e.udpMu.Unlock()
		return true
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := e.dial.DialContext(ctx, "udp", netip.AddrPortFrom(dstIP, dstPort).String())
	cancel()
	if err != nil {
		e.logf("apptunnel: udp dial %s:%d via tunnel: %v", dstIP, dstPort, err)
		e.udpMu.Lock()
		e.udpDirect[key] = now
		e.udpMu.Unlock()
		return true
	}
	fl = &udpFlow{appIP: srcIP, appPort: srcPort, dstIP: dstIP, dstPort: dstPort, conn: conn}
	fl.lastSeen.Store(now)
	ac := *addr
	fl.injAddr.Store(&ac)

	e.udpMu.Lock()
	if e.udpStopped { // interception stopped while we were dialing — don't leak the flow
		e.udpMu.Unlock()
		conn.Close()
		return true
	}
	if existing, ok := e.udpFlows[key]; ok { // lost a creation race
		e.udpMu.Unlock()
		conn.Close()
		existing.lastSeen.Store(now)
		nbWrite(existing.conn, payload)
		return false
	}
	e.udpFlows[key] = fl
	e.udpMu.Unlock()

	e.logf("apptunnel: %s owns udp :%d -> %s:%d (tunnel)", e.pidName(pid), srcPort, dstIP, dstPort)
	go e.udpReader(key, fl)
	nbWrite(conn, payload)
	return false
}

// nbWrite sends a datagram without blocking the single packet loop: a past write deadline makes Write drop (timeout) instead of stalling when the tunnel's send buffer is full under high bitrate (screen share).
func nbWrite(c net.Conn, b []byte) error {
	c.SetWriteDeadline(time.Now())
	_, err := c.Write(b)
	return err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (e *Engine) evictUDP(key udpKey, fl *udpFlow) {
	e.udpMu.Lock()
	if e.udpFlows[key] == fl {
		delete(e.udpFlows, key)
	}
	e.udpMu.Unlock()
	fl.conn.Close() // unblocks its reader
}

// udpReader relays tunnel-side replies for one flow back to the app as inbound UDP until the socket is closed (by the sweeper on idle, on a write failure, or on Stop). The packet buffer is reused across replies.
func (e *Engine) udpReader(key udpKey, fl *udpFlow) {
	buf := make([]byte, 65535)
	pkt := make([]byte, 65535)
	for {
		n, err := fl.conn.Read(buf)
		if err != nil {
			break
		}
		fl.lastSeen.Store(time.Now().UnixNano())
		e.injectUDPReply(fl, pkt, buf[:n])
	}
	e.udpMu.Lock()
	if e.udpFlows[key] == fl {
		delete(e.udpFlows, key)
	}
	e.udpMu.Unlock()
	fl.conn.Close()
}

// buildUDPReply writes an inbound UDP/IP datagram (from server srcIP:srcPort to app dstIP:dstPort) into pkt and returns its length, or -1 if pkt is too small. pkt is reused across replies, so the header is cleared first.
func buildUDPReply(pkt []byte, srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) int {
	total := 28 + len(payload) // 20 IPv4 + 8 UDP
	if total > len(pkt) {
		return -1
	}
	p := pkt[:total]
	for i := 0; i < 28; i++ {
		p[i] = 0
	}
	p[0] = 0x45 // IPv4, IHL 5
	binary.BigEndian.PutUint16(p[2:], uint16(total))
	p[8] = 64 // TTL
	p[9] = 17 // UDP
	setIP(p, 12, srcIP)
	setIP(p, 16, dstIP)
	binary.BigEndian.PutUint16(p[20:], srcPort)
	binary.BigEndian.PutUint16(p[22:], dstPort)
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload)
	return total
}

// injectUDPReply builds the reply into the reusable pkt buffer and injects it through the current UDP handle so the app sees it as if it came direct.
func (e *Engine) injectUDPReply(fl *udpFlow, pkt, payload []byte) {
	h := windivert.Handle(e.udpH.Load())
	if h == 0 {
		return
	}
	n := buildUDPReply(pkt, fl.dstIP, fl.appIP, fl.dstPort, fl.appPort, payload)
	if n < 0 {
		return
	}
	ap := fl.injAddr.Load()
	if ap == nil {
		return
	}
	a := *ap
	a.SetOutbound(false)
	a.ClearChecksums()
	h.CalcChecksums(pkt[:n], &a, 0)
	h.Send(pkt[:n], &a)
}

// udpSweeper closes idle UDP flows (their reader then cleans up) and prunes stale direct-decision entries.
func (e *Engine) udpSweeper() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for range t.C {
		e.mu.Lock()
		running := e.running
		e.mu.Unlock()
		if !running {
			return
		}
		cutoff := time.Now().Add(-udpIdleTimeout).UnixNano()
		var dead []net.Conn
		e.udpMu.Lock()
		for k, fl := range e.udpFlows {
			if fl.lastSeen.Load() < cutoff {
				dead = append(dead, fl.conn)
				delete(e.udpFlows, k)
			}
		}
		for k, ts := range e.udpDirect {
			if ts < cutoff {
				delete(e.udpDirect, k)
			}
		}
		e.udpMu.Unlock()
		for _, c := range dead {
			c.Close()
		}
	}
}

func (e *Engine) udpPID(port uint16) uint32 {
	if m := e.udpPortPID.Load(); m != nil {
		if pid := (*m)[port]; pid != 0 {
			return pid
		}
	}
	m := procnet.UDPPortPID()
	if m == nil {
		return 0
	}
	e.udpPortPID.Store(&m)
	return m[port]
}

func finish(h windivert.Handle, p []byte, addr *windivert.Address) {
	addr.SetOutbound(false) // inject as inbound so the local stack receives it
	addr.ClearChecksums()
	h.CalcChecksums(p, addr, 0)
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
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		e.mu.Lock()
		running := e.running
		e.mu.Unlock()
		if !running {
			return
		}
		if m := procnet.TCPPortPID(); m != nil {
			e.portPID.Store(&m)
		}
		if m := procnet.UDPPortPID(); m != nil {
			e.udpPortPID.Store(&m)
		}
	}
}
