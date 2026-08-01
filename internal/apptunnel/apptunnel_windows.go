//go:build windows

// Package apptunnel transparently forces chosen processes' traffic through a Dialer (the VPN tunnel) via WinDivert, using two network-layer handles. TCP is captured broadly ("outbound and tcp") — safe because the WG tunnel is UDP, so its packets are never touched — and a target's TCP is redirected to a local listener that dials through the tunnel. UDP is captured narrowly, only on the target apps' own source ports (so the tunnel's own UDP is never captured, which would starve the handshake), and NAT-ed through a netstack UDP socket with replies injected back. Needs admin.
package apptunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"os"
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

// lowest WinDivert priority + "not impostor": a co-running DPI-bypass tool (zapret) crafts and re-injects first, and we never re-divert its fakes (re-diverting would decrement their TTL and break the bypass). -30000 is the WinDivert floor, so we sit below zapret whatever priority it picks.
const tcpFilter = "outbound and tcp and not impostor"

const divertPriority int16 = -30000

// maxUDPPorts bounds the per-port UDP filter. It stays scoped to the routed apps' own ports on purpose: capturing all UDP would push every QUIC and voice datagram on the machine through userspace and put us in the path of a co-running DPI-bypass tool. WinDivert compiles a filter to a bounded number of instructions, so the OR-chain cannot grow without limit; 120 is far above what voice and games actually use.
const maxUDPPorts = 120

// selfPID identifies this process so the tunnel's own encrypted datagrams are never captured, which would starve the handshake.
var selfPID = uint32(os.Getpid())

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var errHandleClosed = errors.New("windivert: handle closed")

// divHandle guards injections so a send can never run on a value that was already closed — Windows reuses handle numbers, so that write could land on an unrelated object. Recv is deliberately unguarded: closing the handle is what unblocks it.
type divHandle struct {
	mu     sync.RWMutex
	h      windivert.Handle
	closed bool
}

func newDivHandle(h windivert.Handle) *divHandle { return &divHandle{h: h} }

func (d *divHandle) send(p []byte, a *windivert.Address) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return errHandleClosed
	}
	_, err := d.h.Send(p, a)
	return err
}

// recv copies the handle out before blocking, since holding the lock across a receive would stall the close that is meant to unblock it.
func (d *divHandle) recv(buf []byte) (uint, windivert.Address, error) {
	d.mu.RLock()
	h, closed := d.h, d.closed
	d.mu.RUnlock()
	if closed {
		return 0, windivert.Address{}, errHandleClosed
	}
	return h.Recv(buf)
}

// calcChecksums needs no live handle (WinDivertHelperCalcChecksums is a pure helper), so it stays safe after close.
func (d *divHandle) calcChecksums(p []byte, a *windivert.Address) { d.h.CalcChecksums(p, a, 0) }

func (d *divHandle) isClosed() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.closed
}

func (d *divHandle) close() {
	d.mu.Lock()
	if !d.closed {
		d.closed = true
		d.h.Close()
	}
	d.mu.Unlock()
}

type mapping struct {
	appIP   netip.Addr
	dstIP   netip.Addr
	dstPort uint16
	pid     uint32 // owner at decision time, so a recycled port isn't matched against a stale mapping
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

// stats are cheap counters emitted periodically so a later log read shows whether the tunnel path actually carried traffic and where packets were lost.
type stats struct {
	udpOut     atomic.Uint64 // app -> tunnel datagrams
	udpIn      atomic.Uint64 // tunnel -> app datagrams
	udpDrop    atomic.Uint64 // dropped because the tunnel send buffer was full
	udpDialErr atomic.Uint64
	tcpRouted  atomic.Uint64 // connections handed to the tunnel
	sendClosed atomic.Uint64 // injection hit a closed handle, i.e. the guard caught a reopen/stop race
	sendErr    atomic.Uint64
	pruned     atomic.Uint64 // stale per-port decisions swept
	v6Blocked  atomic.Uint64 // routed apps' IPv6 dropped: the tunnel is IPv4-only, so passing it would leak
	tcpDirect  atomic.Uint64 // connections decided direct (not a routed app)
	reSYN      atomic.Uint64 // a fresh SYN retired a stale decision for that port
	redirOK    atomic.Uint64
	redirNoMap atomic.Uint64 // reached the listener with no mapping
	redirDeny  atomic.Uint64 // source did not match the mapping
	redirDial  atomic.Uint64 // tunnel dial failed
	udpUnknown atomic.Uint64 // dropped because the owner could not be resolved
}

type Engine struct {
	dial Dialer
	logf func(string, ...any)

	// Ready reports whether the tunnel can actually carry traffic. Without it a reconnecting tunnel turns every redirected connection into a 20s stall; with it the app fails immediately and retries, and nothing escapes in the clear.
	Ready func() bool

	st           stats
	lastStatSum  atomic.Uint64 // a stopped generation's sweeper can briefly overlap the new one
	v6RefreshAt  atomic.Int64  // throttles the on-miss IPv6 table walk
	udpRefreshAt atomic.Int64  // throttles the on-miss UDP table walk
	lastDialLog  atomic.Int64  // rate-limits the fail-closed log so a dead tunnel can't turn voice traffic into a write-per-datagram storm
	lastDialFail atomic.Int64  // suppresses repeat dials while the tunnel is down

	opMu sync.Mutex // serializes SetApps start/stop so transitions can't interleave

	mu           sync.Mutex
	apps         map[string]bool
	lastSel      map[string]bool // last selection, so a tunnel flap doesn't make every app look freshly added
	pendingReset map[string]bool // apps whose interception was paused: their sockets reconnected direct meanwhile and must be pulled back in
	running      bool
	gen          uint64 // bumped per start() so background goroutines from a previous run exit instead of fighting the current one
	ln           net.Listener
	tcpH         *divHandle // static broad TCP capture

	udpH atomic.Pointer[divHandle] // narrow UDP capture handle (target apps' ports only); managed by udpSupervisor

	connMu    sync.Mutex
	redirects map[net.Conn]net.Conn // accepted app side -> tunnel side, so a stop can close them instead of leaving their teardown to escape the tunnel

	trackMu   sync.Mutex
	tracked   map[uint16]mapping
	seen      map[uint16]uint32 // local port -> owning PID at decision time (0 when it could not be resolved)
	trackMiss map[uint16]int

	portPID     atomic.Pointer[map[uint16]uint32]
	udpPortPID  atomic.Pointer[map[uint16]uint32]
	portPID6    atomic.Pointer[map[uint16]uint32]
	udpPortPID6 atomic.Pointer[map[uint16]uint32]

	nameMu    sync.Mutex
	nameCache map[uint32]string
	nameBad   map[uint32]time.Time // short-lived negative entries, so a failed lookup neither storms nor sticks

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
	old := e.lastSel
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
	for n := range e.pendingReset { // paused apps reconnected outside the tunnel; leaving them would be a silent bypass
		if e.apps[n] {
			added[n] = true
		}
	}
	running := e.running
	e.mu.Unlock()

	switch {
	case want && !running:
		if err := e.start(); err != nil {
			e.logf("apptunnel: start failed (need admin?): %v", err)
		}
	case !want && running:
		e.stopLocked()
	}
	e.udpMu.Lock()
	e.udpDirect = map[udpKey]int64{} // the selection changed, so cached direct decisions must be re-made or a newly routed app keeps bypassing
	e.udpMu.Unlock()
	e.mu.Lock()
	active := e.running
	if active || !want {
		e.pendingReset = nil
	} else {
		// Start failed: carry these apps so a later successful start still pulls their connections in, while lastSel below keeps every reconcile in the meantime from re-resetting them.
		e.pendingReset = maps.Clone(e.apps)
	}
	e.lastSel = maps.Clone(e.apps)
	e.mu.Unlock()
	if active && len(added) > 0 {
		go e.resetAppConnections(added) // pull the newly-added apps into the tunnel
	}
}

// Suspend stops interception but records which apps were routed, so resuming pulls exactly those back in (their sockets reconnected outside the tunnel meanwhile) instead of treating every app as freshly selected.
func (e *Engine) Suspend() {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.mu.Lock()
	if len(e.apps) > 0 {
		e.pendingReset = maps.Clone(e.apps)
	}
	e.apps = map[string]bool{}
	running := e.running
	e.mu.Unlock()
	if running {
		e.stopLocked()
	}
}

func (e *Engine) targetApp(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.apps[name]
}

// Active reports whether interception is running, so the daemon can tell a paused engine from one that merely has no apps.
func (e *Engine) Active() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

func (e *Engine) anyApps() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.apps) > 0
}

func (e *Engine) start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", redirPort))
	if err != nil {
		return fmt.Errorf("redirect listener: %w", err)
	}
	rawTCP, err := windivert.Open(tcpFilter, windivert.LayerNetwork, divertPriority, 0)
	if err != nil {
		ln.Close()
		return fmt.Errorf("tcp capture (need admin / WinDivert?): %w", err)
	}
	tcpH := newDivHandle(rawTCP)
	e.trackMu.Lock()
	e.tracked = map[uint16]mapping{}
	e.seen = map[uint16]uint32{}
	e.trackMiss = map[uint16]int{}
	e.trackMu.Unlock()

	e.udpMu.Lock()
	e.udpFlows = map[udpKey]*udpFlow{}
	e.udpDirect = map[udpKey]int64{}
	e.udpStopped = false
	e.udpMu.Unlock()

	e.connMu.Lock()
	e.redirects = map[net.Conn]net.Conn{}
	e.connMu.Unlock()

	e.refreshSnapshots()

	e.mu.Lock()
	e.gen++
	gen := e.gen
	e.ln, e.tcpH, e.running = ln, tcpH, true
	e.mu.Unlock()

	go e.refreshPorts(gen)
	go e.udpSweeper(gen)
	go e.serveRedirect(ln)
	go e.divertPackets(tcpH)
	go e.udpSupervisor(gen)
	e.logf("apptunnel: interception active gen %d (redirect :%d; pri %d; tcp %q; narrow udp)", gen, redirPort, divertPriority, tcpFilter)
	return nil
}

// refreshSnapshots refreshes the port→PID views for both families; the IPv6 ones decide whether a v6 packet belongs to a routed app.
func (e *Engine) refreshSnapshots() {
	if m := procnet.TCPPortPID(); m != nil {
		e.portPID.Store(&m)
	}
	if m := procnet.UDPPortPID(); m != nil {
		e.udpPortPID.Store(&m)
	}
	if m := procnet.TCP6PortPID(); m != nil {
		e.portPID6.Store(&m)
	}
	if m := procnet.UDP6PortPID(); m != nil {
		e.udpPortPID6.Store(&m)
	}
}

// Stop tears interception down; it takes opMu so an external Close can't interleave with a SetApps transition that is mid-start.
func (e *Engine) Stop() {
	e.opMu.Lock()
	defer e.opMu.Unlock()
	e.stopLocked()
}

func (e *Engine) stopLocked() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	ln, tcpH := e.ln, e.tcpH
	e.ln, e.tcpH = nil, nil
	e.mu.Unlock()

	// Redirected connections must be torn down while the capture handle is still open, or their FIN/RST would no longer be rewritten and would leave for the real destination with the real source IP.
	e.connMu.Lock()
	live := e.redirects
	e.redirects = nil // a connection accepted during the stop sees nil and bails instead of lingering untracked
	e.connMu.Unlock()
	for app, up := range live {
		if tc, ok := app.(*net.TCPConn); ok {
			tc.SetLinger(0) // reset rather than FIN: a graceful close leaves the app free to keep sending in CLOSE_WAIT, and those packets would leave unrewritten once the handle is gone
		}
		app.Close()
		if up != nil {
			up.Close()
		}
	}
	if len(live) > 0 {
		time.Sleep(100 * time.Millisecond) // let the loop rewrite those teardown packets before the handle goes away; whatever is still queued when a handle closes is not ours to reason about
	}

	if tcpH != nil {
		tcpH.close()
	}
	if h := e.udpH.Swap(nil); h != nil {
		h.close()
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

	e.logf("apptunnel: interception stopped")
}

// RunningNetApps lists processes currently holding TCP connections — the useful candidates to route.
func RunningNetApps() []string { return procnet.RunningTCPApps() }

// RunningNetAppsNamed maps each candidate app's exe base name to a display name.
func RunningNetAppsNamed() map[string]string { return procnet.RunningTCPAppsNamed() }

func (e *Engine) resetAppConnections(names map[string]bool) {
	e.logf("apptunnel: newly selected %v — resetting their connections (a tunnel flap alone must not land here)", sortedNames(names))
	if n := procnet.ResetAppTCP(names); n > 0 {
		e.logf("apptunnel: reset %d existing connection(s) to re-route through the tunnel", n)
	}
}

func sortedNames(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for n := range m {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// EnsureFirewallRule allows the redirected (inbound-looking) SYNs to reach the listener; without it every captured connection blackholes. It runs once at engine start rather than per interception cycle, since netsh can take seconds and would otherwise stall the command that triggered it.
func EnsureFirewallRule() error {
	if ruleExists() {
		return nil // netsh rules are persistent: deleting first would open a window where redirected SYNs are blocked, and a failed re-add would leave none at all
	}
	return firewallRule(true)
}

func ruleExists() bool {
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=fortochka-redirect", "dir=in")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000}
	return cmd.Run() == nil
}

func firewallRule(add bool) error {
	args := []string{"advfirewall", "firewall", "add", "rule", "name=fortochka-redirect",
		"dir=in", "action=allow", "protocol=TCP", "localport=1083"}
	if !add {
		args = []string{"advfirewall", "firewall", "delete", "rule", "name=fortochka-redirect"}
	}
	cmd := exec.Command("netsh", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd.Run()
}

// genOK reports whether this goroutine still belongs to the current run; a stopped-then-restarted engine must not keep the old goroutines alive.
func (e *Engine) genOK(gen uint64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running && e.gen == gen
}

// --- narrow UDP capture: a handle scoped to the routed apps' UDP source ports, reopened when that set changes ---

func (e *Engine) udpSupervisor(gen uint64) {
	t := time.NewTicker(time.Second) // debounce reopens; short enough to pick up a new voice/video port quickly
	defer t.Stop()
	cur := ""
	for {
		if !e.genOK(gen) {
			return // Stop closes the handle; a newer run owns it otherwise
		}
		if want := e.udpFilter(); want != cur {
			if e.reopenUDP(gen, want) { // cache only on success, or one failed open would leave udp uncaptured for the rest of the run
				cur = want
			}
		}
		<-t.C
	}
}

// udpFilter returns a filter matching only the routed apps' current UDP source ports, or "" when there are none (no UDP handle).
func (e *Engine) udpFilter() string {
	ports := e.targetUDPPorts()
	if len(ports) == 0 {
		return ""
	}
	terms := make([]string, 0, len(ports))
	for _, p := range ports {
		terms = append(terms, fmt.Sprintf("udp.SrcPort == %d", p))
	}
	return "outbound and udp and not impostor and (" + strings.Join(terms, " or ") + ")"
}

func (e *Engine) targetUDPPorts() []uint16 {
	decided := map[uint32]bool{}
	seen := map[uint16]bool{}
	var ports []uint16
	// Both families: udp.SrcPort matches either, so listing v6 ports too lets handleIPv6 see (and drop) a routed app's IPv6 datagrams instead of them leaving uncaptured.
	for _, snap := range []*map[uint16]uint32{e.udpPortPID.Load(), e.udpPortPID6.Load()} {
		if snap == nil {
			continue
		}
		for port, pid := range *snap {
			t, ok := decided[pid]
			if !ok {
				t = pid != 0 && pid != selfPID && e.targetApp(e.pidName(pid))
				decided[pid] = t
			}
			if t && !seen[port] {
				seen[port] = true
				ports = append(ports, port)
			}
		}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	if len(ports) > maxUDPPorts {
		e.logf("apptunnel: %d routed udp ports exceed the %d the filter can hold — the rest stay direct", len(ports), maxUDPPorts)
		ports = ports[:maxUDPPorts]
	}
	return ports
}

// reopenUDP swaps the UDP handle to one using filter (or none if filter is ""); the old handle's loop exits when it's closed.
func (e *Engine) reopenUDP(gen uint64, filter string) bool {
	if !e.genOK(gen) {
		return false
	}
	if filter == "" {
		e.mu.Lock() // swap under the lock with the generation check, or a restart between the two would let us close the new run's handle
		if !e.running || e.gen != gen {
			e.mu.Unlock()
			return false
		}
		old := e.udpH.Swap(nil)
		e.mu.Unlock()
		if old != nil {
			old.close()
		}
		return true
	}
	// Open before swapping: closing first would leave the app's UDP going direct until the new handle is up, and leave it direct for the whole run if the open failed.
	nh, err := windivert.Open(filter, windivert.LayerNetwork, divertPriority, 0)
	if err != nil {
		e.logf("apptunnel: udp capture open failed (%v) — keeping the current handle, will retry", err)
		return false
	}
	g := newDivHandle(nh)
	e.mu.Lock()
	if !e.running || e.gen != gen {
		e.mu.Unlock()
		g.close()
		return false
	}
	old := e.udpH.Swap(g)
	e.mu.Unlock()
	go e.divertPackets(g)
	if old != nil {
		old.close()
	}
	return true
}

func (e *Engine) pidName(pid uint32) string {
	e.nameMu.Lock()
	defer e.nameMu.Unlock()
	if e.nameCache == nil {
		e.nameCache = map[uint32]string{}
		e.nameBad = map[uint32]time.Time{}
	}
	if n, ok := e.nameCache[pid]; ok {
		if n != "" {
			return n
		}
		if until, bad := e.nameBad[pid]; bad && time.Now().Before(until) {
			return ""
		}
		delete(e.nameBad, pid)
	}
	if len(e.nameCache) > 1024 { // bound memory / staleness from PID reuse
		e.nameCache = map[uint32]string{}
	}
	n := strings.ToLower(procnet.ProcName(pid))
	e.nameCache[pid] = n
	if n == "" {
		// Cache the failure only briefly: some PIDs can never be opened and a syscall per packet under this lock is worse, but a lasting empty name would keep declassifying the app.
		e.nameBad[pid] = time.Now().Add(2 * time.Second)
	}
	return n
}

func (e *Engine) divertPackets(h *divHandle) {
	defer func() {
		if r := recover(); r != nil {
			e.logf("apptunnel: packet loop panic: %v", r)
		}
	}()
	buf := make([]byte, 65535)
	var sendErrs int
	var lastErrLog time.Time
	for {
		n, addr, err := h.recv(buf)
		if err != nil {
			if !h.isClosed() { // a reopen or stop closes the handle under us and Recv reports an abort; only an unexpected failure is worth a line
				e.logf("apptunnel: packet loop ended unexpectedly: %v", err)
			}
			return
		}
		p := buf[:n]
		if e.handlePacket(h, p, &addr) {
			if err := h.send(p, &addr); err != nil {
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
func (e *Engine) handlePacket(h *divHandle, p []byte, addr *windivert.Address) bool {
	if len(p) < 20 {
		return true
	}
	if p[0]>>4 == 6 {
		return e.handleIPv6(p)
	}
	if p[0]>>4 != 4 {
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

// handleIPv6 drops a routed app's IPv6 rather than letting it out: the tunnel carries IPv4 only, so reinjecting would leak the real address past the tunnel. Dropping makes the app fall back to IPv4 (Happy Eyeballs) instead. Everything else is passed through untouched.
func (e *Engine) handleIPv6(p []byte) bool {
	const v6HeaderLen = 40
	if len(p) < v6HeaderLen+4 {
		return true
	}
	if !e.anyApps() {
		return true // nothing is routed, so never pay for an ownership lookup on this loop
	}
	tcp := p[6] == 6
	if !tcp && p[6] != 17 { // next header; extension headers and fragments are left alone
		return true
	}
	dst, ok := netip.AddrFromSlice(p[24:40])
	if !ok || dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst.IsMulticast() || dst.IsPrivate() {
		return true // local IPC and LAN traffic never wanted the tunnel; dropping it would break the app
	}
	port := binary.BigEndian.Uint16(p[v6HeaderLen:])
	pid := e.pid6(port, tcp)
	if pid == 0 || pid == selfPID || !e.targetApp(e.pidName(pid)) {
		return true
	}
	e.st.v6Blocked.Add(1)
	return false
}

// pid6 resolves the owner of an IPv6 local port, refreshing on a miss: a connect() emits its SYN before the 500ms snapshot catches up, and passing that packet would leak the real address and then strand the connection once later packets start dropping.
func (e *Engine) pid6(port uint16, tcp bool) uint32 {
	snap, refresh := &e.portPID6, procnet.TCP6PortPID
	if !tcp {
		snap, refresh = &e.udpPortPID6, procnet.UDP6PortPID
	}
	if m := snap.Load(); m != nil {
		if pid := (*m)[port]; pid != 0 {
			return pid
		}
	}
	// Throttled: this runs on the loop that carries all outbound TCP, and a port that never resolves would otherwise walk the whole table for every packet of every process.
	now := time.Now().UnixNano()
	last := e.v6RefreshAt.Load()
	if now-last < int64(250*time.Millisecond) || !e.v6RefreshAt.CompareAndSwap(last, now) {
		return 0
	}
	m := refresh()
	if m == nil {
		return 0
	}
	snap.Store(&m)
	return m[port]
}

func (e *Engine) handleTCP(h *divHandle, p []byte, addr *windivert.Address, ihl int, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) bool {
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

	if isLocalDst(dstIP) {
		return true // loopback, LAN and multicast were never meant for the tunnel; deciding on them would also let an unrelated local socket disturb a routed port's mapping
	}

	e.trackMu.Lock()
	m, isTarget := e.tracked[srcPort]
	seenPID, wasSeen := e.seen[srcPort]
	e.trackMu.Unlock()

	// A fresh SYN to a different destination is a new connection, so any decision held for this port is stale — a port reused by the same process would otherwise be redirected to the previous connection's destination. The destination check keeps a retransmitted SYN, or an unrelated socket that merely shares the port number, from discarding a live mapping.
	if isTarget || wasSeen {
		fresh := flags&tcpSYN != 0 && flags&tcpACK == 0
		stale := false
		if fresh {
			owner := e.portOwner(srcPort) // safe to consult only here: on a new connection a changed owner really is a recycled port
			if isTarget {
				stale = m.dstIP != dstIP || m.dstPort != dstPort || (owner != 0 && owner != m.pid)
			} else {
				stale = owner != 0 && owner != seenPID // a retransmitted SYN on a port already decided direct must not re-run the whole decision
			}
		}
		if stale {
			e.forgetPort(srcPort)
			e.st.reSYN.Add(1)
			isTarget, wasSeen = false, false
		}
		// Deliberately no owner-mismatch check here: the port→PID view is keyed by port alone, so two sockets sharing a number look like a change, and dropping the mapping mid-connection would push the rest of it out in the clear with no way back. A genuinely recycled port always opens with a SYN, which the branch above catches.
	}

	// Case A: known target flow. The mapping deliberately outlives FIN/RST — dropping it mid-teardown would send the retransmitted FIN out to the real destination with the real source IP; the sweeper retires the port once it leaves the table.
	if isTarget {
		setIP(p, 12, m.dstIP)
		setIP(p, 16, m.appIP)
		binary.BigEndian.PutUint16(p[ihl+2:], redirPort)
		finish(h, p, addr)
		return true
	}

	if wasSeen {
		return true // already decided as direct
	}
	if flags&tcpSYN == 0 || flags&tcpACK != 0 {
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
	e.seen[srcPort] = pid
	delete(e.trackMiss, srcPort) // a reused port starts a fresh strike count, or a leftover strike could evict this live connection
	if target {
		e.tracked[srcPort] = mapping{appIP: srcIP, dstIP: dstIP, dstPort: dstPort, pid: pid}
	}
	e.trackMu.Unlock()

	if !target {
		e.st.tcpDirect.Add(1)
	}
	if target {
		e.st.tcpRouted.Add(1)
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
	if isLocalDst(dstIP) {
		return true // leave loopback (local proxy, local DNS), LAN and multicast alone
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
				e.st.udpDrop.Add(1)
				return false // send buffer full: drop this datagram (video is lossy), keep the flow
			}
			e.evictUDP(key, fl)
			return false // the app is routed: drop rather than emit its datagram in the clear
		}
		e.st.udpOut.Add(1)
		return false
	}
	if direct {
		e.udpMu.Unlock()
		return true // deliberately not re-stamped: refreshing it per datagram would make an active flow immortal, so one bad ownership lookup could pin a routed app to the clear for the whole session
	}
	e.udpMu.Unlock()

	pid := e.udpPID(srcPort)
	if pid == 0 {
		e.st.udpUnknown.Add(1)
		return false // the filter only carries routed apps' ports, so an unresolvable owner is far more likely ours than not: drop rather than emit in the clear, and do not cache so the next datagram retries
	}
	if pid == selfPID || !e.targetApp(e.pidName(pid)) { // selfPID: the tunnel's own encrypted datagrams must never be captured
		e.udpMu.Lock()
		e.udpDirect[key] = now
		e.udpMu.Unlock()
		return true
	}

	now = time.Now().UnixNano()
	if last := e.lastDialFail.Load(); last != 0 && now-last < int64(time.Second) {
		e.st.udpDialErr.Add(1)
		return false // a dial just failed: retrying per datagram would run a 5s dial on the capture loop at voice packet rates
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := e.dial.DialContext(ctx, "udp", netip.AddrPortFrom(dstIP, dstPort).String())
	cancel()
	if err != nil {
		e.st.udpDialErr.Add(1)
		e.lastDialFail.Store(time.Now().UnixNano()) // stamp the failure, not the pre-dial time, or a slow dial would consume the whole suppression window
		now = time.Now().UnixNano()
		if last := e.lastDialLog.Load(); now-last > int64(2*time.Second) && e.lastDialLog.CompareAndSwap(last, now) {
			e.logf("apptunnel: udp dial %s:%d via tunnel: %v (dropping, app is routed)", dstIP, dstPort, err)
		}
		return false // fail closed: caching this as direct would send a routed app's traffic in the clear until the engine restarts
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

// udpWriteTimeout must stay above zero — gonet reports a timeout before it ever writes when the deadline is already past, dropping every datagram — yet stay small, since it bounds how long a full send buffer stalls the single capture loop. 1ms leaves room for scheduler preemption, which at ~100us would drop datagrams that had buffer space.
const udpWriteTimeout = time.Millisecond

// nbWrite sends a datagram without blocking the single packet loop: a short write deadline makes Write drop (timeout) instead of stalling when the tunnel's send buffer is full under high bitrate (screen share).
func nbWrite(c net.Conn, b []byte) error {
	c.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
	_, err := c.Write(b)
	return err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// sweepTracked drops per-port TCP decisions whose local port is gone, so a recycled ephemeral port can't inherit a stale destination (misroute) or a stale direct decision (tunnel bypass). Only ports missing from two sweeps are dropped, since the port snapshot lags by up to 500ms.
// isLocalDst reports destinations that were never meant for the tunnel. RFC1918 is included: a routed app still has to reach the NAS, the printer, the router's DNS and its LAN broadcasts, and sending those to the peer would break them (or hand them to a machine on the far side that happens to hold the same private address). Domain rules that legitimately point at a private address go through the proxy, which does not use this.
func isLocalDst(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func (e *Engine) portOwner(port uint16) uint32 {
	if m := e.portPID.Load(); m != nil {
		return (*m)[port]
	}
	return 0
}

func (e *Engine) forgetPort(port uint16) {
	e.trackMu.Lock()
	delete(e.tracked, port)
	delete(e.seen, port)
	delete(e.trackMiss, port)
	e.trackMu.Unlock()
}

func (e *Engine) sweepTracked() {
	live := e.portPID.Load()
	if live == nil || len(*live) == 0 { // an empty snapshot means the table walk failed; trusting it would evict every live mapping
		return
	}
	e.trackMu.Lock()
	defer e.trackMu.Unlock()
	for port := range e.seen { // every tracked port is also in seen, so one pass covers both without double-counting a miss
		e.noteTrackMiss(*live, port)
	}
}

func (e *Engine) noteTrackMiss(live map[uint16]uint32, port uint16) {
	if _, ok := live[port]; ok {
		delete(e.trackMiss, port)
		return
	}
	e.trackMiss[port]++
	if e.trackMiss[port] >= 2 {
		delete(e.tracked, port)
		delete(e.seen, port)
		delete(e.trackMiss, port)
		e.st.pruned.Add(1)
	}
}

// logStats emits one compact line whenever a counter moved, so a log read after the fact shows what the tunnel path actually did.
func (e *Engine) logStats() {
	s := &e.st
	o, i, d, de := s.udpOut.Load(), s.udpIn.Load(), s.udpDrop.Load(), s.udpDialErr.Load()
	t, td, sc, se := s.tcpRouted.Load(), s.tcpDirect.Load(), s.sendClosed.Load(), s.sendErr.Load()
	pr, v6, rs, uu := s.pruned.Load(), s.v6Blocked.Load(), s.reSYN.Load(), s.udpUnknown.Load()
	ro, rn, rd, rl := s.redirOK.Load(), s.redirNoMap.Load(), s.redirDeny.Load(), s.redirDial.Load()
	sum := o + i + d + de + t + td + sc + se + pr + v6 + rs + uu + ro + rn + rd + rl
	if e.lastStatSum.Swap(sum) == sum {
		return
	}
	e.logf("apptunnel: udp out=%d in=%d drop=%d dialerr=%d unknown=%d | tcp routed=%d direct=%d resyn=%d pruned=%d | redirect ok=%d nomap=%d deny=%d dialerr=%d | inject closed=%d err=%d | v6 blocked=%d",
		o, i, d, de, uu, t, td, rs, pr, ro, rn, rd, rl, sc, se, v6)
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
	h := e.udpH.Load()
	if h == nil {
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
	h.calcChecksums(pkt[:n], &a)
	switch err := h.send(pkt[:n], &a); {
	case err == nil:
		e.st.udpIn.Add(1)
	case errors.Is(err, errHandleClosed):
		e.st.sendClosed.Add(1)
	default:
		e.st.sendErr.Add(1)
	}
}

// udpSweeper closes idle UDP flows (their reader then cleans up) and prunes stale direct-decision entries.
// statsEvery is how many 5s sweeps pass between health lines.
const statsEvery = 12

func (e *Engine) udpSweeper(gen uint64) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	ticks := 0
	for range t.C {
		if !e.genOK(gen) {
			return
		}
		e.sweepTracked()
		if ticks++; ticks%statsEvery == 0 { // once a minute: a 5s cadence would bury a day's log
			e.logStats()
			e.nameMu.Lock()
			e.nameCache = map[uint32]string{} // bound staleness from PID reuse
			e.nameBad = map[uint32]time.Time{}
			e.nameMu.Unlock()
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
	// Refresh on miss so a brand-new port isn't dropped, but throttled: an unresolvable port would otherwise walk the whole table for every datagram on the capture loop.
	now := time.Now().UnixNano()
	last := e.udpRefreshAt.Load()
	if now-last < int64(250*time.Millisecond) || !e.udpRefreshAt.CompareAndSwap(last, now) {
		return 0
	}
	if m := procnet.UDPPortPID(); m != nil {
		e.udpPortPID.Store(&m)
		if pid := m[port]; pid != 0 {
			return pid
		}
	}
	// Only once IPv4 has genuinely missed: a dual-stack socket bound to :: is listed solely in the IPv6 table even though its IPv4 datagrams are captured. Consulting it earlier would let an unrelated process holding the same port number on IPv6 answer for this one.
	if m6 := procnet.UDP6PortPID(); m6 != nil {
		e.udpPortPID6.Store(&m6)
		return m6[port]
	}
	return 0
}

func finish(h *divHandle, p []byte, addr *windivert.Address) {
	addr.SetOutbound(false) // inject as inbound so the local stack receives it
	addr.ClearChecksums()
	h.calcChecksums(p, addr)
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
	e.connMu.Lock()
	if e.redirects == nil { // stopped between Accept and here
		e.connMu.Unlock()
		return
	}
	e.redirects[c] = nil
	e.connMu.Unlock()
	defer func() {
		e.connMu.Lock()
		delete(e.redirects, c)
		e.connMu.Unlock()
	}()
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return
	}
	appPort := uint16(ra.Port)
	e.trackMu.Lock()
	m, found := e.tracked[appPort]
	e.trackMu.Unlock()
	if !found {
		e.st.redirNoMap.Add(1)
		e.logf("apptunnel: redirect from :%d has no mapping", appPort)
		return
	}
	// The redirected SYN was injected with the destination as its source, so anything else reaching this listener is not ours — without the check any host allowed to :1083 could be relayed through the tunnel by guessing a live port.
	if rip, ok := netip.AddrFromSlice(ra.IP.To4()); !ok || rip != m.dstIP {
		e.st.redirDeny.Add(1)
		e.logf("apptunnel: refusing redirect for :%d from %s (mapping expects %s)", appPort, ra.IP, m.dstIP)
		return
	}
	target := net.JoinHostPort(m.dstIP.String(), fmt.Sprint(m.dstPort))
	// The app's connect() already succeeded (we answered its SYN), so an instant refusal reads as a dropped connection and it retries at once. A short timeout while the tunnel is down fails it quickly without that storm, and still never sends anything in the clear.
	timeout := 20 * time.Second
	if e.Ready != nil && !e.Ready() {
		timeout = 5 * time.Second // rides out a first handshake right after Connect without looking like a hang
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	up, err := e.dial.DialContext(ctx, "tcp", target)
	if err != nil {
		e.st.redirDial.Add(1)
		e.logf("apptunnel: dial %s via tunnel: %v", target, err)
		return
	}
	e.st.redirOK.Add(1)
	defer up.Close()
	e.connMu.Lock()
	if e.redirects == nil {
		e.connMu.Unlock()
		return
	}
	e.redirects[c] = up
	e.connMu.Unlock()
	e.logf("apptunnel: %s -> tunnel", target)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(up, c); halfClose(up) }()
	go func() { defer wg.Done(); io.Copy(c, up); halfClose(c) }()
	wg.Wait()
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

func (e *Engine) refreshPorts(gen uint64) {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		if !e.genOK(gen) {
			return
		}
		e.refreshSnapshots()
	}
}
