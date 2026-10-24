//go:build windows

// Package apptunnel tunnels chosen processes' traffic via WinDivert, deciding ownership per packet. Needs admin.
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
	"runtime"
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

const socketFilter = "udp"

func udpFilterFor(ports []uint16) string {
	if len(ports) == 0 {
		return ""
	}
	terms := make([]string, 0, len(ports))
	for _, p := range ports {
		terms = append(terms, fmt.Sprintf("udp.SrcPort == %d", p))
	}
	return "outbound and udp and not impostor and (" + strings.Join(terms, " or ") + ")"
}

// selfPID identifies this process so the tunnel's own encrypted datagrams are never captured, which would starve the handshake.
var selfPID = uint32(os.Getpid())

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

var errHandleClosed = errors.New("windivert: handle closed")

var errShortWrite = errors.New("apptunnel: the tunnel socket took only part of the datagram")

const systemPID = 4

const missInterval = 250 * time.Millisecond

type missThrottle struct {
	mu   sync.Mutex
	last map[uint16]int64
}

func (t *missThrottle) allow(port uint16) bool {
	now := time.Now().UnixNano()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.last == nil {
		t.last = map[uint16]int64{}
	}
	if now-t.last[port] < int64(missInterval) {
		return false
	}
	t.last[port] = now
	return true
}

func (t *missThrottle) prune() {
	cutoff := time.Now().Add(-missInterval).UnixNano()
	t.mu.Lock()
	defer t.mu.Unlock()
	for p, at := range t.last {
		if at < cutoff {
			delete(t.last, p)
		}
	}
}

// divHandle guards injections so a send can never run on a value that was already closed — Windows reuses handle numbers, so that write could land on an unrelated object. Recv is deliberately unguarded: closing the handle is what unblocks it.
type divKind int

const (
	divTCP divKind = iota
	divUDP
	divSock
)

type divHandle struct {
	mu       sync.RWMutex
	h        windivert.Handle
	closed   bool
	draining bool // shutdown issued: no new packets are diverted, but the queue is still being read back out
	reads    atomic.Uint64
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
func (d *divHandle) calcChecksums(p []byte, a *windivert.Address) {
	if d == nil {
		return
	}
	d.h.CalcChecksums(p, a, 0)
}

func (d *divHandle) isClosed() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.closed
}

// retiring reports a handle on its way out, so its packet loop ending is expected rather than a fault worth logging.
func (d *divHandle) retiring() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.closed || d.draining
}

// drainGrace bounds how long a retiring handle waits for its packet loop to empty the queue before closing anyway, so a reader that is gone or wedged cannot leak it.
const drainGrace = 2 * time.Second

// close retires the handle in the order WinDivert documents: stop diverting first, let the loop read back and re-inject whatever the driver already took out of the network stack, and only then close. Closing outright discards that queue, and those packets are lost to whoever sent them — which need not be a routed app at all.
func (d *divHandle) close() {
	d.mu.Lock()
	if d.closed || d.draining {
		d.mu.Unlock()
		return
	}
	d.draining = true
	h := d.h
	d.mu.Unlock()

	if err := h.Shutdown(windivert.ShutdownRecv); err != nil {
		d.finish() // nothing left to drain, so do not leave it open
		return
	}
	time.AfterFunc(drainGrace, d.finish)
}

// finish performs the close itself; it is idempotent because the packet loop and the grace timer both race to call it.
func (d *divHandle) finish() {
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

type sockEntry struct {
	pid uint32
	at  time.Time
}

// sockGrace outlasts four 500ms table passes, so a fresh bind is not pruned for being absent from them yet.
const sockGrace = 2 * time.Second

type udpDecision struct {
	at  int64
	pid uint32
}

type udpFlow struct {
	appIP      netip.Addr
	appPort    uint16
	dstIP      netip.Addr
	dstPort    uint16
	conn       net.Conn
	pid        uint32
	injAddr    atomic.Pointer[windivert.Address] // refreshed per outbound packet so replies use the current interface
	lastSeen   atomic.Int64
	stalls     atomic.Uint32 // consecutive full-buffer drops; any successful write clears it
	misses     atomic.Uint32 // consecutive sweeps that found no table listing the app port
	ownerMiss  atomic.Uint32 // consecutive sweeps that found the app port owned by another process
	lastOut    atomic.Int64
	lastIn     atomic.Int64
	silentFrom atomic.Int64
}

// stats are cheap counters emitted periodically so a later log read shows whether the tunnel path actually carried traffic and where packets were lost.
type stats struct {
	udpOut     atomic.Uint64 // app -> tunnel datagrams
	udpIn      atomic.Uint64 // tunnel -> app datagrams
	udpDrop    atomic.Uint64 // dropped because the tunnel send buffer was full
	udpStalled atomic.Uint64 // flows torn down because their send buffer stopped draining
	udpForeign atomic.Uint64 // owner not found, passed through
	udpLate    atomic.Uint64 // routed port not yet in the sampled table
	udpGaps    atomic.Uint64 // silences on an active flow
	udpPassed  atomic.Uint64 // passed through by a cached direct decision
	udpRetired atomic.Uint64 // cached decisions dropped because the port changed owner
	udpCapped  atomic.Uint64 // flows dropped because the table hit its ceiling
	udpReopens atomic.Uint64 // capture filter rebuilds
	loopStalls atomic.Uint64
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
	tcpUnknown atomic.Uint64 // SYNs sent direct because the owner's name could not be read
}

type Engine struct {
	dial Dialer
	logf func(string, ...any)

	// Ready reports whether the tunnel can actually carry traffic. Without it a reconnecting tunnel turns every redirected connection into a 20s stall; with it the app fails immediately and retries, and nothing escapes in the clear.
	Ready func() bool

	st          stats
	lastStatSum atomic.Uint64 // a stopped generation's sweeper can briefly overlap the new one
	sockH       *divHandle
	sockMu      sync.Mutex
	sockPorts   map[uint16]sockEntry
	filterWake  chan struct{}
	stickyMu    sync.Mutex
	sticky      map[uint16]time.Time
	lastCompact time.Time

	udpMiss      missThrottle
	udp6Miss     missThrottle
	tcp6Miss     missThrottle
	tcpMiss      missThrottle
	lastTCPWalk  atomic.Int64
	lastDialLog  atomic.Int64 // rate-limits the fail-closed log so a dead tunnel can't turn voice traffic into a write-per-datagram storm
	lastDialFail atomic.Int64 // suppresses repeat dials while the tunnel is down

	lastReviveLog atomic.Int64
	panicH        [3]atomic.Pointer[divHandle] // per divKind, the handle whose loop died on a bug of ours; only that handle must not be reopened

	opMu sync.Mutex // serializes SetApps start/stop so transitions can't interleave

	mu           sync.Mutex
	apps         map[string]bool
	lastSel      map[string]bool // last selection, so a tunnel flap doesn't make every app look freshly added
	pendingReset map[string]bool // apps whose interception was paused: their sockets reconnected direct meanwhile and must be pulled back in
	running      bool
	gen          uint64 // bumped per start() so background goroutines from a previous run exit instead of fighting the current one
	ln           net.Listener
	tcpH         *divHandle // static broad TCP capture

	udpH atomic.Pointer[divHandle] // UDP capture handle, also used to inject replies back to the app

	liveUDP atomic.Pointer[map[uint16]bool] // ports a routed app owns right now, as opposed to ones the filter merely still carries

	capturedPorts atomic.Pointer[map[uint16]bool]

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
	udpDirect  map[udpKey]udpDecision
	sweepH     *divHandle
	sweepReads uint64
}

func New(dial Dialer, logf func(string, ...any)) *Engine {
	return &Engine{dial: dial, logf: logf, apps: map[string]bool{}, sockPorts: map[uint16]sockEntry{}, filterWake: make(chan struct{}, 1)}
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
	e.udpDirect = map[udpKey]udpDecision{}
	owners := make(map[udpKey]uint32, len(e.udpFlows))
	for k, fl := range e.udpFlows {
		owners[k] = fl.pid
	}
	e.udpMu.Unlock()

	drop := make([]udpKey, 0, len(owners))
	for k, pid := range owners {
		// Only on a readable name, as retireStale does: the 2s negative cache would else tear down a selected app's live call.
		if n := e.pidName(pid); n != "" && !e.targetApp(n) {
			drop = append(drop, k)
		}
	}

	var stale []net.Conn
	e.udpMu.Lock()
	for _, k := range drop {
		if fl, ok := e.udpFlows[k]; ok && fl.pid == owners[k] {
			stale = append(stale, fl.conn)
			delete(e.udpFlows, k)
		}
	}
	e.udpMu.Unlock()
	for _, c := range stale {
		c.Close()
	}
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
		e.wakeFilter()                  // the app's UDP sockets were bound before it was selected, so no bind event will arrive to pull its ports into the filter
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

// targetApp folds the name: the selection is stored lower-cased while Windows reports the exe's on-disk casing, so comparing them raw makes every capitalised name silently never route.
func (e *Engine) targetApp(name string) bool {
	name = strings.ToLower(name)
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

	e.trackMu.Lock()
	e.tracked = map[uint16]mapping{}
	e.seen = map[uint16]uint32{}
	e.trackMiss = map[uint16]int{}
	e.trackMu.Unlock()

	e.udpMu.Lock()
	e.udpFlows = map[udpKey]*udpFlow{}
	e.udpDirect = map[udpKey]udpDecision{}
	e.udpStopped = false
	e.udpMu.Unlock()

	e.connMu.Lock()
	e.redirects = map[net.Conn]net.Conn{}
	e.connMu.Unlock()

	e.panicH[divTCP].Store(nil)
	e.panicH[divUDP].Store(nil)
	e.panicH[divSock].Store(nil)

	// Retained ports belong to the run that collected them: keeping them would start the filter carrying ports the system has since handed to other processes, and would eat into the limit for no benefit.
	e.stickyMu.Lock()
	e.sticky = map[uint16]time.Time{}
	e.lastCompact = time.Time{}
	e.stickyMu.Unlock()

	e.refreshSnapshots()

	// Sniff, or the socket layer blocks what it diverts and RecvOnly cannot allow it back: every UDP bind would fail.
	rawSock, err := windivert.Open(socketFilter, windivert.LayerSocket, divertPriority, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		ln.Close()
		return fmt.Errorf("socket events (need admin / WinDivert?): %w", err)
	}
	sockH := newDivHandle(rawSock)

	e.sockMu.Lock()
	e.sockPorts = map[uint16]sockEntry{}
	e.sockMu.Unlock()
	e.liveUDP.Store(&map[uint16]bool{})

	// Opened last and read at once: it takes all outbound TCP out of the stack, and an unread queue overflows machine-wide.
	rawTCP, err := windivert.Open(tcpFilter, windivert.LayerNetwork, divertPriority, 0)
	if err != nil {
		sockH.close()
		ln.Close()
		return fmt.Errorf("tcp capture (need admin / WinDivert?): %w", err)
	}
	tcpH := newDivHandle(rawTCP)
	go e.divertPackets(tcpH, divTCP)

	e.mu.Lock()
	e.gen++
	gen := e.gen
	e.ln, e.tcpH, e.sockH, e.running = ln, tcpH, sockH, true
	e.mu.Unlock()

	go e.watchSockets(gen, sockH)
	go e.udpSupervisor(gen)
	go e.refreshPorts(gen)
	go e.udpSweeper(gen)
	go e.serveRedirect(ln)
	e.logf("apptunnel: interception active gen %d (redirect :%d; pri %d; tcp %q; udp per routed port)", gen, redirPort, divertPriority, tcpFilter)
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
	ln, tcpH, sockH := e.ln, e.tcpH, e.sockH
	e.ln, e.tcpH, e.sockH = nil, nil, nil
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
	if sockH != nil {
		sockH.close()
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
	reset, failed := procnet.ResetAppTCP(names)
	if reset > 0 {
		e.logf("apptunnel: reset %d existing connection(s) to re-route through the tunnel", reset)
	}
	if failed > 0 {
		// Only established connections can be reset at all, so one that was still opening keeps running outside the tunnel for its whole life. Saying so is the only way to tell that from a working route.
		e.logf("apptunnel: %d connection(s) could not be reset and stay outside the tunnel until the app reopens them", failed)
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

func (e *Engine) isRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

func (e *Engine) pidName(pid uint32) string {
	e.nameMu.Lock()
	if e.nameCache == nil {
		e.nameCache = map[uint32]string{}
		e.nameBad = map[uint32]time.Time{}
	}
	if n, ok := e.nameCache[pid]; ok {
		if n != "" {
			e.nameMu.Unlock()
			return n
		}
		if until, bad := e.nameBad[pid]; bad && time.Now().Before(until) {
			e.nameMu.Unlock()
			return ""
		}
		delete(e.nameBad, pid)
	}
	e.nameMu.Unlock()

	n := strings.ToLower(procnet.ProcName(pid))

	e.nameMu.Lock()
	if len(e.nameCache) > 1024 { // bound memory / staleness from PID reuse
		e.nameCache = map[uint32]string{}
		e.nameBad = map[uint32]time.Time{}
	}
	e.nameCache[pid] = n
	if n == "" {
		e.nameBad[pid] = time.Now().Add(2 * time.Second)
	}
	e.nameMu.Unlock()
	return n
}

func ipProto(p []byte) int {
	if len(p) < 10 {
		return 0
	}
	if p[0]>>4 == 6 {
		return int(p[6])
	}
	return int(p[9])
}

func (e *Engine) divertPackets(h *divHandle, kind divKind) {
	defer func() {
		if r := recover(); r != nil {
			// The handle must not outlive its reader. WinDivert keeps taking matching packets out of the network stack for as long as a handle is open, and with nobody left to re-inject them they are simply lost — for the broad TCP filter that is every outbound connection on the machine, until the service is stopped. Losing interception (routed apps fall back to direct) is the lesser failure by a wide margin.
			e.logf("apptunnel: packet loop panic: %v — closing the handle, its traffic now goes direct", r)
			e.panicH[kind].Store(h)
			h.finish()
		}
	}()
	buf := make([]byte, 65535)
	var sendErrs int
	var lastStallLog time.Time
	var lastErrLog time.Time
	for {
		n, addr, err := h.recv(buf)
		if err != nil {
			if !h.retiring() { // a reopen or stop retires the handle under us and Recv reports an abort or an empty queue; only an unexpected failure is worth a line
				e.logf("apptunnel: packet loop ended unexpectedly: %v", err)
			}
			h.finish() // the queue is drained: close now rather than waiting out the grace timer
			return
		}
		h.reads.Add(1)
		p := buf[:n]
		// Interception has been torn down and this is the tail of a retiring handle's queue: hand those packets back exactly as they were. Rewriting them now would aim them at a redirect listener that is already closing, and from this moment on the app's traffic goes direct anyway — so untouched is both correct and what the app is about to get regardless.
		if h.retiring() && !e.isRunning() {
			h.send(p, &addr)
			continue
		}
		started := time.Now()
		pass := e.handlePacket(h, p, &addr)
		if took := time.Since(started); took > loopStallWarn {
			e.st.loopStalls.Add(1)
			if time.Since(lastStallLog) > time.Second {
				lastStallLog = time.Now()
				e.logf("apptunnel: packet handling blocked the loop for %s (proto %d, %d bytes)", took.Round(time.Millisecond), ipProto(p), n)
			}
		}
		if pass {
			if err := h.send(p, &addr); err != nil {
				if errors.Is(err, errHandleClosed) {
					e.st.sendClosed.Add(1)
				} else {
					e.st.sendErr.Add(1)
				}
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
	if ihl < 20 || len(p) < ihl+8 {
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
	if pid == 0 || pid == selfPID || pid == systemPID || !e.targetApp(e.pidName(pid)) {
		return true
	}
	e.st.v6Blocked.Add(1)
	return false
}

// pid6 resolves the owner of an IPv6 local port, refreshing on a miss: a connect() emits its SYN before the 500ms snapshot catches up, and passing that packet would leak the real address and then strand the connection once later packets start dropping.
func (e *Engine) pid6(port uint16, tcp bool) uint32 {
	snap, refresh, miss := &e.portPID6, procnet.TCP6PortPID, &e.tcp6Miss
	if !tcp {
		snap, refresh, miss = &e.udpPortPID6, procnet.UDP6PortPID, &e.udp6Miss
	}
	if m := snap.Load(); m != nil {
		if pid := (*m)[port]; pid != 0 {
			return pid
		}
	}
	// Throttled: this runs on the loop that carries all outbound TCP, and a port that never resolves would otherwise walk the whole table for every packet of every process.
	if !miss.allow(port) {
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
		// The destination must be the peer this mapping names. The listener accepts on 0.0.0.0 and the firewall rule has no scope, so without this a probe from the LAN that merely reused a tracked port number would have the listener's RST rewritten and injected into that app's live connection.
		if !ok || dstIP != m.dstIP {
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
		// A SYN-ACK is the one packet a tracked flow can never send: it is an outbound client connection. So this port now belongs to a listener, which keeps it in the table forever and therefore out of the sweep's reach.
		if isTarget && flags&tcpSYN != 0 && flags&tcpACK != 0 {
			if owner := e.portOwner(srcPort); owner != 0 && owner != m.pid {
				e.forgetPort(srcPort)
				e.st.reSYN.Add(1)
				isTarget, wasSeen = false, false
			}
		}
		// Otherwise deliberately no owner-mismatch check: the port→PID view is keyed by port alone, so two sockets sharing a number look like a change, and dropping the mapping mid-connection would push the rest of it out in the clear with no way back. A genuinely recycled port always opens with a SYN, which the branch above catches.
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
	if pid == 0 && e.tcpMiss.allow(srcPort) && e.allowTCPWalk() {
		if m := procnet.TCPPortPID(); m != nil { // refresh now so a brand-new port isn't leaked direct
			e.portPID.Store(&m)
			pid = m[srcPort]
		}
	}
	if pid == 0 {
		pid = e.pid6(srcPort, true) // dual-stack sockets on :: are listed only in the IPv6 table
	}
	var name string
	if pid != 0 && pid != systemPID {
		// An unreadable name is not one the user picked, so it goes direct; dropping the SYN would blackhole that process's TCP.
		if name = e.pidName(pid); name == "" {
			e.st.tcpUnknown.Add(1)
		}
	}
	target := name != "" && e.targetApp(name)

	e.trackMu.Lock()
	if name != "" { // an unreadable name is not a decision: caching it would hold the port direct without ever re-deciding
		e.seen[srcPort] = pid
	}
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
		e.logf("apptunnel: %s owns :%d -> %s:%d (redirect)", name, srcPort, dstIP, dstPort)
		setIP(p, 12, dstIP)
		setIP(p, 16, srcIP)
		binary.BigEndian.PutUint16(p[ihl+2:], redirPort)
		finish(h, p, addr)
	}
	return true
}

func (e *Engine) refreshUDPPID(port uint16) uint32 {
	if !e.udpMiss.allow(port) {
		return 0
	}
	m := procnet.UDPPortPID()
	if m == nil {
		return 0
	}
	e.udpPortPID.Store(&m)
	return m[port]
}

// maxUDPPorts bounds the per-port UDP filter. It stays scoped to the routed apps' own ports on purpose: capturing all UDP would push every QUIC and voice datagram on the machine through userspace and put us in the path of a co-running DPI-bypass tool. WinDivert compiles a filter to a bounded number of instructions, so the OR-chain cannot grow without limit: it rejects 254 ports as too long, and 250 keeps a margin below that.
const maxUDPPorts = 250

const maxUDPDirect = 8192

const maxUDPFlows = 1024

func (e *Engine) capFlowsLocked() []net.Conn {
	over := len(e.udpFlows) - maxUDPFlows
	if over <= 0 {
		return nil
	}
	type aged struct {
		key  udpKey
		seen int64
	}
	all := make([]aged, 0, len(e.udpFlows))
	for k, fl := range e.udpFlows {
		all = append(all, aged{k, fl.lastSeen.Load()})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen < all[j].seen })
	out := make([]net.Conn, 0, over)
	for _, a := range all[:over] {
		if fl, ok := e.udpFlows[a.key]; ok {
			out = append(out, fl.conn)
			delete(e.udpFlows, a.key)
		}
	}
	e.st.udpCapped.Add(uint64(len(out)))
	return out
}

func (e *Engine) watchSockets(gen uint64, h *divHandle) {
	defer h.finish()
	defer func() {
		if r := recover(); r != nil {
			// Unrecovered this takes the whole service with it — the tunnel, the proxy and the IPC listener share this process. Giving up on the stream only costs the filter its head start over the sampled port tables.
			e.panicH[divSock].Store(h)
			e.logf("apptunnel: socket event loop panic: %v — the capture filter falls back to the sampled port tables", r)
		}
	}()
	for {
		_, addr, err := h.recv(nil)
		if err != nil {
			if !h.retiring() {
				e.logf("apptunnel: socket events ended: %v", err)
			}
			return
		}
		if !e.genOK(gen) {
			return
		}
		s := addr.Socket()
		port, pid := s.LocalPort, s.ProcessID
		if port == 0 {
			continue
		}
		switch addr.Event() {
		case windivert.EventSocketBind, windivert.EventSocketConnect:
			e.sockMu.Lock()
			e.sockPorts[port] = sockEntry{pid: pid, at: time.Now()}
			e.sockMu.Unlock()
			if pid != selfPID && pid != systemPID && e.targetApp(e.pidName(pid)) {
				e.wakeFilter()
			}
		case windivert.EventSocketClose:
			e.sockMu.Lock()
			if e.sockPorts[port].pid == pid {
				delete(e.sockPorts, port)
			}
			e.sockMu.Unlock()
		}
	}
}

// udpPortTTL is how long a port stays in the filter after the routed app that owned it let it go. Removals are what made the filter churn: a port leaving is harmless to keep, while a port arriving must be picked up at once or that flow leaves untunnelled, so only arrivals justify reopening the handle. Expired ports are dropped in one batch, which turns a stream of reopens into one every TTL.
const udpPortTTL = 5 * time.Minute

const filterSettle = 200 * time.Millisecond

// Both sources: the tables cover sockets older than interception, the events cover a socket before its first datagram.
func (e *Engine) routedUDPPorts() []uint16 {
	live := e.liveUDPPorts()
	e.sockMu.Lock()
	owners := make(map[uint16]uint32, len(e.sockPorts))
	for p, ent := range e.sockPorts {
		owners[p] = ent.pid
	}
	e.sockMu.Unlock()
	decided := map[uint32]bool{}
	for p, pid := range owners {
		t, seen := decided[pid]
		if !seen {
			t = pid != 0 && pid != selfPID && pid != systemPID && e.targetApp(e.pidName(pid))
			decided[pid] = t
		}
		if t {
			live[p] = true
		}
	}
	liveCopy := make(map[uint16]bool, len(live))
	for p := range live {
		liveCopy[p] = true
	}
	e.liveUDP.Store(&liveCopy)

	now := time.Now()
	e.stickyMu.Lock()
	defer e.stickyMu.Unlock()
	if e.sticky == nil {
		e.sticky = map[uint16]time.Time{}
	}
	for p := range live {
		e.sticky[p] = now
	}
	if now.Sub(e.lastCompact) >= udpPortTTL {
		for p, seen := range e.sticky {
			if now.Sub(seen) >= udpPortTTL {
				delete(e.sticky, p)
			}
		}
		e.lastCompact = now
	}

	ports := make([]uint16, 0, len(e.sticky))
	for p := range e.sticky {
		ports = append(ports, p)
	}
	if total := len(ports); total > maxUDPPorts {
		sort.Slice(ports, func(i, j int) bool {
			ti, tj := e.sticky[ports[i]], e.sticky[ports[j]]
			if !ti.Equal(tj) {
				return ti.After(tj)
			}
			return ports[i] < ports[j]
		})
		for _, p := range ports[maxUDPPorts:] {
			delete(e.sticky, p)
		}
		ports = ports[:maxUDPPorts]
		e.logf("apptunnel: %d routed udp ports exceed the %d the filter can hold — the %d seen longest ago were dropped", total, maxUDPPorts, total-maxUDPPorts)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports
}

// portListed reports whether either sampled table still names the port, and whether either had anything to say at all. Either family is evidence, neither is not: refreshSnapshots keeps a failed walk out, and an empty map means the walk found nothing — acting on that would retire every live flow, the way sweepTracked refuses to.
func portListed(v4, v6 *map[uint16]uint32, port uint16) (listed, known bool) {
	known = (v4 != nil && len(*v4) > 0) || (v6 != nil && len(*v6) > 0)
	listed = (v4 != nil && (*v4)[port] != 0) || (v6 != nil && (*v6)[port] != 0)
	return listed, known
}

func (e *Engine) liveUDPPort(port uint16) bool {
	lm := e.liveUDP.Load()
	return lm != nil && (*lm)[port]
}

func (e *Engine) liveUDPPorts() map[uint16]bool {
	decided := map[uint32]bool{}
	seen := map[uint16]bool{}
	for _, snap := range []*map[uint16]uint32{e.udpPortPID.Load(), e.udpPortPID6.Load()} {
		if snap == nil {
			continue
		}
		for port, pid := range *snap {
			t, ok := decided[pid]
			if !ok {
				t = pid != 0 && pid != selfPID && pid != systemPID && e.targetApp(e.pidName(pid))
				decided[pid] = t
			}
			if t {
				seen[port] = true
			}
		}
	}
	return seen
}

func (e *Engine) pruneSockPorts() {
	v4, v6 := e.udpPortPID.Load(), e.udpPortPID6.Load()
	if v4 == nil && v6 == nil {
		return
	}
	now := time.Now()
	e.sockMu.Lock()
	defer e.sockMu.Unlock()
	for p, ent := range e.sockPorts {
		if now.Sub(ent.at) < sockGrace {
			continue // the tables are sampled every 500ms and have not had time to list this bind; dropping it now would leave the owner unnamed and pass the app's first datagrams in the clear
		}
		if v4 != nil && (*v4)[p] == ent.pid {
			continue
		}
		if v6 != nil && (*v6)[p] == ent.pid {
			continue
		}
		delete(e.sockPorts, p)
	}
}

func (e *Engine) wakeFilter() {
	select {
	case e.filterWake <- struct{}{}:
	default:
	}
}

func (e *Engine) udpSupervisor(gen uint64) {
	cur := ""
	var built time.Time
	for {
		if !e.genOK(gen) {
			return
		}
		if ph := e.panicH[divUDP].Load(); ph != nil && ph == e.udpH.Load() {
			e.mu.Lock()
			current := e.running && e.gen == gen
			e.mu.Unlock()
			if !current {
				return // a restart already replaced this run's handle; tearing it down would strand the new one
			}
			if old := e.udpH.Swap(nil); old != nil {
				old.close()
			}
			// Without this the flows stay half-open: their readers keep refreshing lastSeen so the idle sweep never reaches them, and every reply is injected into a closed handle.
			e.udpMu.Lock()
			e.udpStopped = true // a draining loop can still reach handleUDP for up to drainGrace, and a flow built after this teardown would have no reader and no sweeper
			dead := make([]net.Conn, 0, len(e.udpFlows))
			for k, fl := range e.udpFlows {
				dead = append(dead, fl.conn)
				delete(e.udpFlows, k)
			}
			e.udpMu.Unlock()
			for _, c := range dead {
				c.Close()
			}
			e.logf("apptunnel: udp capture gave up after a packet loop panic — routed apps' UDP goes direct for this run")
			return
		}
		if since := time.Since(built); since < filterSettle {
			time.Sleep(filterSettle - since) // let a burst of binds settle into one rebuild instead of one per socket
			if !e.genOK(gen) {
				return
			}
		}
		ports := e.routedUDPPorts()
		want := udpFilterFor(ports)
		h := e.udpH.Load()
		if want != cur || (want != "" && (h == nil || h.isClosed())) {
			// Stamped on the attempt, not the success, or a failing reopen leaves the settle window disengaged.
			built = time.Now()
			if e.reopenUDP(gen, want) {
				cur = want
				set := make(map[uint16]bool, len(ports))
				for _, p := range ports {
					set[p] = true
				}
				e.capturedPorts.Store(&set)
			}
		}
		select {
		case <-e.filterWake:
		case <-time.After(5 * time.Second):
		}
	}
}

// reopenUDP swaps the UDP handle to one using filter (or none if filter is ""); the old handle's loop exits when it's closed.
func (e *Engine) reopenUDP(gen uint64, filter string) bool {
	if filter == "" {
		e.mu.Lock()
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
	nh, err := windivert.Open(filter, windivert.LayerNetwork, divertPriority, 0)
	if err != nil {
		e.logf("apptunnel: udp capture open failed (%v) — keeping the current handle", err)
		return false
	}
	g := newDivHandle(nh)
	go e.divertPackets(g, divUDP)
	e.mu.Lock()
	if !e.running || e.gen != gen {
		e.mu.Unlock()
		g.close()
		return false
	}
	old := e.udpH.Swap(g)
	e.mu.Unlock()
	if old != nil {
		old.close()
	}
	e.st.udpReopens.Add(1)
	return true
}

func (e *Engine) reviveHandles(gen uint64) {
	e.mu.Lock()
	ok := e.running && e.gen == gen
	tcpDead := ok && e.panicH[divTCP].Load() != e.tcpH && (e.tcpH == nil || e.tcpH.isClosed())
	sockDead := ok && e.panicH[divSock].Load() != e.sockH && (e.sockH == nil || e.sockH.isClosed())
	e.mu.Unlock()
	if tcpDead {
		e.reopenTCP(gen)
	}
	if sockDead {
		e.reopenSock(gen)
	}
}

// reviveLog rate-limits these lines: a handle that keeps failing to reopen would otherwise write on every 5s tick.
func (e *Engine) reviveLog(format string, args ...any) {
	now := time.Now().UnixNano()
	if last := e.lastReviveLog.Load(); now-last > int64(30*time.Second) && e.lastReviveLog.CompareAndSwap(last, now) {
		e.logf(format, args...)
	}
}

func (e *Engine) reopenTCP(gen uint64) {
	raw, err := windivert.Open(tcpFilter, windivert.LayerNetwork, divertPriority, 0)
	if err != nil {
		e.reviveLog("apptunnel: tcp capture ended and could not be reopened: %v — routed apps' TCP goes direct until it recovers", err)
		return
	}
	h := newDivHandle(raw)
	go e.divertPackets(h, divTCP)
	e.mu.Lock()
	if !e.running || e.gen != gen {
		e.mu.Unlock()
		h.close()
		return
	}
	old := e.tcpH
	e.tcpH = h
	e.mu.Unlock()
	if old != nil {
		old.close()
	}
	e.reviveLog("apptunnel: tcp capture reopened after its packet loop ended")
}

func (e *Engine) reopenSock(gen uint64) {
	raw, err := windivert.Open(socketFilter, windivert.LayerSocket, divertPriority, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		e.reviveLog("apptunnel: socket events ended and could not be reopened: %v — the capture filter falls back to the sampled port tables", err)
		return
	}
	h := newDivHandle(raw)
	go e.watchSockets(gen, h)
	e.mu.Lock()
	if !e.running || e.gen != gen {
		e.mu.Unlock()
		h.close()
		return
	}
	old := e.sockH
	e.sockH = h
	e.mu.Unlock()
	if old != nil {
		old.close()
	}
	e.reviveLog("apptunnel: socket events reopened after the stream ended")
}

// A live flow is left alone: closing its tunnel socket reads as a dead media path and a voice client stops transmitting.
func (e *Engine) retireStale(key udpKey, owner uint32) {
	e.udpMu.Lock()
	dec, hasDec := e.udpDirect[key]
	e.udpMu.Unlock()
	if !hasDec || dec.pid == owner {
		return
	}
	name := e.pidName(owner)
	if name == "" || owner == selfPID || owner == systemPID || !e.targetApp(name) {
		return
	}
	e.udpMu.Lock()
	if cur, ok := e.udpDirect[key]; ok && cur == dec {
		delete(e.udpDirect, key)
		e.st.udpRetired.Add(1)
	}
	e.udpMu.Unlock()
}

// handleUDP tunnels a target app's UDP by feeding the payload into a per-flow netstack UDP socket (replies come back via udpReader), dropping the original. The narrow UDP filter already limits capture to target ports; the ownership check guards against a port being reused by another process before the filter catches up.
func (e *Engine) handleUDP(p []byte, addr *windivert.Address, ihl int, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) bool {
	if isLocalDst(dstIP) {
		return true // leave loopback (local proxy, local DNS), LAN and multicast alone
	}
	key := udpKey{srcPort, dstIP, dstPort}
	now := time.Now().UnixNano()
	payload := p[ihl+8:]

	if owner, _ := e.udpPID(srcPort); owner != 0 {
		e.retireStale(key, owner)
	}

	e.udpMu.Lock()
	fl, ok := e.udpFlows[key]
	_, direct := e.udpDirect[key]
	if ok {
		e.udpMu.Unlock()
		fl.lastSeen.Store(now)
		fl.lastOut.Store(now)
		ac := *addr
		fl.injAddr.Store(&ac)
		if err := nbWrite(fl.conn, payload); err != nil {
			if dropped(err) {
				e.st.udpDrop.Add(1)
				// One datagram lost to a burst is the intended cost (video is lossy). A socket whose buffer never drains again is not: lastSeen is refreshed above by the very datagrams being dropped, so the idle sweep never reaches such a flow and it keeps discarding everything the app sends for as long as it keeps sending. Tearing it down after a run of failures lets the next datagram build a working one.
				if fl.stalls.Add(1) >= udpStallLimit {
					e.st.udpStalled.Add(1)
					e.evictUDP(key, fl)
				}
				return false
			}
			e.evictUDP(key, fl)
			return false // the app is routed: drop rather than emit its datagram in the clear
		}
		fl.stalls.Store(0)
		e.st.udpOut.Add(1)
		return false
	}
	if direct {
		e.udpMu.Unlock()
		e.st.udpPassed.Add(1)
		return true
	}
	e.udpMu.Unlock()

	pid, known := e.udpPID(srcPort)
	if pid == 0 {
		// Retained port: probably another process now, so pass. Live port: the lookup lagged, and passing would leak the real address.
		if !e.liveUDPPort(srcPort) {
			e.st.udpForeign.Add(1)
			return true
		}
		e.st.udpUnknown.Add(1)
		return false
	}
	if pid == selfPID || pid == systemPID { // never capture the tunnel's own datagrams; System has no name to read
		e.udpMu.Lock()
		e.udpDirect[key] = udpDecision{at: now, pid: pid}
		e.udpMu.Unlock()
		return true
	}
	name := e.pidName(pid)
	if name == "" {
		if fresh := e.refreshUDPPID(srcPort); fresh != 0 && fresh != pid { // throttled inside: this walks the whole table on the packet loop
			pid, name = fresh, e.pidName(fresh)
		}
		if name == "" {
			if !e.liveUDPPort(srcPort) {
				e.st.udpForeign.Add(1)
				return true
			}
			e.st.udpUnknown.Add(1)
			return false
		}
	}
	if !e.targetApp(name) {
		e.udpMu.Lock()
		e.udpDirect[key] = udpDecision{at: now, pid: pid}
		e.udpMu.Unlock()
		return true
	}

	if e.Ready != nil && !e.Ready() {
		// A UDP dial through netstack never blocks, so without this the datagram is accepted into a flow and discarded by a tunnel that has no handshake, counted as sent.
		e.st.udpDialErr.Add(1)
		return false
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
	fl = &udpFlow{appIP: srcIP, appPort: srcPort, dstIP: dstIP, dstPort: dstPort, conn: conn, pid: pid}
	fl.lastSeen.Store(now)
	fl.lastOut.Store(now)
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
		existing.lastOut.Store(now)
		e.countWrite(nbWrite(existing.conn, payload))
		return false
	}
	e.udpFlows[key] = fl
	evicted := e.capFlowsLocked()
	e.udpMu.Unlock()
	for _, c := range evicted {
		c.Close()
	}

	late := ""
	if !known {
		e.st.udpLate.Add(1)
		late = " late: the port table did not know this port yet"
	}
	e.logf("apptunnel: %s owns udp :%d -> %s:%d (tunnel)%s", name, srcPort, dstIP, dstPort, late)
	go e.udpReader(key, fl)
	e.countWrite(nbWrite(conn, payload))
	return false
}

// countWrite records a flow's first datagram, which is sent outside the steady-state path above and would otherwise be missing from the counters the log is read by.
func (e *Engine) countWrite(err error) {
	switch {
	case err == nil:
		e.st.udpOut.Add(1)
	case dropped(err):
		e.st.udpDrop.Add(1)
	}
}

// udpWriteTimeout must stay above zero — gonet reports a timeout before it ever writes when the deadline is already past, dropping every datagram — yet stay small, since it bounds how long a full send buffer stalls the single capture loop. 1ms leaves room for scheduler preemption, which at ~100us would drop datagrams that had buffer space.
const udpWriteTimeout = time.Millisecond

// nbWrite sends a datagram without blocking the single packet loop: a short write deadline makes Write drop (timeout) instead of stalling when the tunnel's send buffer is full under high bitrate (screen share).
func nbWrite(c net.Conn, b []byte) error {
	c.SetWriteDeadline(time.Now().Add(udpWriteTimeout))
	n, err := c.Write(b)
	if err != nil {
		return err
	}
	// gonet retries a blocked write with a payload reader the first attempt already drained, so it can report success having sent an empty datagram. Counting that as delivered loses the app's payload silently.
	if n != len(b) {
		return errShortWrite
	}
	return nil
}

// dropped reports an error that cost this datagram but left the socket usable, so the flow is worth keeping.
func dropped(err error) bool { return isTimeout(err) || errors.Is(err, errShortWrite) }

// udpStallLimit is how many consecutive full-buffer drops mark a flow as wedged rather than merely bursty. At voice packet rates this is a fraction of a second: short enough to rebuild before it is audible, long enough not to discard a flow over an ordinary burst.
const udpStallLimit = 20

const loopStallWarn = 100 * time.Millisecond

const udpGapWarn = 5 * time.Second

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isLocalDst reports destinations that were never meant for the tunnel. RFC1918 is included: a routed app still has to reach the NAS, the printer, the router's DNS and its LAN broadcasts, and sending those to the peer would break them (or hand them to a machine on the far side that happens to hold the same private address). Domain rules that legitimately point at a private address go through the proxy, which does not use this.
func isLocalDst(ip netip.Addr) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

// tcpWalkInterval bounds how often the capture loop may walk the whole connection table. The per-port throttle alone bounds nothing: every new connection has a new port, so under connection churn the loop that carries all outbound TCP on the machine would walk the table once per connection.
const tcpWalkInterval = 20 * time.Millisecond

func (e *Engine) allowTCPWalk() bool {
	now := time.Now().UnixNano()
	last := e.lastTCPWalk.Load()
	return now-last >= int64(tcpWalkInterval) && e.lastTCPWalk.CompareAndSwap(last, now)
}

func (e *Engine) portOwner(port uint16) uint32 {
	for _, m := range []*map[uint16]uint32{e.portPID.Load(), e.portPID6.Load()} {
		if m != nil {
			if pid := (*m)[port]; pid != 0 {
				return pid
			}
		}
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

// sweepTracked drops per-port TCP decisions whose local port is gone, so a recycled ephemeral port can't inherit a stale destination (misroute) or a stale direct decision (tunnel bypass). Only ports missing from two sweeps are dropped, since the port snapshot lags by up to 500ms.
func (e *Engine) sweepTracked() {
	v4, v6 := e.portPID.Load(), e.portPID6.Load()
	retired := map[uint16]mapping{}
	e.trackMu.Lock()
	for port := range e.seen { // every tracked port is also in seen, so one pass covers both without double-counting a miss
		if m, ok := e.noteTrackMiss(v4, v6, port); ok {
			retired[port] = m
		}
	}
	e.trackMu.Unlock()
	for port, m := range retired {
		if n := e.closeRelays(port, m.dstIP); n > 0 {
			e.logf("apptunnel: %s :%d -> %s:%d was retired by the port sweep while its relay was still open — closed %d relay(s)", e.pidName(m.pid), port, m.dstIP, m.dstPort, n)
		}
	}
}

func (e *Engine) closeRelays(appPort uint16, dstIP netip.Addr) int {
	var conns []net.Conn
	n := 0
	e.connMu.Lock()
	for c, up := range e.redirects {
		ra, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok || uint16(ra.Port) != appPort {
			continue
		}
		if rip, ok := netip.AddrFromSlice(ra.IP.To4()); !ok || rip != dstIP {
			continue
		}
		n++
		conns = append(conns, c)
		if up != nil {
			conns = append(conns, up)
		}
	}
	e.connMu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	return n
}

func (e *Engine) noteTrackMiss(v4, v6 *map[uint16]uint32, port uint16) (mapping, bool) {
	// Both families: handleTCP resolves a dual-stack socket's owner from the IPv6 table, so a mapping made that way is absent from the v4 one and would be swept out from under a live connection.
	listed, known := portListed(v4, v6, port)
	if !known {
		return mapping{}, false
	}
	if listed {
		delete(e.trackMiss, port)
		return mapping{}, false
	}
	e.trackMiss[port]++
	if e.trackMiss[port] < 2 {
		return mapping{}, false
	}
	m, routed := e.tracked[port]
	delete(e.tracked, port)
	delete(e.seen, port)
	delete(e.trackMiss, port)
	e.st.pruned.Add(1)
	return m, routed
}

// logStats emits one compact line whenever a counter moved, so a log read after the fact shows what the tunnel path actually did.
func (e *Engine) logStats() {
	s := &e.st
	o, i, d, de := s.udpOut.Load(), s.udpIn.Load(), s.udpDrop.Load(), s.udpDialErr.Load()
	t, td, sc, se := s.tcpRouted.Load(), s.tcpDirect.Load(), s.sendClosed.Load(), s.sendErr.Load()
	pr, v6, rs, uu := s.pruned.Load(), s.v6Blocked.Load(), s.reSYN.Load(), s.udpUnknown.Load()
	ro, rn, rd, rl := s.redirOK.Load(), s.redirNoMap.Load(), s.redirDeny.Load(), s.redirDial.Load()
	st, fo := s.udpStalled.Load(), s.udpForeign.Load()
	la, gp, tu := s.udpLate.Load(), s.udpGaps.Load(), s.tcpUnknown.Load()
	rt, cp := s.udpRetired.Load(), s.udpCapped.Load()
	e.udpMu.Lock()
	fn := len(e.udpFlows)
	e.udpMu.Unlock()
	pa, ls, rp := s.udpPassed.Load(), s.loopStalls.Load(), s.udpReopens.Load()
	sum := o + i + d + de + t + td + sc + se + pr + v6 + rs + uu + ro + rn + rd + rl + st + fo + pa + ls + la + gp + tu + rt + cp + rp
	if e.lastStatSum.Swap(sum) == sum {
		return
	}
	e.logf("apptunnel: udp out=%d in=%d drop=%d stalled=%d dialerr=%d unknown=%d foreign=%d passed=%d retired=%d capped=%d reopens=%d flows=%d goroutines=%d late=%d gaps=%d slowloop=%d | tcp routed=%d direct=%d unknown=%d resyn=%d pruned=%d | redirect ok=%d nomap=%d deny=%d dialerr=%d | inject closed=%d err=%d | v6 blocked=%d",
		o, i, d, st, de, uu, fo, pa, rt, cp, rp, fn, runtime.NumGoroutine(), la, gp, ls, t, td, tu, rs, pr, ro, rn, rd, rl, sc, se, v6)
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
	var pkt []byte // built on the first reply, so a flow that only sends costs one buffer instead of two
	var last time.Time
	var got uint64
	for {
		n, err := fl.conn.Read(buf)
		if err != nil {
			break
		}
		now := time.Now()
		if got > 0 && now.Sub(last) > udpGapWarn {
			e.st.udpGaps.Add(1) // counted only: a line per gap fires on every keepalive slower than the threshold
		}
		last, got = now, got+1
		fl.lastSeen.Store(now.UnixNano())
		fl.lastIn.Store(now.UnixNano())
		if pkt == nil {
			pkt = make([]byte, 65535)
		}
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
		e.pruneSockPorts() // every tick, not once a minute: a missed CLOSE leaves an entry naming a dead process as the owner of a port the system has already handed on
		e.reviveHandles(gen)
		if ticks++; ticks%statsEvery == 0 { // once a minute: a 5s cadence would bury a day's log
			e.logStats()
			e.nameMu.Lock()
			e.nameCache = map[uint32]string{} // bound staleness from PID reuse
			e.nameBad = map[uint32]time.Time{}
			e.nameMu.Unlock()
			e.udpMiss.prune()
			e.udp6Miss.prune()
			e.tcp6Miss.prune()
			e.tcpMiss.prune()
		}
		e.sweepFlows()
	}
}

const (
	silentAfter  = 10 * time.Second
	silentWindow = 5 * time.Second
)

type silence struct {
	fl      *udpFlow
	dur     time.Duration
	resumed bool
}

// sweepFlows retires the flows whose app port is gone or idle, and the cached decisions that have expired.
func (e *Engine) sweepFlows() {
	now := time.Now().UnixNano()
	cutoff := now - int64(udpIdleTimeout)
	v4, v6 := e.udpPortPID.Load(), e.udpPortPID6.Load()
	var dead []net.Conn
	var quiet []silence
	e.udpMu.Lock()
	h := e.udpH.Load()
	var total, recent uint64
	if h != nil {
		total = h.reads.Load()
		recent = total
		if h == e.sweepH {
			recent = total - e.sweepReads
		}
	}
	e.sweepH, e.sweepReads = h, total
	for k, fl := range e.udpFlows {
		out, in := fl.lastOut.Load(), fl.lastIn.Load()
		if from := fl.silentFrom.Load(); from == 0 {
			if now-in < int64(silentWindow) && now-out >= int64(silentAfter) {
				fl.silentFrom.Store(out)
				quiet = append(quiet, silence{fl: fl, dur: time.Duration(now - out)})
			}
		} else if out > from {
			fl.silentFrom.Store(0)
			quiet = append(quiet, silence{fl: fl, dur: time.Duration(out - from), resumed: true})
		}
		// A dead app port makes Windows answer the far side with an ICMP unreachable from the real address.
		gone := false
		if listed, known := portListed(v4, v6, fl.appPort); known && !listed {
			// Two strikes as in noteTrackMiss: a flow built from a socket event exists before the tables list its port.
			gone = fl.misses.Add(1) >= 2
		} else if listed {
			fl.misses.Store(0)
		}
		// A port handed to another process keeps this flow tunnelling that process's datagrams: the port stays listed so the check above never fires, and its own traffic keeps the idle timer fresh. Struck twice, like the rest, because the port tables are keyed by port alone and two sockets sharing a number look like a change.
		owner := uint32(0)
		if v4 != nil {
			owner = (*v4)[fl.appPort]
		}
		if owner == 0 && v6 != nil {
			owner = (*v6)[fl.appPort]
		}
		if owner != 0 && owner != fl.pid {
			if fl.ownerMiss.Add(1) >= 2 {
				gone = true
			}
		} else {
			fl.ownerMiss.Store(0)
		}
		if gone || fl.lastSeen.Load() < cutoff {
			dead = append(dead, fl.conn)
			delete(e.udpFlows, k)
		}
	}
	for k, dec := range e.udpDirect {
		if dec.at < cutoff {
			delete(e.udpDirect, k)
		}
	}
	capped := len(e.udpDirect) > maxUDPDirect
	if capped {
		e.udpDirect = map[udpKey]udpDecision{}
	}
	e.udpMu.Unlock()
	if capped {
		e.logf("apptunnel: cached udp decisions passed %d — table dropped, each port decides again on its next datagram", maxUDPDirect)
	}
	for _, c := range dead {
		c.Close()
	}
	for _, q := range quiet {
		name := e.pidName(q.fl.pid)
		if q.resumed {
			e.logf("apptunnel: %s udp :%d -> %s:%d is sending again after %s of silence", name, q.fl.appPort, q.fl.dstIP, q.fl.dstPort, q.dur.Round(time.Second))
			continue
		}
		captured := "unknown"
		if set := e.capturedPorts.Load(); set != nil {
			captured = "no"
			if (*set)[q.fl.appPort] {
				captured = "yes"
			}
		}
		e.logf("apptunnel: %s udp :%d -> %s:%d is receiving but has sent nothing for %s (port in capture filter: %s; capture handle read %d packets since the last sweep)", name, q.fl.appPort, q.fl.dstIP, q.fl.dstPort, q.dur.Round(time.Second), captured, recent)
	}
}

// udpPID names a port's owner, and reports whether the sampled tables already knew the port.
func (e *Engine) udpPID(port uint16) (uint32, bool) {
	// Both families: a dual-stack socket on :: sends IPv4 yet is listed only in the IPv6 table.
	for _, m := range []*map[uint16]uint32{e.udpPortPID.Load(), e.udpPortPID6.Load()} {
		if m == nil {
			continue
		}
		if pid := (*m)[port]; pid != 0 {
			return pid, true
		}
	}
	e.sockMu.Lock()
	pid := e.sockPorts[port].pid
	e.sockMu.Unlock()
	return pid, false
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
	started := time.Now()
	var upBytes, downBytes int64
	var once sync.Once
	var why string
	settle := func(reader, writer string, readErr, writeErr error) {
		once.Do(func() {
			switch {
			case writeErr != nil:
				why = writer + " failed first: " + writeErr.Error()
			case readErr != nil:
				why = reader + " failed first: " + readErr.Error()
			default:
				why = reader + " closed first"
			}
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		var readErr, writeErr error
		upBytes, readErr, writeErr = pump(up, c)
		settle("app", "tunnel", readErr, writeErr)
		halfClose(up)
	}()
	go func() {
		defer wg.Done()
		var readErr, writeErr error
		downBytes, readErr, writeErr = pump(c, up)
		settle("tunnel", "app", readErr, writeErr)
		halfClose(c)
	}()
	wg.Wait()
	e.logf("apptunnel: %s :%d -> %s closed after %s (%d up / %d down bytes, %s)", e.pidName(m.pid), appPort, target, time.Since(started).Round(time.Millisecond), upBytes, downBytes, why)
}

// pump copies like io.Copy but keeps a read failure apart from a write failure, so a relay can tell which end gave up.
func pump(dst io.Writer, src io.Reader) (n int64, readErr, writeErr error) {
	buf := make([]byte, 32*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			if nw < 0 || nw > nr {
				nw = 0
				if ew == nil {
					ew = errors.New("invalid write result")
				}
			}
			n += int64(nw)
			if ew != nil {
				return n, nil, ew
			}
			if nw != nr {
				return n, nil, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return n, nil, nil
			}
			return n, er, nil
		}
	}
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
