//go:build windows

package apptunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fortochka/internal/windivert"
)

// tunnelConn stands in for a netstack UDP socket: writes succeed, reads block until the flow is torn down.
type tunnelConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
	writes atomic.Int32
}

func newTunnelConn() *tunnelConn { return &tunnelConn{closed: make(chan struct{})} }

func (c *tunnelConn) SetWriteDeadline(time.Time) error { return nil }
func (c *tunnelConn) Write(b []byte) (int, error)      { c.writes.Add(1); return len(b), nil }
func (c *tunnelConn) Read([]byte) (int, error)         { <-c.closed; return 0, io.EOF }
func (c *tunnelConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

type fakeDialer struct {
	conn  net.Conn
	err   error
	calls atomic.Int32
}

func (d *fakeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	d.calls.Add(1)
	if d.err != nil {
		return nil, d.err
	}
	return d.conn, nil
}

// routedUDPEngine is a running engine whose only selected app owns the datagram's source port.
func routedUDPEngine(t *testing.T, d Dialer, ready func() bool) *Engine {
	t.Helper()
	e := quietEngine()
	e.dial = d
	e.Ready = ready
	e.nameCache = map[uint32]string{fakePID: fakeApp}
	e.nameBad = map[uint32]time.Time{}
	e.apps = map[string]bool{fakeApp: true}
	e.udpFlows = map[udpKey]*udpFlow{}
	e.udpDirect = map[udpKey]udpDecision{}
	e.udpPortPID.Store(snap(map[uint16]uint32{51100: fakePID}))
	return e
}

func routedDatagram(t *testing.T) ([]byte, udpKey) {
	t.Helper()
	dst := netip.MustParseAddr("8.8.8.8")
	pkt := make([]byte, 64)
	n := buildUDPReply(pkt, testApp, dst, 51100, 443, []byte("voice"))
	if n < 0 {
		t.Fatal("building the test datagram failed")
	}
	return pkt[:n], udpKey{appPort: 51100, dstIP: dst, dstPort: 443}
}

// TestHandleUDPTunnelsRoutedApp pins the path the whole subsystem exists for: a selected app's datagram is fed into a tunnel socket and the original is dropped rather than reinjected.
func TestHandleUDPTunnelsRoutedApp(t *testing.T) {
	conn := newTunnelConn()
	t.Cleanup(func() { conn.Close() })
	d := &fakeDialer{conn: conn}
	e := routedUDPEngine(t, d, func() bool { return true })
	p, key := routedDatagram(t)

	if e.handlePacket(nil, p, &windivert.Address{}) {
		t.Fatal("a routed app's datagram must be consumed into the tunnel, not reinjected in the clear")
	}
	fl, ok := e.udpFlows[key]
	if !ok {
		t.Fatal("the flow must be registered, or every datagram re-dials")
	}
	if fl.pid != fakePID {
		t.Errorf("flow owner = %d, want %d", fl.pid, fakePID)
	}
	if got := d.calls.Load(); got != 1 {
		t.Errorf("dials = %d, want 1", got)
	}
	if got := conn.writes.Load(); got != 1 {
		t.Errorf("writes into the tunnel = %d, want 1", got)
	}
	if got := e.st.udpOut.Load(); got != 1 {
		t.Errorf("udpOut = %d, want 1", got)
	}
	if len(e.udpDirect) != 0 {
		t.Error("a tunnelled datagram must not leave a direct decision behind")
	}
}

// TestHandleUDPWaitsForTunnel pins the readiness gate. A UDP dial through netstack never blocks and never fails while the device exists, so without it a reconnecting tunnel accepts the datagram into a flow and discards it with no handshake, counted as sent.
func TestHandleUDPWaitsForTunnel(t *testing.T) {
	conn := newTunnelConn()
	t.Cleanup(func() { conn.Close() })
	d := &fakeDialer{conn: conn}
	ready := false
	e := routedUDPEngine(t, d, func() bool { return ready })
	p, key := routedDatagram(t)

	if e.handlePacket(nil, p, &windivert.Address{}) {
		t.Fatal("while the tunnel cannot carry it, a routed app's datagram must be dropped, not emitted in the clear")
	}
	if got := d.calls.Load(); got != 0 {
		t.Errorf("dials = %d, want none before the tunnel is ready", got)
	}
	if _, ok := e.udpFlows[key]; ok {
		t.Error("no flow may be built into a tunnel that cannot carry it")
	}
	if len(e.udpDirect) != 0 {
		t.Error("the drop must not be cached, or the app stays broken after the tunnel returns")
	}
	if e.lastDialFail.Load() != 0 {
		t.Error("a not-ready drop must not stamp the dial-failure window, or it suppresses the first real dial after recovery")
	}

	ready = true
	if e.handlePacket(nil, p, &windivert.Address{}) {
		t.Fatal("the datagram must still be consumed")
	}
	if _, ok := e.udpFlows[key]; !ok {
		t.Error("once the tunnel is ready the next datagram must build the flow")
	}
}

// TestHandleUDPFailsClosedOnDialError pins that a failed dial drops rather than falling back to the clear, and that the failure suppresses a retry per datagram.
func TestHandleUDPFailsClosedOnDialError(t *testing.T) {
	d := &fakeDialer{err: errors.New("tunnel not connected")}
	e := routedUDPEngine(t, d, func() bool { return true })
	p, key := routedDatagram(t)

	if e.handlePacket(nil, p, &windivert.Address{}) {
		t.Fatal("a failed dial must drop the datagram, not emit a routed app's traffic in the clear")
	}
	if _, ok := e.udpFlows[key]; ok {
		t.Error("no flow may be registered for a failed dial")
	}
	if len(e.udpDirect) != 0 {
		t.Error("a dial failure must not be cached as direct, or the app bypasses the tunnel until the engine restarts")
	}
	if e.lastDialFail.Load() == 0 {
		t.Error("the failure must be stamped so the next datagrams do not each retry")
	}

	if e.handlePacket(nil, p, &windivert.Address{}) {
		t.Fatal("the next datagram must also be dropped")
	}
	if got := d.calls.Load(); got != 1 {
		t.Errorf("dials = %d, want the retry suppressed inside the window", got)
	}
	if got := e.st.udpDialErr.Load(); got != 2 {
		t.Errorf("udpDialErr = %d, want both datagrams counted", got)
	}
}

// TestPidNameIsLowercased pins the casing contract. SetApps lowercases the selection, while Windows reports the exe's on-disk casing — drop the fold and every app with a capitalised name silently never routes, with no counter and no log line.
func TestPidNameIsLowercased(t *testing.T) {
	e := quietEngine()
	name := e.pidName(selfPID)
	if name == "" {
		t.Skip("cannot read this process's own name")
	}
	if name != strings.ToLower(name) {
		t.Errorf("pidName = %q, want it folded to lower case to match the selection", name)
	}
}

// TestRetireStaleHandsPortToRoutedApp pins the only thing that un-caches a direct decision. The filter keeps a port for five minutes after its owner releases it, so when a routed app picks that port up, a cached "direct" would pass its datagrams in the clear until the decision expired.
func TestRetireStaleHandsPortToRoutedApp(t *testing.T) {
	const previousPID uint32 = fakePID + 12

	conn := newTunnelConn()
	t.Cleanup(func() { conn.Close() })
	e := routedUDPEngine(t, &fakeDialer{conn: conn}, func() bool { return true })
	p, key := routedDatagram(t)
	e.udpDirect[key] = udpDecision{at: time.Now().UnixNano(), pid: previousPID}

	if e.handlePacket(nil, p, &windivert.Address{}) {
		t.Fatal("the datagram belongs to a routed app now and must not be passed through")
	}
	if _, stale := e.udpDirect[key]; stale {
		t.Error("the previous owner's direct decision must be retired")
	}
	if _, ok := e.udpFlows[key]; !ok {
		t.Error("the routed app's flow must be built")
	}
	if got := e.st.udpRetired.Load(); got != 1 {
		t.Errorf("udpRetired = %d, want 1", got)
	}
}

// TestTargetAppFoldsCase pins the casing contract where it can be observed. The selection is stored lower-cased by SetApps while Windows reports the exe's on-disk casing, so a raw comparison makes every capitalised name silently never route — no counter, no log line, the tray still shows it ticked.
func TestTargetAppFoldsCase(t *testing.T) {
	e := quietEngine()
	e.apps = map[string]bool{"discord.exe": true}
	for _, n := range []string{"discord.exe", "Discord.exe", "DISCORD.EXE"} {
		if !e.targetApp(n) {
			t.Errorf("targetApp(%q) = false, want true", n)
		}
	}
	if e.targetApp("other.exe") {
		t.Error("an unselected name must not match")
	}
}
