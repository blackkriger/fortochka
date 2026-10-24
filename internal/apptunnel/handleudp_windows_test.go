//go:build windows

package apptunnel

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"fortochka/internal/windivert"
)

// closeConn records a Close without needing a real socket: a retired flow's conn is only ever closed.
type closeConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *closeConn) Close() error { c.closed.Store(true); return nil }

// udpPacket builds an outbound IPv4/UDP datagram the capture loop would hand to handlePacket.
func udpPacket(t *testing.T, srcPort, dstPort uint16, dst string) []byte {
	t.Helper()
	pkt := make([]byte, 64)
	n := buildUDPReply(pkt, netip.MustParseAddr("192.168.1.50"), netip.MustParseAddr(dst), srcPort, dstPort, []byte("probe"))
	if n < 0 {
		t.Fatal("building the test packet failed")
	}
	return pkt[:n]
}

// TestHandleUDPUnresolvedOwnerOnRetainedPort pins the pass side. The filter keeps a port for a while after the routed app releases it, and the system recycles those to other processes — most often the DNS client — so dropping there would break traffic that was never ours.
func TestHandleUDPUnresolvedOwnerOnRetainedPort(t *testing.T) {
	e := quietEngine()
	e.liveUDP.Store(&map[uint16]bool{}) // the port is retained, not live
	var addr windivert.Address

	if !e.handlePacket(nil, udpPacket(t, 51000, 53, "8.8.8.8"), &addr) {
		t.Fatal("an unidentified sender on a merely retained port must be passed through")
	}
	if got := e.st.udpForeign.Load(); got != 1 {
		t.Errorf("udpForeign = %d, want 1", got)
	}
	if got := e.st.udpUnknown.Load(); got != 0 {
		t.Errorf("nothing was dropped, so udpUnknown must stay 0, got %d", got)
	}
}

// TestHandleUDPUnresolvedOwnerOnLivePort pins the fail-closed side, which a rework had flipped to fail-open. On a port a routed app owns right now, an unresolved owner means the lookup has not caught up — passing the datagram puts the app's real address on the wire.
func TestHandleUDPUnresolvedOwnerOnLivePort(t *testing.T) {
	e := quietEngine()
	e.liveUDP.Store(&map[uint16]bool{51000: true})
	var addr windivert.Address

	if e.handlePacket(nil, udpPacket(t, 51000, 443, "8.8.8.8"), &addr) {
		t.Fatal("an unresolved owner on a live routed port must be dropped, not emitted in the clear")
	}
	if got := e.st.udpUnknown.Load(); got != 1 {
		t.Errorf("udpUnknown = %d, want 1", got)
	}
	if got := e.st.udpForeign.Load(); got != 0 {
		t.Errorf("the datagram was dropped, so udpForeign must stay 0, got %d", got)
	}
}

// TestHandleUDPLeavesLocalAlone pins that loopback and LAN destinations never reach the ownership check: a routed app still has to talk to the local proxy, the NAS and the router.
func TestHandleUDPLeavesLocalAlone(t *testing.T) {
	e := quietEngine()
	e.liveUDP.Store(&map[uint16]bool{51000: true}) // live, so only the local check can save it
	var addr windivert.Address

	for _, dst := range []string{"127.0.0.1", "192.168.1.1", "224.0.0.251"} {
		if !e.handlePacket(nil, udpPacket(t, 51000, 53, dst), &addr) {
			t.Errorf("a datagram to %s must be passed through untouched", dst)
		}
	}
	if got := e.st.udpUnknown.Load(); got != 0 {
		t.Errorf("local traffic must not be counted as undecided, got %d", got)
	}
}

// reapplyEngine is the state reconcile actually produces: interception already running, and the same selection applied again on a tunnel state change. A stopped engine cannot hold UDP flows, and on a running one SetApps(nil) tears everything down through stopLocked before the retirement loop is reached.
func reapplyEngine(flows map[udpKey]*udpFlow, selected ...string) *Engine {
	e := quietEngine()
	e.nameCache = map[uint32]string{fakePID: fakeApp}
	e.nameBad = map[uint32]time.Time{}
	e.apps = map[string]bool{}
	e.lastSel = map[string]bool{}
	for _, n := range selected {
		e.apps[n] = true
		e.lastSel[n] = true // already selected, so nothing counts as added and no connection reset is spawned
	}
	e.running = true
	e.udpFlows = flows
	return e
}

// TestSetAppsKeepsFlowsWithUnreadableOwner pins that an unreadable exe name is not read as "not selected". The negative name cache lasts 2s, and reconcile calls SetApps on every tunnel state change, so treating "" as an answer tore down a still-selected app's live call.
func TestSetAppsKeepsFlowsWithUnreadableOwner(t *testing.T) {
	kept := &closeConn{}
	key := udpKey{appPort: 51000}
	e := reapplyEngine(map[udpKey]*udpFlow{key: {appPort: 51000, conn: kept, pid: 0xFFFFFFF0}}, fakeApp) // a PID that cannot be opened

	e.SetApps([]string{fakeApp})

	if _, ok := e.udpFlows[key]; !ok {
		t.Fatal("a flow whose owner's name cannot be read must be left alone")
	}
	if kept.closed.Load() {
		t.Error("its tunnel socket must stay open")
	}
}

// TestSetAppsKeepsFlowsOfSelectedApp pins the common case: reconcile reapplies the same selection on every tunnel flap, and a routed app's live call must survive it.
func TestSetAppsKeepsFlowsOfSelectedApp(t *testing.T) {
	kept := &closeConn{}
	key := udpKey{appPort: 51002}
	e := reapplyEngine(map[udpKey]*udpFlow{key: {appPort: 51002, conn: kept, pid: fakePID}}, fakeApp)

	e.SetApps([]string{fakeApp})

	if _, ok := e.udpFlows[key]; !ok {
		t.Fatal("a still-selected app's flow must survive a reapply")
	}
	if kept.closed.Load() {
		t.Error("its tunnel socket must stay open")
	}
}

// TestSetAppsDropsFlowsOfDeselectedApp pins the other side: an app removed from the selection keeps refreshing its own idle timer with every datagram, so nothing else would ever retire its flow.
func TestSetAppsDropsFlowsOfDeselectedApp(t *testing.T) {
	gone := &closeConn{}
	key := udpKey{appPort: 51001}
	e := reapplyEngine(map[udpKey]*udpFlow{key: {appPort: 51001, conn: gone, pid: fakePID}}, "other.exe")

	e.SetApps([]string{"other.exe"})

	if _, ok := e.udpFlows[key]; ok {
		t.Fatal("a flow whose owner is no longer selected must be retired")
	}
	if !gone.closed.Load() {
		t.Error("its tunnel socket must be closed")
	}
}
