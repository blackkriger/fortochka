//go:build windows

package apptunnel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"fortochka/internal/windivert"
)

// fakePID stands in for a routed app's process. selfPID cannot be used: handleUDP and handleIPv6 exclude it by design, so the tunnel never captures its own datagrams.
const fakePID uint32 = 0x7FFFFFF0

const fakeApp = "game.exe"

// targetEngine routes fakeApp by seeding the name cache, so the ownership branches run without depending on a real process being present.
func targetEngine(t *testing.T, routed bool) *Engine {
	t.Helper()
	e := quietEngine()
	e.nameCache = map[uint32]string{fakePID: fakeApp}
	e.nameBad = map[uint32]time.Time{}
	e.apps = map[string]bool{}
	if routed {
		e.apps[fakeApp] = true
	}
	e.tracked = map[uint16]mapping{}
	e.seen = map[uint16]uint32{}
	e.trackMiss = map[uint16]int{}
	return e
}

func synPacket(srcPort, dstPort uint16, dst netip.Addr) []byte {
	p := make([]byte, 40)
	p[0], p[9] = 0x45, 6
	setIP(p, 12, testApp)
	setIP(p, 16, dst)
	binary.BigEndian.PutUint16(p[20:], srcPort)
	binary.BigEndian.PutUint16(p[22:], dstPort)
	p[33] = tcpSYN
	return p
}

// TestHandleTCPRoutesTargetSYN pins the single most load-bearing branch in the file: the one that decides a connection belongs to a routed app and redirects it. It must write the mapping, rewrite the packet to the local listener, and mark the packet inbound so the local stack receives it instead of the network.
func TestHandleTCPRoutesTargetSYN(t *testing.T) {
	e := targetEngine(t, true)
	e.portPID.Store(snap(map[uint16]uint32{52346: fakePID}))
	var addr windivert.Address
	addr.SetOutbound(true)
	p := synPacket(52346, 443, testPeer)

	if !e.handlePacket(nil, p, &addr) {
		t.Fatal("the redirected SYN must be reinjected; dropping it blackholes every routed TCP connection")
	}
	{

		e.trackMu.Lock()
		m, tracked := e.tracked[52346]
		seen, ok := e.seen[52346]
		e.trackMu.Unlock()
		if !tracked {
			t.Fatal("a routed app's SYN must be recorded, or its later packets are passed through in the clear")
		}
		if m.dstIP != testPeer || m.dstPort != 443 || m.appIP != testApp || m.pid != fakePID {
			t.Errorf("mapping = %+v, want the app, its destination and its owner", m)
		}
		if !ok || seen != fakePID {
			t.Errorf("seen[52346] = (%d, %v), want (%d, true)", seen, ok, fakePID)
		}
		if got := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]}); got != testPeer {
			t.Errorf("source = %s, want the destination the app dialled (%s)", got, testPeer)
		}
		if got := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]}); got != testApp {
			t.Errorf("destination = %s, want the app (%s)", got, testApp)
		}
		if got := binary.BigEndian.Uint16(p[22:]); got != redirPort {
			t.Errorf("destination port = %d, want the redirect listener (%d)", got, redirPort)
		}
		if addr.Outbound() {
			t.Error("the packet must be injected inbound, or the redirected SYN leaves on the wire instead of reaching the listener")
		}
		if got := e.st.tcpRouted.Load(); got != 1 {
			t.Errorf("tcpRouted = %d, want 1", got)
		}
	}
}

// TestHandleTCPPassesUnselectedSYN pins the other side: a process the user did not pick must be left alone and recorded as decided, so its following packets cost nothing.
func TestHandleTCPPassesUnselectedSYN(t *testing.T) {
	e := targetEngine(t, false)
	e.portPID.Store(snap(map[uint16]uint32{52347: fakePID}))
	var addr windivert.Address
	addr.SetOutbound(true)
	p := synPacket(52347, 443, testPeer)
	before := bytes.Clone(p)

	if !e.handlePacket(nil, p, &addr) {
		t.Fatal("an unselected process's SYN must be passed through")
	}
	if !bytes.Equal(before, p) {
		t.Errorf("the packet must not be rewritten: %x -> %x", before, p)
	}
	if !addr.Outbound() {
		t.Error("the packet must stay outbound")
	}
	e.trackMu.Lock()
	_, tracked := e.tracked[52347]
	_, seen := e.seen[52347]
	e.trackMu.Unlock()
	if tracked {
		t.Error("an unselected process must not get a mapping")
	}
	if !seen {
		t.Error("the decision must be recorded, or every packet of the connection re-runs it")
	}
	if got := e.st.tcpDirect.Load(); got != 1 {
		t.Errorf("tcpDirect = %d, want 1", got)
	}
}

func v6Packet(nextHeader byte, srcPort uint16, dst netip.Addr) []byte {
	p := make([]byte, 48)
	p[0], p[6] = 0x60, nextHeader
	copy(p[24:40], dst.AsSlice())
	binary.BigEndian.PutUint16(p[40:], srcPort)
	return p
}

// TestHandleIPv6DropsRoutedApp pins the IPv6 drop. The tunnel carries IPv4 only, so reinjecting a routed app's IPv6 would put its real address on the wire; dropping makes the app fall back to IPv4 instead.
func TestHandleIPv6DropsRoutedApp(t *testing.T) {
	global := netip.MustParseAddr("2001:db8::1")

	e := targetEngine(t, true)
	e.portPID6.Store(snap(map[uint16]uint32{52348: fakePID}))
	if e.handlePacket(nil, v6Packet(6, 52348, global), &windivert.Address{}) {
		t.Error("a routed app's IPv6 must be dropped, not passed through")
	}
	if got := e.st.v6Blocked.Load(); got != 1 {
		t.Errorf("v6Blocked = %d, want 1", got)
	}

	other := targetEngine(t, false)
	other.portPID6.Store(snap(map[uint16]uint32{52348: fakePID}))
	if !other.handlePacket(nil, v6Packet(6, 52348, global), &windivert.Address{}) {
		t.Error("an unselected process's IPv6 must be passed through")
	}

	e.st.v6Blocked.Store(0)
	if !e.handlePacket(nil, v6Packet(6, 52348, netip.MustParseAddr("fd00::1")), &windivert.Address{}) {
		t.Error("a private IPv6 destination must be passed through, or LAN access breaks")
	}
	if got := e.st.v6Blocked.Load(); got != 0 {
		t.Errorf("local traffic must not be counted as blocked, got %d", got)
	}
}

// TestHandleTCPRewritesTrackedFlow pins the steady-state path: every later packet of an already-decided routed connection must be rewritten to the listener and reinjected. Dropping it instead blackholes the connection after its SYN, and the SYN path cannot catch that because it never runs again.
func TestHandleTCPRewritesTrackedFlow(t *testing.T) {
	e := targetEngine(t, true)
	e.tracked[52370] = mapping{appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}
	e.seen[52370] = fakePID
	e.portPID.Store(snap(map[uint16]uint32{52370: fakePID}))
	var addr windivert.Address
	addr.SetOutbound(true)

	p := synPacket(52370, 443, testPeer)
	p[33] = tcpACK // mid-connection data, not a fresh SYN

	if !e.handlePacket(nil, p, &addr) {
		t.Fatal("a tracked connection's packet must be reinjected after rewriting; dropping it blackholes the connection")
	}
	if got := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]}); got != testPeer {
		t.Errorf("source = %s, want the destination the app dialled (%s)", got, testPeer)
	}
	if got := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]}); got != testApp {
		t.Errorf("destination = %s, want the app (%s)", got, testApp)
	}
	if got := binary.BigEndian.Uint16(p[22:]); got != redirPort {
		t.Errorf("destination port = %d, want the redirect listener (%d)", got, redirPort)
	}
	if addr.Outbound() {
		t.Error("the packet must be injected inbound")
	}
}
