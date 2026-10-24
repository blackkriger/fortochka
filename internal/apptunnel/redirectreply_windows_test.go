//go:build windows

package apptunnel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"fortochka/internal/windivert"
)

var (
	testApp  = netip.MustParseAddr("192.168.1.10")
	testPeer = netip.MustParseAddr("203.0.113.9")
)

// replyPacket builds what the redirect listener sends back to a routed app: source port 1083, destination the connection's peer.
func replyPacket(dst netip.Addr, dstPort uint16) []byte {
	p := make([]byte, 40)
	p[0], p[9] = 0x45, 6
	setIP(p, 12, testApp)
	setIP(p, 16, dst)
	binary.BigEndian.PutUint16(p[20:], redirPort)
	binary.BigEndian.PutUint16(p[22:], dstPort)
	p[33] = tcpACK
	return p
}

func trackedEngine() *Engine {
	e := quietEngine()
	e.tracked = map[uint16]mapping{52345: {appIP: testApp, dstIP: testPeer, dstPort: 443, pid: 1234}}
	e.seen = map[uint16]uint32{}
	e.trackMiss = map[uint16]int{}
	return e
}

// TestRedirectReplyRejectsForeignPeer pins the source check on the listener's own packets. The listener accepts on 0.0.0.0 and the firewall rule has no scope, so a probe from the LAN that merely reused a tracked port number would otherwise have the listener's RST rewritten and injected into that app's live tunneled connection, killing it.
func TestRedirectReplyRejectsForeignPeer(t *testing.T) {
	e := trackedEngine()
	var addr windivert.Address
	p := replyPacket(netip.MustParseAddr("192.168.1.77"), 52345)
	before := bytes.Clone(p)

	if !e.handleTCP(nil, p, &addr, 20, testApp, redirPort, netip.MustParseAddr("192.168.1.77"), 52345) {
		t.Fatal("a packet for a peer this mapping does not name must be passed through")
	}
	if !bytes.Equal(before, p) {
		t.Errorf("the packet must not be rewritten: %x -> %x", before, p)
	}
}

// TestRedirectReplyRejectsUntrackedPort pins that a port with no mapping is left alone.
func TestRedirectReplyRejectsUntrackedPort(t *testing.T) {
	e := trackedEngine()
	var addr windivert.Address
	p := replyPacket(testPeer, 40000)
	before := bytes.Clone(p)

	if !e.handleTCP(nil, p, &addr, 20, testApp, redirPort, testPeer, 40000) {
		t.Fatal("an untracked port must be passed through")
	}
	if !bytes.Equal(before, p) {
		t.Errorf("the packet must not be rewritten: %x -> %x", before, p)
	}
}

// TestRedirectReplyRewritesNamedPeer pins the other side: the real reply must still be rewritten to look like it came from the destination the app dialled, or the app sees traffic from the redirect listener and resets.
func TestRedirectReplyRewritesNamedPeer(t *testing.T) {
	e := trackedEngine()
	var addr windivert.Address
	addr.SetOutbound(true)
	p := replyPacket(testPeer, 52345)

	if !e.handleTCP(nil, p, &addr, 20, testApp, redirPort, testPeer, 52345) {
		t.Fatal("the rewritten reply must be reinjected; dropping it kills every routed connection after its SYN-ACK")
	}
	{
		if got := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]}); got != testPeer {
			t.Errorf("source = %s, want the destination the app dialled (%s)", got, testPeer)
		}
		if got := binary.BigEndian.Uint16(p[20:]); got != 443 {
			t.Errorf("source port = %d, want 443", got)
		}
		if got := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]}); got != testApp {
			t.Errorf("destination = %s, want the app (%s)", got, testApp)
		}
		if addr.Outbound() {
			t.Error("the reply must be injected inbound, or it leaves on the wire instead of reaching the app")
		}
	}
}
