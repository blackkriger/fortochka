//go:build windows

package apptunnel

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"fortochka/internal/windivert"
)

// TestHandleTCPRetiresStaleMapping pins the re-decision on a recycled port. A port reused by the same process for a new connection would otherwise be redirected to the previous connection's destination.
func TestHandleTCPRetiresStaleMapping(t *testing.T) {
	otherPeer := netip.MustParseAddr("198.51.100.4")

	e := targetEngine(t, true)
	e.tracked[52350] = mapping{appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}
	e.seen[52350] = fakePID
	e.portPID.Store(snap(map[uint16]uint32{52350: fakePID}))
	var addr windivert.Address
	addr.SetOutbound(true)
	p := synPacket(52350, 8443, otherPeer)

	if !e.handlePacket(nil, p, &addr) {
		t.Fatal("the redirected SYN must be reinjected")
	}
	{

		e.trackMu.Lock()
		m, ok := e.tracked[52350]
		e.trackMu.Unlock()
		if !ok {
			t.Fatal("the new connection must get a mapping")
		}
		if m.dstIP != otherPeer || m.dstPort != 8443 {
			t.Errorf("mapping = %s:%d, want the new destination %s:8443 — the stale one was not retired", m.dstIP, m.dstPort, otherPeer)
		}
		if got := e.st.reSYN.Load(); got != 1 {
			t.Errorf("reSYN = %d, want 1", got)
		}
		if got := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]}); got != otherPeer {
			t.Errorf("source = %s, want the new destination %s", got, otherPeer)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type stalledConn struct {
	net.Conn
	closed bool
}

func (c *stalledConn) SetWriteDeadline(time.Time) error { return nil }
func (c *stalledConn) Write([]byte) (int, error)        { return 0, timeoutErr{} }
func (c *stalledConn) Close() error                     { c.closed = true; return nil }

// TestHandleUDPEvictsWedgedFlow pins the stall ceiling. A flow whose send buffer never drains again refreshes its own idle timer with the very datagrams it is dropping, so the idle sweep never reaches it and it discards everything the app sends for as long as the app keeps sending.
func TestHandleUDPEvictsWedgedFlow(t *testing.T) {
	e := quietEngine()
	c := &stalledConn{}
	key := udpKey{appPort: 51010, dstIP: netip.MustParseAddr("8.8.8.8"), dstPort: 443}
	fl := &udpFlow{appIP: testApp, appPort: 51010, dstIP: key.dstIP, dstPort: 443, conn: c, pid: fakePID}
	fl.lastSeen.Store(time.Now().UnixNano())
	e.udpFlows = map[udpKey]*udpFlow{key: fl}
	e.udpDirect = map[udpKey]udpDecision{}

	pkt := make([]byte, 64)
	n := buildUDPReply(pkt, testApp, key.dstIP, 51010, 443, []byte("voice"))
	var addr windivert.Address

	for i := 1; i < udpStallLimit; i++ {
		if e.handlePacket(nil, pkt[:n], &addr) {
			t.Fatalf("datagram %d: a routed app's datagram must be dropped, not emitted in the clear", i)
		}
		if _, ok := e.udpFlows[key]; !ok {
			t.Fatalf("the flow must survive %d consecutive drops; a burst is the intended cost", i)
		}
	}
	if e.handlePacket(nil, pkt[:n], &addr) {
		t.Fatal("the datagram must still be dropped")
	}
	if _, ok := e.udpFlows[key]; ok {
		t.Errorf("after %d consecutive drops the flow must be torn down so the next datagram can build a working one", udpStallLimit)
	}
	if !c.closed {
		t.Error("its tunnel socket must be closed")
	}
	if got := e.st.udpStalled.Load(); got != 1 {
		t.Errorf("udpStalled = %d, want 1", got)
	}
	if got := e.st.udpDrop.Load(); got != uint64(udpStallLimit) {
		t.Errorf("udpDrop = %d, want %d", got, udpStallLimit)
	}
}

// TestHandleTCPDropsMappingOnRecycledPort pins the case where retiring the mapping is the only thing that happens: the port moved to a process the user did not pick, so no new mapping overwrites the old one, and leaving it would redirect that process's next packet to the previous owner's destination.
func TestHandleTCPDropsMappingOnRecycledPort(t *testing.T) {
	const otherPID uint32 = fakePID + 4

	e := targetEngine(t, true)
	e.nameCache[otherPID] = "other.exe"
	e.tracked[52351] = mapping{appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}
	e.seen[52351] = fakePID
	e.portPID.Store(snap(map[uint16]uint32{52351: otherPID})) // the system handed the port on
	var addr windivert.Address
	addr.SetOutbound(true)
	p := synPacket(52351, 443, netip.MustParseAddr("198.51.100.7"))

	if !e.handlePacket(nil, p, &addr) {
		t.Fatal("the new owner is not selected, so its SYN must be passed through")
	}
	e.trackMu.Lock()
	m, ok := e.tracked[52351]
	e.trackMu.Unlock()
	if ok {
		t.Errorf("the previous owner's mapping must be retired, or this port's next packet is redirected to %s", m.dstIP)
	}
	if got := e.st.reSYN.Load(); got != 1 {
		t.Errorf("reSYN = %d, want 1", got)
	}
	if !addr.Outbound() {
		t.Error("the packet must stay outbound")
	}
}

// TestHandleTCPReleasesPortToListener pins the one packet a tracked flow can never send. A tracked mapping is an outbound client connection, so a SYN-ACK on its port comes from a socket that has since taken the port — and a listener keeps that port in the connection table forever, which puts it permanently out of the sweep's reach. Left unchecked, every connection that listener accepts has its SYN-ACK rewritten and injected at the old app, so the real client never gets an answer.
func TestHandleTCPReleasesPortToListener(t *testing.T) {
	const listenerPID uint32 = fakePID + 8

	e := targetEngine(t, true)
	e.nameCache[listenerPID] = "server.exe"
	e.tracked[52360] = mapping{appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}
	e.seen[52360] = fakePID
	e.portPID.Store(snap(map[uint16]uint32{52360: listenerPID})) // the port is a listener's now
	var addr windivert.Address
	addr.SetOutbound(true)

	p := synPacket(52360, 443, netip.MustParseAddr("198.51.100.9"))
	p[33] = tcpSYN | tcpACK // answering an inbound connection
	before := make([]byte, len(p))
	copy(before, p)

	if !e.handlePacket(nil, p, &addr) {
		t.Fatal("the listener's answer must be passed through")
	}
	for i := range p {
		if p[i] != before[i] {
			t.Fatalf("the listener's answer must not be rewritten: %x -> %x", before, p)
		}
	}
	if !addr.Outbound() {
		t.Error("the packet must stay outbound")
	}
	e.trackMu.Lock()
	_, ok := e.tracked[52360]
	e.trackMu.Unlock()
	if ok {
		t.Error("the previous owner's mapping must be released, or this listener is unreachable for the rest of the run")
	}
	if got := e.st.reSYN.Load(); got != 1 {
		t.Errorf("reSYN = %d, want 1", got)
	}
}
