//go:build windows

package apptunnel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"fortochka/internal/windivert"
)

// TestHandlePacketRejectsMalformed pins the header guards. An IHL below the minimum would make the port parser read the IP version and length fields as ports, and the TCP path would then write the redirect port over the total-length field before reinjecting.
func TestHandlePacketRejectsMalformed(t *testing.T) {
	var e Engine
	var addr windivert.Address

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"shorter than an IPv4 header", make([]byte, 19)},
		{"version 5", func() []byte { p := make([]byte, 40); p[0] = 0x55; return p }()},
		{"not tcp or udp", func() []byte { p := make([]byte, 40); p[0] = 0x45; p[9] = 1; return p }()},
		{"ihl 0 with tcp proto", func() []byte { p := make([]byte, 40); p[0] = 0x40; p[9] = 6; return p }()},
		{"ihl 4 with udp proto", func() []byte { p := make([]byte, 40); p[0] = 0x44; p[9] = 17; return p }()},
	}
	for _, c := range cases {
		before := bytes.Clone(c.pkt)
		if !e.handlePacket(nil, c.pkt, &addr) {
			t.Errorf("%s: must be passed through untouched, not consumed", c.name)
		}
		if !bytes.Equal(before, c.pkt) {
			t.Errorf("%s: the packet was modified: %x -> %x", c.name, before, c.pkt)
		}
	}
}

// TestIPProto pins the loop-stall diagnostic. It printed the WinDivert layer, which is the same constant for every handle, so a TCP stall and a UDP stall were indistinguishable in the log.
func TestIPProto(t *testing.T) {
	v4 := make([]byte, 40)
	v4[0], v4[9] = 0x45, 6
	if got := ipProto(v4); got != 6 {
		t.Errorf("IPv4 proto = %d, want 6", got)
	}
	v4[9] = 17
	if got := ipProto(v4); got != 17 {
		t.Errorf("IPv4 proto = %d, want 17", got)
	}

	v6 := make([]byte, 48)
	v6[0], v6[6] = 0x60, 17
	if got := ipProto(v6); got != 17 {
		t.Errorf("IPv6 next header = %d, want 17", got)
	}

	if got := ipProto(make([]byte, 4)); got != 0 {
		t.Errorf("a packet too short to hold a protocol must report 0, got %d", got)
	}
}

// TestBuildUDPReply pins the reply header. The buffer is reused across replies, so a field left from the previous datagram would travel on this one.
func TestBuildUDPReply(t *testing.T) {
	src := netip.MustParseAddr("1.2.3.4")
	dst := netip.MustParseAddr("10.0.0.2")
	payload := []byte("hello")

	pkt := make([]byte, 64)
	for i := range pkt {
		pkt[i] = 0xFF // dirty, as a reused buffer is
	}
	n := buildUDPReply(pkt, src, dst, 443, 51820, payload)
	if n != 28+len(payload) {
		t.Fatalf("length = %d, want %d", n, 28+len(payload))
	}
	p := pkt[:n]
	if p[0] != 0x45 {
		t.Errorf("version/IHL = %#x, want 0x45", p[0])
	}
	if got := binary.BigEndian.Uint16(p[2:]); int(got) != n {
		t.Errorf("total length = %d, want %d", got, n)
	}
	if p[8] != 64 || p[9] != 17 {
		t.Errorf("ttl/proto = %d/%d, want 64/17", p[8], p[9])
	}
	if got := netip.AddrFrom4([4]byte{p[12], p[13], p[14], p[15]}); got != src {
		t.Errorf("source = %s, want %s", got, src)
	}
	if got := netip.AddrFrom4([4]byte{p[16], p[17], p[18], p[19]}); got != dst {
		t.Errorf("destination = %s, want %s", got, dst)
	}
	if got := binary.BigEndian.Uint16(p[20:]); got != 443 {
		t.Errorf("source port = %d, want 443", got)
	}
	if got := binary.BigEndian.Uint16(p[22:]); got != 51820 {
		t.Errorf("destination port = %d, want 51820", got)
	}
	if got := binary.BigEndian.Uint16(p[24:]); int(got) != 8+len(payload) {
		t.Errorf("udp length = %d, want %d", got, 8+len(payload))
	}
	if !bytes.Equal(p[28:], payload) {
		t.Errorf("payload = %q, want %q", p[28:], payload)
	}
	for _, off := range []int{1, 4, 5, 6, 7, 10, 11, 26, 27} {
		if p[off] != 0 {
			t.Errorf("byte %d left over from the previous reply: %#x", off, p[off])
		}
	}
}

// TestBuildUDPReplyRejectsOversize pins the bounds check: a datagram larger than the inject buffer must be refused rather than truncated or written past the end.
func TestBuildUDPReplyRejectsOversize(t *testing.T) {
	pkt := make([]byte, 32)
	if n := buildUDPReply(pkt, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("10.0.0.2"), 1, 2, make([]byte, 5)); n != -1 {
		t.Errorf("a payload that does not fit must return -1, got %d", n)
	}
	if n := buildUDPReply(pkt, netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("10.0.0.2"), 1, 2, make([]byte, 4)); n != 32 {
		t.Errorf("a payload that exactly fits must be accepted, got %d", n)
	}
}

// TestHandlePacketRejectsShortIHL pins the guard itself, not just the pass-through. Without it the port parser reads the version and total-length bytes as ports, so the datagram is judged against a port its sender never used — and on a port that happens to be live it is dropped.
func TestHandlePacketRejectsShortIHL(t *testing.T) {
	e := quietEngine()
	// 0x40 is version 4 with IHL 0, so a missing guard reads the source port from the first two header bytes.
	const misparsedPort = 0x4000
	e.liveUDP.Store(&map[uint16]bool{misparsedPort: true})

	p := make([]byte, 64)
	p[0], p[9] = 0x40, 17
	copy(p[12:16], []byte{192, 168, 1, 50})
	copy(p[16:20], []byte{8, 8, 8, 8})
	var addr windivert.Address

	if !e.handlePacket(nil, p, &addr) {
		t.Fatal("a header shorter than the minimum must be passed through, not decided on misparsed ports")
	}
	if got := e.st.udpUnknown.Load(); got != 0 {
		t.Errorf("the packet must never reach the ownership check, got udpUnknown = %d", got)
	}
	if got := e.st.udpForeign.Load(); got != 0 {
		t.Errorf("the packet must never reach the ownership check, got udpForeign = %d", got)
	}
}
