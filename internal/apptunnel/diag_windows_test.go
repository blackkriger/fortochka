//go:build windows

package apptunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func logged(lines []string, part string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l, part) {
			n++
		}
	}
	return n
}

func diagEngine() (*Engine, *[]string) {
	e, lines := capturingEngine()
	e.nameCache = map[uint32]string{fakePID: fakeApp}
	e.nameBad = map[uint32]time.Time{}
	return e, lines
}

// TestSweepFlowsReportsSilentSender pins the detector for the Discord outage: the flow keeps receiving while the app's own datagrams stop reaching the capture loop, and every error counter stays still. It must say so once, name the port, and say whether that port was in the capture filter.
func TestSweepFlowsReportsSilentSender(t *testing.T) {
	e, lines := diagEngine()
	c := &closeConn{}
	k := udpKey{appPort: 6000}
	fl := &udpFlow{appPort: 6000, conn: c, pid: fakePID}
	now := time.Now().UnixNano()
	fl.lastSeen.Store(now)
	fl.lastIn.Store(now)
	fl.lastOut.Store(now - int64(20*time.Second))
	e.udpFlows = map[udpKey]*udpFlow{k: fl}
	e.udpDirect = map[udpKey]udpDecision{}
	e.capturedPorts.Store(&map[uint16]bool{6000: true})

	e.sweepFlows()
	if got := logged(*lines, "is receiving but has sent nothing"); got != 1 {
		t.Fatalf("want one silent-sender line, got %d: %q", got, *lines)
	}
	if logged(*lines, "game.exe udp :6000") != 1 || logged(*lines, "port in capture filter: yes") != 1 {
		t.Errorf("the line must name the app, the port and whether it was captured: %q", *lines)
	}

	e.sweepFlows()
	if got := logged(*lines, "is receiving but has sent nothing"); got != 1 {
		t.Errorf("an ongoing silence must be reported once, not every sweep: got %d lines", got)
	}

	fl.lastOut.Store(time.Now().UnixNano())
	e.sweepFlows()
	if got := logged(*lines, "is sending again after"); got != 1 {
		t.Errorf("the recovery must be reported, so the outage has an end time: %q", *lines)
	}
	if _, ok := e.udpFlows[k]; !ok {
		t.Error("reporting must not retire the flow")
	}
}

// TestSweepFlowsSilentSenderNeedsInbound pins what the detector must not report: a flow quiet in both directions is just idle, and one still sending is healthy.
func TestSweepFlowsSilentSenderNeedsInbound(t *testing.T) {
	now := time.Now().UnixNano()
	for _, c := range []struct {
		name    string
		in, out int64
	}{
		{"quiet both ways", now - int64(30*time.Second), now - int64(30*time.Second)},
		{"still sending", now, now},
		{"never received", 0, now - int64(30*time.Second)},
	} {
		e, lines := diagEngine()
		fl := &udpFlow{appPort: 6000, conn: &closeConn{}, pid: fakePID}
		fl.lastSeen.Store(now)
		fl.lastIn.Store(c.in)
		fl.lastOut.Store(c.out)
		e.udpFlows = map[udpKey]*udpFlow{{appPort: 6000}: fl}
		e.udpDirect = map[udpKey]udpDecision{}

		e.sweepFlows()
		if got := logged(*lines, "has sent nothing"); got != 0 {
			t.Errorf("%s: must not be reported as a silent sender: %q", c.name, *lines)
		}
	}
}

type remoteConn struct {
	net.Conn
	remote net.Addr
}

func (c *remoteConn) RemoteAddr() net.Addr { return c.remote }

// TestSweepTrackedClosesLiveRelay pins the D1 signature: a mapping retired by the port sweep while the app's relay is still open. The app's socket is gone by then, so nothing on its side will ever end the relay: the sweep must close both of its ends and say so. A relay that merely shares the port number but talks to another peer belongs to a different connection and must be left alone.
func TestSweepTrackedClosesLiveRelay(t *testing.T) {
	for _, c := range []struct {
		name    string
		open    bool
		relayIP netip.Addr
		closed  bool
	}{
		{"relay to the retired peer", true, testPeer, true},
		{"relay on the same port to another peer", true, netip.MustParseAddr("198.51.100.7"), false},
		{"no relay", false, netip.Addr{}, false},
	} {
		e, lines := diagEngine()
		e.tracked = map[uint16]mapping{5200: {appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}}
		e.seen = map[uint16]uint32{5200: fakePID}
		e.trackMiss = map[uint16]int{}
		e.portPID.Store(snap(map[uint16]uint32{9999: 1}))
		e.portPID6.Store(snap(map[uint16]uint32{8888: 2}))
		e.redirects = map[net.Conn]net.Conn{}
		app, up := &closeConn{}, &closeConn{}
		if c.open {
			e.redirects[&remoteConn{Conn: app, remote: &net.TCPAddr{IP: c.relayIP.AsSlice(), Port: 5200}}] = up
		}

		e.sweepTracked()
		e.sweepTracked()

		want := 0
		if c.closed {
			want = 1
		}
		if got := logged(*lines, "game.exe :5200 -> 203.0.113.9:443 was retired by the port sweep while its relay was still open — closed 1 relay(s)"); got != want {
			t.Errorf("%s: want %d report, got %d: %q", c.name, want, got, *lines)
		}
		if app.closed.Load() != c.closed || up.closed.Load() != c.closed {
			t.Errorf("%s: app side closed=%v, tunnel side closed=%v, want both %v", c.name, app.closed.Load(), up.closed.Load(), c.closed)
		}
	}
}

type pipeDialer struct{ conn net.Conn }

func (d pipeDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.conn, nil
}

// TestHandleRedirectLogsRelayEnd pins the relay's last line: how long it lived, how much it carried, and which side gave up first. That is what tells a dying control connection apart from an app that closed it on purpose.
func TestHandleRedirectLogsRelayEnd(t *testing.T) {
	for _, side := range []string{"app", "tunnel"} {
		e, lines := diagEngine()
		e.tracked = map[uint16]mapping{52345: {appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}}
		e.redirects = map[net.Conn]net.Conn{}

		appSide, appPeer := net.Pipe()
		upSide, upPeer := net.Pipe()
		e.dial = pipeDialer{upSide}
		c := &remoteConn{Conn: appSide, remote: &net.TCPAddr{IP: testPeer.AsSlice(), Port: 52345}}

		done := make(chan struct{})
		go func() { e.handleRedirect(c); close(done) }()

		go appPeer.Write([]byte("hello"))
		got := make([]byte, 5)
		if _, err := io.ReadFull(upPeer, got); err != nil || string(got) != "hello" {
			t.Fatalf("%s: the relay must carry the app's bytes into the tunnel: %q, %v", side, got, err)
		}
		if side == "app" {
			appPeer.Close()
		} else {
			upPeer.Close()
		}

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: the relay did not end", side)
		}

		want := fmt.Sprintf("%s closed first", side)
		if got := logged(*lines, "game.exe :52345 -> 203.0.113.9:443 closed after"); got != 1 {
			t.Fatalf("%s: want one relay-end line naming the app, port and target, got %d: %q", side, got, *lines)
		}
		if logged(*lines, want) != 1 {
			t.Errorf("%s: the line must say %q: %q", side, want, *lines)
		}
		if logged(*lines, "(5 up /") != 1 {
			t.Errorf("%s: the line must carry the bytes sent up: %q", side, *lines)
		}
	}
}

type failReader struct{ err error }

func (r failReader) Read([]byte) (int, error) { return 0, r.err }

type failWriter struct{ err error }

func (w failWriter) Write([]byte) (int, error) { return 0, w.err }

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

// TestPump pins the relay's copy loop. Every redirected TCP connection now runs through it, so it must move every byte exactly as io.Copy does, and keep a failure on the reading end apart from one on the writing end — that difference is the whole reason it replaced io.Copy.
func TestPump(t *testing.T) {
	payload := strings.Repeat("0123456789abcdef", 8192) // 128KiB, several buffers' worth
	var dst strings.Builder
	n, rerr, werr := pump(&dst, strings.NewReader(payload))
	if n != int64(len(payload)) || rerr != nil || werr != nil || dst.String() != payload {
		t.Fatalf("clean copy = (%d, %v, %v), copied %d bytes intact=%v; want every byte and no error", n, rerr, werr, dst.Len(), dst.String() == payload)
	}

	boom := fmt.Errorf("boom")
	if _, rerr, werr := pump(io.Discard, failReader{boom}); rerr != boom || werr != nil {
		t.Errorf("a failing source = (read %v, write %v), want it reported as a read failure", rerr, werr)
	}
	if _, rerr, werr := pump(failWriter{boom}, strings.NewReader("x")); werr != boom || rerr != nil {
		t.Errorf("a failing destination = (read %v, write %v), want it reported as a write failure", rerr, werr)
	}
	if _, rerr, werr := pump(shortWriter{}, strings.NewReader("xyz")); werr != io.ErrShortWrite || rerr != nil {
		t.Errorf("a short write = (read %v, write %v), want io.ErrShortWrite on the write side", rerr, werr)
	}
}

// brokenTunnel accepts nothing: every write fails, and reads wait until the relay closes it.
type brokenTunnel struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (b *brokenTunnel) Write([]byte) (int, error) { return 0, fmt.Errorf("tunnel write broke") }
func (b *brokenTunnel) Read([]byte) (int, error)  { <-b.closed; return 0, io.ErrClosedPipe }
func (b *brokenTunnel) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// TestHandleRedirectBlamesTheFailingWriter pins the case the plain io.Copy got backwards: the goroutine reading from the app ends first, but because writing into the tunnel failed. That is the tunnel's failure, and saying "app" here would point the next investigation at the wrong side.
func TestHandleRedirectBlamesTheFailingWriter(t *testing.T) {
	e, lines := diagEngine()
	e.tracked = map[uint16]mapping{52345: {appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}}
	e.redirects = map[net.Conn]net.Conn{}
	e.dial = pipeDialer{&brokenTunnel{closed: make(chan struct{})}}

	appSide, appPeer := net.Pipe()
	c := &remoteConn{Conn: appSide, remote: &net.TCPAddr{IP: testPeer.AsSlice(), Port: 52345}}
	done := make(chan struct{})
	go func() { e.handleRedirect(c); close(done) }()
	go io.Copy(io.Discard, appPeer)
	go appPeer.Write([]byte("hello"))

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the relay did not end")
	}
	if logged(*lines, "tunnel failed first: tunnel write broke") != 1 {
		t.Errorf("a failed write into the tunnel must be blamed on the tunnel: %q", *lines)
	}
}
