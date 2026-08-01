package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"fortochka/internal/rules"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// handshakeDeadline bounds how long a client may take over the SOCKS/HTTP handshake before its goroutine is reclaimed; cleared once relaying starts.
const handshakeDeadline = 15 * time.Second

// Server is a mixed SOCKS5 + HTTP proxy on one port that asks the engine whether each destination goes Direct or through WG, then splices the streams.
type Server struct {
	Engine *rules.Engine
	Direct Dialer
	WG     Dialer

	// ForceWG reports whether the process owning a client's local TCP port is a per-app-tunneled app; if so its proxied traffic goes through WG regardless of the rules. nil disables the check.
	ForceWG func(localPort uint16) bool

	// WGReady reports whether the tunnel can carry traffic; without it a reconnecting tunnel makes every routed request wait out the full dial timeout instead of failing so the browser can retry. nil disables the check.
	WGReady func() bool

	mu     sync.Mutex
	active map[net.Conn]connRoute

	st stats
}

// stats are cumulative counters for the periodic health line, so a long log can be read without following every connection.
type stats struct {
	wgConns     atomic.Uint64
	directConns atomic.Uint64
	wgFailed    atomic.Uint64
	directFail  atomic.Uint64
	forced      atomic.Uint64 // sent to WG because the owning process is per-app routed
	wgUp        atomic.Int64
	wgDown      atomic.Int64
	directUp    atomic.Int64
	directDown  atomic.Int64
}

// Summary returns a one-line snapshot of what the proxy has routed so far.
func (s *Server) Summary() string {
	s.mu.Lock()
	live := len(s.active)
	s.mu.Unlock()
	return fmt.Sprintf("live=%d | wg conns=%d failed=%d %.1fMB up/%.1fMB down (forced=%d) | direct conns=%d failed=%d %.1fMB up/%.1fMB down",
		live,
		s.st.wgConns.Load(), s.st.wgFailed.Load(), mb(s.st.wgUp.Load()), mb(s.st.wgDown.Load()), s.st.forced.Load(),
		s.st.directConns.Load(), s.st.directFail.Load(), mb(s.st.directUp.Load()), mb(s.st.directDown.Load()))
}

func mb(n int64) float64 { return float64(n) / (1024 * 1024) }

type connRoute struct {
	host   string
	wg     bool
	forced bool // routed to WG because the owning process is per-app-tunneled, not by rule
}

func (s *Server) track(c net.Conn, host string, wg, forced bool) {
	s.mu.Lock()
	if s.active == nil {
		s.active = map[net.Conn]connRoute{}
	}
	s.active[c] = connRoute{host, wg, forced}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
}

// Rebalance closes active connections whose Direct/WG decision changed after a rules update, so the client reconnects onto the new route at once instead of riding the old one until it idles out. Per-app-forced connections are left alone — they stay on WG regardless of rules.
func (s *Server) Rebalance() {
	s.mu.Lock()
	var stale []net.Conn
	for c, r := range s.active {
		if r.forced {
			continue
		}
		if (s.Engine.Decide(r.host) == rules.WG) != r.wg {
			stale = append(stale, c)
		}
	}
	s.mu.Unlock()
	for _, c := range stale {
		c.Close()
	}
	if len(stale) > 0 {
		log.Printf("proxy: rerouted %d connection(s) after rules change", len(stale))
	}
}

func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("proxy: recovered panic from %s: %v", conn.RemoteAddr(), r)
		}
	}()
	conn.SetReadDeadline(time.Now().Add(handshakeDeadline))
	br := bufio.NewReader(conn)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	forceWG := s.forceWGFor(conn)
	if first[0] == 0x05 {
		s.handleSocks(conn, br, forceWG)
		return
	}
	s.handleHTTP(conn, br, forceWG)
}

// forceWGFor asks whether the process behind this client connection is a per-app-tunneled app, so all its proxied traffic is forced through WG (this is what makes marking a proxy-aware app actually tunnel everything it sends, not just rule-matched hosts).
func (s *Server) forceWGFor(conn net.Conn) bool {
	if s.ForceWG == nil {
		return false
	}
	ra, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	return s.ForceWG(uint16(ra.Port))
}

// dialTimeout shortens the wait while the tunnel is reconnecting: the client already got a success reply by this point, so refusing outright would look like a dropped connection and invite an immediate retry — a quick failure lets it back off normally instead of waiting out the full timeout.
func (s *Server) dialTimeout(viaWG bool) time.Duration {
	if viaWG && s.WGReady != nil && !s.WGReady() {
		return 5 * time.Second // long enough to ride out a first handshake right after Connect, short enough not to look like a hang
	}
	return 20 * time.Second
}

func (s *Server) dialerFor(host string, forceWG bool) (Dialer, string) {
	if forceWG || s.Engine.Decide(host) == rules.WG {
		return s.WG, "wg"
	}
	return s.Direct, "direct"
}

func (s *Server) relay(client net.Conn, host, port string, forceWG bool) {
	client.SetReadDeadline(time.Time{})
	dialer, route := s.dialerFor(host, forceWG)
	viaWG := route == "wg"
	s.track(client, host, viaWG, forceWG)
	defer s.untrack(client)
	if viaWG {
		s.st.wgConns.Add(1)
		if forceWG {
			s.st.forced.Add(1)
		}
	} else {
		s.st.directConns.Add(1)
	}
	log.Printf("proxy: %s -> %s:%s via %s", client.RemoteAddr(), host, port, route)
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout(viaWG))
	defer cancel()
	upstream, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		if viaWG {
			s.st.wgFailed.Add(1)
		} else {
			s.st.directFail.Add(1)
		}
		log.Printf("proxy: dial %s:%s via %s failed: %v", host, port, route, err)
		return
	}
	defer upstream.Close()
	up, down := pipe(client, upstream)
	if viaWG {
		s.st.wgUp.Add(up)
		s.st.wgDown.Add(down)
	} else {
		s.st.directUp.Add(up)
		s.st.directDown.Add(down)
	}
	log.Printf("proxy: %s:%s via %s closed (%d up / %d down bytes)", host, port, route, up, down)
}

func pipe(client, upstream net.Conn) (up, down int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); up, _ = io.Copy(upstream, client); halfClose(upstream) }()
	go func() { defer wg.Done(); down, _ = io.Copy(client, upstream); halfClose(client) }()
	wg.Wait()
	return up, down
}

func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
		return
	}
	c.Close()
}

// --- SOCKS5 (CONNECT only, no auth) ---

func (s *Server) handleSocks(conn net.Conn, br *bufio.Reader, forceWG bool) {
	// greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if _, err := io.CopyN(io.Discard, br, int64(head[1])); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[1] != 0x01 { // only CONNECT
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch req[3] {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(br, lb); err != nil {
			return
		}
		buf := make([]byte, lb[0])
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return
		}
		host = net.IP(buf).String()
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(br, pb); err != nil {
		return
	}
	port := strconv.Itoa(int(binary.BigEndian.Uint16(pb)))

	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	s.relay(conn, host, port, forceWG)
}

// --- HTTP (CONNECT tunnel, plus best-effort plain proxying) ---

const httpIdleTimeout = 60 * time.Second

func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader, forceWG bool) {
	for {
		conn.SetReadDeadline(time.Now().Add(httpIdleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method == http.MethodConnect {
			host, port := splitHostPort(req.Host, "443")
			if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
				return
			}
			s.relay(conn, host, port, forceWG)
			return
		}
		if !s.forwardHTTP(conn, req, forceWG) {
			return
		}
	}
}

// forwardHTTP proxies one plain-HTTP request and reads the whole response back with http.ReadResponse (so the body is properly delimited), reporting whether the client connection may carry another request (keep-alive).
func (s *Server) forwardHTTP(conn net.Conn, req *http.Request, forceWG bool) bool {
	host, port := splitHostPort(req.Host, "80")
	dialer, route := s.dialerFor(host, forceWG)
	s.track(conn, host, route == "wg", forceWG)
	defer s.untrack(conn)
	log.Printf("proxy: %s -> %s:%s via %s (http %s)", conn.RemoteAddr(), host, port, route, req.Method)

	viaWG := route == "wg"
	if viaWG {
		s.st.wgConns.Add(1)
	} else {
		s.st.directConns.Add(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.dialTimeout(viaWG))
	upstream, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	cancel()
	if err != nil {
		if viaWG {
			s.st.wgFailed.Add(1)
		} else {
			s.st.directFail.Add(1)
		}
		log.Printf("proxy: dial %s:%s via %s failed: %v", host, port, route, err)
		return false
	}
	defer upstream.Close()

	conn.SetReadDeadline(time.Time{})
	req.RequestURI = ""
	if err := req.Write(upstream); err != nil {
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if err := resp.Write(conn); err != nil {
		return false
	}
	return !req.Close && !resp.Close
}

func splitHostPort(hostport, defPort string) (string, string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return hostport, defPort
}
