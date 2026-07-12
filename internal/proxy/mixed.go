package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
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

	mu     sync.Mutex
	active map[net.Conn]connRoute
}

type connRoute struct {
	host string
	wg   bool
}

func (s *Server) track(c net.Conn, host string, wg bool) {
	s.mu.Lock()
	if s.active == nil {
		s.active = map[net.Conn]connRoute{}
	}
	s.active[c] = connRoute{host, wg}
	s.mu.Unlock()
}

func (s *Server) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.active, c)
	s.mu.Unlock()
}

// Rebalance closes active connections whose Direct/WG decision changed after a rules update, so the client reconnects onto the new route at once instead of riding the old one until it idles out.
func (s *Server) Rebalance() {
	s.mu.Lock()
	var stale []net.Conn
	for c, r := range s.active {
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
	if first[0] == 0x05 {
		s.handleSocks(conn, br)
		return
	}
	s.handleHTTP(conn, br)
}

func (s *Server) dialerFor(host string) (Dialer, string) {
	if s.Engine.Decide(host) == rules.WG {
		return s.WG, "wg"
	}
	return s.Direct, "direct"
}

func (s *Server) relay(client net.Conn, host, port string) {
	client.SetReadDeadline(time.Time{})
	dialer, route := s.dialerFor(host)
	s.track(client, host, route == "wg")
	defer s.untrack(client)
	log.Printf("proxy: %s -> %s:%s via %s", client.RemoteAddr(), host, port, route)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	upstream, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		log.Printf("proxy: dial %s:%s via %s failed: %v", host, port, route, err)
		return
	}
	defer upstream.Close()
	up, down := pipe(client, upstream)
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

func (s *Server) handleSocks(conn net.Conn, br *bufio.Reader) {
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
	s.relay(conn, host, port)
}

// --- HTTP (CONNECT tunnel, plus best-effort plain proxying) ---

const httpIdleTimeout = 60 * time.Second

func (s *Server) handleHTTP(conn net.Conn, br *bufio.Reader) {
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
			s.relay(conn, host, port)
			return
		}
		if !s.forwardHTTP(conn, req) {
			return
		}
	}
}

// forwardHTTP proxies one plain-HTTP request and reads the whole response back with http.ReadResponse (so the body is properly delimited), reporting whether the client connection may carry another request (keep-alive).
func (s *Server) forwardHTTP(conn net.Conn, req *http.Request) bool {
	host, port := splitHostPort(req.Host, "80")
	dialer, route := s.dialerFor(host)
	s.track(conn, host, route == "wg")
	defer s.untrack(conn)
	log.Printf("proxy: %s -> %s:%s via %s (http %s)", conn.RemoteAddr(), host, port, route, req.Method)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	upstream, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	cancel()
	if err != nil {
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
