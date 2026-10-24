package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"fortochka/internal/rules"
)

type netDialer struct{}

func (netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func startUpstream(t *testing.T, want int) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, want)
		n, _ := io.ReadFull(c, buf)
		got <- buf[:n]
	}()
	return ln.Addr().String(), got
}

func startProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{Engine: rules.New(rules.Direct), Direct: netDialer{}, WG: netDialer{}}
	go s.Serve(ln)
	return ln.Addr().String()
}

func TestRelayKeepsBytesSentRightAfterTheHandshake(t *testing.T) {
	const early = "sent before the reply"
	for _, kind := range []string{"http", "socks5"} {
		target, got := startUpstream(t, len(early))
		c, err := net.Dial("tcp", startProxy(t))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(5 * time.Second))

		var hello []byte
		replyLen := 0
		if kind == "http" {
			hello = []byte("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")
		} else {
			host, portStr, _ := net.SplitHostPort(target)
			port, _ := strconv.Atoi(portStr)
			hello = []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01}
			hello = append(hello, net.ParseIP(host).To4()...)
			hello = binary.BigEndian.AppendUint16(hello, uint16(port))
			replyLen = 2 + 10
		}
		if _, err := c.Write(append(hello, early...)); err != nil {
			t.Fatal(err)
		}

		if kind == "http" {
			resp, err := bufio.NewReader(c).ReadString('\n')
			if err != nil || resp[:12] != "HTTP/1.1 200" {
				t.Fatalf("%s: want a 200 for the CONNECT, got %q, %v", kind, resp, err)
			}
		} else {
			reply := make([]byte, replyLen)
			if _, err := io.ReadFull(c, reply); err != nil || reply[3] != 0x00 {
				t.Fatalf("%s: want a success reply, got %v, %v", kind, reply, err)
			}
		}

		select {
		case b := <-got:
			if string(b) != early {
				t.Errorf("%s: upstream got %q, want the bytes the client pipelined after the handshake: %q", kind, b, early)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s: upstream never received the pipelined bytes", kind)
		}
		c.Close()
	}
}
