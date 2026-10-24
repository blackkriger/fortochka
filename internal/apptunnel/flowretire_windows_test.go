//go:build windows

package apptunnel

import (
	"net"
	"testing"
	"time"
)

type shortConn struct {
	net.Conn
	n int
}

func (c *shortConn) SetWriteDeadline(time.Time) error { return nil }
func (c *shortConn) Write(b []byte) (int, error)      { return c.n, nil }

// TestNBWriteShortWrite pins the short write as a failure. gonet retries a blocked write with a payload reader the first attempt already drained, so it can report success having put an empty datagram on the wire — counted as delivered, with the app's payload gone and the original packet already dropped.
func TestNBWriteShortWrite(t *testing.T) {
	payload := []byte("hello")

	err := nbWrite(&shortConn{n: len(payload) - 1}, payload)
	if err == nil {
		t.Fatal("a partial write must be reported, not counted as delivered")
	}
	if !dropped(err) {
		t.Error("a short write cost the datagram but left the socket usable, so the flow must be kept")
	}

	if err := nbWrite(&shortConn{n: len(payload)}, payload); err != nil {
		t.Errorf("a full write must succeed: %v", err)
	}
}

// TestPortListed pins the retirement rule, which has been wrong twice: once consulting only the IPv4 table (tearing down dual-stack flows every tick) and once requiring both tables (disabling the check on a host whose IPv6 walk fails).
func TestPortListed(t *testing.T) {
	v4 := snap(map[uint16]uint32{10: 100})
	v6 := snap(map[uint16]uint32{20: 200})
	empty := snap(map[uint16]uint32{})

	cases := []struct {
		name         string
		v4, v6       *map[uint16]uint32
		port         uint16
		listed, know bool
	}{
		{"v4 names it", v4, v6, 10, true, true},
		{"v6 names it, as a dual-stack socket on :: is", v4, v6, 20, true, true},
		{"neither names it", v4, v6, 30, false, true},
		{"only v4 walked, and names it", v4, nil, 10, true, true},
		{"only v4 walked, and does not", v4, nil, 30, false, true},
		{"only v6 walked, and names it", nil, v6, 20, true, true},
		{"both walks failed", nil, nil, 10, false, false},
		{"both walks came back empty", empty, empty, 10, false, false},
		{"one empty, one with rows", empty, v6, 20, true, true},
	}
	for _, c := range cases {
		listed, known := portListed(c.v4, c.v6, c.port)
		if listed != c.listed || known != c.know {
			t.Errorf("%s: portListed = (%v, %v), want (%v, %v)", c.name, listed, known, c.listed, c.know)
		}
	}
}
