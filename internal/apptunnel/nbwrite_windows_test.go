//go:build windows

package apptunnel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// TestNBWrite covers the regression where a write deadline of "now" made gonet report a timeout before it ever wrote, silently dropping every tunneled datagram.
func TestNBWrite(t *testing.T) {
	dev, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("10.0.0.2")},
		[]netip.Addr{netip.MustParseAddr("1.1.1.1")},
		1420,
	)
	if err != nil {
		t.Fatalf("netstack: %v", err)
	}
	defer dev.Close()

	go func() { // drain the device so a full outbound queue can't be mistaken for a write failure
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		for {
			if _, err := dev.Read(bufs, sizes, 0); err != nil {
				return
			}
		}
	}()

	conn, err := tnet.DialUDPAddrPort(netip.AddrPort{}, netip.MustParseAddrPort("10.0.0.3:1234"))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now()); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := conn.Write([]byte("x")); err == nil {
		t.Fatal("a past deadline must fail: that mechanism is what silently dropped every datagram")
	}

	// Repeat: a deadline that stayed expired would make only the first write succeed.
	for i := 0; i < 200; i++ {
		if err := nbWrite(conn, []byte("hello")); err != nil {
			t.Fatalf("nbWrite #%d: %v", i, err)
		}
	}
}
