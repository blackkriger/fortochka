//go:build windows

package apptunnel

import (
	"net/netip"
	"testing"
)

// TestIsLocalDst pins the destinations a routed app must still reach without the tunnel: sending these to the peer breaks LAN access, or hands local traffic to the far side.
func TestIsLocalDst(t *testing.T) {
	local := []string{
		"127.0.0.1",       // loopback: an app's own IPC
		"192.168.1.10",    // LAN host: NAS, printer
		"192.168.1.255",   // directed broadcast: LAN discovery
		"10.0.0.5",        // LAN host
		"172.16.3.4",      // LAN host
		"169.254.10.1",    // link-local
		"224.0.0.251",     // mDNS
		"239.255.255.250", // SSDP
		"255.255.255.255", // broadcast
		"0.0.0.0",
	}
	for _, s := range local {
		if !isLocalDst(netip.MustParseAddr(s)) {
			t.Errorf("isLocalDst(%s) = false, want true", s)
		}
	}
	remote := []string{"1.1.1.1", "8.8.8.8", "146.103.117.79", "104.16.0.1"}
	for _, s := range remote {
		if isLocalDst(netip.MustParseAddr(s)) {
			t.Errorf("isLocalDst(%s) = true, want false", s)
		}
	}
}
