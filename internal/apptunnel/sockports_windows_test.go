//go:build windows

package apptunnel

import (
	"testing"
	"time"
)

func snap(m map[uint16]uint32) *map[uint16]uint32 { return &m }

// TestUDPPIDBothFamilies pins that a port listed only in the IPv6 table still resolves. A dual-stack socket bound to :: sends IPv4 datagrams yet appears only in the AF_INET6 table, so a v4-only lookup left its owner unnamed.
func TestUDPPIDBothFamilies(t *testing.T) {
	var e Engine
	e.udpPortPID.Store(snap(map[uint16]uint32{1111: 10}))
	e.udpPortPID6.Store(snap(map[uint16]uint32{2222: 20}))
	e.sockPorts = map[uint16]sockEntry{3333: {pid: 30, at: time.Now()}}

	for _, c := range []struct {
		port  uint16
		pid   uint32
		known bool
		from  string
	}{
		{1111, 10, true, "v4 table"},
		{2222, 20, true, "v6 table"},
		{3333, 30, false, "socket events"},
		{4444, 0, false, "nothing"},
	} {
		pid, known := e.udpPID(c.port)
		if pid != c.pid || known != c.known {
			t.Errorf("udpPID(%d) from %s = (%d, %v), want (%d, %v)", c.port, c.from, pid, known, c.pid, c.known)
		}
	}
}

// TestUDPPIDTableWinsOverEvents pins the source order. A socket event never matched by a CLOSE would otherwise shadow the table's correct answer for as long as the process lives.
func TestUDPPIDTableWinsOverEvents(t *testing.T) {
	var e Engine
	e.udpPortPID.Store(snap(map[uint16]uint32{5555: 10}))
	e.sockPorts = map[uint16]sockEntry{5555: {pid: 99, at: time.Now()}}
	if pid, known := e.udpPID(5555); pid != 10 || !known {
		t.Errorf("udpPID = (%d, %v), want the table's (10, true)", pid, known)
	}
}

// TestPruneSockPortsGrace pins the grace window. The tables are sampled every 500ms, so pruning a bind they have not listed yet would leave the owner unnamed and pass the app's first datagrams in the clear.
func TestPruneSockPortsGrace(t *testing.T) {
	now := time.Now()
	old := now.Add(-2 * sockGrace)

	var e Engine
	e.udpPortPID.Store(snap(map[uint16]uint32{20: 200, 40: 999}))
	e.udpPortPID6.Store(snap(map[uint16]uint32{30: 300}))
	e.sockPorts = map[uint16]sockEntry{
		10: {pid: 100, at: now}, // fresh, in no table: must survive the grace
		20: {pid: 200, at: old}, // confirmed by the v4 table
		30: {pid: 300, at: old}, // confirmed by the v6 table
		40: {pid: 400, at: old}, // the table names a different owner
		50: {pid: 500, at: old}, // elapsed and unconfirmed
	}

	e.pruneSockPorts()

	for _, p := range []uint16{10, 20, 30} {
		if _, ok := e.sockPorts[p]; !ok {
			t.Errorf("port %d must survive pruning", p)
		}
	}
	for _, p := range []uint16{40, 50} {
		if _, ok := e.sockPorts[p]; ok {
			t.Errorf("port %d must be pruned", p)
		}
	}
}

// TestPruneSockPortsNoSnapshots pins that a failed table walk prunes nothing: trusting an absent snapshot would drop every entry at once.
func TestPruneSockPortsNoSnapshots(t *testing.T) {
	var e Engine
	e.sockPorts = map[uint16]sockEntry{10: {pid: 100, at: time.Now().Add(-2 * sockGrace)}}
	e.pruneSockPorts()
	if len(e.sockPorts) != 1 {
		t.Errorf("no snapshots must prune nothing, got %d entries", len(e.sockPorts))
	}
}
