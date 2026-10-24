//go:build windows

package apptunnel

import (
	"testing"
	"time"
)

// TestSweepTrackedKeepsDualStackMapping pins the pruning rule against the family split. handleTCP resolves a dual-stack socket's owner from the IPv6 table, so a mapping made that way is absent from the IPv4 one — and a sweeper that consulted only IPv4 tore the mapping out from under a live connection after ~10s, after which the app's packets were reinjected unchanged, with its real address, to the real destination.
func TestSweepTrackedKeepsDualStackMapping(t *testing.T) {
	e := quietEngine()
	e.tracked = map[uint16]mapping{5000: {appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}}
	e.seen = map[uint16]uint32{5000: fakePID}
	e.trackMiss = map[uint16]int{}
	e.portPID.Store(snap(map[uint16]uint32{9999: 1}))        // IPv4 table has rows, but not this port
	e.portPID6.Store(snap(map[uint16]uint32{5000: fakePID})) // the socket is bound to ::

	for i := 0; i < 4; i++ {
		e.sweepTracked()
	}
	if _, ok := e.tracked[5000]; !ok {
		t.Fatal("a mapping the IPv6 table still names must survive any number of sweeps")
	}
	if got := e.st.pruned.Load(); got != 0 {
		t.Errorf("pruned = %d, want 0", got)
	}
}

// TestSweepTrackedTwoStrikes pins the strike count: the port snapshot lags by up to 500ms, so one miss must not evict a live mapping.
func TestSweepTrackedTwoStrikes(t *testing.T) {
	e := quietEngine()
	e.tracked = map[uint16]mapping{5000: {appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}}
	e.seen = map[uint16]uint32{5000: fakePID}
	e.trackMiss = map[uint16]int{}
	e.portPID.Store(snap(map[uint16]uint32{9999: 1}))
	e.portPID6.Store(snap(map[uint16]uint32{8888: 2}))

	e.sweepTracked()
	if _, ok := e.tracked[5000]; !ok {
		t.Fatal("one missed sweep must not evict: the snapshot lags behind the socket")
	}
	e.sweepTracked()
	if _, ok := e.tracked[5000]; ok {
		t.Error("two sweeps without the port must retire the mapping")
	}
	if _, ok := e.seen[5000]; ok {
		t.Error("the decision must be dropped with the mapping, or the port stays direct")
	}
	if got := e.st.pruned.Load(); got != 1 {
		t.Errorf("pruned = %d, want 1", got)
	}
}

// TestSweepTrackedWithoutTables pins that a failed table walk prunes nothing: acting on no evidence would evict every live mapping at once.
func TestSweepTrackedWithoutTables(t *testing.T) {
	e := quietEngine()
	e.tracked = map[uint16]mapping{5000: {appIP: testApp, dstIP: testPeer, dstPort: 443, pid: fakePID}}
	e.seen = map[uint16]uint32{5000: fakePID}
	e.trackMiss = map[uint16]int{}

	for i := 0; i < 4; i++ {
		e.sweepTracked()
	}
	if _, ok := e.tracked[5000]; !ok {
		t.Error("no snapshots must mean no strikes")
	}
}

func flowEngine(port uint16) (*Engine, *closeConn, udpKey) {
	e := quietEngine()
	c := &closeConn{}
	k := udpKey{appPort: port}
	fl := &udpFlow{appPort: port, conn: c, pid: fakePID}
	fl.lastSeen.Store(time.Now().UnixNano())
	e.udpFlows = map[udpKey]*udpFlow{k: fl}
	e.udpDirect = map[udpKey]udpDecision{}
	return e, c, k
}

// TestSweepFlowsKeepsDualStackFlow pins the same family split on the UDP side: a socket on :: sends IPv4 datagrams yet is listed only in the IPv6 table, and retiring its flow rebuilds it on a new tunnel-side port, which a voice peer reads as a dead media path.
func TestSweepFlowsKeepsDualStackFlow(t *testing.T) {
	e, c, k := flowEngine(6000)
	e.udpPortPID.Store(snap(map[uint16]uint32{9999: 1}))
	e.udpPortPID6.Store(snap(map[uint16]uint32{6000: fakePID}))

	for i := 0; i < 4; i++ {
		e.sweepFlows()
	}
	if _, ok := e.udpFlows[k]; !ok {
		t.Fatal("a flow whose port the IPv6 table still names must survive")
	}
	if c.closed.Load() {
		t.Error("its tunnel socket must stay open")
	}
}

// TestSweepFlowsTwoStrikes pins the grace a flow gets: it is built from a socket event, which arrives before the sampled tables list the port, so the first miss must not retire it.
func TestSweepFlowsTwoStrikes(t *testing.T) {
	e, c, k := flowEngine(6000)
	e.udpPortPID.Store(snap(map[uint16]uint32{9999: 1}))
	e.udpPortPID6.Store(snap(map[uint16]uint32{8888: 2}))

	e.sweepFlows()
	if _, ok := e.udpFlows[k]; !ok {
		t.Fatal("one missed sweep must not retire a flow built before the tables caught up")
	}
	e.sweepFlows()
	if _, ok := e.udpFlows[k]; ok {
		t.Error("two sweeps without the port must retire the flow")
	}
	if !c.closed.Load() {
		t.Error("its tunnel socket must be closed")
	}
}

// TestSweepFlowsWithoutTables pins that an empty or failed walk retires nothing. An empty map means the walk found no rows, not that the app closed its socket — acting on it tore down every live call.
func TestSweepFlowsWithoutTables(t *testing.T) {
	for _, c := range []struct {
		name   string
		v4, v6 *map[uint16]uint32
	}{
		{"both walks failed", nil, nil},
		{"both walks came back empty", snap(map[uint16]uint32{}), snap(map[uint16]uint32{})},
	} {
		e, conn, k := flowEngine(6000)
		if c.v4 != nil {
			e.udpPortPID.Store(c.v4)
		}
		if c.v6 != nil {
			e.udpPortPID6.Store(c.v6)
		}
		for i := 0; i < 4; i++ {
			e.sweepFlows()
		}
		if _, ok := e.udpFlows[k]; !ok {
			t.Errorf("%s: the flow must survive", c.name)
		}
		if conn.closed.Load() {
			t.Errorf("%s: its tunnel socket must stay open", c.name)
		}
	}
}

// TestSweepFlowsRetiresIdle pins the idle timeout, which is the only thing that retires a flow whose app stopped sending.
func TestSweepFlowsRetiresIdle(t *testing.T) {
	e, c, k := flowEngine(6000)
	e.udpPortPID.Store(snap(map[uint16]uint32{6000: fakePID}))
	e.udpFlows[k].lastSeen.Store(time.Now().Add(-udpIdleTimeout - time.Second).UnixNano())

	e.sweepFlows()
	if _, ok := e.udpFlows[k]; ok {
		t.Error("an idle flow must be retired even while its port is still listed")
	}
	if !c.closed.Load() {
		t.Error("its tunnel socket must be closed")
	}
}

// TestSweepFlowsRetiresFlowWhoseOwnerChanged pins the mirror of the cached-decision check. Once the system hands the port to another process, the flow tunnels that process's datagrams: the port stays listed so the port check never fires, and its own traffic keeps the idle timer fresh, so nothing else would ever retire it.
func TestSweepFlowsRetiresFlowWhoseOwnerChanged(t *testing.T) {
	const newOwner uint32 = fakePID + 16

	e, c, k := flowEngine(6000)
	e.udpPortPID.Store(snap(map[uint16]uint32{6000: newOwner}))

	e.sweepFlows()
	if _, ok := e.udpFlows[k]; !ok {
		t.Fatal("one sweep must not retire it: the port tables are keyed by port alone, so two sockets sharing a number look like a change")
	}
	e.sweepFlows()
	if _, ok := e.udpFlows[k]; ok {
		t.Error("a port that has provably changed owner must retire the flow")
	}
	if !c.closed.Load() {
		t.Error("its tunnel socket must be closed")
	}
}

// TestSweepFlowsKeepsFlowWhoseOwnerHolds pins the other side: the owner is unchanged, so the flow must survive any number of sweeps.
func TestSweepFlowsKeepsFlowWhoseOwnerHolds(t *testing.T) {
	e, c, k := flowEngine(6000)
	e.udpPortPID.Store(snap(map[uint16]uint32{6000: fakePID}))

	for i := 0; i < 4; i++ {
		e.sweepFlows()
	}
	if _, ok := e.udpFlows[k]; !ok {
		t.Fatal("a flow whose owner still holds the port must survive")
	}
	if c.closed.Load() {
		t.Error("its tunnel socket must stay open")
	}
}
