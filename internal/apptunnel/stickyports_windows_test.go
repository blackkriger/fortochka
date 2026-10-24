//go:build windows

package apptunnel

import (
	"fmt"
	"testing"
	"time"
)

func quietEngine() *Engine { return &Engine{logf: func(string, ...any) {}} }

// TestRoutedUDPPortsCapIsDeterministic pins the tie-break. Every live port is stamped with the same instant, so without one the unstable sort returned a different 120 on every pass: the filter string changed each time, the handle reopened every few seconds, and a different set of live ports dropped out of capture each round.
func TestRoutedUDPPortsCapIsDeterministic(t *testing.T) {
	e, lines := capturingEngine()
	stamp := time.Now()
	e.sticky = map[uint16]time.Time{}
	for p := uint16(1000); p < 1000+uint16(maxUDPPorts)+10; p++ {
		e.sticky[p] = stamp
	}
	e.lastCompact = stamp // keep compaction out of this case

	got := e.routedUDPPorts()
	if len(got) != maxUDPPorts {
		t.Fatalf("want the filter capped at %d ports, got %d", maxUDPPorts, len(got))
	}
	for i, p := range got {
		if want := uint16(1000 + i); p != want {
			t.Fatalf("port %d = %d, want %d: ties must break on the port so the kept set is the same every pass", i, p, want)
		}
	}
	if len(e.sticky) != maxUDPPorts {
		t.Errorf("the dropped ports must leave sticky, got %d entries", len(e.sticky))
	}
	want := fmt.Sprintf("%d routed udp ports exceed the %d the filter can hold — the 10 seen longest ago were dropped", maxUDPPorts+10, maxUDPPorts)
	if logged(*lines, want) != 1 {
		t.Errorf("the cap must log how many ports there were and how many it dropped, want %q in %q", want, *lines)
	}
}

// TestRoutedUDPPortsTTL pins that a port the app released leaves the filter, and that an unexpired one stays: removals are what made the filter churn, so only arrivals justify reopening the handle.
func TestRoutedUDPPortsTTL(t *testing.T) {
	e := quietEngine()
	now := time.Now()
	e.sticky = map[uint16]time.Time{
		7000: now.Add(-udpPortTTL - time.Minute),
		7001: now,
	}
	// lastCompact stays zero, so this call is due a compaction.

	got := e.routedUDPPorts()
	if len(got) != 1 || got[0] != 7001 {
		t.Fatalf("want only the unexpired port, got %v", got)
	}
	if e.lastCompact.IsZero() {
		t.Error("a compaction must record when it ran, or it would repeat on every call")
	}
}

// TestRoutedUDPPortsPublishesLiveOnly pins the distinction handleUDP fails closed on: the filter also carries ports a routed app has already released, and those get recycled to other processes. A retained port must not look live, or an unidentified sender on it would be dropped instead of passed.
func TestRoutedUDPPortsPublishesLiveOnly(t *testing.T) {
	e := quietEngine()
	e.sticky = map[uint16]time.Time{8000: time.Now()}
	e.lastCompact = time.Now()

	got := e.routedUDPPorts()
	if len(got) != 1 || got[0] != 8000 {
		t.Fatalf("a retained port must stay in the filter, got %v", got)
	}
	if e.liveUDP.Load() == nil {
		t.Fatal("the live set must be published on every rebuild, or handleUDP has nothing to consult")
	}
	if e.liveUDPPort(8000) {
		t.Error("a port held only by the TTL must not be reported live")
	}
}

// TestRoutedUDPPortsPublishesRoutedPorts pins the branch the whole fail-closed path depends on. If liveUDPPorts ever stops resolving a routed app, every test that only asserts an empty live set still passes while the app's first datagrams go out in the clear.
func TestRoutedUDPPortsPublishesRoutedPorts(t *testing.T) {
	e := quietEngine()
	e.nameCache = map[uint32]string{fakePID: fakeApp, 4242: "other.exe"}
	e.nameBad = map[uint32]time.Time{}
	e.apps = map[string]bool{fakeApp: true}
	e.udpPortPID.Store(snap(map[uint16]uint32{7000: fakePID, 7001: 4242}))
	e.udpPortPID6.Store(snap(map[uint16]uint32{7002: fakePID})) // a dual-stack socket on ::

	got := e.routedUDPPorts()
	if len(got) != 2 || got[0] != 7000 || got[1] != 7002 {
		t.Fatalf("filter ports = %v, want both families' routed ports [7000 7002]", got)
	}
	for _, p := range []uint16{7000, 7002} {
		if !e.liveUDPPort(p) {
			t.Errorf("port %d is owned by a routed app right now and must be reported live", p)
		}
	}
	if e.liveUDPPort(7001) {
		t.Error("a port owned by an unselected process must not be reported live")
	}
}

// TestLiveUDPPortBeforeFirstRebuild pins the startup default. The set is published before any capture handle exists, but an unset pointer must read as not-live rather than panicking.
func TestLiveUDPPortBeforeFirstRebuild(t *testing.T) {
	var e Engine
	if e.liveUDPPort(1234) {
		t.Error("an unpublished live set must report not-live")
	}
	e.liveUDP.Store(&map[uint16]bool{1234: true})
	if !e.liveUDPPort(1234) {
		t.Error("a published live port must report live")
	}
	if e.liveUDPPort(1235) {
		t.Error("a port absent from the live set must report not-live")
	}
}
