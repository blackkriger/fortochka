//go:build windows

package apptunnel

import (
	"testing"
	"time"
)

// TestMissThrottlePerPort pins the throttle to one port at a time. A single global timestamp let one unresolvable port starve every other port's lookup, so a brand-new routed port stayed unidentified and its datagrams left untunnelled.
func TestMissThrottlePerPort(t *testing.T) {
	var m missThrottle
	if !m.allow(1000) {
		t.Fatal("first call for a port must be allowed")
	}
	if m.allow(1000) {
		t.Error("a second call inside the interval must be refused")
	}
	if !m.allow(1001) {
		t.Error("another port must not be blocked by the first one's refusal")
	}

	m.mu.Lock()
	m.last[1000] = time.Now().Add(-2 * missInterval).UnixNano()
	m.mu.Unlock()
	if !m.allow(1000) {
		t.Error("a port whose interval has elapsed must be allowed again")
	}
}

// TestMissThrottlePrune pins that prune drops only elapsed entries, so the map cannot grow for the life of the run.
func TestMissThrottlePrune(t *testing.T) {
	var m missThrottle
	m.allow(2000)
	m.allow(2001)
	m.mu.Lock()
	m.last[2000] = time.Now().Add(-2 * missInterval).UnixNano()
	m.mu.Unlock()

	m.prune()

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.last[2000]; ok {
		t.Error("an elapsed entry must be pruned")
	}
	if _, ok := m.last[2001]; !ok {
		t.Error("a fresh entry must survive pruning")
	}
}
