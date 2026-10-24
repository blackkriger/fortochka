//go:build windows

package apptunnel

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
)

func capturingEngine() (*Engine, *[]string) {
	var lines []string
	e := &Engine{logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}
	return e, &lines
}

// TestLogStatsFormat pins the stats line's verbs against its arguments. The line carries 28 counters whose declaration order differs from their print order, so a counter added in the middle silently shifted every label after it.
func TestLogStatsFormat(t *testing.T) {
	e, lines := capturingEngine()
	// Every counter gets its own value: at zero, any two labels could be swapped and the line would read the same.
	for i, c := range []*atomic.Uint64{
		&e.st.udpOut, &e.st.udpIn, &e.st.udpDrop, &e.st.udpStalled, &e.st.udpDialErr,
		&e.st.udpUnknown, &e.st.udpForeign, &e.st.udpPassed, &e.st.udpRetired, &e.st.udpCapped,
		&e.st.udpReopens, &e.st.udpLate, &e.st.udpGaps, &e.st.loopStalls, &e.st.tcpRouted,
		&e.st.tcpDirect, &e.st.tcpUnknown, &e.st.reSYN, &e.st.pruned, &e.st.redirOK,
		&e.st.redirNoMap, &e.st.redirDeny, &e.st.redirDial, &e.st.sendClosed, &e.st.sendErr,
		&e.st.v6Blocked,
	} {
		c.Store(uint64(i + 1))
	}
	e.logStats()

	if len(*lines) != 1 {
		t.Fatalf("want one stats line, got %d", len(*lines))
	}
	got := (*lines)[0]
	if strings.Contains(got, "%!") {
		t.Fatalf("verb/argument mismatch in the stats line: %s", got)
	}
	// Runs of neighbouring fields, not single labels: the line carries dialerr= and unknown= twice each, so a swap between the two pairs would satisfy any one-field check.
	for _, want := range []string{
		"udp out=1 in=2 drop=3 stalled=4 dialerr=5 unknown=6 foreign=7 passed=8 retired=9 capped=10 reopens=11 flows=0",
		"late=12 gaps=13 slowloop=14",
		"tcp routed=15 direct=16 unknown=17 resyn=18 pruned=19",
		"redirect ok=20 nomap=21 deny=22 dialerr=23",
		"inject closed=24 err=25",
		"v6 blocked=26",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("stats line is missing %q, so a label and its counter have come apart: %s", want, got)
		}
	}
}

// TestLogStatsSkipsUnchanged pins the quiet case: a 5s sweep that logged regardless would bury a day's log.
func TestLogStatsSkipsUnchanged(t *testing.T) {
	e, lines := capturingEngine()
	e.st.udpOut.Add(1)
	e.logStats()
	e.logStats()
	if len(*lines) != 1 {
		t.Fatalf("an unchanged line must be skipped, got %d lines", len(*lines))
	}
}

// TestLogStatsNoticesReopens pins udpReopens into the change detector. Left out of it, a thrashing capture filter on an otherwise idle engine moved no other counter, so the line was suppressed and the churn was invisible.
func TestLogStatsNoticesReopens(t *testing.T) {
	e, lines := capturingEngine()
	e.st.udpOut.Add(1)
	e.logStats()
	e.st.udpReopens.Add(1)
	e.logStats()

	if len(*lines) != 2 {
		t.Fatalf("a filter rebuild alone must emit a line, got %d", len(*lines))
	}
	if !strings.Contains((*lines)[1], "reopens=1") {
		t.Errorf("want reopens=1 in %s", (*lines)[1])
	}
}

// TestCapFlowsLocked pins the flow ceiling. The key carries the destination, so one peer-to-peer app becomes thousands of flows, each holding a tunnel socket, a goroutine and a 64KiB buffer for two minutes after its last datagram.
func TestCapFlowsLocked(t *testing.T) {
	e := quietEngine()
	e.udpFlows = map[udpKey]*udpFlow{}
	const over = 3
	for i := 0; i < maxUDPFlows+over; i++ {
		k := udpKey{appPort: uint16(1000 + i)}
		fl := &udpFlow{appPort: k.appPort}
		fl.lastSeen.Store(int64(i)) // the lowest are the least recently used
		e.udpFlows[k] = fl
	}

	evicted := e.capFlowsLocked()

	if len(evicted) != over {
		t.Fatalf("want %d evictions, got %d", over, len(evicted))
	}
	if len(e.udpFlows) != maxUDPFlows {
		t.Errorf("want the table back at %d, got %d", maxUDPFlows, len(e.udpFlows))
	}
	for i := 0; i < over; i++ {
		if _, ok := e.udpFlows[udpKey{appPort: uint16(1000 + i)}]; ok {
			t.Errorf("flow %d was the least recently used and must be evicted", 1000+i)
		}
	}
	if _, ok := e.udpFlows[udpKey{appPort: uint16(1000 + maxUDPFlows + over - 1)}]; !ok {
		t.Error("the most recently used flow must survive")
	}
	if got := e.st.udpCapped.Load(); got != over {
		t.Errorf("udpCapped = %d, want %d", got, over)
	}
}

// TestCapFlowsLockedUnderCap pins that a table under the ceiling is left alone, so nothing is torn down while there is room.
func TestCapFlowsLockedUnderCap(t *testing.T) {
	e := quietEngine()
	e.udpFlows = map[udpKey]*udpFlow{{appPort: 1}: {}}
	if got := e.capFlowsLocked(); got != nil {
		t.Errorf("want no evictions, got %d", len(got))
	}
	if len(e.udpFlows) != 1 {
		t.Error("the flow must stay")
	}
}
