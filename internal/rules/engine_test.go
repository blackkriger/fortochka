package rules

import "testing"

// TestManualBeatsMoreSpecificListEntry pins the override contract: the fetched lists carry entries like www.youtube.com, and a manual youtube.com must still win. Deciding by longest suffix across both sets made the override lose exactly on the hosts a user cares about.
func TestManualBeatsMoreSpecificListEntry(t *testing.T) {
	e := New(Direct)
	e.SetList([]Rule{
		{Suffix: "www.youtube.com", Action: WG},
		{Suffix: "m.youtube.com", Action: WG},
		{Suffix: "youtube.com", Action: WG},
		{Suffix: "example.org", Action: WG},
	})
	e.SetManual([]Rule{{Suffix: "youtube.com", Action: Direct}})

	for _, host := range []string{"youtube.com", "www.youtube.com", "m.youtube.com", "deep.www.youtube.com"} {
		if got := e.Decide(host); got != Direct {
			t.Errorf("Decide(%s) = %v, want Direct", host, got)
		}
	}
	if got := e.Decide("example.org"); got != WG {
		t.Errorf("Decide(example.org) = %v, want WG — the list must still apply where no manual rule covers it", got)
	}
	if got := e.Decide("unlisted.test"); got != Direct {
		t.Errorf("Decide(unlisted.test) = %v, want the default", got)
	}
}

func TestCIDRAndKeyword(t *testing.T) {
	e := New(Direct)
	e.SetList([]Rule{{CIDR: "203.0.113.0/24", Action: WG}})
	e.SetManual([]Rule{{CIDR: "203.0.113.5/32", Action: Direct}, {Keyword: "tracker", Action: WG}})

	if got := e.Decide("203.0.113.5"); got != Direct {
		t.Errorf("a manual /32 must beat a list /24, got %v", got)
	}
	if got := e.Decide("203.0.113.9"); got != WG {
		t.Errorf("the list range must still apply elsewhere, got %v", got)
	}
	if got := e.Decide("my-tracker.test"); got != WG {
		t.Errorf("keyword rule not applied, got %v", got)
	}
}
