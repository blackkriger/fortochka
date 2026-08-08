package selfupdate

import (
	"strings"
	"testing"
)

// TestSumFromNotes pins where the digest comes from: the release notes, since that is where it is published and no file carries it.
func TestSumFromNotes(t *testing.T) {
	const want = "af236fd08184e33aea9ee16da7e87e85a1d6e3939b87f328155591e743d222c2"
	notes := "Show the engine version in the tray menu\n\n**fortochka.exe** — `sha256:" + strings.ToUpper(want) + "`\n"
	if got := strings.ToLower(sumPattern.FindString(notes)); got != want {
		t.Errorf("sum = %q, want %q", got, want)
	}
	if got := sumPattern.FindString("no digest here, just words and a v0.7.0 tag"); got != "" {
		t.Errorf("matched %q in notes that carry no digest", got)
	}
}

// TestNewer pins the comparison against the case a string compare gets wrong: 0.10.0 is above 0.9.0, and reading it the other way would leave every later release uninstalled.
func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.6.0", "0.5.1", true},
		{"0.10.0", "0.9.0", true},
		{"0.5.1", "0.5.1", false},
		{"0.5.1", "0.6.0", false},
		{"1.0", "0.9.9", true},
		{"0.6", "0.6.0", false},
		{"0.6.1", "0.6", true},
	}
	for _, c := range cases {
		if got := newer(c.a, c.b); got != c.want {
			t.Errorf("newer(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
