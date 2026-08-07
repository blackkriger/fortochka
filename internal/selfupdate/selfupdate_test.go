package selfupdate

import "testing"

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
