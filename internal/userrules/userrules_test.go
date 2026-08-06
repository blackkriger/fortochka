package userrules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fortochka/internal/rules"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	content := `# comment
example.org
!direct.example
198.51.100.7
!203.0.113.0/24
http://198.51.100.7:8082/
!
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []rules.Rule{
		{Suffix: "example.org", Action: rules.WG},
		{Suffix: "direct.example", Action: rules.Direct},
		{CIDR: "198.51.100.7/32", Action: rules.WG},
		{CIDR: "203.0.113.0/24", Action: rules.Direct},
		{CIDR: "198.51.100.7/32", Action: rules.WG},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rules %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

// TestEnsureDefaultRefreshesHeader covers upgrading an existing file: the header gains newly documented syntax while every rule and every note the user wrote below it survives untouched.
func TestEnsureDefaultRefreshesHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	old := "# Everything not listed here (and not in the block lists) goes out directly.\n#\n# Examples:\n#   x.com\n\nclaude.ai\n# my own note\n!youtube\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDefault(path); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := "claude.ai\n# my own note\n!youtube\n"
	if !strings.HasSuffix(string(got), body) {
		t.Fatalf("user content was altered; file now ends with:\n%q", string(got))
	}
	if !strings.Contains(string(got), "A service name stands for") {
		t.Error("header was not refreshed with the current template")
	}
}

// TestEnsureDefaultKeepsForeignHeader: a file whose top comments are the user's own must never be rewritten.
func TestEnsureDefaultKeepsForeignHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.txt")
	mine := "# my personal list, do not touch\nclaude.ai\n"
	if err := os.WriteFile(path, []byte(mine), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := EnsureDefault(path); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != mine {
		t.Errorf("file was rewritten:\n%q", string(got))
	}
}

// TestLoadGroup covers the service keyword: every domain YouTube needs must come out with one action, or the site half-works with its parts on different paths.
func TestLoadGroup(t *testing.T) {
	for _, tc := range []struct {
		line string
		want rules.Action
	}{{"youtube", rules.WG}, {"!youtube", rules.Direct}} {
		path := filepath.Join(t.TempDir(), "rules.txt")
		if err := os.WriteFile(path, []byte(tc.line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := Load(path)
		if err != nil {
			t.Fatalf("load %q: %v", tc.line, err)
		}
		if len(got) != len(groups["youtube"]) {
			t.Fatalf("%q expanded to %d rules, want %d", tc.line, len(got), len(groups["youtube"]))
		}
		for _, r := range got {
			if r.Action != tc.want {
				t.Errorf("%q: %s got action %v, want %v", tc.line, r.Suffix, r.Action, tc.want)
			}
			if r.Suffix == "" {
				t.Errorf("%q produced a rule with no domain: %+v", tc.line, r)
			}
		}
	}
}
