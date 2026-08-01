package userrules

import (
	"os"
	"path/filepath"
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
