package lists

import (
	"testing"
	"time"

	"fortochka/internal/rules"
)

// TestCacheRoundTrip pins the promise that a start with no network still has rules: whatever was last fetched must come back intact.
func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := []rules.Rule{
		{Suffix: "youtube.com", Action: rules.WG},
		{Suffix: "googlevideo.com", Action: rules.WG},
		{CIDR: "203.0.113.0/24", Action: rules.WG},
	}
	if err := saveCache(dir, want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, at, err := loadCache(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d rules %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("rule %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if d := time.Since(at); d < 0 || d > time.Minute {
		t.Errorf("timestamp %v is not recent (age %v)", at, d)
	}
}

func TestLoadCacheMissing(t *testing.T) {
	if _, _, err := loadCache(t.TempDir()); err == nil {
		t.Fatal("expected an error when no cache file exists")
	}
	if _, _, err := loadCache(""); err == nil {
		t.Fatal("expected an error when no cache dir is configured")
	}
}
