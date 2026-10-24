package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInstallDecision(t *testing.T) {
	const own = "0.8.1"
	for _, c := range []struct {
		name      string
		installed installedCopy
		install   bool
		handOff   bool
	}{
		{"nothing installed yet", installedCopy{}, true, false},
		{"this very build is installed", installedCopy{exists: true, same: true}, false, true},
		{"a newer build is installed", installedCopy{exists: true, version: "0.9.0"}, false, true},
		{"an older build is installed", installedCopy{exists: true, version: "0.8.0"}, true, false},
		{"a rebuild of the same version", installedCopy{exists: true, version: own}, true, false},
		{"the installed copy cannot say its version", installedCopy{exists: true}, true, false},
	} {
		if got := needsInstall(own, c.installed); got != c.install {
			t.Errorf("%s: needsInstall = %v, want %v", c.name, got, c.install)
		}
		if got := shouldHandOff(own, c.installed); got != c.handOff {
			t.Errorf("%s: shouldHandOff = %v, want %v", c.name, got, c.handOff)
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPlaceBinary(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.exe")
	dst := filepath.Join(dir, "Program Files", "fortochka", "fortochka.exe")
	writeFile(t, src, "build one")

	if replaced, err := placeBinary(src, dst); err != nil || !replaced {
		t.Fatalf("first install = (%v, %v), want the binary placed", replaced, err)
	}
	if got := readFile(t, dst); got != "build one" {
		t.Fatalf("installed copy = %q, want the source", got)
	}

	if replaced, err := placeBinary(src, dst); err != nil || replaced {
		t.Fatalf("installing the same bits again = (%v, %v), want a no-op so the service is not restarted for nothing", replaced, err)
	}
	if _, err := os.Stat(dst + ".old"); err == nil {
		t.Error("a no-op install must not leave a .old behind")
	}

	writeFile(t, src, "build two")
	if replaced, err := placeBinary(src, dst); err != nil || !replaced {
		t.Fatalf("installing a new build = (%v, %v), want it placed", replaced, err)
	}
	if got := readFile(t, dst); got != "build two" {
		t.Errorf("installed copy = %q, want the new build", got)
	}
	if got := readFile(t, dst+".old"); got != "build one" {
		t.Errorf("the previous build must be moved aside, since a running image can be renamed but not overwritten: got %q", got)
	}
	if _, err := os.Stat(dst + ".new"); err == nil {
		t.Error("the staging copy must not be left behind")
	}

	held, err := os.Open(dst + ".old")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, src, "build three")
	replaced, err := placeBinary(src, dst)
	held.Close()
	if err != nil || !replaced {
		t.Fatalf("a .old still held by a running process must not block the next install: (%v, %v)", replaced, err)
	}
	if got := readFile(t, dst); got != "build three" {
		t.Errorf("installed copy = %q, want the newest build", got)
	}
	olds, _ := filepath.Glob(dst + ".old-*")
	if len(olds) != 1 || readFile(t, olds[0]) != "build two" {
		t.Fatalf("the displaced build must be kept under a unique name, got %v", olds)
	}

	removeOldBinaries(dst)
	if left, _ := filepath.Glob(dst + ".old*"); len(left) != 0 {
		t.Errorf("leftover builds must all be cleaned up once nothing holds them, got %v", left)
	}
	if got := readFile(t, dst); got != "build three" {
		t.Errorf("cleanup must not touch the installed copy, got %q", got)
	}
}

func TestSamePath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "fortochka.exe")
	writeFile(t, p, "x")
	if !samePath(p, filepath.Join(dir, ".", "FORTOCHKA.EXE")) {
		t.Error("paths differing only in case or a dot segment name the same file")
	}
	if samePath(p, filepath.Join(dir, "other.exe")) {
		t.Error("different files must not match")
	}
}
