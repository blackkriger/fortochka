//go:build windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const usersWriteBits = windows.ACCESS_MASK(0x2 | 0x4 | 0x10 | 0x40 | 0x100 | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER)

func usersRights(t *testing.T, path string) windows.ACCESS_MASK {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if dacl == nil {
		t.Fatalf("%s has a NULL DACL, which grants everyone full access", path)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		t.Fatal(err)
	}
	var mask windows.ACCESS_MASK
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(users) {
			mask |= ace.Mask
		}
	}
	return mask
}

func TestSecureDataDir(t *testing.T) {
	dir := t.TempDir()
	me, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = applySDDL(dir, "D:P(A;OICI;FA;;;"+me.User.Sid.String()+")", true, false)
	})

	yaml := filepath.Join(dir, "fortochka.yaml")
	writeFile(t, yaml, "listen:\n  proxy: 127.0.0.1:1080\n")
	if err := applySDDL(yaml, "D:(A;;FA;;;BU)", false, false); err != nil {
		t.Fatal(err)
	}

	if err := secureDataDir(dir, false); err != nil {
		t.Fatalf("secureDataDir: %v", err)
	}

	if m := usersRights(t, dir); m&usersWriteBits != 0 {
		t.Errorf("Users can still create or change files in the data dir: mask %#x", m)
	}
	if m := usersRights(t, yaml); m&usersWriteBits != 0 {
		t.Errorf("a grant planted on fortochka.yaml must be wiped: Users mask %#x", m)
	}
	rules := filepath.Join(dir, "rules.txt")
	if _, err := os.Stat(rules); err != nil {
		t.Fatalf("rules.txt must exist so the tray has a file it may edit: %v", err)
	}
	if m := usersRights(t, rules); m&0x2 == 0 {
		t.Errorf("the tray must still be able to edit rules.txt: Users mask %#x", m)
	}
}

func TestShellExecuteInfoLayout(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("layout pinned for amd64 builds")
	}
	if got := unsafe.Sizeof(shellExecuteInfo{}); got != 112 {
		t.Errorf("SHELLEXECUTEINFOW is 112 bytes on amd64, got %d: ShellExecuteExW would reject the call", got)
	}
}
