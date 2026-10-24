//go:build windows

package apptunnel

import (
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestUDPFilterFor pins the filter to the routed apps' own ports. Capturing all UDP put every datagram on the machine through one userspace loop, and whatever it could not drain in time the driver dropped — DNS first, since a lost query has no IP-level retry.
func TestUDPFilterFor(t *testing.T) {
	if got := udpFilterFor(nil); got != "" {
		t.Errorf("no ports must yield no filter (the handle is closed instead), got %q", got)
	}
	if got := udpFilterFor([]uint16{}); got != "" {
		t.Errorf("no ports must yield no filter, got %q", got)
	}

	one := udpFilterFor([]uint16{51820})
	for _, want := range []string{"outbound", "udp", "not impostor", "udp.SrcPort == 51820"} {
		if !strings.Contains(one, want) {
			t.Errorf("filter %q is missing %q", one, want)
		}
	}
	if strings.Contains(one, "udp.SrcPort == 51820 or") {
		t.Errorf("a single port must not leave a dangling or: %q", one)
	}

	many := udpFilterFor([]uint16{53, 443, 3074})
	if n := strings.Count(many, "udp.SrcPort =="); n != 3 {
		t.Errorf("want 3 port terms, got %d in %q", n, many)
	}
	if n := strings.Count(many, " or "); n != 2 {
		t.Errorf("3 terms need 2 or-joins, got %d in %q", n, many)
	}
	if !strings.HasSuffix(many, ")") || !strings.Contains(many, "and (") {
		t.Errorf("the port terms must be parenthesised, or `and` would bind tighter than `or`: %q", many)
	}
}

func TestUDPFilterAtCapCompiles(t *testing.T) {
	dll, err := filepath.Abs(filepath.Join("..", "windivert", "bin", "WinDivert.dll"))
	if err != nil {
		t.Fatal(err)
	}
	compile := windows.NewLazyDLL(dll).NewProc("WinDivertHelperCompileFilter")
	if err := compile.Find(); err != nil {
		t.Fatalf("the bundled WinDivert.dll must load: %v", err)
	}
	ports := make([]uint16, maxUDPPorts)
	for i := range ports {
		ports[i] = uint16(65535 - i)
	}
	filter, err := windows.BytePtrFromString(udpFilterFor(ports))
	if err != nil {
		t.Fatal(err)
	}
	var errStr *byte
	var errPos uint32
	if r, _, _ := compile.Call(uintptr(unsafe.Pointer(filter)), 0, 0, 0, uintptr(unsafe.Pointer(&errStr)), uintptr(unsafe.Pointer(&errPos))); r == 0 {
		t.Fatalf("a filter of %d five-digit ports must compile, WinDivert says: %s", maxUDPPorts, windows.BytePtrToString(errStr))
	}
}
