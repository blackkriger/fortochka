//go:build windows

package daemon

import (
	"log"
	"os/exec"
	"strings"
	"syscall"
)

// secureFile restricts a file to SYSTEM + Administrators (dropping inherited Users access) so the WireGuard private key it holds isn't readable by other local users. S-1-5-18 = LocalSystem, S-1-5-32-544 = Administrators.
func secureFile(path string) {
	cmd := exec.Command("icacls", path, "/inheritance:r",
		"/grant:r", "*S-1-5-18:F", "/grant:r", "*S-1-5-32-544:F", "/C", "/Q")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("daemon: secure %s failed: %v (%s)", path, err, strings.TrimSpace(string(out)))
	}
}
