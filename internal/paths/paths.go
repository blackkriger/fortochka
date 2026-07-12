// Package paths resolves the machine-wide locations the LocalSystem service and per-user tray both use for state, the saved tunnel, custom rules and logs.
package paths

import (
	"os"
	"path/filepath"
)

// DataDir is the shared machine-wide fortochka data directory (%ProgramData%\fortochka), writable by the LocalSystem service and readable by the tray; created if missing.
func DataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	dir := filepath.Join(base, "fortochka")
	_ = os.MkdirAll(dir, 0o755)
	return dir
}
