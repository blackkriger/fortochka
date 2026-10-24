// Package paths resolves the machine-wide locations the LocalSystem service and per-user tray both use for state, the saved tunnel, custom rules and logs.
package paths

import "path/filepath"

// DataDir is the shared machine-wide fortochka data directory (%ProgramData%\fortochka). The LocalSystem service creates and owns it; the tray only reads it, apart from rules.txt.
func DataDir() string { return filepath.Join(programData(), "fortochka") }

func InstallDir() string { return filepath.Join(programFiles(), "fortochka") }

func InstalledExe() string { return filepath.Join(InstallDir(), "fortochka.exe") }

func UserDir() string { return filepath.Join(localAppData(), "fortochka") }
