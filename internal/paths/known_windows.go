//go:build windows

package paths

import (
	"os"

	"golang.org/x/sys/windows"
)

func knownFolder(id *windows.KNOWNFOLDERID, fallback string) string {
	if p, err := windows.KnownFolderPath(id, 0); err == nil && p != "" {
		return p
	}
	return fallback
}

func programData() string { return knownFolder(windows.FOLDERID_ProgramData, `C:\ProgramData`) }

func programFiles() string { return knownFolder(windows.FOLDERID_ProgramFiles, `C:\Program Files`) }

func localAppData() string {
	return knownFolder(windows.FOLDERID_LocalAppData, os.Getenv("LOCALAPPDATA"))
}
