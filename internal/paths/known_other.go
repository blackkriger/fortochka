//go:build !windows

package paths

import "os"

func programData() string { return os.TempDir() }

func programFiles() string { return os.TempDir() }

func localAppData() string { return os.TempDir() }
