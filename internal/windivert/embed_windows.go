//go:build windows

package windivert

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

//go:embed bin/WinDivert.dll
var dllBin []byte

//go:embed bin/WinDivert64.sys
var sysBin []byte

// Init writes the embedded WinDivert.dll and WinDivert64.sys into dir (only when missing or changed) and points the API at the extracted DLL, so a single self-contained exe carries the driver and needs no loose files on disk.
func Init(dir string) error {
	if err := place(filepath.Join(dir, "WinDivert.dll"), dllBin); err != nil {
		return err
	}
	if err := place(filepath.Join(dir, "WinDivert64.sys"), sysBin); err != nil {
		return err
	}
	bind(filepath.Join(dir, "WinDivert.dll"))
	return nil
}

// bind re-points the lazily-loaded DLL and its procs at an absolute path, so LoadLibrary reads our extracted copy — and WinDivert finds its .sys in the same directory — instead of searching the default path.
func bind(dllPath string) {
	dll = windows.NewLazyDLL(dllPath)
	procOpen = dll.NewProc("WinDivertOpen")
	procRecv = dll.NewProc("WinDivertRecv")
	procSend = dll.NewProc("WinDivertSend")
	procClose = dll.NewProc("WinDivertClose")
	procCalcChecksums = dll.NewProc("WinDivertHelperCalcChecksums")
}

// place writes data to path unless an identical file is already there; if the write fails but a copy exists (e.g. the .sys is loaded and locked), it keeps that copy rather than failing.
func place(path string, data []byte) error {
	if same(path, data) {
		return nil
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		if _, statErr := os.Stat(path); statErr == nil {
			return nil
		}
		return fmt.Errorf("windivert: extract %s: %w", filepath.Base(path), err)
	}
	return nil
}

func same(path string, data []byte) bool {
	b, err := os.ReadFile(path)
	return err == nil && bytes.Equal(b, data)
}
