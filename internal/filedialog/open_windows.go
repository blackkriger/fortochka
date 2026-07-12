//go:build windows

package filedialog

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	comdlg32           = windows.NewLazySystemDLL("comdlg32.dll")
	procGetOpenFileNam = comdlg32.NewProc("GetOpenFileNameW")
)

const (
	ofnFileMustExist = 0x00001000
	ofnPathMustExist = 0x00000800
	ofnExplorer      = 0x00080000
	ofnNoChangeDir   = 0x00000008
)

type openfilenameW struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

// Open shows the native "Open File" dialog and returns the chosen path, or an empty string if the user cancelled.
func Open(title string) (string, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	buf := make([]uint16, 1024)
	filter := utf16List("WireGuard config (*.conf)", "*.conf", "All files (*.*)", "*.*")

	var ofn openfilenameW
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	ofn.lpstrFilter = &filter[0]
	ofn.lpstrFile = &buf[0]
	ofn.nMaxFile = uint32(len(buf))
	ofn.flags = ofnFileMustExist | ofnPathMustExist | ofnExplorer | ofnNoChangeDir
	if title != "" {
		if t, err := windows.UTF16PtrFromString(title); err == nil {
			ofn.lpstrTitle = t
		}
	}

	ret, _, _ := procGetOpenFileNam.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		return "", nil
	}
	return windows.UTF16ToString(buf), nil
}

func utf16List(items ...string) []uint16 {
	var out []uint16
	for _, s := range items {
		u, err := windows.UTF16FromString(s)
		if err != nil {
			continue
		}
		out = append(out, u...) // each ends with a NUL
	}
	out = append(out, 0) // final double-NUL terminates the list
	return out
}
