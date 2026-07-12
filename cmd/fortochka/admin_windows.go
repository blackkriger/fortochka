//go:build windows

package main

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func isAdmin() bool {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	return tok.IsElevated()
}

// ensureAdmin relaunches the process elevated (UAC) if needed, returning false when a relaunch was triggered and the caller should exit.
func ensureAdmin() bool {
	if isAdmin() {
		return true
	}
	exe, err := os.Executable()
	if err != nil {
		return true // can't relaunch — carry on unelevated
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	exePtr, _ := windows.UTF16PtrFromString(exe)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	var argPtr *uint16
	if args := strings.Join(os.Args[1:], " "); args != "" {
		argPtr, _ = windows.UTF16PtrFromString(args)
	}
	windows.ShellExecute(0, verb, exePtr, argPtr, dir, windows.SW_SHOWNORMAL)
	return false
}
