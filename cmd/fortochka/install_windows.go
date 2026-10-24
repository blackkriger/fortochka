//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"fortochka/internal/paths"
)

var installDeclined bool

func handOffToInstalled() bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	target := paths.InstalledExe()
	if samePath(self, target) {
		return false
	}
	c := inspectInstalled(self, target)
	if needsInstall(version, c) {
		log.Printf("tray: installing this build (v%s) to %s", version, target)
		if err := runElevated("-install"); err != nil {
			installDeclined = errors.Is(err, windows.ERROR_CANCELLED)
			log.Printf("tray: install: %v", err)
		}
		c = inspectInstalled(self, target)
	}
	if !shouldHandOff(version, c) {
		log.Printf("tray: staying on %s — the installed copy could not take over", self)
		return false
	}
	cmd := exec.Command(target)
	if err := cmd.Start(); err != nil {
		log.Printf("tray: start %s: %v", target, err)
		return false
	}
	_ = cmd.Process.Release()
	log.Printf("tray: handed over to %s", target)
	return true
}

func inspectInstalled(self, target string) installedCopy {
	var c installedCopy
	if _, err := os.Stat(target); err != nil {
		return c
	}
	c.exists = true
	if same, err := sameContent(self, target); err == nil && same {
		c.same = true
		return c
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, target, "-version")
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW}
	if out, err := cmd.Output(); err == nil {
		c.version = strings.TrimSpace(string(out))
	}
	return c
}

type shellExecuteInfo struct {
	size          uint32
	mask          uint32
	hwnd          windows.Handle
	verb          *uint16
	file          *uint16
	parameters    *uint16
	directory     *uint16
	show          int32
	instApp       windows.Handle
	idList        uintptr
	class         *uint16
	keyClass      windows.Handle
	hotKey        uint32
	iconOrMonitor windows.Handle
	process       windows.Handle
}

const (
	seeMaskNoCloseProcess = 0x00000040
	seeMaskNoAsync        = 0x00000100
)

var procShellExecuteExW = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

func runElevated(args string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(args)
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	info := shellExecuteInfo{
		mask:       seeMaskNoCloseProcess | seeMaskNoAsync,
		verb:       verb,
		file:       file,
		parameters: params,
		directory:  dir,
		show:       windows.SW_HIDE,
	}
	info.size = uint32(unsafe.Sizeof(info))
	if r, _, e := procShellExecuteExW.Call(uintptr(unsafe.Pointer(&info))); r == 0 {
		return e
	}
	if info.process == 0 {
		return errors.New("elevated process started without a handle to wait on")
	}
	defer windows.CloseHandle(info.process)
	ev, err := windows.WaitForSingleObject(info.process, 120000)
	if err != nil {
		return err
	}
	if ev != windows.WAIT_OBJECT_0 {
		return errors.New("timed out waiting for the elevated step")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.process, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("elevated step exited with code %d", code)
	}
	return nil
}

func removeLegacyDriverFiles(dir string) {
	for _, name := range []string{"WinDivert.dll", "WinDivert64.sys"} {
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err == nil {
			log.Printf("removed %s — WinDivert now lives in %s", p, paths.InstallDir())
		}
	}
}
