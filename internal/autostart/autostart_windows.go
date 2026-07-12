//go:build windows

package autostart

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows/registry"
)

// The tray is a plain non-elevated login app started by a per-user Run key alongside Explorer; the privileged engine is a separate SCM-managed auto-start service, so no scheduled task or UAC is involved here.

const (
	runKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
	valName = "fortochka"
	oldTask = "fortochka" // leftover scheduled task from the single-exe version
)

func hidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x08000000} // CREATE_NO_WINDOW
	return cmd
}

func IsEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(valName)
	return err == nil
}

func Enable(exePath string) error {
	removeOldTask()
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(valName, `"`+exePath+`"`)
}

func Disable() error {
	removeOldTask()
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	k.DeleteValue(valName) // ignore "not found"
	return nil
}

// removeOldTask deletes the leftover elevated logon task from the single-exe version so it can't launch a second, conflicting instance at login.
func removeOldTask() {
	_ = hidden("schtasks", "/delete", "/tn", oldTask, "/f").Run()
}
