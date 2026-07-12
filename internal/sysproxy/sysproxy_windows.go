//go:build windows

package sysproxy

import (
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var wininet = windows.NewLazyDLL("wininet.dll")

const settingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

const (
	internetOptionSettingsChanged = 39
	internetOptionRefresh         = 37
)

// Enable points the Windows/WinINET system proxy at our PAC URL.
func Enable(pacURL string) error {
	key, err := registry.OpenKey(registry.CURRENT_USER, settingsPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := key.SetStringValue("AutoConfigURL", pacURL); err != nil {
		return err
	}
	notifyWinINET()
	return nil
}

// Disable removes the PAC URL, restoring the previous (direct) configuration.
func Disable() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, settingsPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if err := key.DeleteValue("AutoConfigURL"); err != nil && err != registry.ErrNotExist {
		return err
	}
	notifyWinINET()
	return nil
}

func notifyWinINET() {
	set := wininet.NewProc("InternetSetOptionW")
	set.Call(0, internetOptionSettingsChanged, 0, 0)
	set.Call(0, internetOptionRefresh, 0, 0)
}
