//go:build !windows

package autostart

func IsEnabled() bool             { return false }
func Enable(exePath string) error { return nil }
func Disable() error              { return nil }
