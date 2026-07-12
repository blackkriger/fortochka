//go:build !windows

package sysproxy

import "errors"

var errUnsupported = errors.New("sysproxy: automatic system proxy is only implemented on Windows")

func Enable(pacURL string) error { return errUnsupported }

func Disable() error { return errUnsupported }
