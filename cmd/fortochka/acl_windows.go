//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"fortochka/internal/userrules"
)

const (
	dataDirSDDL   = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	inheritSDDL   = "D:"
	userWriteSDDL = "D:(A;;0x1301bf;;;BU)"
)

var serviceOwnedFiles = []string{
	"fortochka.yaml", "state.json", "lists.cache",
	"fortochka.log", "fortochka.log.1", "fortochka.log.2",
	"fortochka-tray.log", "fortochka-tray.log.1",
	"WinDivert.dll", "WinDivert64.sys",
}

func secureDataDir(dir string, setOwner bool) error {
	rules := userrules.Path(dir)
	ensureErr := userrules.EnsureDefault(rules)
	if err := applySDDL(dir, dataDirSDDL, true, setOwner); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	var errs []error
	for _, name := range serviceOwnedFiles {
		p := filepath.Join(dir, name)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if err := applySDDL(p, inheritSDDL, false, setOwner); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	if ensureErr != nil {
		errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(rules), ensureErr))
	} else if err := applySDDL(rules, userWriteSDDL, false, setOwner); err != nil {
		errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(rules), err))
	}
	return errors.Join(errs...)
}

func applySDDL(path, sddl string, protected, setOwner bool) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.New("refusing to apply a NULL DACL")
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if protected {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	var owner *windows.SID
	if setOwner {
		if owner, err = windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid); err != nil {
			return err
		}
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil)
}
