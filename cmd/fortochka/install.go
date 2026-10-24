package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fortochka/internal/selfupdate"
)

type installedCopy struct {
	exists  bool
	same    bool
	version string
}

func needsInstall(own string, c installedCopy) bool {
	switch {
	case !c.exists:
		return true
	case c.same:
		return false
	case c.version != "" && selfupdate.Newer(c.version, own):
		return false
	default:
		return true
	}
}

func shouldHandOff(own string, c installedCopy) bool {
	return c.exists && (c.same || (c.version != "" && selfupdate.Newer(c.version, own)))
}

func samePath(a, b string) bool {
	if strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) {
		return true
	}
	fa, errA := os.Stat(a)
	fb, errB := os.Stat(b)
	return errA == nil && errB == nil && os.SameFile(fa, fb)
}

func fileSum(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func sameContent(a, b string) (bool, error) {
	sa, err := fileSum(a)
	if err != nil {
		return false, err
	}
	sb, err := fileSum(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(sa, sb), nil
}

func placeBinary(src, dst string) (bool, error) {
	if same, err := sameContent(src, dst); err == nil && same {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	tmp := dst + ".new"
	if err := copyFile(src, tmp); err != nil {
		os.Remove(tmp)
		return false, err
	}
	if _, err := os.Stat(dst); err == nil {
		old := dst + ".old"
		if err := os.Remove(old); err != nil && !os.IsNotExist(err) {
			old = fmt.Sprintf("%s.old-%d", dst, time.Now().UnixNano())
		}
		if err := os.Rename(dst, old); err != nil {
			os.Remove(tmp)
			return false, err
		}
		if err := os.Rename(tmp, dst); err != nil {
			os.Rename(old, dst)
			os.Remove(tmp)
			return false, err
		}
		return true, nil
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return false, err
	}
	return true, nil
}

func removeOldBinaries(exe string) {
	olds, _ := filepath.Glob(exe + ".old*")
	for _, p := range olds {
		os.Remove(p)
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
