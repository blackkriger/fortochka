// Package selfupdate replaces the running executable in place from the project's GitHub releases. Windows keeps a running image locked against writing and deletion but not against renaming, so the current file is moved aside and the new one takes its path; the service then restarts onto it without its registration ever changing.
package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	releaseAPI = "https://api.github.com/repos/blackkriger/fortochka/releases/latest"
	assetName  = "fortochka.exe"
	checkEvery = 24 * time.Hour
	retryAfter = time.Hour
)

type Source struct {
	// Version is the running build, as stamped at link time. A build with no version is never replaced.
	Version string

	// Dial routes the download through the tunnel: the release host is commonly throttled where fortochka is used, and a direct download would also announce the upgrade to the ISP.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Ready reports whether the tunnel can carry the download.
	Ready func() bool

	// Enabled reports whether the user has left automatic updating on; it is read at each check so the tray toggle takes effect without a restart.
	Enabled func() bool

	// Wake is signalled when the tunnel comes up, so the first check happens then instead of failing and waiting out the retry.
	Wake <-chan struct{}

	// Restart stops and starts the service so it runs the replaced binary.
	Restart func() error
}

// Run checks for a newer release and installs it, then keeps checking until ctx is cancelled. Every failure is logged and retried later, never fatal: a broken update path must not cost the user their tunnel.
func Run(ctx context.Context, src Source) {
	if src.Version == "" || src.Version == "dev" {
		log.Printf("update: unversioned build — automatic updates are off")
		return
	}
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-src.Wake:
		}
		wait := checkEvery
		if src.Enabled != nil && !src.Enabled() {
			arm(t, wait)
			continue
		}
		if src.Ready != nil && !src.Ready() {
			arm(t, retryAfter)
			continue
		}
		if err := checkAndApply(ctx, src); err != nil {
			log.Printf("update: %v", err)
			wait = retryAfter
		}
		arm(t, wait)
	}
}

func arm(t *time.Timer, d time.Duration) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	t.Reset(d)
}

func checkAndApply(ctx context.Context, src Source) error {
	rel, err := latest(ctx, src)
	if err != nil {
		return err
	}
	if !newer(rel.Version, src.Version) {
		return nil
	}
	// Checked only once a newer release exists: releases published before the binary got a stable name carry differently named assets, and demanding them earlier would log a failure on every check with nothing to install.
	if rel.URL == "" || rel.SumURL == "" {
		return fmt.Errorf("release %s has no %s + .sha256 pair", rel.Version, assetName)
	}
	log.Printf("update: %s is available (running %s)", rel.Version, src.Version)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	if err := install(ctx, src, rel, exe); err != nil {
		return err
	}
	log.Printf("update: installed %s, restarting the service", rel.Version)
	if src.Restart == nil {
		return nil
	}
	return src.Restart()
}

// install downloads beside the running binary and swaps it in. The temporary file is a sibling on purpose: a rename is atomic only within one volume, so staging in the temp directory would turn the swap into a copy with a window where the file on disk is incomplete.
func install(ctx context.Context, src Source, rel release, exe string) error {
	want, err := expectedSum(ctx, src, rel)
	if err != nil {
		return err
	}
	tmp := exe + ".new"
	sum, err := download(ctx, src, rel.URL, tmp)
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if sum != want {
		os.Remove(tmp)
		return fmt.Errorf("checksum mismatch: got %s, want %s", sum, want)
	}
	old := exe + ".old"
	os.Remove(old) // a leftover from a previous update would block the rename
	if err := os.Rename(exe, old); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("move running binary aside: %w", err)
	}
	if err := os.Rename(tmp, exe); err != nil {
		os.Rename(old, exe) // put the working binary back rather than leave no binary at all
		os.Remove(tmp)
		return fmt.Errorf("install new binary: %w", err)
	}
	return nil
}

// CleanOld removes the binary left behind by the previous update; it can only be deleted once the process that was running it has exited, so this belongs at startup rather than right after the swap.
func CleanOld() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	old := exe + ".old"
	if _, err := os.Stat(old); err != nil {
		return
	}
	if err := os.Remove(old); err != nil {
		log.Printf("update: leftover %s could not be removed: %v", filepath.Base(old), err)
	}
}

type release struct {
	Version string
	URL     string
	SumURL  string
}

func latest(ctx context.Context, src Source) (release, error) {
	var body struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
	}
	resp, err := get(ctx, src, releaseAPI)
	if err != nil {
		return release{}, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return release{}, fmt.Errorf("parse release: %w", err)
	}
	rel := release{Version: strings.TrimPrefix(strings.TrimSpace(body.TagName), "v")}
	for _, a := range body.Assets {
		switch a.Name {
		case assetName:
			rel.URL = a.URL
		case assetName + ".sha256":
			rel.SumURL = a.URL
		}
	}
	if rel.Version == "" {
		return release{}, fmt.Errorf("release has no tag")
	}
	return rel, nil
}

// expectedSum reads the checksum published alongside the binary. It is a guard against a truncated or corrupted download, not against a tampered release: both files come from the same place, so whoever could replace one could replace the other.
func expectedSum(ctx context.Context, src Source, rel release) (string, error) {
	resp, err := get(ctx, src, rel.SumURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	sum, _, _ := strings.Cut(strings.TrimSpace(string(data)), " ")
	if len(sum) != 64 {
		return "", fmt.Errorf("malformed checksum file")
	}
	return strings.ToLower(sum), nil
}

func download(ctx context.Context, src Source, url, dest string) (string, error) {
	resp, err := get(ctx, src, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), resp.Body); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func get(ctx context.Context, src Source, url string) (*http.Response, error) {
	c := &http.Client{Transport: &http.Transport{
		DialContext:           src.Dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/octet-stream, application/vnd.github+json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: status %s", url, resp.Status)
	}
	return resp, nil
}

// newer compares dotted numeric versions field by field, so 0.10.0 sorts above 0.9.0 where a string compare would not.
func newer(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		x, y := field(as, i), field(bs, i)
		if x != y {
			return x > y
		}
	}
	return false
}

func field(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimFunc(parts[i], func(r rune) bool { return r < '0' || r > '9' }))
	if err != nil {
		return 0
	}
	return n
}

// Restart hands the stop/start to a detached copy of the freshly installed binary: a service cannot restart itself, since the SCM will not process the start while the stop it is serving has not returned.
func Restart() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "-restart-service")
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
