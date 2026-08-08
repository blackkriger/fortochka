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
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	releaseAPI = "https://api.github.com/repos/blackkriger/fortochka/releases/latest"
	assetName  = "fortochka.exe"
)

type Source struct {
	// Version is the running build, as stamped at link time. A build with no version is never replaced.
	Version string

	// Dial routes the download through the tunnel: the release host is commonly throttled where fortochka is used, and a direct download would also announce the upgrade to the ISP.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Restart stops and starts the service so it runs the replaced binary.
	Restart func() error
}

// Check looks for a newer release once and installs it. There is no schedule: the tray asks for this when it starts, which is the moment a new version can actually matter to the user. Failures are logged by the caller and simply wait for the next launch — a broken update path must not cost the user their tunnel.
func Check(ctx context.Context, src Source) error {
	if src.Version == "" || src.Version == "dev" {
		log.Printf("update: unversioned build — nothing to compare against")
		return nil
	}
	log.Printf("update: checking for a release newer than %s", src.Version)
	rel, err := latest(ctx, src, src.Version)
	if err != nil {
		return err
	}
	if !newer(rel.Version, src.Version) {
		log.Printf("update: latest release is %s, nothing to install", dash(rel.Version))
		return nil
	}
	log.Printf("update: %s is available (running %s)", rel.Version, src.Version)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	if err := install(ctx, src, rel, exe); err != nil {
		return err
	}
	if src.Restart == nil {
		return nil
	}
	log.Printf("update: restarting the service onto %s", rel.Version)
	if err := src.Restart(); err != nil {
		return fmt.Errorf("restart failed, %s is installed and starts with the next launch: %w", rel.Version, err)
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// install downloads beside the running binary and swaps it in. The temporary file is a sibling on purpose: a rename is atomic only within one volume, so staging in the temp directory would turn the swap into a copy with a window where the file on disk is incomplete.
func install(ctx context.Context, src Source, rel release, exe string) error {
	tmp := exe + ".new"
	log.Printf("update: downloading %s through the tunnel", rel.URL)
	sum, n, err := download(ctx, src, rel.URL, tmp)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("download: %w", err)
	}
	if sum != rel.Sum {
		os.Remove(tmp)
		return fmt.Errorf("checksum mismatch after %d bytes: got %s, want %s", n, sum, rel.Sum)
	}
	log.Printf("update: downloaded %d bytes, checksum matches the release notes", n)
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
	Sum     string // the sha256, read out of the release notes where it is published
}

// sumPattern picks the digest out of the release notes: a sha256 is the only 64-character hex run that appears there.
var sumPattern = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)

func latest(ctx context.Context, src Source, current string) (release, error) {
	var body struct {
		TagName string `json:"tag_name"`
		Body    string `json:"body"`
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
	if !newer(rel.Version, current) {
		return rel, nil // assets are only worth checking for a release we would actually install
	}
	rel.Sum = strings.ToLower(sumPattern.FindString(body.Body))
	for _, a := range body.Assets {
		if a.Name == assetName {
			rel.URL = a.URL
		}
	}
	if rel.URL == "" {
		return release{}, fmt.Errorf("release %q has no %s", body.TagName, assetName)
	}
	if rel.Sum == "" {
		return release{}, fmt.Errorf("release %q publishes no sha256 for %s", body.TagName, assetName)
	}
	return rel, nil
}

func download(ctx context.Context, src Source, url, dest string) (string, int64, error) {
	resp, err := get(ctx, src, url)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", 0, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), resp.Body)
	if err != nil {
		f.Close()
		return "", n, err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return "", n, err
	}
	if err := f.Close(); err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
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

// Newer reports whether a is a later version than b; the tray uses it to notice that the engine has moved ahead of it.
func Newer(a, b string) bool { return newer(a, b) }

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
