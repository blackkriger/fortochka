package userrules

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fortochka/internal/rules"
)

const fileName = "rules.txt"

const template = `# List the sites and addresses that should go THROUGH the VPN tunnel.
# One entry per line. Lines starting with # are comments and are ignored.
#
# A domain also matches its subdomains:
#   rutracker.org        also covers www.rutracker.org, api.rutracker.org, ...
#
# Examples:
#   instagram.com
#   x.com
#   198.51.100.7         a single IP address
#   203.0.113.0/24       a whole IP range (CIDR)
#   http://198.51.100.7:8082/  a full URL or host:port also works (scheme/port/path are ignored)
#
# Everything not listed here (and not in the block lists) goes out directly.
# Save the file, changes automatically.

`

func Path(dir string) string { return filepath.Join(dir, fileName) }

// EnsureDefault writes the commented template if the file does not exist yet.
func EnsureDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, []byte(template), 0o600)
}

// Load parses the file into rules that route matching traffic through the VPN.
func Load(path string) ([]rules.Rule, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []rules.Rule
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		line = normalizeEntry(line)
		if line == "" {
			continue
		}
		if isAddr(line) {
			if !strings.Contains(line, "/") {
				line += "/32"
			}
			out = append(out, rules.Rule{CIDR: line, Action: rules.WG})
		} else {
			out = append(out, rules.Rule{Suffix: strings.TrimPrefix(line, "."), Action: rules.WG})
		}
	}
	return out, sc.Err()
}

// normalizeEntry reduces a user line (which may be a full URL or host:port) to the bare host or CIDR the engine matches on, so "http://198.51.100.7:8082/" becomes "198.51.100.7".
func normalizeEntry(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if _, err := netip.ParsePrefix(s); err == nil {
		return s
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.TrimSpace(s)
}

func isAddr(s string) bool {
	if _, err := netip.ParsePrefix(s); err == nil {
		return true
	}
	_, err := netip.ParseAddr(s)
	return err == nil
}

// Watch calls onChange whenever the file's modification time changes.
func Watch(ctx context.Context, path string, onChange func()) {
	last := modTime(path)
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if m := modTime(path); m != last {
				last = m
				onChange()
			}
		}
	}
}

func modTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime()
	}
	return time.Time{}
}
