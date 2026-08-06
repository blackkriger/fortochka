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

const template = `# Everything not listed here (and not in the block lists) goes out directly.
#
# A domain also matches its subdomains:
#   example.org          also covers www.example.org, api.example.org, ...
#
# Examples:
#   x.com
#   198.51.100.7         a single IP address
#   203.0.113.0/24       a whole IP range (CIDR)
#   http://198.51.100.7:8082/  a full URL or host:port also works (scheme/port/path are ignored)
#
# Prefix a line with "!" to force it DIRECT instead: it bypasses the tunnel even when a fetched block list would route it through.
#   !example.com
#
# A service name stands for every domain it needs, so its parts can't end up on different paths:
#   youtube, instagram    the whole service through the tunnel
#   !youtube              the whole service direct

`

// groups expand one keyword into every domain a service actually uses. Listing them by hand is error-prone: routing only youtube.com and googlevideo.com leaves the thumbnails, avatars and the player API on the other path, and the site half-works.
var groups = map[string][]string{
	"youtube": {
		"youtube.com",
		"youtu.be",
		"googlevideo.com",
		"ytimg.com",
		"ggpht.com",
		"youtubei.googleapis.com",
		"youtube.googleapis.com",
		"youtubeembeddedplayer.googleapis.com",
	},
	"instagram": {
		"instagram.com",
		"cdninstagram.com",
		"fbcdn.net", // Instagram's media comes from Facebook's CDN, so this also moves Facebook and Messenger media
	},
}

func Path(dir string) string { return filepath.Join(dir, fileName) }

// headerMark identifies a header fortochka wrote. A file whose top comments do not carry it belongs to the user and is left exactly as found.
const headerMark = "goes out directly."

// EnsureDefault writes the commented template when the file is missing, and refreshes an outdated header on an existing one so newly added syntax is documented where it is actually used. Only the leading block of comments is replaced; rules and any notes below them are kept byte for byte.
func EnsureDefault(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return os.WriteFile(path, []byte(template), 0o600)
	}
	if err != nil {
		return err
	}
	head, body := splitHeader(string(data))
	current, _ := splitHeader(template)
	if head == current || !strings.Contains(head, headerMark) {
		return nil
	}
	return os.WriteFile(path, []byte(current+body), 0o600)
}

// splitHeader separates the leading run of comments and blank lines from everything below, so the header can be swapped without a rule ever being touched.
func splitHeader(s string) (head, body string) {
	lines := strings.SplitAfter(s, "\n")
	i := 0
	for ; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t != "" && !strings.HasPrefix(t, "#") {
			break
		}
	}
	return strings.Join(lines[:i], ""), strings.Join(lines[i:], "")
}

// Load parses the file into routing rules: a plain entry routes through the tunnel, a "!"-prefixed entry forces it direct (overriding the fetched block lists).
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
		action := rules.WG
		if strings.HasPrefix(line, "!") {
			action = rules.Direct
			line = strings.TrimSpace(line[1:])
		}
		if doms, ok := groups[strings.ToLower(line)]; ok {
			for _, d := range doms {
				out = append(out, rules.Rule{Suffix: d, Action: action})
			}
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
			out = append(out, rules.Rule{CIDR: line, Action: action})
		} else {
			out = append(out, rules.Rule{Suffix: strings.TrimPrefix(line, "."), Action: action})
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
