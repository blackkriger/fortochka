package lists

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fortochka/internal/rules"
)

// Backoff after a failed download, doubling from retryMin to retryMax: the quick failure (the tunnel is up but its route has not settled) clears within the first tries, and a list host that is simply unreachable is not hammered.
const (
	retryMin = 30 * time.Second
	retryMax = 30 * time.Minute
)

type Source struct {
	DomainsURL string
	IPsURL     string
	Refresh    time.Duration

	// Dial routes the download through the tunnel. Fetching directly would be pointless where the lists matter most (the host serving them is commonly blocked there too) and would tell the ISP what this machine is downloading.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)

	// Ready reports whether the tunnel can carry the download.
	Ready func() bool

	// CacheDir holds the last good copy so a start with no network still has rules; an empty list would silently send everything direct.
	CacheDir string

	// Wake is signalled when the tunnel comes up, so a refresh that is due happens then rather than waiting out the interval. Without it the schedule and the tunnel being available would have to coincide by luck.
	Wake <-chan struct{}
}

// Run seeds the engine from the cached copy, then keeps it refreshed through the tunnel until ctx is cancelled. Failures are logged and retried on a later tick, never fatal.
func Run(ctx context.Context, src Source, engine *rules.Engine) {
	fetchedAt := time.Time{}
	if r, at, err := loadCache(src.CacheDir); err == nil && len(r) > 0 {
		engine.SetList(r)
		fetchedAt = at
		log.Printf("lists: %d entries from cache (%s old)", len(r), time.Since(at).Round(time.Minute))
	} else {
		log.Printf("lists: no cache yet — rules from the fetched lists start applying once the tunnel is up")
	}

	// The timer is armed for whenever the next attempt is due; the tunnel coming up short-circuits the wait. Nothing polls.
	next := time.NewTimer(0)
	defer next.Stop()
	backoff := retryMin
	for {
		if time.Since(fetchedAt) >= src.Refresh && (src.Ready == nil || src.Ready()) {
			if r, err := fetch(ctx, src); err != nil {
				log.Printf("lists: refresh failed, retrying in %s: %v", backoff, err)
				arm(next, backoff)
				backoff = min(backoff*2, retryMax)
			} else {
				engine.SetList(r)
				fetchedAt = time.Now()
				if err := saveCache(src.CacheDir, r); err != nil {
					log.Printf("lists: cache write: %v", err)
				}
				log.Printf("lists: loaded %d entries through the tunnel", len(r))
				arm(next, src.Refresh)
				backoff = retryMin
			}
		} else {
			arm(next, max(src.Refresh-time.Since(fetchedAt), time.Minute))
		}
		select {
		case <-ctx.Done():
			return
		case <-next.C:
		case <-src.Wake:
		}
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

const cacheName = "lists.cache"

// The cache is the flattened rule set: one line per entry, "d " for a domain and "i " for a CIDR, after a timestamp header.
func saveCache(dir string, r []rules.Rule) error {
	if dir == "" {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d\n", time.Now().Unix())
	for _, rule := range r {
		if rule.Suffix != "" {
			b.WriteString("d " + rule.Suffix + "\n")
		} else if rule.CIDR != "" {
			b.WriteString("i " + rule.CIDR + "\n")
		}
	}
	path := filepath.Join(dir, cacheName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

func loadCache(dir string) ([]rules.Rule, time.Time, error) {
	if dir == "" {
		return nil, time.Time{}, os.ErrNotExist
	}
	f, err := os.Open(filepath.Join(dir, cacheName))
	if err != nil {
		return nil, time.Time{}, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	if !sc.Scan() {
		return nil, time.Time{}, fmt.Errorf("empty cache")
	}
	sec, err := strconv.ParseInt(strings.TrimSpace(sc.Text()), 10, 64)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("cache header: %w", err)
	}
	at := time.Unix(sec, 0)

	var out []rules.Rule
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 3 {
			continue
		}
		switch line[0] {
		case 'd':
			out = append(out, rules.Rule{Suffix: line[2:], Action: rules.WG})
		case 'i':
			out = append(out, rules.Rule{CIDR: line[2:], Action: rules.WG})
		}
	}
	return out, at, sc.Err()
}

func fetch(ctx context.Context, src Source) ([]rules.Rule, error) {
	log.Printf("lists: refreshing from %s / %s", src.DomainsURL, src.IPsURL)
	c := clientFor(src.Dial)
	var out []rules.Rule
	if src.DomainsURL != "" {
		lines, err := download(ctx, c, src.DomainsURL)
		if err != nil {
			return nil, fmt.Errorf("domains: %w", err)
		}
		for _, d := range lines {
			out = append(out, rules.Rule{Suffix: d, Action: rules.WG})
		}
	}
	if src.IPsURL != "" {
		lines, err := download(ctx, c, src.IPsURL)
		if err != nil {
			return nil, fmt.Errorf("ips: %w", err)
		}
		for _, ip := range lines {
			if !strings.Contains(ip, "/") {
				ip += "/32"
			}
			out = append(out, rules.Rule{CIDR: ip, Action: rules.WG})
		}
	}
	return out, nil
}

// clientFor bounds the handshake and header wait so a server that accepts and then stalls can't wedge the loop, while a slow but progressing multi-MB download is left alone.
func clientFor(dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext:           dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}}
}

func download(ctx context.Context, c *http.Client, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %s", resp.Status)
	}

	var lines []string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
