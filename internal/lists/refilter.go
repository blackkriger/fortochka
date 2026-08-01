package lists

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"fortochka/internal/rules"
)

type Source struct {
	DomainsURL string
	IPsURL     string
	Refresh    time.Duration
}

// Run fetches the Re:filter lists once, applies them to the engine, then keeps them refreshed until ctx is cancelled; fetch failures are logged, not fatal.
func Run(ctx context.Context, src Source, engine *rules.Engine) {
	load := func() {
		log.Printf("lists: refreshing from %s / %s", src.DomainsURL, src.IPsURL)
		r, err := fetch(ctx, src)
		if err != nil {
			log.Printf("lists: refresh failed: %v", err)
			return
		}
		engine.SetList(r)
		log.Printf("lists: loaded %d entries", len(r))
	}

	load()
	ticker := time.NewTicker(src.Refresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			load()
		}
	}
}

func fetch(ctx context.Context, src Source) ([]rules.Rule, error) {
	var out []rules.Rule
	if src.DomainsURL != "" {
		lines, err := download(ctx, src.DomainsURL)
		if err != nil {
			return nil, fmt.Errorf("domains: %w", err)
		}
		for _, d := range lines {
			out = append(out, rules.Rule{Suffix: d, Action: rules.WG})
		}
	}
	if src.IPsURL != "" {
		lines, err := download(ctx, src.IPsURL)
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

// client bounds the handshake and header wait so a server that accepts and then stalls can't wedge the refresh loop for the process lifetime, while a slow but progressing multi-MB download is left alone.
var client = &http.Client{Transport: &http.Transport{
	Proxy:                 http.ProxyFromEnvironment,
	ForceAttemptHTTP2:     true,
	TLSHandshakeTimeout:   30 * time.Second,
	ResponseHeaderTimeout: 60 * time.Second,
}}

func download(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
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
