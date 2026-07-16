package pac

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// Handler serves a PAC file that sends every host to the local proxy (leaving Direct-vs-WG to the rule engine), except loopback, plain hostnames, and the given direct suffixes — those return DIRECT so they bypass the proxy entirely (e.g. Discord, left to a co-running DPI-bypass tool).
func Handler(proxyAddr string, directSuffixes []string) http.Handler {
	body := script(proxyAddr, directSuffixes)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write([]byte(body))
	})
}

func URL(pacAddr string) string {
	return fmt.Sprintf("http://%s/proxy.pac", pacAddr)
}

func script(proxyAddr string, directSuffixes []string) string {
	host, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		host, port = "127.0.0.1", "1080"
	}
	var directBlock string
	if len(directSuffixes) > 0 {
		conds := make([]string, 0, len(directSuffixes)*2)
		for _, d := range directSuffixes {
			conds = append(conds, fmt.Sprintf(`shExpMatch(host, "%s")`, d), fmt.Sprintf(`shExpMatch(host, "*.%s")`, d))
		}
		directBlock = fmt.Sprintf("  if (%s) {\n    return \"DIRECT\";\n  }\n", strings.Join(conds, " ||\n      "))
	}
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (isPlainHostName(host) ||
      shExpMatch(host, "localhost") ||
      isInNet(host, "127.0.0.0", "255.0.0.0")) {
    return "DIRECT";
  }
%s  return "PROXY %s:%s";
}
`, directBlock, host, port)
}
