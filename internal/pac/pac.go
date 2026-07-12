package pac

import (
	"fmt"
	"net"
	"net/http"
)

// Handler serves a PAC file that sends every host to the local proxy (leaving Direct-vs-WG to the rule engine), except loopback and plain hostnames — so private IPs like the tunnel gateway can be routed by rule too.
func Handler(proxyAddr string) http.Handler {
	body := script(proxyAddr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.Write([]byte(body))
	})
}

func URL(pacAddr string) string {
	return fmt.Sprintf("http://%s/proxy.pac", pacAddr)
}

func script(proxyAddr string) string {
	host, port, err := net.SplitHostPort(proxyAddr)
	if err != nil {
		host, port = "127.0.0.1", "1080"
	}
	return fmt.Sprintf(`function FindProxyForURL(url, host) {
  if (isPlainHostName(host) ||
      shExpMatch(host, "localhost") ||
      isInNet(host, "127.0.0.0", "255.0.0.0")) {
    return "DIRECT";
  }
  return "PROXY %s:%s";
}
`, host, port)
}
