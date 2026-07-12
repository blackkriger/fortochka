package wgconf

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"

	"fortochka/internal/wg"
)

// ParseFile reads a standard WireGuard .conf and maps it to a wg.Config; AllowedIPs are ignored since the userspace tunnel always routes what the proxy dials and split-routing is decided by the rule engine.
func ParseFile(path string) (wg.Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return wg.Config{}, err
	}
	defer f.Close()
	return parse(f)
}

// Parse maps standard WireGuard .conf contents to a wg.Config.
func Parse(data []byte) (wg.Config, error) {
	return parse(bytes.NewReader(data))
}

func parse(r io.Reader) (wg.Config, error) {
	var c wg.Config
	var section string

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				c.PrivateKey = val
			case "address":
				c.Address = firstField(val)
			case "dns":
				c.DNS = firstField(val)
			}
		case "peer":
			switch key {
			case "publickey":
				c.ServerPublicKey = val
			case "presharedkey":
				c.PresharedKey = val
			case "endpoint":
				c.Endpoint = val
			}
		}
	}
	if err := sc.Err(); err != nil {
		return wg.Config{}, err
	}

	if c.PrivateKey == "" || c.ServerPublicKey == "" || c.Endpoint == "" || c.Address == "" {
		return wg.Config{}, fmt.Errorf("incomplete WireGuard config: need PrivateKey, PublicKey, Endpoint and Address")
	}
	if c.DNS == "" {
		c.DNS = "1.1.1.1"
	}
	return c, nil
}

func firstField(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
