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
			case "jc":
				c.Jc = val
			case "jmin":
				c.Jmin = val
			case "jmax":
				c.Jmax = val
			case "s1":
				c.S1 = val
			case "s2":
				c.S2 = val
			case "s3":
				c.S3 = val
			case "s4":
				c.S4 = val
			case "h1":
				c.H1 = val
			case "h2":
				c.H2 = val
			case "h3":
				c.H3 = val
			case "h4":
				c.H4 = val
			case "i1":
				c.I1 = val
			case "i2":
				c.I2 = val
			case "i3":
				c.I3 = val
			case "i4":
				c.I4 = val
			case "i5":
				c.I5 = val
			case "headerprotectionkey":
				c.HeaderProtectionKey = val
			case "contentpaddingaddition":
				c.ContentPaddingAddition = val
			case "rekeyaftertime":
				c.RekeyAfterTime = val
			case "rekeytimeout":
				c.RekeyTimeout = val
			case "rejectaftertime":
				c.RejectAfterTime = val
			case "keepalivetimeout":
				c.KeepaliveTimeout = val
			case "maxhandshakeattempts":
				c.MaxHandshakeAttempts = val
			case "randomtrailers":
				c.RandomTrailers = val
			case "disablecookies":
				c.DisableCookies = val
			}
		case "peer":
			switch key {
			case "publickey":
				c.ServerPublicKey = val
			case "presharedkey":
				c.PresharedKey = val
			case "endpoint":
				c.Endpoint = val
			case "persistentkeepalive":
				c.PersistentKeepalive = val
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
