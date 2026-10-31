package wg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

const tunnelMTU = 1420

// handshakeStaleAfter counts the tunnel as down; margin over RejectAfterTime (180s) so a healthy tunnel that re-handshakes late isn't flagged. hsFails is the fast signal.
const handshakeStaleAfter = 210

const defaultKeepalive = "25"

type Config struct {
	Endpoint            string
	PrivateKey          string
	ServerPublicKey     string
	PresharedKey        string
	Address             string
	DNS                 string
	PersistentKeepalive string

	// AmneziaWG obfuscation; empty = plain WireGuard.
	Jc, Jmin, Jmax, S1, S2, S3, S4, H1, H2, H3, H4 string
	I1, I2, I3, I4, I5                             string
	HeaderProtectionKey, ContentPaddingAddition    string
	RekeyAfterTime, RekeyTimeout, RejectAfterTime  string
	KeepaliveTimeout, MaxHandshakeAttempts         string
	RandomTrailers, DisableCookies                 string
}

// Device is a userspace WireGuard tunnel whose DialContext sends connections out through the tunnel, so the rule engine can pick it for blocked targets.
type Device struct {
	dev        *device.Device
	net        *netstack.Net
	staleAfter int64
	hsFails    atomic.Int32 // consecutive failed re-handshakes; a dying tunnel
	lastHS     atomic.Int64 // last handshake timestamp seen, so a completed one can clear the streak
}

func New(c Config) (*Device, error) {
	addr, err := netip.ParsePrefix(c.Address)
	if err != nil {
		return nil, fmt.Errorf("wg address %q: %w", c.Address, err)
	}
	dns, err := netip.ParseAddr(c.DNS)
	if err != nil {
		return nil, fmt.Errorf("wg dns %q: %w", c.DNS, err)
	}

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr.Addr()}, []netip.Addr{dns}, tunnelMTU)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	d := &Device{net: tnet, staleAfter: staleAfter(c)}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			d.noteHandshake(format)
			if wgLogWorthy(format) {
				log.Printf("wg: "+format, args...)
			}
		},
		Errorf: func(format string, args ...any) { log.Printf("wg: ERROR: "+format, args...) },
	}
	d.dev = device.NewDevice(tun, conn.NewDefaultBind(), logger)

	ipc, err := ipcConfig(c)
	if err != nil {
		d.dev.Close()
		return nil, err
	}
	if err := d.dev.IpcSet(ipc); err != nil {
		d.dev.Close()
		return nil, fmt.Errorf("wg ipc set: %w", err)
	}
	if err := d.dev.Up(); err != nil {
		d.dev.Close()
		return nil, fmt.Errorf("wg up: %w", err)
	}
	return d, nil
}

// wgLogWorthy keeps the WG log to meaningful lines (handshakes, errors) and drops the per-routine/keepalive spam that otherwise floods the file, especially during rebuild loops.
func wgLogWorthy(format string) bool {
	return strings.Contains(format, "andshake") ||
		strings.Contains(format, "Failed") ||
		strings.Contains(format, "Invalid") ||
		strings.Contains(format, "error")
}

// noteHandshake tracks re-handshake failures so a silently dead tunnel is spotted in seconds instead of waiting out the whole reject window.
func (d *Device) noteHandshake(format string) {
	switch {
	case strings.Contains(format, "Received handshake response"):
		d.hsFails.Store(0)
	case strings.Contains(format, "Handshake did not complete"):
		d.hsFails.Add(1)
	}
}

func (d *Device) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.net.DialContext(ctx, network, address)
}

func (d *Device) Close() error {
	d.dev.Close()
	return nil
}

// HandshakeOK reports whether the peer handshake is recent enough that the tunnel is actually live (a stale handshake means the session has died).
func (d *Device) HandshakeOK() bool {
	cfg, err := d.dev.IpcGet()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(cfg, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			sec, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
			if err != nil || sec == 0 {
				return false
			}
			// A handshake that actually completed clears the failure streak. Without this a tunnel revived by a peer-initiated rekey stays "failing" forever — that path never logs the line the counter watches — and the supervisor eventually tears down a working tunnel.
			if sec > d.lastHS.Swap(sec) {
				d.hsFails.Store(0)
			}
			if d.hsFails.Load() >= 3 {
				return false
			}
			return time.Now().Unix()-sec < d.staleAfter
		}
	}
	return false
}

func ipcConfig(c Config) (string, error) {
	priv, err := keyToHex(c.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private_key: %w", err)
	}
	pub, err := keyToHex(c.ServerPublicKey)
	if err != nil {
		return "", fmt.Errorf("server_public_key: %w", err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	if c.HeaderProtectionKey != "" {
		hpk, err := keyToHex(c.HeaderProtectionKey)
		if err != nil {
			return "", fmt.Errorf("header_protection_key: %w", err)
		}
		for i, s := range []string{c.S1, c.S2, c.S3, c.S4} {
			if n, _ := strconv.Atoi(s); n < device.HeaderCipherNonceSize {
				return "", fmt.Errorf("HeaderProtectionKey needs S1-S4 of at least %d, S%d is %d", device.HeaderCipherNonceSize, i+1, n)
			}
		}
		fmt.Fprintf(&b, "header_protection_key=%s\n", hpk)
	}
	for _, p := range []struct{ key, val string }{
		{"jc", c.Jc}, {"jmin", c.Jmin}, {"jmax", c.Jmax},
		{"s1", c.S1}, {"s2", c.S2}, {"s3", c.S3}, {"s4", c.S4},
		{"h1", c.H1}, {"h2", c.H2}, {"h3", c.H3}, {"h4", c.H4},
		{"i1", c.I1}, {"i2", c.I2}, {"i3", c.I3}, {"i4", c.I4}, {"i5", c.I5},
		{"content_padding_addition", c.ContentPaddingAddition},
		{"rekey_after_time", c.RekeyAfterTime},
		{"rekey_timeout", c.RekeyTimeout},
		{"reject_after_time", c.RejectAfterTime},
		{"keepalive_timeout", c.KeepaliveTimeout},
		{"max_handshake_attempts", c.MaxHandshakeAttempts},
		{"random_trailers", uapiBool(c.RandomTrailers)},
		{"disable_cookies", uapiBool(c.DisableCookies)},
	} {
		if p.val != "" {
			fmt.Fprintf(&b, "%s=%s\n", p.key, p.val)
		}
	}
	fmt.Fprintf(&b, "public_key=%s\n", pub)
	if c.PresharedKey != "" {
		psk, err := keyToHex(c.PresharedKey)
		if err != nil {
			return "", fmt.Errorf("preshared_key: %w", err)
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	fmt.Fprintf(&b, "endpoint=%s\n", c.Endpoint)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%s\n", keepalive(c))
	return b.String(), nil
}

func keepalive(c Config) string {
	switch strings.ToLower(c.PersistentKeepalive) {
	case "", "0", "0-0", "off", "(off)":
		return defaultKeepalive
	}
	return c.PersistentKeepalive
}

func uapiBool(v string) string {
	switch strings.ToLower(v) {
	case "":
		return ""
	case "on", "1", "true", "t", "yes":
		return "1"
	}
	return "0"
}

func staleAfter(c Config) int64 {
	reject := rangeHi(c.RejectAfterTime, device.RejectAfterTime)
	rekey := rangeHi(c.RekeyAfterTime, device.RekeyAfterTime) + rangeHi(keepalive(c), 0)
	return handshakeStaleAfter - int64(device.RejectAfterTime/time.Second) + max(reject, rekey)
}

func rangeHi(v string, def time.Duration) int64 {
	lo, hi, found := strings.Cut(v, "-")
	if !found {
		hi = lo
	}
	if n, err := strconv.ParseInt(strings.TrimSpace(hi), 10, 64); err == nil && n > 0 {
		return n
	}
	return int64(def / time.Second)
}

func keyToHex(key string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(key))
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("expected 32-byte key, got %d bytes", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
