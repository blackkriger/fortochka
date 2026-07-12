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

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const tunnelMTU = 1420

// handshakeStaleAfter counts the tunnel as down; margin over RejectAfterTime (180s) so a healthy tunnel that re-handshakes late isn't flagged. hsFails is the fast signal.
const handshakeStaleAfter = 210

type Config struct {
	Endpoint        string
	PrivateKey      string
	ServerPublicKey string
	PresharedKey    string
	Address         string
	DNS             string
}

// Device is a userspace WireGuard tunnel whose DialContext sends connections out through the tunnel, so the rule engine can pick it for blocked targets.
type Device struct {
	dev     *device.Device
	net     *netstack.Net
	hsFails atomic.Int32 // consecutive failed re-handshakes; a dying tunnel
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

	d := &Device{net: tnet}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Printf("wg: "+format, args...)
			d.noteHandshake(format)
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
	if d.hsFails.Load() >= 3 {
		return false
	}
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
			return time.Now().Unix()-sec < handshakeStaleAfter
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
	fmt.Fprintf(&b, "persistent_keepalive_interval=25\n")
	return b.String(), nil
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
