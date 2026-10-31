package wg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
)

func TestIpcConfigPlainWireGuard(t *testing.T) {
	priv, _ := genKey(t)
	_, pub := genKey(t)
	ipc, err := ipcConfig(Config{PrivateKey: priv, ServerPublicKey: pub, Endpoint: "203.0.113.5:51820"})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"jc=", "s1=", "h1=", "i1=", "header_protection_key=", "random_trailers="} {
		if strings.Contains(ipc, key) {
			t.Errorf("a plain WireGuard config must not set %q:\n%s", key, ipc)
		}
	}
	if !strings.Contains(ipc, "persistent_keepalive_interval=25\n") {
		t.Errorf("without a keepalive in the config the default must be used:\n%s", ipc)
	}
}

func TestIpcConfigAmneziaWG31(t *testing.T) {
	priv, _ := genKey(t)
	_, pub := genKey(t)
	hpk, _ := genKey(t)
	c := awg31(Config{PrivateKey: priv, ServerPublicKey: pub, Endpoint: "203.0.113.5:51822"}, hpk)
	c.RandomTrailers = "on"
	c.DisableCookies = "off"
	ipc, err := ipcConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(hpk)
	for _, line := range []string{
		"header_protection_key=" + hex.EncodeToString(raw),
		"s3=20", "s4=23", "h1=1", "i1=" + c.I1,
		"content_padding_addition=32-128",
		"rekey_after_time=100-160",
		"random_trailers=1",
		"disable_cookies=0",
		"persistent_keepalive_interval=20-30",
	} {
		if !strings.Contains(ipc, line+"\n") {
			t.Errorf("missing %q in:\n%s", line, ipc)
		}
	}
}

func TestIpcConfigHeaderProtectionNeedsPaddings(t *testing.T) {
	priv, _ := genKey(t)
	_, pub := genKey(t)
	hpk, _ := genKey(t)
	c := awg31(Config{PrivateKey: priv, ServerPublicKey: pub, Endpoint: "203.0.113.5:51822"}, hpk)
	c.S3 = ""
	if _, err := ipcConfig(c); err == nil || !strings.Contains(err.Error(), "S3") {
		t.Errorf("a header protection key with S3 unset must be refused naming S3, got %v", err)
	}
}

func TestStaleAfterFollowsTimings(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    Config
		want int64
	}{
		{"defaults", Config{}, handshakeStaleAfter},
		{"keepalive range within the default window", Config{PersistentKeepalive: "20-30"}, handshakeStaleAfter},
		{"longer reject window", Config{RejectAfterTime: "300-400"}, 430},
		{"slow keepalive", Config{PersistentKeepalive: "100-150"}, 300},
		{"slow rekey", Config{RekeyAfterTime: "200"}, 255},
	} {
		if got := staleAfter(tc.c); got != tc.want {
			t.Errorf("%s: staleAfter = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestTunnelBetweenEngines(t *testing.T) {
	hpk, _ := genKey(t)
	otherHPK, _ := genKey(t)
	for _, tc := range []struct {
		name         string
		client, peer func(Config) Config
		works        bool
	}{
		{"plain WireGuard", same, same, true},
		{"AmneziaWG 2.0", awg20, awg20, true},
		{"AmneziaWG 3.1", func(c Config) Config { return awg31(c, hpk) }, func(c Config) Config { return awg31(c, hpk) }, true},
		{"AmneziaWG 3.1 with another server key", func(c Config) Config { return awg31(c, hpk) }, func(c Config) Config { return awg31(c, otherHPK) }, false},
		{"client-only knobs against a 2.0 server", clientKnobs, awg20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := pairConfigs(t)
			cnet, snet := startPair(t, tc.client(client), tc.peer(server))
			timeout := 10 * time.Second
			if !tc.works {
				timeout = 3 * time.Second
			}
			err := echo(cnet, snet, timeout)
			if tc.works && err != nil {
				t.Fatalf("data must flow through the tunnel: %v", err)
			}
			if !tc.works && err == nil {
				t.Fatal("the tunnel must not come up")
			}
		})
	}
}

func same(c Config) Config { return c }

func awg20(c Config) Config {
	c.Jc, c.Jmin, c.Jmax = "5", "50", "1000"
	c.S1, c.S2, c.S3, c.S4 = "15", "18", "20", "23"
	c.H1, c.H2, c.H3, c.H4 = "100000-100100", "200000-200100", "300000-300100", "400000-400100"
	c.I1 = "<b 0xc700000001><r 16><t>"
	return c
}

func awg31(c Config, hpk string) Config {
	c = awg20(c)
	c.H1, c.H2, c.H3, c.H4 = "1", "2", "3", "4"
	c.HeaderProtectionKey = hpk
	c.RandomTrailers = "on"
	c.ContentPaddingAddition = "32-128"
	c.RekeyAfterTime = "100-160"
	c.PersistentKeepalive = "20-30"
	return c
}

func clientKnobs(c Config) Config {
	c = awg20(c)
	c.I2 = "<rc 8>"
	c.ContentPaddingAddition = "32-128"
	c.RekeyAfterTime = "100-160"
	c.KeepaliveTimeout = "8-12"
	c.PersistentKeepalive = "20-30"
	return c
}

func genKey(t *testing.T) (priv, pub string) {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	k[0] &= 248
	k[31] = k[31]&127 | 64
	p, err := curve25519.X25519(k[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(k[:]), base64.StdEncoding.EncodeToString(p)
}

func pairConfigs(t *testing.T) (client, server Config) {
	cpriv, cpub := genKey(t)
	spriv, spub := genKey(t)
	client = Config{PrivateKey: cpriv, ServerPublicKey: spub, Address: "10.66.0.2/32", Endpoint: "127.0.0.1:1"}
	server = Config{PrivateKey: spriv, ServerPublicKey: cpub, Address: "10.66.0.1/32"}
	return client, server
}

func startPair(t *testing.T, client, server Config) (cnet, snet *netstack.Net) {
	binds := bindtest.NewChannelBinds()
	snet = startEngine(t, server, binds[1], true)
	return startEngine(t, client, binds[0], false), snet
}

func startEngine(t *testing.T, c Config, bind conn.Bind, server bool) *netstack.Net {
	t.Helper()
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParsePrefix(c.Address).Addr()}, nil, tunnelMTU)
	if err != nil {
		t.Fatal(err)
	}
	dev := device.NewDevice(tun, bind, device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(dev.Close)
	ipc, err := ipcConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	if server {
		ipc = strings.NewReplacer(
			"endpoint=\n", "",
			"persistent_keepalive_interval="+keepalive(c)+"\n", "persistent_keepalive_interval=0\n",
		).Replace(ipc)
	}
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("engine refused the config: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatal(err)
	}
	return tnet
}

func echo(cnet, snet *netstack.Net, timeout time.Duration) error {
	ln, err := snet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 66, 0, 1), Port: 7000})
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		defer s.Close()
		io.Copy(s, s)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := cnet.DialContext(ctx, "tcp", "10.66.0.1:7000")
	if err != nil {
		return err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))
	msg := []byte(strings.Repeat("fortochka ", 500))
	if _, err := c.Write(msg); err != nil {
		return err
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		return err
	}
	if string(got) != string(msg) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
