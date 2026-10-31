package wgconf

import (
	"testing"

	"fortochka/internal/wg"
)

func TestParseAmneziaWG31(t *testing.T) {
	got, err := Parse([]byte(`[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 10.8.1.2/32, fd00::2/128
DNS = 9.9.9.9
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 15
S2 = 18
S3 = 20
S4 = 23
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0xc700000001><r 16><t>
I2 = <rc 8>
HeaderProtectionKey = aGVhZGVy
ContentPaddingAddition = 32-128
RekeyAfterTime = 100-160
RekeyTimeout = 4-6
RejectAfterTime = 170-190
KeepaliveTimeout = 8-12
MaxHandshakeAttempts = 15-20
RandomTrailers = on
DisableCookies = off

[Peer]
PublicKey = cHVibGlj
PresharedKey = cHNr
Endpoint = 203.0.113.5:51822
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 20-30
`))
	if err != nil {
		t.Fatal(err)
	}
	want := wg.Config{
		Endpoint:               "203.0.113.5:51822",
		PrivateKey:             "cHJpdmF0ZQ==",
		ServerPublicKey:        "cHVibGlj",
		PresharedKey:           "cHNr",
		Address:                "10.8.1.2/32",
		DNS:                    "9.9.9.9",
		PersistentKeepalive:    "20-30",
		Jc:                     "5",
		Jmin:                   "50",
		Jmax:                   "1000",
		S1:                     "15",
		S2:                     "18",
		S3:                     "20",
		S4:                     "23",
		H1:                     "1",
		H2:                     "2",
		H3:                     "3",
		H4:                     "4",
		I1:                     "<b 0xc700000001><r 16><t>",
		I2:                     "<rc 8>",
		HeaderProtectionKey:    "aGVhZGVy",
		ContentPaddingAddition: "32-128",
		RekeyAfterTime:         "100-160",
		RekeyTimeout:           "4-6",
		RejectAfterTime:        "170-190",
		KeepaliveTimeout:       "8-12",
		MaxHandshakeAttempts:   "15-20",
		RandomTrailers:         "on",
		DisableCookies:         "off",
	}
	if got != want {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestParsePlainWireGuard(t *testing.T) {
	got, err := Parse([]byte(`[Interface]
PrivateKey = cHJpdmF0ZQ==
Address = 10.8.1.2/32

[Peer]
PublicKey = cHVibGlj
Endpoint = 203.0.113.5:51820
PersistentKeepalive = 25
`))
	if err != nil {
		t.Fatal(err)
	}
	want := wg.Config{
		Endpoint:            "203.0.113.5:51820",
		PrivateKey:          "cHJpdmF0ZQ==",
		ServerPublicKey:     "cHVibGlj",
		Address:             "10.8.1.2/32",
		DNS:                 "1.1.1.1",
		PersistentKeepalive: "25",
	}
	if got != want {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}
