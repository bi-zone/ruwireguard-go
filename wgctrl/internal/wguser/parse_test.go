package wguser

import (
	"net"
	"testing"
	"time"

	"github.com/bi-zone/ruwireguard-go/wgctrl/wgtypes"
	"github.com/google/go-cmp/cmp"
)

// Example string source (with some slight modifications to use all fields):
// https://www.wireguard.com/xplatform/#example-dialog.
const okGet = `private_key=7b049989510ff1dc6e3dcc62d5895c8495184d32f41fa25bb0aaab187cae3dab
listen_port=12912
fwmark=1
public_key=02257e1f3d82d97d0a2ec18e279b06779148391eeb434fa4608df59b39ba0a95c4
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
allowed_ip=192.168.4.4/32
endpoint=[abcd:23::33%2]:51820
last_handshake_time_sec=1
last_handshake_time_nsec=2
public_key=034799ea40dc7b4c312d4467929cc4eb33e0dc2ad88bcb64317703a6e53aa4b5f1
tx_bytes=38333
rx_bytes=2224
allowed_ip=192.168.4.6/32
persistent_keepalive_interval=111
endpoint=182.122.22.19:3233
last_handshake_time_sec=0
last_handshake_time_nsec=0
public_key=0383434e463388dcc58d22a1806a771c80ffe10234bb2179b0837dea4a6229e0b9
endpoint=5.152.198.39:51820
last_handshake_time_sec=0
last_handshake_time_nsec=0
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
tx_bytes=1212111
rx_bytes=1929999999
protocol_version=1
errno=0

`

func TestClientDevices(t *testing.T) {
	// Used to trigger "parse peers" mode easily.
	const okKey = "public_key=0000000000000000000000000000000000000000000000000000000000000000\n"

	tests := []struct {
		name string
		res  []byte
		ok   bool
		d    *wgtypes.Device
	}{
		{
			name: "invalid key=value",
			res:  []byte("foo=bar=baz"),
		},
		{
			name: "invalid public_key",
			res:  []byte("public_key=xxx"),
		},
		{
			name: "short public_key",
			res:  []byte("public_key=abcd"),
		},
		{
			name: "invalid fwmark",
			res:  []byte("fwmark=foo"),
		},
		{
			name: "invalid endpoint",
			res:  []byte(okKey + "endpoint=foo"),
		},
		{
			name: "invalid allowed_ip",
			res:  []byte(okKey + "allowed_ip=foo"),
		},
		{
			name: "error",
			res:  []byte("errno=2\n\n"),
		},
		{
			name: "ok",
			res:  []byte(okGet),
			ok:   true,
			d: &wgtypes.Device{
				Name:         testDevice,
				Type:         wgtypes.Userspace,
				PrivateKey:   wgtypes.Key{0x7b, 0x04, 0x99, 0x89, 0x51, 0x0f, 0xf1, 0xdc, 0x6e, 0x3d, 0xcc, 0x62, 0xd5, 0x89, 0x5c, 0x84, 0x95, 0x18, 0x4d, 0x32, 0xf4, 0x1f, 0xa2, 0x5b, 0xb0, 0xaa, 0xab, 0x18, 0x7c, 0xae, 0x3d, 0xab},
				PublicKey:    wgtypes.Key{0x03, 0x63, 0x61, 0xc4, 0x7e, 0xae, 0xae, 0x85, 0xdb, 0xd0, 0x0b, 0x10, 0x48, 0x8d, 0x8c, 0x6e, 0xb3, 0xd4, 0x92, 0xe1, 0x6c, 0x39, 0x0c, 0x71, 0x22, 0x2d, 0x4b, 0xc7, 0x47, 0xa9, 0xb0, 0x67, 0x4b},
				ListenPort:   12912,
				FirewallMark: 1,
				Peers: []wgtypes.Peer{
					{
						PublicKey:    wgtypes.Key{0x02, 0x25, 0x7e, 0x1f, 0x3d, 0x82, 0xd9, 0x7d, 0x0a, 0x2e, 0xc1, 0x8e, 0x27, 0x9b, 0x06, 0x77, 0x91, 0x48, 0x39, 0x1e, 0xeb, 0x43, 0x4f, 0xa4, 0x60, 0x8d, 0xf5, 0x9b, 0x39, 0xba, 0x0a, 0x95, 0xc4},
						PresharedKey: wgtypes.Key{0x18, 0x85, 0x15, 0x9, 0x3e, 0x95, 0x2f, 0x5f, 0x22, 0xe8, 0x65, 0xce, 0xf3, 0x1, 0x2e, 0x72, 0xf8, 0xb5, 0xf0, 0xb5, 0x98, 0xac, 0x3, 0x9, 0xd5, 0xda, 0xcc, 0xe3, 0xb7, 0xf, 0xcf, 0x52},
						Endpoint: &net.UDPAddr{
							IP:   net.ParseIP("abcd:23::33"),
							Port: 51820,
							Zone: "2",
						},
						LastHandshakeTime: time.Unix(1, 2),
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0x4},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
					},
					{
						PublicKey: wgtypes.Key{0x03, 0x47, 0x99, 0xea, 0x40, 0xdc, 0x7b, 0x4c, 0x31, 0x2d, 0x44, 0x67, 0x92, 0x9c, 0xc4, 0xeb, 0x33, 0xe0, 0xdc, 0x2a, 0xd8, 0x8b, 0xcb, 0x64, 0x31, 0x77, 0x03, 0xa6, 0xe5, 0x3a, 0xa4, 0xb5, 0xf1},
						Endpoint: &net.UDPAddr{
							IP:   net.IPv4(182, 122, 22, 19),
							Port: 3233,
						},
						// Zero-value because UNIX timestamp of 0. Explicitly
						// set for documentation purposes here.
						LastHandshakeTime:           time.Time{},
						PersistentKeepaliveInterval: 111000000000,
						ReceiveBytes:                2224,
						TransmitBytes:               38333,
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0x6},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
					},
					{
						PublicKey: wgtypes.Key{0x03, 0x83, 0x43, 0x4e, 0x46, 0x33, 0x88, 0xdc, 0xc5, 0x8d, 0x22, 0xa1, 0x80, 0x6a, 0x77, 0x1c, 0x80, 0xff, 0xe1, 0x02, 0x34, 0xbb, 0x21, 0x79, 0xb0, 0x83, 0x7d, 0xea, 0x4a, 0x62, 0x29, 0xe0, 0xb9},
						Endpoint: &net.UDPAddr{
							IP:   net.IPv4(5, 152, 198, 39),
							Port: 51820,
						},
						ReceiveBytes:  1929999999,
						TransmitBytes: 1212111,
						AllowedIPs: []net.IPNet{
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0xa},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
							{
								IP:   net.IP{0xc0, 0xa8, 0x4, 0xb},
								Mask: net.IPMask{0xff, 0xff, 0xff, 0xff},
							},
						},
						ProtocolVersion: 1,
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, tt.res)
			defer done()

			devs, err := c.Devices()

			if tt.ok && err != nil {
				t.Fatalf("failed to get devices: %v", err)
			}
			if !tt.ok && err == nil {
				t.Fatal("expected an error, but none occurred")
			}
			if err != nil {
				return
			}

			if diff := cmp.Diff([]*wgtypes.Device{tt.d}, devs); diff != "" {
				t.Fatalf("unexpected Devices (-want +got):\n%s", diff)
			}
		})
	}
}
