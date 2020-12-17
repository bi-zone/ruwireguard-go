package wguser

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/bi-zone/ruwireguard-go/wgctrl/internal/wgtest"
	"github.com/bi-zone/ruwireguard-go/wgctrl/wgtypes"
)

// Example string source (with some slight modifications to use all fields):
// https://www.wireguard.com/xplatform/#cross-platform-userspace-implementation.
const okSet = `set=1
private_key=e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a
listen_port=12912
fwmark=0
replace_peers=true
public_key=02e330d5efee687eb475edbca2893db68d14ef130a9cab4888b2e97342674e0d54
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
endpoint=[abcd:23::33%2]:51820
replace_allowed_ips=true
allowed_ip=192.168.4.4/32
public_key=023ef21c87e83f4a6857045608646cd698254267f0b6ad2ada1a61264f442fc592
update_only=true
endpoint=182.122.22.19:3233
persistent_keepalive_interval=111
replace_allowed_ips=true
allowed_ip=192.168.4.6/32
public_key=028b68831f4d5db40e542aee17d6146559f218fe59723a0c93b8dd7f47c9323820
endpoint=5.152.198.39:51820
replace_allowed_ips=true
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
public_key=0359e831800490155a8a3df22a68f9404a01b6c6fa3074f4e98c5cf8bf87a2d08f
remove=true

`

func TestClientConfigureDeviceError(t *testing.T) {
	tests := []struct {
		name     string
		device   string
		cfg      wgtypes.Config
		res      []byte
		notExist bool
	}{
		{
			name:     "not found",
			device:   "wg1",
			notExist: true,
		},
		{
			name:   "bad errno",
			device: testDevice,
			res:    []byte("errno=1\n\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, tt.res)
			defer done()

			err := c.ConfigureDevice(tt.device, tt.cfg)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			if !tt.notExist && os.IsNotExist(err) {
				t.Fatalf("expected other error, but got not exist: %v", err)
			}
			if tt.notExist && !os.IsNotExist(err) {
				t.Fatalf("expected not exist error, but got: %v", err)
			}
		})
	}
}

func TestClientConfigureDeviceOK(t *testing.T) {
	tests := []struct {
		name string
		cfg  wgtypes.Config
		req  string
	}{
		{
			name: "ok, none",
			req:  "set=1\n\n",
		},
		{
			name: "ok, clear key",
			cfg: wgtypes.Config{
				PrivateKey: &wgtypes.Key{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			},
			req: "set=1\nprivate_key=0000000000000000000000000000000000000000000000000000000000000000\n\n",
		},
		{
			name: "ok, all",
			cfg: wgtypes.Config{
				PrivateKey:   keyPtr(wgtest.MustHexKey("e84b5a6d2717c1003a13b431570353dbaca9146cf150c5f8575680feba52027a")),
				ListenPort:   intPtr(12912),
				FirewallMark: intPtr(0),
				ReplacePeers: true,
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         wgtest.MustHexKey("02e330d5efee687eb475edbca2893db68d14ef130a9cab4888b2e97342674e0d54"),
						PresharedKey:      keyPtr(wgtest.MustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
						Endpoint:          wgtest.MustUDPAddr("[abcd:23::33%2]:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.4/32"),
						},
					},
					{
						PublicKey:                   wgtest.MustHexKey("023ef21c87e83f4a6857045608646cd698254267f0b6ad2ada1a61264f442fc592"),
						UpdateOnly:                  true,
						Endpoint:                    wgtest.MustUDPAddr("182.122.22.19:3233"),
						PersistentKeepaliveInterval: durPtr(111 * time.Second),
						ReplaceAllowedIPs:           true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.6/32"),
						},
					},
					{
						PublicKey:         wgtest.MustHexKey("028b68831f4d5db40e542aee17d6146559f218fe59723a0c93b8dd7f47c9323820"),
						Endpoint:          wgtest.MustUDPAddr("5.152.198.39:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.10/32"),
							wgtest.MustCIDR("192.168.4.11/32"),
						},
					},
					{
						PublicKey: wgtest.MustHexKey("0359e831800490155a8a3df22a68f9404a01b6c6fa3074f4e98c5cf8bf87a2d08f"),
						Remove:    true,
					},
				},
			},
			req: okSet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, nil)

			if err := c.ConfigureDevice(testDevice, tt.cfg); err != nil {
				t.Fatalf("failed to configure device: %v", err)
			}

			req := done()

			if want, got := tt.req, string(req); want != got {
				t.Fatalf("unexpected configure request:\nwant:\n%s\ngot:\n%s", want, got)
			}
		})
	}
}
