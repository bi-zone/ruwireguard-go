/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package set

import (
	"bytes"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/bi-zone/ruwireguard-go/wgctrl/wgtypes"
)

func TestParseInt(t *testing.T) {
	testVectors := []struct {
		input  string
		result int
		err    bool
	}{
		{"1234", 1234, false},
		{" 1234 ", 1234, false},
		{"", 0, true},
		{"123456789123456789123456789", 0, true},
	}

	for _, v := range testVectors {
		res, err := parseInt(v.input)
		if (res != v.result) && (!v.err) {
			t.Fail()
		}
		if (err == nil) && v.err {
			t.Fail()
		}
	}
}

func TestParseFwmark(t *testing.T) {
	testVectors := []struct {
		input  string
		result *int
		err    bool
	}{
		{"0", nil, false},
		{" 0 ", nil, false},
		{"off", nil, false},
		{" off ", nil, false},
		{"", nil, true},
		{"10", new(int), false},
		{"0x10", new(int), false},
		{"123456789123456789123456789", nil, true},
	}

	*testVectors[5].result = 10
	*testVectors[6].result = 16

	for _, v := range testVectors {
		res, err := parseFwmark(v.input)
		if (res != nil) && (*res != *v.result) && (!v.err) {
			t.Fail()
		}
		if (err == nil) && v.err {
			t.Fail()
		}
	}
}

func TestParsePrivateKey(t *testing.T) {
	testVectors := []struct {
		input    string
		result   wgtypes.Key
		errorMsg string
	}{
		{"", nil, "invalid private key length"},
		{"dGVzdA==", nil, "invalid private key length"},
		{"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", wgtypes.Key{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, ""},
		{"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g", nil, "invalid private key length"},
	}

	for _, v := range testVectors {
		res, err := parsePrivateKey(v.input)
		if err != nil && err.Error() != v.errorMsg {
			t.Fail()
		}
		if err == nil && res != nil && !bytes.Equal(*res, v.result) {
			t.Fail()
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	testVectors := []struct {
		input    string
		result   wgtypes.Key
		errorMsg string
	}{
		{"", nil, "invalid public key length"},
		{"dGVzdA==", nil, "invalid public key length"},
		{"AgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f", wgtypes.Key{0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}, ""},
	}

	for _, v := range testVectors {
		res, err := parsePublicKey(v.input)
		if err != nil && err.Error() != v.errorMsg {
			t.Fail()
		}
		if err == nil && res != nil && !bytes.Equal(res, v.result) {
			t.Fail()
		}
	}
}

func TestSplitHostZone(t *testing.T) {
	testVectors := []struct {
		input string
		host  string
		zone  string
	}{
		{"fe80::1ff:fe23:4567:890a", "fe80::1ff:fe23:4567:890a", ""},
		{"fe80::1ff:fe23:4567:890a%eth0", "fe80::1ff:fe23:4567:890a", "eth0"},
	}

	for _, v := range testVectors {
		host, zone := splitHostZone(v.input)
		if host != v.host && zone != v.zone {
			t.Fail()
		}
	}
}

func TestParseEndpoint(t *testing.T) {
	testVectors := []struct {
		input string
		host  net.IP
		port  int
		zone  string
	}{
		{"192.168.1.1:1337", net.IPv4(192, 168, 1, 1), 1337, ""},
		{"[192.168.1.1]:1337", net.IPv4(192, 168, 1, 1), 1337, ""},
		{"[fe80::1ff:fe23:4567:890a]:1337", net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xfe, 0x23, 0x45, 0x67, 0x89, 0x0a}, 1337, ""},
		{"[fe80::1ff:fe23:4567:890a%eth0]:1337", net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xfe, 0x23, 0x45, 0x67, 0x89, 0x0a}, 1337, "eth0"},
	}

	for _, v := range testVectors {
		ip, err := parseEndpoint(v.input)

		if err != nil {
			t.Fail()
		}

		if ip != nil && (!net.IP.Equal(ip.IP, v.host) || ip.Port != v.port || ip.Zone != v.zone) {
			t.Fail()
		}
	}
}

func TestParseAllowedIPs(t *testing.T) {
	testVectors := []struct {
		input  string
		result []net.IPNet
	}{
		{
			"192.168.1.1/24",
			[]net.IPNet{
				{IP: net.IPv4(192, 168, 1, 0).Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)},
			},
		},
		{
			"192.168.1.1/24,10.10.1.1/32",
			[]net.IPNet{
				{IP: net.IPv4(192, 168, 1, 0).Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)},
				{IP: net.IPv4(10, 10, 1, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
			},
		},
		{
			"fe80::1ff:fe23:4567:890a/64",
			[]net.IPNet{
				{IP: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, Mask: net.CIDRMask(64, 128)},
			},
		},
		{
			"10.10.1.1/32,fe80::1ff:fe23:4567:890a/64",
			[]net.IPNet{
				{IP: net.IPv4(10, 10, 1, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
				{IP: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, Mask: net.CIDRMask(64, 128)},
			},
		},
	}

	for _, v := range testVectors {
		ipNet, err := parseAllowedIPs(v.input)

		if err != nil {
			t.Fail()
		}

		if ipNet != nil && !reflect.DeepEqual(ipNet, v.result) {
			t.Fail()
		}
	}
}

func TestParsePersistentKeepalive(t *testing.T) {
	testVectors := []struct {
		input  string
		result *time.Duration
		errMsg string
	}{
		{"0", nil, ""},
		{" 0 ", nil, ""},
		{"off", nil, ""},
		{" off ", nil, ""},
		{"", nil, "string is empty"},
		{"100", new(time.Duration), ""},
		{"10000000", nil, "persistent keepalive interval is neither 0/off nor 1-65535: 10000000"},
	}

	*testVectors[5].result = time.Duration(100) * time.Second

	for _, v := range testVectors {
		td, err := parsePersistentKeepalive(v.input)

		if err != nil && err.Error() != v.errMsg {
			t.Fail()
		}

		if err != nil && v.errMsg == "" {
			t.Fail()
		}

		if td != nil && v.result != nil && (*td != *v.result) {
			t.Fail()
		}
	}
}

func TestParseCmd(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := path.Join(tempDir, "wg-test-private-key")
	pskFile := path.Join(tempDir, "wg-test-preshared-key")

	wgTestPrivateKey, err := os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	wgTestPreSharedKey, err := os.Create(pskFile)
	if err != nil {
		t.Fatal(err)
	}

	_, err = wgTestPrivateKey.WriteString("27Ra+J32PrdNntVpH0gI4aRhvPRFRLHQPmT3vhICfVk=")
	if err != nil {
		t.Fatal(err)
	}
	_, err = wgTestPreSharedKey.WriteString("3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=")
	if err != nil {
		t.Fatal(err)
	}

	cmdArgs := []string{
		"listen-port", "1337",
		"fwmark", "0x10",
		"private-key", keyFile,
		"peer", "AtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u",
		"remove",
		"peer", "AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1",
		"endpoint", "192.168.0.1:1337",
		"allowed-ips", "10.10.10.1/32",
		"persistent-keepalive", "3",
		"preshared-key", pskFile,
	}

	expectedConfig := &wgtypes.Config{
		PrivateKey:   &wgtypes.Key{0xdb, 0xb4, 0x5a, 0xf8, 0x9d, 0xf6, 0x3e, 0xb7, 0x4d, 0x9e, 0xd5, 0x69, 0x1f, 0x48, 0x08, 0xe1, 0xa4, 0x61, 0xbc, 0xf4, 0x45, 0x44, 0xb1, 0xd0, 0x3e, 0x64, 0xf7, 0xbe, 0x12, 0x02, 0x7d, 0x59},
		ListenPort:   new(int), // need to complete
		FirewallMark: new(int), // need to complete
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: wgtypes.Key{0x02, 0xd0, 0x19, 0x45, 0x37, 0xec, 0x19, 0xd7, 0x96, 0xd4, 0x45, 0xf1, 0xd3, 0x27, 0x8e, 0xf4, 0xa6, 0x3e, 0x70, 0x0f, 0x78, 0x90, 0x93, 0x0f, 0x2f, 0xbd, 0x50, 0xd6, 0xe1, 0xca, 0xc7, 0x1e, 0xae},
				Remove:    true,
			},
			{
				PublicKey:    wgtypes.Key{0x03, 0x0a, 0x07, 0xb2, 0x59, 0x17, 0xa7, 0x14, 0xb3, 0x19, 0x4e, 0x12, 0x5a, 0x5c, 0x18, 0x56, 0x6b, 0xd5, 0x84, 0x35, 0xd1, 0x05, 0xf6, 0xd2, 0xfa, 0xeb, 0x91, 0x90, 0xa3, 0xa6, 0x28, 0x35, 0x35},
				PresharedKey: &wgtypes.Key{0xde, 0x30, 0x79, 0xa3, 0x9f, 0xaa, 0x47, 0x73, 0x1c, 0xe6, 0x20, 0xcc, 0x1a, 0x16, 0x92, 0xac, 0xed, 0x46, 0x1a, 0xfc, 0x96, 0x85, 0x20, 0x0a, 0xd3, 0xfe, 0x9f, 0x4f, 0x54, 0x11, 0xf5, 0x72},
				Endpoint: &net.UDPAddr{
					IP:   net.IPv4(192, 168, 0, 1),
					Port: 1337,
				},
				PersistentKeepaliveInterval: new(time.Duration), // need to complete
				ReplaceAllowedIPs:           true,
				AllowedIPs:                  []net.IPNet{{IP: net.IPv4(10, 10, 10, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)}},
			},
		},
	}

	*expectedConfig.ListenPort = 1337
	*expectedConfig.FirewallMark = 16
	*expectedConfig.Peers[1].PersistentKeepaliveInterval = time.Duration(3) * time.Second

	result, err := parseCmd(cmdArgs)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(expectedConfig, result); diff != "" {
		t.Errorf("parseCmd() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}

func TestParseConfigFile(t *testing.T) {
	config := `
[Interface]
PrivateKey = 27Ra+J32PrdNntVpH0gI4aRhvPRFRLHQPmT3vhICfVk=
ListenPort = 1337
FwMark = 0x10

[Peer]
PublicKey = AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1
Endpoint = 192.168.0.1:1337
AllowedIPs = 10.10.10.1/32, 192.168.1.1/24
PersistentKeepalive = 3
PresharedKey = 3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=

[Peer]
PublicKey = AtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u
Endpoint = [fe80::1ff:fe23:4567:890a%eth0]:1337
AllowedIPs = 10.10.10.2/32
`

	expectedConfig := &wgtypes.Config{
		PrivateKey:   &wgtypes.Key{0xdb, 0xb4, 0x5a, 0xf8, 0x9d, 0xf6, 0x3e, 0xb7, 0x4d, 0x9e, 0xd5, 0x69, 0x1f, 0x48, 0x08, 0xe1, 0xa4, 0x61, 0xbc, 0xf4, 0x45, 0x44, 0xb1, 0xd0, 0x3e, 0x64, 0xf7, 0xbe, 0x12, 0x02, 0x7d, 0x59},
		ListenPort:   new(int), // need to complete
		FirewallMark: new(int), // need to complete
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey:    wgtypes.Key{0x03, 0x0a, 0x07, 0xb2, 0x59, 0x17, 0xa7, 0x14, 0xb3, 0x19, 0x4e, 0x12, 0x5a, 0x5c, 0x18, 0x56, 0x6b, 0xd5, 0x84, 0x35, 0xd1, 0x05, 0xf6, 0xd2, 0xfa, 0xeb, 0x91, 0x90, 0xa3, 0xa6, 0x28, 0x35, 0x35},
				PresharedKey: &wgtypes.Key{0xde, 0x30, 0x79, 0xa3, 0x9f, 0xaa, 0x47, 0x73, 0x1c, 0xe6, 0x20, 0xcc, 0x1a, 0x16, 0x92, 0xac, 0xed, 0x46, 0x1a, 0xfc, 0x96, 0x85, 0x20, 0x0a, 0xd3, 0xfe, 0x9f, 0x4f, 0x54, 0x11, 0xf5, 0x72},
				Endpoint: &net.UDPAddr{
					IP:   net.IPv4(192, 168, 0, 1),
					Port: 1337,
				},
				PersistentKeepaliveInterval: new(time.Duration), // need to complete
				AllowedIPs: []net.IPNet{
					{IP: net.IPv4(10, 10, 10, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
					{IP: net.IPv4(192, 168, 1, 0).Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)},
				},
			},
			{
				PublicKey: wgtypes.Key{0x02, 0xd0, 0x19, 0x45, 0x37, 0xec, 0x19, 0xd7, 0x96, 0xd4, 0x45, 0xf1, 0xd3, 0x27, 0x8e, 0xf4, 0xa6, 0x3e, 0x70, 0x0f, 0x78, 0x90, 0x93, 0x0f, 0x2f, 0xbd, 0x50, 0xd6, 0xe1, 0xca, 0xc7, 0x1e, 0xae},
				Endpoint: &net.UDPAddr{
					IP:   net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xfe, 0x23, 0x45, 0x67, 0x89, 0x0a},
					Port: 1337,
					Zone: "eth0",
				},
				AllowedIPs: []net.IPNet{
					{IP: net.IPv4(10, 10, 10, 2).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
				},
			},
		},
	}

	*expectedConfig.ListenPort = 1337
	*expectedConfig.FirewallMark = 16
	*expectedConfig.Peers[0].PersistentKeepaliveInterval = time.Duration(3) * time.Second

	configReader := strings.NewReader(config)

	result, err := parseConfigFile(configReader)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(expectedConfig, result); diff != "" {
		t.Errorf("parseConfigFile() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}
