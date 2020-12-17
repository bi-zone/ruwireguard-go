/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package show

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/bi-zone/ruwireguard-go/wgctrl/wgtypes"
)

func TestPrettyTime(t *testing.T) {
	testVectors := []struct {
		time   int64
		result string
	}{
		{0, ""},
		{1, "1 second"},
		{10, "10 seconds"},
		{60, "1 minute"},
		{150, "2 minutes, 30 seconds"},
		{3600, "1 hour"},
		{7220, "2 hours, 20 seconds"},
		{86400, "1 day"},
		{249201, "2 days, 21 hours, 13 minutes, 21 seconds"},
		{31536000, "1 year"},
		{347436473, "11 years, 6 days, 6 hours, 7 minutes, 53 seconds"},
	}

	for _, v := range testVectors {
		if prettyTime(v.time) != v.result {
			t.Fail()
		}
	}
}

func TestPrettyBytes(t *testing.T) {
	testVectors := []struct {
		size   int64
		result string
	}{
		{0, "0 B"},
		{10, "10 B"},
		{1024, "1.00 KiB"},
		{123456, "120.56 KiB"},
		{1048576, "1.00 MiB"},
		{123456789, "117.74 MiB"},
		{1073741824, "1.00 GiB"},
		{12345678912, "11.50 GiB"},
		{1099511627776, "1.00 TiB"},
		{12345678912345, "11.23 TiB"},
	}

	for _, v := range testVectors {
		if prettyBytes(v.size) != v.result {
			t.Fail()
		}
	}
}

var testDevice = &wgtypes.Device{
	Name:         "wg0",
	Type:         wgtypes.Userspace,
	PrivateKey:   wgtypes.Key{0xdb, 0xb4, 0x5a, 0xf8, 0x9d, 0xf6, 0x3e, 0xb7, 0x4d, 0x9e, 0xd5, 0x69, 0x1f, 0x48, 0x08, 0xe1, 0xa4, 0x61, 0xbc, 0xf4, 0x45, 0x44, 0xb1, 0xd0, 0x3e, 0x64, 0xf7, 0xbe, 0x12, 0x02, 0x7d, 0x59},
	PublicKey:    wgtypes.Key{0x03, 0xe1, 0x60, 0x12, 0xec, 0xe1, 0xcd, 0xaf, 0xbd, 0x07, 0xdb, 0xd4, 0xf5, 0x07, 0xa5, 0xf9, 0x79, 0xf5, 0x80, 0xb2, 0x62, 0x6a, 0x1e, 0x5b, 0x58, 0xb1, 0x4c, 0x97, 0x6d, 0x9b, 0xac, 0xf1, 0x36},
	ListenPort:   1337,
	FirewallMark: 16,
	Peers: []wgtypes.Peer{
		{
			PublicKey:    wgtypes.Key{0x03, 0x0a, 0x07, 0xb2, 0x59, 0x17, 0xa7, 0x14, 0xb3, 0x19, 0x4e, 0x12, 0x5a, 0x5c, 0x18, 0x56, 0x6b, 0xd5, 0x84, 0x35, 0xd1, 0x05, 0xf6, 0xd2, 0xfa, 0xeb, 0x91, 0x90, 0xa3, 0xa6, 0x28, 0x35, 0x35},
			PresharedKey: wgtypes.Key{0xde, 0x30, 0x79, 0xa3, 0x9f, 0xaa, 0x47, 0x73, 0x1c, 0xe6, 0x20, 0xcc, 0x1a, 0x16, 0x92, 0xac, 0xed, 0x46, 0x1a, 0xfc, 0x96, 0x85, 0x20, 0x0a, 0xd3, 0xfe, 0x9f, 0x4f, 0x54, 0x11, 0xf5, 0x72},
			Endpoint: &net.UDPAddr{
				IP:   net.IPv4(192, 168, 0, 1),
				Port: 1337,
			},
			PersistentKeepaliveInterval: 3,
			LastHandshakeTime:           time.Unix(time.Now().Unix()-10, 0),
			ReceiveBytes:                5000000,
			TransmitBytes:               10000000,
			AllowedIPs: []net.IPNet{
				{IP: net.IPv4(10, 10, 10, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
				{IP: net.IPv4(192, 168, 1, 0).Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)},
			},
		},
		{
			PublicKey:    wgtypes.Key{0x02, 0xd0, 0x19, 0x45, 0x37, 0xec, 0x19, 0xd7, 0x96, 0xd4, 0x45, 0xf1, 0xd3, 0x27, 0x8e, 0xf4, 0xa6, 0x3e, 0x70, 0x0f, 0x78, 0x90, 0x93, 0x0f, 0x2f, 0xbd, 0x50, 0xd6, 0xe1, 0xca, 0xc7, 0x1e, 0xae},
			PresharedKey: wgtypes.Key{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
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

func TestPrettyPrint(t *testing.T) {
	expectedOutput := `interface: wg0
  public key: A+FgEuzhza+9B9vU9Qel+Xn1gLJiah5bWLFMl22brPE2
  private key: 27Ra+J32PrdNntVpH0gI4aRhvPRFRLHQPmT3vhICfVk=
  listening port: 1337
  fwmark: 0x10

peer: AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1
  preshared key: 3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=
  endpoint: 192.168.0.1:1337
  allowed-ips: 10.10.10.1/32, 192.168.1.0/24
  latest handshake: 10 seconds
  transfer: 4.77 MiB received, 9.54 MiB sent

peer: AtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u
  endpoint: [fe80::1ff:fe23:4567:890a%eth0]:1337
  allowed-ips: 10.10.10.2/32
`

	result := bytes.NewBufferString("")
	prettyPrint(result, testDevice)

	if diff := cmp.Diff(expectedOutput, result.String()); diff != "" {
		t.Errorf("prettyPrint() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}

func TestDumpPrint(t *testing.T) {
	expectedOutput1 := `27Ra+J32PrdNntVpH0gI4aRhvPRFRLHQPmT3vhICfVk=	A+FgEuzhza+9B9vU9Qel+Xn1gLJiah5bWLFMl22brPE2	1337	0x10
AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1	3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=	192.168.0.1:1337	10.10.10.1/32,192.168.1.0/24	10	5000000	10000000	0
AtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u	(none)	[fe80::1ff:fe23:4567:890a%eth0]:1337	10.10.10.2/32	0	0	0	off
`
	expectedOutput2 := `wg0	27Ra+J32PrdNntVpH0gI4aRhvPRFRLHQPmT3vhICfVk=	A+FgEuzhza+9B9vU9Qel+Xn1gLJiah5bWLFMl22brPE2	1337	0x10
wg0	AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1	3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=	192.168.0.1:1337	10.10.10.1/32,192.168.1.0/24	10	5000000	10000000	0
wg0	AtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u	(none)	[fe80::1ff:fe23:4567:890a%eth0]:1337	10.10.10.2/32	0	0	0	off
`

	testDevice.Peers[0].LastHandshakeTime = time.Unix(time.Now().Unix()-10, 0)

	result := bytes.NewBufferString("")
	dumpPrint(result, testDevice, false)

	if diff := cmp.Diff(expectedOutput1, result.String()); diff != "" {
		t.Errorf("dumpPrint() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}

	result = bytes.NewBufferString("")
	dumpPrint(result, testDevice, true)

	if diff := cmp.Diff(expectedOutput2, result.String()); diff != "" {
		t.Errorf("dumpPrint() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}

func TestUglyPrint(t *testing.T) {
	testVectors := []struct {
		param          string
		showDeviceName bool
		result         string
	}{
		{"public-key", false, "A+FgEuzhza+9B9vU9Qel+Xn1gLJiah5bWLFMl22brPE2\n"},
		{"public-key", true, "wg0\tA+FgEuzhza+9B9vU9Qel+Xn1gLJiah5bWLFMl22brPE2\n"},

		{"private-key", false, "27Ra+J32PrdNntVpH0gI4aRhvPRFRLHQPmT3vhICfVk=\n"},
		{"private-key", true, "wg0\t27Ra+J32PrdNntVpH0gI4aRhvPRFRLHQPmT3vhICfVk=\n"},

		{"listen-port", false, "1337\n"},
		{"listen-port", true, "wg0\t1337\n"},

		{"fwmark", false, "0x10\n"},
		{"fwmark", true, "wg0\t0x10\n"},

		{"endpoints", false, "AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t192.168.0.1:1337\nAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t[fe80::1ff:fe23:4567:890a%eth0]:1337\n"},
		{"endpoints", true, "wg0\tAwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t192.168.0.1:1337\nwg0\tAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t[fe80::1ff:fe23:4567:890a%eth0]:1337\n"},

		{"allowed-ips", false, "AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t10.10.10.1/32 192.168.1.0/24\nAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t10.10.10.2/32\n"},
		{"allowed-ips", true, "wg0\tAwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t10.10.10.1/32 192.168.1.0/24\nwg0\tAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t10.10.10.2/32\n"},

		{"latest-handshakes", false, "AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t10\nAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t0\n"},
		{"latest-handshakes", true, "wg0\tAwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t10\nwg0\tAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t0\n"},

		{"transfer", false, "AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t5000000\t10000000\nAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t0\t0\n"},
		{"transfer", true, "wg0\tAwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t5000000\t10000000\nwg0\tAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t0\t0\n"},

		{"persistent-keepalive", false, "AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t0\nAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\toff\n"},
		{"persistent-keepalive", true, "wg0\tAwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t0\nwg0\tAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\toff\n"},

		{"preshared-keys", false, "AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=\nAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t(none)\n"},
		{"preshared-keys", true, "wg0\tAwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\t3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=\nwg0\tAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\t(none)\n"},

		{"peers", false, "AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\nAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\n"},
		{"peers", true, "wg0\tAwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1\nwg0\tAtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u\n"},
	}

	testDevice.Peers[0].LastHandshakeTime = time.Unix(time.Now().Unix()-10, 0)

	for _, v := range testVectors {
		result := bytes.NewBufferString("")
		_ = uglyPrint(result, testDevice, v.param, v.showDeviceName)

		if diff := cmp.Diff(v.result, result.String()); diff != "" {
			t.Errorf("uglyPrint() mismatch (-want +got):\n%s", diff)
			t.Fail()
		}
	}
}

func TestPrintConf(t *testing.T) {
	expextedOutput := `[Interface]
ListenPort = 1337
FwMark = 0x10
PrivateKey = 27Ra+J32PrdNntVpH0gI4aRhvPRFRLHQPmT3vhICfVk=

[Peer]
PublicKey = AwoHslkXpxSzGU4SWlwYVmvVhDXRBfbS+uuRkKOmKDU1
PresharedKey = 3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=
AllowedIPs = 10.10.10.1/32, 192.168.1.0/24
Endpoint = 192.168.0.1:1337
PersistentKeepalive = 0

[Peer]
PublicKey = AtAZRTfsGdeW1EXx0yeO9KY+cA94kJMPL71Q1uHKxx6u
AllowedIPs = 10.10.10.2/32
Endpoint = [fe80::1ff:fe23:4567:890a%eth0]:1337
`

	result := bytes.NewBufferString("")
	printConf(result, testDevice)

	if diff := cmp.Diff(expextedOutput, result.String()); diff != "" {
		t.Errorf("printConf() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}
