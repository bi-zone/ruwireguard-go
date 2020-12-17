/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package device

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bi-zone/ruwireguard-go/tun/tuntest"
)

func getFreePort(t *testing.T) string {
	l, err := net.ListenPacket("udp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return fmt.Sprintf("%d", l.LocalAddr().(*net.UDPAddr).Port)
}

func TestTwoDevicePing(t *testing.T) {
	for i := 0; i < 1; i++ {
		twoDevicePing(t)
	}
}

func twoDevicePing(t *testing.T) {
	port1 := getFreePort(t)
	port2 := getFreePort(t)

	priv1, err := newNoisePrivateKey(rand.Reader)
	if err != nil {
		t.Fatal("peer 1 private key generation")
	}
	pub1 := priv1.PublicKey()

	priv2, err := newNoisePrivateKey(rand.Reader)
	if err != nil {
		t.Fatal("peer 2 private key generation")
	}
	pub2 := priv2.PublicKey()

	cfg1 := `private_key={{PRIVATE}}
listen_port={{PORT1}}
replace_peers=true
public_key={{PUBLIC}}
protocol_version=1
replace_allowed_ips=true
allowed_ip=1.0.0.2/32
endpoint=127.0.0.1:{{PORT2}}`

	cfg1 = strings.ReplaceAll(cfg1, "{{PORT1}}", port1)
	cfg1 = strings.ReplaceAll(cfg1, "{{PORT2}}", port2)
	cfg1 = strings.ReplaceAll(cfg1, "{{PRIVATE}}", priv1.ToHex())
	cfg1 = strings.ReplaceAll(cfg1, "{{PUBLIC}}", pub2.ToHex())

	tun1 := tuntest.NewChannelTUN()
	dev1 := NewDevice(tun1.TUN(), NewLogger(LogLevelDebug, "dev1: "))
	dev1.Up()
	defer dev1.Close()
	if err := dev1.IpcSetOperation(bufio.NewReader(strings.NewReader(cfg1))); err != nil {
		t.Fatal(err)
	}

	cfg2 := `private_key={{PRIVATE}}
listen_port={{PORT2}}
replace_peers=true
public_key={{PUBLIC}}
protocol_version=1
replace_allowed_ips=true
allowed_ip=1.0.0.1/32
endpoint=127.0.0.1:{{PORT1}}`
	cfg2 = strings.ReplaceAll(cfg2, "{{PORT1}}", port1)
	cfg2 = strings.ReplaceAll(cfg2, "{{PORT2}}", port2)
	cfg2 = strings.ReplaceAll(cfg2, "{{PRIVATE}}", priv2.ToHex())
	cfg2 = strings.ReplaceAll(cfg2, "{{PUBLIC}}", pub1.ToHex())

	tun2 := tuntest.NewChannelTUN()
	dev2 := NewDevice(tun2.TUN(), NewLogger(LogLevelDebug, "dev2: "))
	dev2.Up()
	defer dev2.Close()
	if err := dev2.IpcSetOperation(bufio.NewReader(strings.NewReader(cfg2))); err != nil {
		t.Fatal(err)
	}

	t.Run("ping 1.0.0.1", func(t *testing.T) {
		msg2to1 := tuntest.Ping(net.ParseIP("1.0.0.1"), net.ParseIP("1.0.0.2"))
		tun2.Outbound <- msg2to1
		select {
		case msgRecv := <-tun1.Inbound:
			if !bytes.Equal(msg2to1, msgRecv) {
				t.Error("ping did not transit correctly")
			}
		case <-time.After(300 * time.Millisecond):
			t.Error("ping did not transit")
		}
	})

	t.Run("ping 1.0.0.2", func(t *testing.T) {
		msg1to2 := tuntest.Ping(net.ParseIP("1.0.0.2"), net.ParseIP("1.0.0.1"))
		tun1.Outbound <- msg1to2
		select {
		case msgRecv := <-tun2.Inbound:
			if !bytes.Equal(msg1to2, msgRecv) {
				t.Error("return ping did not transit correctly")
			}
		case <-time.After(300 * time.Millisecond):
			t.Error("return ping did not transit")
		}
	})
}

func assertNil(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func assertEqual(t *testing.T, a, b []byte) {
	if !bytes.Equal(a, b) {
		t.Fatal(a, "!=", b)
	}
}

func randDevice(t *testing.T) *Device {
	sk, err := newNoisePrivateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tun := newDummyTUN("dummy")
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun, logger)
	if err = device.SetPrivateKey(sk); err != nil {
		t.Fatal(err)
	}
	return device
}

func hexReader(s string) io.Reader {
	fmt.Println(s)
	res, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return bytes.NewBuffer(res)
}

func staticDevice(t *testing.T, s, e string) *Device {
	sk, err := newNoisePrivateKey(hexReader(s))
	if err != nil {
		t.Fatal(err)
	}
	tun := newDummyTUN("dummy")
	logger := NewLogger(LogLevelError, "")
	device := NewDevice(tun, logger)
	if err = device.SetPrivateKey(sk); err != nil {
		t.Fatal(err)
	}
	device.rng = hexReader(e)
	return device
}
