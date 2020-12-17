/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */
package device

import (
	"encoding/hex"
	"testing"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012256"
	"github.com/bi-zone/ruwireguard-go/crypto/kdf"
)

func assertEquals(t *testing.T, a string, b string) {
	if a != b {
		t.Fatal("expected", a, "=", b)
	}
}

func TestBasicKDF(t *testing.T) {
	var t0 []byte
	var t1, t2, t3 [gost34112012256.Size]byte
	var s0, s1, s2, s3 string

	key := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	seed := []byte{0xaf, 0x21, 0x43, 0x41, 0x45, 0x65, 0x63, 0x78}

	KDF1(&t1, key, seed)
	t0 = kdf.KDFTree(key, []byte(KDF1Label), seed, 32)
	s0 = hex.EncodeToString(t0[:])
	s1 = hex.EncodeToString(t1[:])
	assertEquals(t, s0, s1)

	KDF2(&t1, &t2, key, seed)
	t0 = kdf.KDFTree(key, []byte(KDF2Label), seed, 64)
	s0 = hex.EncodeToString(t0[:])
	s1 = hex.EncodeToString(t1[:])
	s2 = hex.EncodeToString(t2[:])
	assertEquals(t, s0, s1+s2)

	KDF3(&t1, &t2, &t3, key, seed)
	t0 = kdf.KDFTree(key, []byte(KDF3Label), seed, 96)
	s0 = hex.EncodeToString(t0[:])
	s1 = hex.EncodeToString(t1[:])
	s2 = hex.EncodeToString(t2[:])
	s3 = hex.EncodeToString(t3[:])
	assertEquals(t, s0, s1+s2+s3)
}
