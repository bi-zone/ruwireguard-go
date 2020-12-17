/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package kdf

import (
	"crypto/hmac"
	"encoding/binary"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012256"
)

// KDFTree implements KDF_TREE_GOSTR3411_2012_256 algorithm for r = 1.
// https://tools.ietf.org/html/rfc7836#section-4.5
//
// Where:
//
// secret    Derivation key.
//
// label, seed
//         The parameters that MUST be assigned by a protocol; their lengths SHOULD be fixed by a protocol.
//
// length  The required size octets of the generated keying material: an integer, not exceeding 32*(2^8-1).
func KDFTree(secret []byte, label, seed []byte, length int) []byte {
	if length == 0 ||
		length%32 != 0 ||
		length > 32*(1<<8-1) {
		panic("KDFtree wrong length parameter")
	}

	out := make([]byte, 0, length)

	L := uint16(8 * length)
	Lb := make([]byte, 2)
	binary.BigEndian.PutUint16(Lb, L)

	n := uint8(length / 32) // The number of iterations, n <= 255

	for i := uint8(1); i <= n; i++ {
		mac := hmac.New(gost34112012256.New, secret)
		mac.Write([]byte{i})
		mac.Write(label)
		mac.Write([]byte{0x00})
		mac.Write(seed)
		mac.Write(Lb)
		out = append(out, mac.Sum(nil)...)
	}

	return out
}
