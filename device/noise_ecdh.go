/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */
package device

import (
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"
)

const (
	NoisePublicKeySize  = 32 + 1 // size of Noise public key encoded in compressed ANSI X9.62 format.
	NoisePrivateKeySize = 32     // size of Noise private key.
)

var (
	curve = gost3410.CurveIdtc26gost34102012256paramSetA()
)

type (
	NoisePrivateKey [NoisePrivateKeySize]byte
	NoisePublicKey  [NoisePublicKeySize]byte
)

func newNoisePrivateKey(rng io.Reader) (sk NoisePrivateKey, err error) {
	b, _, _, err := gost3410.GenerateKey(curve, rng)
	copy(sk[:], b)
	return
}

// SharedSecret computes a 256-bit shared secret using VKO GOST R 34.10-2012 key agreement function.
func (key *NoisePrivateKey) SharedSecret(peerPublicKeyBytes NoisePublicKey) []byte {
	x, y := gost3410.UnmarshalCompressed(curve, peerPublicKeyBytes[:])
	if x == nil {
		return nil
	}

	ukm := big.NewInt(1)
	sharedSecret, err := curve.KEK2012256(key[:], x, y, ukm)
	if err != nil {
		return nil
	}
	return sharedSecret
}

// PublicKey returns a public key encoded in compressed ANSI X9.62 format.
func (key *NoisePrivateKey) PublicKey() (pk NoisePublicKey) {
	x, y, err := curve.ScalarBaseMult(key[:])
	if err != nil {
		return
	}
	copy(pk[:], gost3410.MarshalCompressed(curve, x, y))
	return
}

func (key NoisePrivateKey) IsZero() bool {
	var zero NoisePrivateKey
	return key.Equals(zero)
}

func (key NoisePrivateKey) Equals(tar NoisePrivateKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func (key *NoisePrivateKey) FromMaybeZeroHex(src string) (err error) {
	err = loadExactHex(key[:], src)
	if key.IsZero() {
		return
	}
	gost3410.Reverse(key[:])
	return
}

func (key NoisePrivateKey) ToHex() string {
	// inverted according to GOST 34.10 standard.
	return hex.EncodeToString(gost3410.Reversed(key[:]))
}

// ---

func (key *NoisePublicKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key NoisePublicKey) ToHex() string {
	return hex.EncodeToString(key[:])
}

func (key NoisePublicKey) Equals(tar NoisePublicKey) bool {
	return subtle.ConstantTimeCompare(key[:], tar[:]) == 1
}

func loadExactHex(dst []byte, src string) error {
	slice, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	if len(slice) != len(dst) {
		return errors.New("hex string does not fit the slice")
	}
	copy(dst, slice)
	return nil
}
