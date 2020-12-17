/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */
package device

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012256"
	"github.com/bi-zone/ruwireguard-go/crypto/kdf"
)

const (
	KDF1Label = "KDF_GOST_R_3411_2012_256_LABEL_1"
	KDF2Label = "KDF_GOST_R_3411_2012_256_LABEL_2"
	KDF3Label = "KDF_GOST_R_3411_2012_256_LABEL_3"
)
const (
	AEADSymmetricKeySize = 32
	AEADNonceSize        = 16
	AEADTagSize          = 16
)

type (
	AEADSymmetricKey [AEADSymmetricKeySize]byte
	AEADNonce        [AEADNonceSize]byte
)

// MAC computes the keyed MAC value based on HMAC_GOSTR3411_2012_256.
func MAC(sum *[gost34112012256.Size]byte, key, in0 []byte) {
	mac := hmac.New(gost34112012256.New, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func Hash(dst *[gost34112012256.Size]byte, data []byte) {
	hash := gost34112012256.New()
	hash.Write(data)
	hash.Sum(dst[:0])
	hash.Reset()
}

func KDF1(t1 *[gost34112012256.Size]byte, key, input []byte) {
	prk := kdf.KDFTree(key, []byte(KDF1Label), input, gost34112012256.Size)
	copy(t1[:], prk)
	setZero(prk[:])
}

func KDF2(t1, t2 *[gost34112012256.Size]byte, key, input []byte) {
	prk := kdf.KDFTree(key, []byte(KDF2Label), input, 2*gost34112012256.Size)
	copy(t1[:], prk[:gost34112012256.Size])
	copy(t2[:], prk[gost34112012256.Size:])
	setZero(prk[:])
}

func KDF3(t1, t2, t3 *[gost34112012256.Size]byte, key, input []byte) {
	prk := kdf.KDFTree(key, []byte(KDF3Label), input, 3*gost34112012256.Size)
	copy(t1[:], prk[:gost34112012256.Size])
	copy(t2[:], prk[gost34112012256.Size:2*gost34112012256.Size])
	copy(t3[:], prk[2*gost34112012256.Size:])
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func (key *AEADSymmetricKey) FromHex(src string) error {
	return loadExactHex(key[:], src)
}

func (key AEADSymmetricKey) ToHex() string {
	return hex.EncodeToString(key[:])
}

// getMGMNonce generates a random nonce with the higher bit set to 0 according to the MGM spec.
func getMGMNonce(nonce *[AEADNonceSize]byte) error {
	n, err := rand.Read(nonce[:])
	if err != nil {
		return err
	}
	if n > 0 {
		nonce[0] = nonce[0] & 0x7F
		return nil
	}
	return fmt.Errorf("unable to generate an MGM nonce")
}
