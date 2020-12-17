// SPDX-License-Identifier: MIT
// Copyright (c) 2020 BI.ZONE LLC.

package tests

import (
	"bytes"
	"crypto/rand"
	prng "math/rand"
	"testing"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3412128"
	"github.com/bi-zone/ruwireguard-go/crypto/gosthopper"
	"github.com/bi-zone/ruwireguard-go/crypto/mgm"
)

func TestFuzz(t *testing.T) {

	var deadline time.Time
	if testing.Short() {
		deadline = time.Now().Add(100 * time.Millisecond)
	} else {
		deadline = time.Now().Add(5 * time.Second)
	}

	for time.Now().Before(deadline) {

		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}

		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		nonce[0] &= 0x0F

		adLen := prng.Intn(2000) + 1
		ad := make([]byte, adLen)
		if _, err := rand.Read(ad); err != nil {
			t.Fatal(err)
		}

		plaintextLen := prng.Intn(10000) + 1
		plaintext := make([]byte, plaintextLen)

		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}

		cipher1, err := gosthopper.NewCipher(key)
		if err != nil {
			t.Fatalf("new gosthopper instantiation error: %s", err)
		}

		aead1, err := mgm.NewMGM(cipher1)
		if err != nil {
			t.Fatalf("mgm instantiation error: %s", err)
		}

		cipher2 := gost3412128.NewCipher(key)

		aead2, err := mgm.NewMGM(cipher2)
		if err != nil {
			t.Fatalf("mgm instantiation error: %s", err)
		}

		var ciphertext1, ciphertext2 []byte

		ciphertext1 = aead1.Seal(ciphertext1[:0], nonce, plaintext, ad)
		ciphertext2 = aead2.Seal(ciphertext2[:0], nonce, plaintext, ad)

		if !bytes.Equal(ciphertext1, ciphertext2) {
			t.Fatalf("ciphertexts are not the same")
		}

		plaintext1 := make([]byte, plaintextLen)
		plaintext2 := make([]byte, plaintextLen)

		plaintext1, err = aead1.Open(plaintext1[:0], nonce, ciphertext2, ad)
		if err != nil {
			t.Fatalf("refCiphertext opening error")
		}
		if !bytes.Equal(plaintext, plaintext1) {
			t.Fatalf("plaintext1 is not equal to plaintext")
		}

		plaintext2, err = aead2.Open(plaintext2[:0], nonce, ciphertext1, ad)
		if err != nil {
			t.Fatalf("ciphertext1 opening error")
		}

		if !bytes.Equal(plaintext, plaintext2) {
			t.Fatalf("plaintext2 is not equal to plaintext")
		}
	}
}
