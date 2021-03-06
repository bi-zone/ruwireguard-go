/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package device

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestCurveWrappers(t *testing.T) {
	sk1, err := newNoisePrivateKey(rand.Reader)
	assertNil(t, err)

	sk2, err := newNoisePrivateKey(rand.Reader)
	assertNil(t, err)

	ss1 := sk1.SharedSecret(sk2.PublicKey())
	ss2 := sk2.SharedSecret(sk1.PublicKey())

	if !bytes.Equal(ss1, ss2) {
		t.Fatal("Failed to compute shared secret by VKO")
	}
}

func TestNoiseHandshake(t *testing.T) {
	dev1 := randDevice(t)
	dev2 := randDevice(t)

	defer dev1.Close()
	defer dev2.Close()

	peer1, _ := dev2.NewPeer(dev1.staticIdentity.privateKey.PublicKey())
	peer2, _ := dev1.NewPeer(dev2.staticIdentity.privateKey.PublicKey())

	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := dev1.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	assertNil(t, err)
	peer := dev2.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := dev2.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = dev1.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	key1 := peer1.keypairs.loadNext()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	func() {
		testMsg := []byte("wireguard test message 1")
		var err error
		var out []byte
		var nonce [AEADNonceSize]byte
		out = key1.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key2.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()

	func() {
		testMsg := []byte("wireguard test message 2")
		var err error
		var out []byte
		var nonce [AEADNonceSize]byte
		out = key2.send.Seal(out, nonce[:], testMsg, nil)
		out, err = key1.receive.Open(out[:0], nonce[:], out, nil)
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()
}

func TestNoiseHandshakeVectors(t *testing.T) {
	initiatorStaticSecretKey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	responderStaticSecretKey := "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	initiatorEphemeralSecretKey := "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"
	responderEphemeralSecretKey := "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"

	t.Logf("initiator static secret: % x", initiatorStaticSecretKey)
	t.Logf("initiator ephemeral secret: % x", initiatorEphemeralSecretKey)
	t.Logf("responder static secret: % x", responderStaticSecretKey)
	t.Logf("responder ephemeral secret: % x", responderEphemeralSecretKey)

	initiator := staticDevice(t, initiatorStaticSecretKey, initiatorEphemeralSecretKey)
	responder := staticDevice(t, responderStaticSecretKey, responderEphemeralSecretKey)

	defer initiator.Close()
	defer responder.Close()

	peer1, _ := responder.NewPeer(initiator.staticIdentity.privateKey.PublicKey())
	peer2, _ := initiator.NewPeer(responder.staticIdentity.privateKey.PublicKey())

	var peer1CookieGenerator, peer2CookieGenerator CookieGenerator
	peer1CookieGenerator.Init(responder.staticIdentity.privateKey.PublicKey())
	peer2CookieGenerator.Init(initiator.staticIdentity.privateKey.PublicKey())

	assertEqual(
		t,
		peer1.handshake.precomputedStaticStatic[:],
		peer2.handshake.precomputedStaticStatic[:],
	)

	/* simulate handshake */

	// initiation message

	t.Log("exchange initiation message")

	msg1, err := initiator.CreateMessageInitiation(peer2)
	assertNil(t, err)

	packet := make([]byte, 0, 256)
	writer := bytes.NewBuffer(packet)
	err = binary.Write(writer, binary.LittleEndian, msg1)
	assertNil(t, err)

	peer := responder.ConsumeMessageInitiation(msg1)
	if peer == nil {
		t.Fatal("handshake failed at initiation message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)
	t.Log("initiator's  state after sending initiation message:")
	t.Logf("chainkey state: % x", peer1.handshake.chainKey[:])

	testChainKey1, err := hex.DecodeString("69b5cc4a8d6956325b0ab2939a3fad634000cdb9e0b647101a325805772fe13d")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(peer1.handshake.chainKey[:], testChainKey1) {
		t.Fatal("wrong chain key state")
	}

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	// response message

	t.Log("exchange response message")

	msg2, err := responder.CreateMessageResponse(peer1)
	assertNil(t, err)

	peer = initiator.ConsumeMessageResponse(msg2)
	if peer == nil {
		t.Fatal("handshake failed at response message")
	}

	assertEqual(
		t,
		peer1.handshake.chainKey[:],
		peer2.handshake.chainKey[:],
	)

	assertEqual(
		t,
		peer1.handshake.hash[:],
		peer2.handshake.hash[:],
	)

	t.Log("responder's  state after sending response message:")
	t.Logf("chainkey state: % x", peer2.handshake.chainKey[:])

	testChainKey2, err := hex.DecodeString("22bf0e8be82132d8ee3f2d0ec52d27f542b5689b778eb8f2b19665b69494e27c")
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(peer2.handshake.chainKey[:], testChainKey2) {
		t.Fatal("wrong chain key state")
	}

	// key pairs

	t.Log("deriving keys")

	err = peer1.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 1", err)
	}

	err = peer2.BeginSymmetricSession()
	if err != nil {
		t.Fatal("failed to derive keypair for peer 2", err)
	}

	key1 := peer1.keypairs.loadNext()
	key2 := peer2.keypairs.current

	// encrypting / decryption test

	t.Log("test key pairs")

	initiatorIndex := uint32(1)
	responderIndex := uint32(2)

	func() {
		testMsg := []byte("ru wireguard test message 1-----")
		t.Logf("test  message 1: % x", testMsg)
		var err error
		var out []byte
		var nonce [AEADNonceSize]byte
		t.Logf("test msg1 nonce 1: % x", nonce)

		var additionalData [AdditionalDataSize]byte
		binary.LittleEndian.PutUint32(additionalData[0:4], MessageTransportType)
		binary.LittleEndian.PutUint32(additionalData[4:8], initiatorIndex)
		binary.LittleEndian.PutUint32(additionalData[8:12], responderIndex)
		t.Logf("test msg1 ad: % x", additionalData)

		out = key1.send.Seal(out, nonce[:], testMsg, additionalData[:])
		t.Logf("encrypted message 1 : % x", out)

		testOut, err := hex.DecodeString("9d652aa28d7c6abef1f7f4dbdc8b3745af776cc2ef10199066bcaf179203edd5282656b14ef89945942bdf8a1063f868")
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(out, testOut) {
			t.Fatal("wrong ciphertext for message 1")
		}

		out, err = key2.receive.Open(out[:0], nonce[:], out, additionalData[:])
		assertNil(t, err)
		assertEqual(t, out, testMsg)

	}()

	func() {
		testMsg := []byte("ru wireguard test message 2-----")
		t.Logf("test  message 2: % x", testMsg)
		var err error
		var out []byte
		var nonce [AEADNonceSize]byte
		t.Logf("test msg1 nonce 1: % x", nonce)

		var additionalData [AdditionalDataSize]byte
		binary.LittleEndian.PutUint32(additionalData[0:4], MessageTransportType)
		binary.LittleEndian.PutUint32(additionalData[4:8], responderIndex)
		binary.LittleEndian.PutUint32(additionalData[8:12], initiatorIndex)
		t.Logf("test msg1 ad: % x", additionalData)

		out = key2.send.Seal(out, nonce[:], testMsg, additionalData[:])
		t.Logf("encrypted message 2 : % x", out)

		testOut, err := hex.DecodeString("c11b69a043ff5b77afd1b6b1b0ecaa3a3f6e46cc40814b50d99b49179e00ffa73c14186c574954fa26522f50ee3b2f8b")
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(out, testOut) {
			t.Fatal("wrong ciphertext for message 2")
		}

		out, err = key1.receive.Open(out[:0], nonce[:], out, additionalData[:])
		assertNil(t, err)
		assertEqual(t, out, testMsg)
	}()
}
