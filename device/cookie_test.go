/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2020 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package device

import (
	"crypto/rand"
	"testing"
)

func TestCookieMAC1(t *testing.T) {

	// setup generator / checker

	var (
		generator CookieGenerator
		checker   CookieChecker
	)

	sk, err := newNoisePrivateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := sk.PublicKey()

	generator.Init(pk)
	checker.Init(pk)

	// check mac1

	src := []byte{192, 168, 13, 37, 10, 10, 10}

	checkMAC1 := func(msg []byte) {
		generator.AddMacs(msg)
		if !checker.CheckMAC1(msg) {
			t.Fatal("MAC1 generation/verification failed")
		}
		if checker.CheckMAC2(msg, src) {
			t.Fatal("MAC2 generation/verification failed")
		}
	}

	var firstMsg [MessageInitiationSize]byte
	_, err = rand.Read(firstMsg[:])
	if err != nil {
		t.Fatal("fail to read from rand: ", err)
	}
	checkMAC1(firstMsg[:])

	var secondMsg [MessageResponseSize]byte
	_, err = rand.Read(secondMsg[:])
	if err != nil {
		t.Fatal("fail to read from rand: ", err)
	}
	checkMAC1(secondMsg[:])

	// exchange cookie reply

	func() {
		var firstMsg [MessageInitiationSize]byte
		_, err = rand.Read(firstMsg[:])
		if err != nil {
			t.Fatal("fail to read from rand: ", err)
		}
		generator.AddMacs(firstMsg[:])
		reply, err := checker.CreateReply(firstMsg[:], 1377, src)
		if err != nil {
			t.Fatal("Failed to create cookie reply:", err)
		}
		if !generator.ConsumeReply(reply) {
			t.Fatal("Failed to consume cookie reply")
		}
	}()

	// check mac2

	checkMAC2 := func(msg []byte) {
		generator.AddMacs(msg)

		if !checker.CheckMAC1(msg) {
			t.Fatal("MAC1 generation/verification failed")
		}
		if !checker.CheckMAC2(msg, src) {
			t.Fatal("MAC2 generation/verification failed")
		}

		msg[5] ^= 0x20

		if checker.CheckMAC1(msg) {
			t.Fatal("MAC1 generation/verification failed")
		}
		if checker.CheckMAC2(msg, src) {
			t.Fatal("MAC2 generation/verification failed")
		}

		msg[5] ^= 0x20

		srcBad1 := []byte{192, 168, 13, 37, 40, 01}
		if checker.CheckMAC2(msg, srcBad1) {
			t.Fatal("MAC2 generation/verification failed")
		}

		srcBad2 := []byte{192, 168, 13, 38, 40, 01}
		if checker.CheckMAC2(msg, srcBad2) {
			t.Fatal("MAC2 generation/verification failed")
		}
	}

	var msg [MessageInitiationSize]byte
	_, err = rand.Read(msg[:])
	if err != nil {
		t.Fatal("fail to read from rand: ", err)
	}

	checkMAC2(msg[:])
}
