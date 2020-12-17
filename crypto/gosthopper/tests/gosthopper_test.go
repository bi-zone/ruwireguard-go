// Various tests and examples for block cipher Kuznechik, GOST R 34.12-2015, implementation.
// Includes part with GCM: AEAD mode for cipher.
// Author: Alexander Venedioukhin, https://dxdt.ru/
// Date: 17/02/2019
// Free software, distribution unlimited.

// Modified Copyright (c) 2020 BI.ZONE LLC.

package tests

import (
	"bytes"
	"crypto/cipher"
	"math/rand"
	"testing"
	"time"

	"github.com/bi-zone/ruwireguard-go/crypto/gosthopper"
)

func TestGOSTHopper(t *testing.T) {
	// Test vectors.
	// Standard test key.
	var testK = [32]uint8{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	// Standard test plain text block and corresponding cipher text.
	var testPt = [16]uint8{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}
	var referenceCt = [16]uint8{0x7F, 0x67, 0x9D, 0x90, 0xBE, 0xBC, 0x24, 0x30, 0x5A, 0x46, 0x8D, 0x42, 0xB9, 0xD4, 0xED, 0xCD}
	// Additional key, one bit changed test_K.
	var testK1 = [32]uint8{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcf, 0xef}
	// Example key (non-standard).
	var exampleK = [32]uint8{0x17, 0x19, 0xca, 0xfe, 0x0c, 0x10, 0x03, 0x15, 0x2d, 0x19, 0x27, 0x13, 0x07, 0xab, 0x71, 0x67,
		0x1f, 0xe9, 0xa7, 0x31, 0x87, 0x15, 0x78, 0x61, 0x65, 0x03, 0x01, 0xef, 0x4a, 0xec, 0x9f, 0xf3}

	// Test vectors for GCM.
	var varK = []byte{0x31, 0x89, 0x9a, 0x7e, 0x1a, 0x03, 0x03, 0x51, 0xd2, 0x97, 0x79, 0x3b, 0x7f, 0xaf, 0xfe, 0x71,
		0xff, 0xe0, 0xca, 0x13, 0x42, 0x5e, 0x99, 0x77, 0x6b, 0xd3, 0xee, 0x11, 0xba, 0xc7, 0x92, 0x8f}
	var gcmNonce = []byte{0x3c, 0x81, 0x9d, 0x9a, 0x9b, 0xed, 0x08, 0x76, 0x15, 0x03, 0x0b, 0x65}
	var gcmExampleAD = []byte{'T', 'O', ':', ' ', 'S', 'e', 'a', 'p', 'o', 'r', 't', ',', ' ', 'a', 'g', 'e', 'n', 't', ' ', 'Z', 'o', 'r', 'k', 'a'}
	var gcmExampleADm = []byte{'T', 'O', ':', ' ', 'S', 'e', 'a', 'p', 'o', 'r', 't', ',', ' ', 'a', 'g', 'e', 'n', 't', ' ', 'D', 'a', 's', 'h', 'a'}
	var gcmExamplePt = []byte{'S', 'e', 'a', 'r', 'c', 'h', ' ', 't', 'h', 'e', ' ', 'b', 'i', 'g', ' ', 'w', 'h', 'i', 't', 'e', ' ', 's', 'h', 'i', 'p', '.'}
	// Test text for counter mode.
	var counterModeExamplePt = "The hunter will softly and suddenly vanish away, and never be met with again."
	// Non-standard example plain text.
	var examplePt = [16]uint8{'S', 'e', 'a', 'r', 'c', 'h', ' ', 't', 'h', 'e', ' ', 's', 'h', 'i', 'p', '.'}
	// 16 blocks used in simple performance test.
	var randPt [16][16]uint8

	// For performance test we use non-standard test vector as a key - example_K.
	rkeys := gosthopper.StretchKey(exampleK)          // Generate round keys for encryption.
	decRkeys := gosthopper.GetDecryptRoundKeys(rkeys) // Generate round keys for decryption.

	gosthopper.InitCipher() // Generate lookup tables.

	t.Logf("\nGOST R 34.12-2015 test\n\n")
	t.Logf("| Standard test key:\n| %X\n| Standard test plain text:\n| %X\n\n", testK, testPt)
	t.Logf("---\n\n(1) Standard key vector\n")

	testCT := gosthopper.Encrypt(testK, testPt)
	t.Logf("(1.1) Plain text:\t\t\t%X\n(1.2) Cipher text:\t\t\t%X - ", testPt, testCT)
	if testCT != referenceCt {
		t.Logf("FAILED! [Not equal to reference cipher text!]\n")
	} else {
		t.Logf("OK\n")
	}

	test2PT := gosthopper.Decrypt(testK, testCT)
	t.Logf("(1.3) Plain text decrypted:\t\t%X - ", test2PT)

	if test2PT != testPt {
		t.Logf("FAILED! [PT != D(E(PT,K),K)]\n")
	} else {
		t.Logf("OK\n")
	}

	t.Logf("---\n\n(1a) Incorrect key test\n")
	test2PT1 := gosthopper.Decrypt(testK1, testCT)
	t.Logf("(1a.1) Plain text decrypted (key_1):\t%X - ", test2PT1)

	if test2PT1 != testPt {
		t.Logf("OK (different plain text)\n")
	} else {
		t.Logf("FAILED!\n")
	}

	t.Logf("\n\n(2) Example key and plain text vectors.\n\n")
	testCT = gosthopper.DoEncrypt(examplePt, rkeys)
	t.Logf("(2.1)(Low level DoEncrypt) Cipher text:\t%X\n", testCT)

	test2PT = gosthopper.DoDecrypt(testCT, decRkeys)
	t.Logf("(2.2)(Low level DoDecrypt) Plain text:\t")
	if examplePt != test2PT {
		t.Logf("- FAILED! [Not equal to reference plain text!]\n")
	} else {
		t.Logf("%s - OK\n", test2PT)
	}

	test3PT := gosthopper.Decrypt(exampleK, testCT)
	t.Logf("(2.3)(Decrypt) Plain text:\t\t")
	if examplePt != test3PT {
		t.Logf(" - FAILED! [Not equal to reference plain text!]\n")
	} else {
		t.Logf("%s - OK\n", test3PT)
	}

	t.Logf("\n\n(3) Simple counter mode.\n\n")
	cmCipherText := gosthopper.CMEncrypt(0x1234567, exampleK, []uint8(counterModeExamplePt))
	cmPlainText := gosthopper.CMDecrypt(0x1234567, exampleK, cmCipherText)

	t.Logf("Source PT:\n\t%s\nEncrypted:\n\t%0X\nDecrypted:\n\t%0X\n", counterModeExamplePt, cmCipherText, cmPlainText)

	fcFlag := true

	if len(cmPlainText) != len([]uint8(counterModeExamplePt)) {
		fcFlag = false
	} else {
		for l := range cmPlainText {
			if cmPlainText[l] != counterModeExamplePt[l] {
				fcFlag = false
				break
			}
		}
	}
	if fcFlag {
		t.Logf("\t(%s)\n", cmPlainText)
	}
	t.Logf("\n(3.1) Counter mode test - ")
	if !fcFlag {
		t.Logf("FAILED! [Not equal to source plain text!]\n")
	} else {
		t.Logf("OK\n")
	}

	t.Logf("\n---\n")

	t.Logf("\nTesting GCM (and cipher.Block interface) implementation.\n")

	kCipher, err := gosthopper.NewCipher(varK)
	if err != nil {
		t.Logf("NewCipher failed!\n")
	}

	kuznyechikGCM, err := cipher.NewGCM(kCipher)
	if err != nil {
		t.Logf("NewGCM failed!\n")
	}

	gcmSealed := kuznyechikGCM.Seal(nil, gcmNonce, gcmExamplePt, gcmExampleAD)

	t.Logf("GCM:\n Plain text: %s\n Additional Data: %s\n Nonce: %X\n Encryption result (CT+Tag): %X\n",
		gcmExamplePt, gcmExampleAD, gcmNonce, gcmSealed)

	gsmOpened, err := kuznyechikGCM.Open(nil, gcmNonce, gcmSealed, gcmExampleAD)
	if err != nil {
		t.Logf(" [decrypted] - FAILED!\n")
	}

	t.Logf(" GCM open result: %s - ", gsmOpened)
	if !bytes.Equal(gsmOpened, gcmExamplePt) {
		t.Logf("FAILED! [Not equal to reference plain text!]\n")
	} else {
		t.Logf("OK\n")
	}

	t.Logf(" GCM Manipulated AD check result: ")

	gsmOpened, err = kuznyechikGCM.Open(nil, gcmNonce, gcmSealed, gcmExampleADm)

	if err != nil {
		t.Logf(" [decryption failed] - OK (correct: must fail!)\n")
	} else {
		t.Logf(" [decrypted] - FAILED!\n")
	}

	t.Logf("\n---\n\nMeasuring speed.\nSimple block operations (DoEncrypt()/DoDecrypt()):\n")

	prng := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))

	for i := 0; i < 16; i++ {
		for t := range randPt[i] {
			randPt[i][t] = uint8(prng.Uint32())
		}
	}

	measureStart := time.Now()
	counter := 0

	for i := 0; i < 2300000; i++ {
		for t := range randPt {
			testCT = gosthopper.DoEncrypt(randPt[t], rkeys)
			counter++
		}
	}

	elapsed := time.Since(measureStart)
	eSec := int(elapsed.Seconds())

	t.Logf(" Encryption - %d blocks (%d cbytes), time: %s", counter, counter*16, elapsed)
	if eSec > 0 {
		t.Logf(" (~%d MB/sec)\n", (counter*16)/eSec/1048576)
	} else {
		t.Logf("\n")
	}

	measureStart = time.Now()
	counter = 0

	for i := 0; i < 2300000; i++ {
		for t := range randPt {
			testCT = gosthopper.DoDecrypt(randPt[t], decRkeys)
			counter++
		}
	}

	elapsed = time.Since(measureStart)
	eSec = int(elapsed.Seconds())

	t.Logf(" Decryption - %d blocks (%d bytes), time: %s", counter, counter*16, elapsed)
	if eSec > 0 {
		t.Logf(" (~%d MB/sec)\n", (counter*16)/eSec/1048576)
	} else {
		t.Logf("\n")
	}

	t.Logf("Kuznyechik-GCM:\n")
	LongBuffer := make([]byte, 1048576)
	for t := range LongBuffer {
		LongBuffer[t] = byte(prng.Uint32())
	}

	measureStart = time.Now()

	for i := 0; i < 100; i++ {
		for k := range gcmNonce {
			gcmNonce[k] = byte(prng.Uint32())
		}

		resBuf := kuznyechikGCM.Seal(nil, gcmNonce, LongBuffer, gcmExampleAD)

		LongResult, err := kuznyechikGCM.Open(nil, gcmNonce, resBuf, gcmExampleAD)
		if err != nil {
			t.Logf("GCM.Open Failed!\n")
		}

		if !bytes.Equal(LongBuffer, LongResult) {
			t.Logf("Failed: decrypted cipher text is not equal to source plain text!\n")
		}
	}

	elapsed = time.Since(measureStart)
	eSec = int(elapsed.Seconds())
	t.Logf(" 100 encrypt/decrypt operations on 10M buffer, time: %s", elapsed)
	if eSec > 0 {
		t.Logf(" (~%d MB/sec)\n", 200/eSec)
	} else {
		t.Logf("\n")
	}

	t.Logf("\nDone!\n\n")

}
