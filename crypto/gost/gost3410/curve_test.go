/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package gost3410

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func TestIsOnCurve(t *testing.T) {
	c := CurveIdtc26gost341012512paramSetA()
	if !c.IsOnCurve(c.X, c.Y) {
		t.Fail()
	}
	if c.IsOnCurve(c.Y, c.X) {
		t.Fail()
	}
}

func TestExternalMarshal(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()

	expPrivKeyBytes, err := hex.DecodeString("8599770a520270845c8300d7ee84be3eb5c63255c32620280bc47af444e3a33f")
	if err != nil {
		t.Error("priv key decode:", err)
	}

	xExpPublicBytes, err := hex.DecodeString("464AD0FB4085E06F2499828A3FD787FB4960CC273E337A6914AB295D375A1101")
	if err != nil {
		t.Error("x decode:", err)
	}

	yExpPublicBytes, err := hex.DecodeString("4B122EF70416AD4E92E6E1952ECA65468B7FD571227EEE7B3D5628A1F85A4DE4")
	if err != nil {
		t.Error("y decode:", err)
	}

	privKey, err := NewPrivateKey(c, expPrivKeyBytes)
	if err != nil {
		t.Error("priv key gen:", err)
	}

	marshalledExpPubKeyBytes, err := hex.DecodeString("04464AD0FB4085E06F2499828A3FD787FB4960CC273E337A6914AB295D375A11014B122EF70416AD4E92E6E1952ECA65468B7FD571227EEE7B3D5628A1F85A4DE4")
	if err != nil {
		t.Error("pub key decode:", err)
	}

	pubKey, err := privKey.PublicKey()
	if err != nil {
		t.Error("pub key extraxtion:", err)
	}

	if !bytes.Equal(xExpPublicBytes, pubKey.X.Bytes()) ||
		!bytes.Equal(yExpPublicBytes, pubKey.Y.Bytes()) {
		t.Error("pub key coords comparing")
	}

	if !bytes.Equal(marshalledExpPubKeyBytes, Marshal(c, pubKey.X, pubKey.Y)) {
		t.Error("marshalled pub key comparing")
	}

	unmarshalledX, unmarshalledY := Unmarshal(c, marshalledExpPubKeyBytes)
	if !bytes.Equal(xExpPublicBytes, unmarshalledX.Bytes()) ||
		!bytes.Equal(yExpPublicBytes, unmarshalledY.Bytes()) {
		t.Error("unmarshalled bytes compare")
	}

	compMarshalledExpPubKeyBytes, err := hex.DecodeString("02464ad0fb4085e06f2499828a3fd787fb4960cc273e337a6914ab295d375a1101")
	if err != nil {
		t.Error("compressed marshalled pub key decode:", err)
	}

	if !bytes.Equal(compMarshalledExpPubKeyBytes, MarshalCompressed(c, pubKey.X, pubKey.Y)) {
		t.Error("compressed mpub key comparing")
	}

	compUnmarshalledX, compUnmarshalledY := UnmarshalCompressed(c, compMarshalledExpPubKeyBytes)
	if !bytes.Equal(xExpPublicBytes, compUnmarshalledX.Bytes()) ||
		!bytes.Equal(yExpPublicBytes, compUnmarshalledY.Bytes()) {
		t.Error("compressed unmarshalled bytes compare")
	}

}

func TestMarshallingUnmarshalling(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()

	for i := 1; i < 1000; i++ {
		privKey, err := GenPrivateKey(c, rand.Reader)
		if err != nil {
			t.Error("private key generation")
		}
		pubKey, err := privKey.PublicKey()
		if err != nil {
			t.Error("public key deriving")
		}
		d := Marshal(c, pubKey.X, pubKey.Y)
		x, y := Unmarshal(c, d)
		if !bytes.Equal(x.Bytes(), pubKey.X.Bytes()) ||
			!bytes.Equal(y.Bytes(), pubKey.Y.Bytes()) {
			t.Error("pub key comparing")
		}
	}

	for i := 1; i < 1000; i++ {
		privKey, err := GenPrivateKey(c, rand.Reader)
		if err != nil {
			t.Error("private key generation")
		}
		pubKey, err := privKey.PublicKey()
		if err != nil {
			t.Error("public key deriving")
		}
		d := MarshalCompressed(c, pubKey.X, pubKey.Y)
		x, y := UnmarshalCompressed(c, d)
		if !bytes.Equal(x.Bytes(), pubKey.X.Bytes()) ||
			!bytes.Equal(y.Bytes(), pubKey.Y.Bytes()) {
			t.Error("compressed pub key comparing")
		}
	}
}

func TestGenerateKey(t *testing.T) {
	c := CurveIdtc26gost34102012256paramSetA()
	for i := 1; i < 100; i++ {
		priv, x, y, err := GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal("generate key error:", err)
		}

		if len(priv) != c.PointSize() {
			t.Fatal("key size error")
		}

		raw := Reversed(priv)

		privKey, err := NewPrivateKey(c, raw)
		if err != nil {
			t.Fatal("new private key error:", err)
		}

		pubKey, err := privKey.PublicKey()
		if err != nil {
			t.Error("public key deriving")
		}

		x2 := pubKey.X
		y2 := pubKey.Y

		if !bytes.Equal(x2.Bytes(), x.Bytes()) {
			t.Fatal("x2 and x are not the same")
		}

		if !bytes.Equal(y2.Bytes(), y.Bytes()) {
			t.Fatal("y2 and y are not the same")
		}
	}
}
