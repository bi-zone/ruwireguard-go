/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package gost3410

import (
	"crypto/rand"
	"io"
	"math/big"
)

func GenerateKey(curve *Curve, rng io.Reader) (key []byte, x, y *big.Int, err error) {
	raw := make([]byte, curve.PointSize())
	if rng == nil {
		rng = rand.Reader
	}
	if _, err = io.ReadFull(rng, raw); err != nil {
		return
	}
	key = make([]byte, curve.PointSize())
	for i := 0; i < len(key); i++ {
		key[i] = raw[len(raw)-i-1]
	}

	x, y, err = curve.Exp(new(big.Int).SetBytes(key), curve.X, curve.Y)
	if err != nil {
		return
	}

	return
}

func Reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

func Marshal(curve *Curve, x, y *big.Int) []byte {
	byteLen := curve.PointSize()

	ret := make([]byte, 1+2*byteLen)
	ret[0] = 4 // uncompressed point

	x.FillBytes(ret[1 : 1+byteLen])
	y.FillBytes(ret[1+byteLen : 1+2*byteLen])

	return ret
}

func MarshalCompressed(curve *Curve, x, y *big.Int) []byte {
	byteLen := curve.PointSize()
	compressed := make([]byte, 1+byteLen)
	compressed[0] = byte(y.Bit(0)) | 2
	x.FillBytes(compressed[1:])
	return compressed
}

func Unmarshal(curve *Curve, data []byte) (x, y *big.Int) {
	byteLen := curve.PointSize()
	if len(data) != 1+2*byteLen {
		return nil, nil
	}
	if data[0] != 4 { // uncompressed form
		return nil, nil
	}
	p := curve.P
	x = new(big.Int).SetBytes(data[1 : 1+byteLen])
	y = new(big.Int).SetBytes(data[1+byteLen:])
	if x.Cmp(p) >= 0 || y.Cmp(p) >= 0 {
		return nil, nil
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}

func UnmarshalCompressed(curve *Curve, data []byte) (x, y *big.Int) {
	byteLen := curve.PointSize()
	if len(data) != 1+byteLen {
		return nil, nil
	}
	if data[0] != 2 && data[0] != 3 { // compressed form
		return nil, nil
	}
	p := curve.P
	x = new(big.Int).SetBytes(data[1:])
	if x.Cmp(p) >= 0 {
		return nil, nil
	}
	// y² = x³ + ax + b
	y = polynomial(curve, x)
	y = y.ModSqrt(y, p)
	if y == nil {
		return nil, nil
	}
	if byte(y.Bit(0)) != data[0]&1 {
		y.Neg(y).Mod(y, p)
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil
	}
	return
}
