// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2020 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package gost3410

import (
	"fmt"
	"math/big"
)

type PublicKey struct {
	C *Curve
	X *big.Int
	Y *big.Int
}

func NewPublicKey(curve *Curve, raw []byte) (*PublicKey, error) {
	pointSize := curve.PointSize()
	key := make([]byte, 2*pointSize)
	if len(raw) != len(key) {
		return nil, fmt.Errorf("gogost/gost3410: len(key) != %d", len(key))
	}
	for i := 0; i < len(key); i++ {
		key[i] = raw[len(raw)-i-1]
	}
	return &PublicKey{
		curve,
		bytes2big(key[pointSize : 2*pointSize]),
		bytes2big(key[:pointSize]),
	}, nil
}

func (pub *PublicKey) Raw() []byte {
	pointSize := pub.C.PointSize()
	raw := append(
		pad(pub.Y.Bytes(), pointSize),
		pad(pub.X.Bytes(), pointSize)...,
	)
	reverse(raw)
	return raw
}

func (pub *PublicKey) VerifyDigest(digest, signature []byte) (bool, error) {
	pointSize := pub.C.PointSize()
	if len(signature) != 2*pointSize {
		return false, fmt.Errorf("gogost/gost3410: len(signature) != %d", 2*pointSize)
	}
	s := bytes2big(signature[:pointSize])
	r := bytes2big(signature[pointSize:])
	if r.Cmp(zero) <= 0 ||
		r.Cmp(pub.C.Q) >= 0 ||
		s.Cmp(zero) <= 0 ||
		s.Cmp(pub.C.Q) >= 0 {
		return false, nil
	}
	e := bytes2big(digest)
	e.Mod(e, pub.C.Q)
	if e.Cmp(zero) == 0 {
		e = big.NewInt(1)
	}
	v := big.NewInt(0)
	v.ModInverse(e, pub.C.Q)
	z1 := big.NewInt(0)
	z2 := big.NewInt(0)
	z1.Mul(s, v)
	z1.Mod(z1, pub.C.Q)
	z2.Mul(r, v)
	z2.Mod(z2, pub.C.Q)
	z2.Sub(pub.C.Q, z2)
	p1x, p1y, err := pub.C.Exp(z1, pub.C.X, pub.C.Y)
	if err != nil {
		return false, err
	}
	q1x, q1y, err := pub.C.Exp(z2, pub.X, pub.Y)
	if err != nil {
		return false, err
	}
	lm := big.NewInt(0)
	lm.Sub(q1x, p1x)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pub.C.P)
	}
	lm.ModInverse(lm, pub.C.P)
	z1.Sub(q1y, p1y)
	lm.Mul(lm, z1)
	lm.Mod(lm, pub.C.P)
	lm.Mul(lm, lm)
	lm.Mod(lm, pub.C.P)
	lm.Sub(lm, p1x)
	lm.Sub(lm, q1x)
	lm.Mod(lm, pub.C.P)
	if lm.Cmp(zero) < 0 {
		lm.Add(lm, pub.C.P)
	}
	lm.Mod(lm, pub.C.Q)
	return lm.Cmp(r) == 0, nil
}
