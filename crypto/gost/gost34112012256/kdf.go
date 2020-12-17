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

package gost34112012256

import (
	"crypto/hmac"
	"hash"
)

type KDF struct {
	h hash.Hash
}

func NewKDF(key []byte) *KDF {
	return &KDF{hmac.New(New, key)}
}

func (kdf *KDF) Derive(dst, label, seed []byte) (r []byte) {
	if _, err := kdf.h.Write([]byte{0x01}); err != nil {
		panic(err)
	}
	if _, err := kdf.h.Write(label); err != nil {
		panic(err)
	}
	if _, err := kdf.h.Write([]byte{0x00}); err != nil {
		panic(err)
	}
	if _, err := kdf.h.Write(seed); err != nil {
		panic(err)
	}
	if _, err := kdf.h.Write([]byte{0x01}); err != nil {
		panic(err)
	}
	if _, err := kdf.h.Write([]byte{0x00}); err != nil {
		panic(err)
	}
	r = kdf.h.Sum(dst)
	kdf.h.Reset()
	return r
}
