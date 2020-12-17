// GoGOST -- Pure Go GOST cryptographic functions library
// Copyright (C) 2015-2020 Sergey Matveev <stargrave@stargrave.org>
// Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
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

// Package mgm provides a custom implementation of Multilinear Galois Mode (MGM) suitable for RU-WireGuard.
// The supported tag and block sizes are 128 bit only.
package mgm

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"math/big"
)

var (
	r128 = new(big.Int).SetBytes([]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87},
	)
)

const (
	mgmTagSize   = 16
	mgmBlockSize = 16
	mgmMaxSize   = uint64(1<<uint(mgmBlockSize*8/2) - 1)
	mgmMaxBit    = 128 - 1
)

type MGM struct {
	cipher cipher.Block
}

func NewMGM(cipher cipher.Block) (cipher.AEAD, error) {
	if !(cipher.BlockSize() == 16) {
		return nil, errors.New("ru-wireguard/gogost/mgm: only 128 blocksize allowed")
	}

	mgm := MGM{
		cipher: cipher,
	}

	return &mgm, nil
}

func (mgm *MGM) NonceSize() int {
	return mgmBlockSize
}

func (mgm *MGM) Overhead() int {
	return mgmTagSize
}

func incr(data []byte) {
	for i := len(data) - 1; i >= 0; i-- {
		data[i]++
		if data[i] != 0 {
			return
		}
	}
}

func (mgm *MGM) auth(out, text, ad, icn []byte) {
	var sum [16]byte
	var bufC [mgmBlockSize]byte
	var padded [mgmBlockSize]byte
	var bufP [mgmBlockSize]byte

	adLen := len(ad) * 8
	textLen := len(text) * 8
	icn[0] |= 0x80
	mgm.cipher.Encrypt(bufP[:], icn) // Z_1 = E_K(1 || ICN)
	for len(ad) >= mgmBlockSize {
		mgm.cipher.Encrypt(bufC[:], bufP[:]) // H_i = E_K(Z_i)
		xor(                                 // sum (xor)= H_i (x) A_i
			sum[:],
			sum[:],
			mgm.mul(bufC[:], ad[:mgmBlockSize]),
		)
		incr(bufP[:mgmBlockSize/2]) // Z_{i+1} = incr_l(Z_i)
		ad = ad[mgmBlockSize:]
	}
	if len(ad) > 0 {
		copy(padded[:], ad)
		for i := len(ad); i < mgmBlockSize; i++ {
			padded[i] = 0
		}
		mgm.cipher.Encrypt(bufC[:], bufP[:])
		xor(sum[:], sum[:], mgm.mul(bufC[:], padded[:]))
		incr(bufP[:mgmBlockSize/2])
	}

	for len(text) >= mgmBlockSize {
		mgm.cipher.Encrypt(bufC[:], bufP[:]) // H_{h+j} = E_K(Z_{h+j})
		xor(                                 // sum (xor)= H_{h+j} (x) C_j
			sum[:],
			sum[:],
			mgm.mul(bufC[:], text[:mgmBlockSize]),
		)
		incr(bufP[:mgmBlockSize/2]) // Z_{h+j+1} = incr_l(Z_{h+j})
		text = text[mgmBlockSize:]
	}
	if len(text) > 0 {
		copy(padded[:], text)
		for i := len(text); i < mgmBlockSize; i++ {
			padded[i] = 0
		}
		mgm.cipher.Encrypt(bufC[:], bufP[:])
		xor(sum[:], sum[:], mgm.mul(bufC[:], padded[:]))
		incr(bufP[:mgmBlockSize/2])
	}

	mgm.cipher.Encrypt(bufP[:], bufP[:]) // H_{h+q+1} = E_K(Z_{h+q+1})
	// len(A) || len(C)
	binary.BigEndian.PutUint64(bufC[:], uint64(adLen))
	binary.BigEndian.PutUint64(bufC[mgmBlockSize/2:], uint64(textLen))

	// sum (xor)= H_{h+q+1} (x) (len(A) || len(C))
	xor(sum[:], sum[:], mgm.mul(bufP[:], bufC[:]))
	mgm.cipher.Encrypt(bufP[:], sum[:]) // E_K(sum)
	copy(out, bufP[:mgmTagSize])        // MSB_S(E_K(sum))
}

func (mgm *MGM) crypt(out, in []byte, icn []byte) {
	var bufP [mgmBlockSize]byte
	var bufC [mgmBlockSize]byte

	icn[0] &= 0x7F
	mgm.cipher.Encrypt(bufP[:], icn) // Y_1 = E_K(0 || ICN)
	for len(in) >= mgmBlockSize {
		mgm.cipher.Encrypt(bufC[:], bufP[:]) // E_K(Y_i)
		xor(out, bufC[:], in)                // C_i = P_i (xor) E_K(Y_i)
		incr(bufP[mgmBlockSize/2:])          // Y_i = incr_r(Y_{i-1})
		out = out[mgmBlockSize:]
		in = in[mgmBlockSize:]
	}
	if len(in) > 0 {
		mgm.cipher.Encrypt(bufC[:], bufP[:])
		xor(out, in, bufC[:])
	}
}

func (mgm *MGM) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != mgmBlockSize || nonce[0]&0x80 > 0 {
		panic("mgm: incorrect nonce")
	}
	if len(plaintext) == 0 && len(additionalData) == 0 {
		panic("mgm seal: at least either *text or additionalData must be provided")
	}
	if uint64(len(additionalData)) > mgmMaxSize {
		panic("additionalData is too big")
	}
	if uint64(len(plaintext)+len(additionalData)) > mgmMaxSize {
		panic("*text with additionalData are too big")
	}
	if uint64(len(plaintext)) > mgmMaxSize {
		panic("plaintext is too big")
	}

	ret, out := sliceForAppend(dst, len(plaintext)+mgmTagSize)

	var icn [mgmBlockSize]byte
	copy(icn[:], nonce)

	mgm.crypt(out, plaintext, icn[:])

	mgm.auth(
		out[len(plaintext):len(plaintext)+mgmTagSize],
		out[:len(plaintext)],
		additionalData,
		icn[:],
	)
	return ret
}

func (mgm *MGM) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != mgmBlockSize || nonce[0]&0x80 > 0 {
		panic("mgm: incorrect nonce")
	}
	if len(ciphertext) == 0 && len(additionalData) == 0 {
		panic("mgm open: at least either *text or additionalData must be provided")
	}
	if uint64(len(additionalData)) > mgmMaxSize {
		panic("additionalData is too big")
	}
	if uint64(len(ciphertext)+len(additionalData)) > mgmMaxSize {
		panic("*text with additionalData are too big")
	}
	if uint64(len(ciphertext)-mgmTagSize) > mgmMaxSize {
		panic("ciphertext is too big")
	}

	if len(ciphertext) < mgmTagSize {
		panic("ciphertext is to small")
	}
	ret, out := sliceForAppend(dst, len(ciphertext)-mgmTagSize)
	ct := ciphertext[:len(ciphertext)-mgmTagSize]

	var icn [mgmBlockSize]byte
	copy(icn[:], nonce)

	var expectedTag [mgmTagSize]byte
	mgm.auth(expectedTag[:], ct, additionalData, icn[:])
	if !hmac.Equal(expectedTag[:], ciphertext[len(ciphertext)-mgmTagSize:]) {
		return nil, errors.New("gogost/mgm: invalid authentication tag")
	}
	mgm.crypt(out, ct, icn[:])
	return ret, nil
}
