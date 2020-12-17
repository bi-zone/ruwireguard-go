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

package mgm

import (
	"math/big"
)

func (mgm *MGM) mul(xBuf, yBuf []byte) []byte {
	var mulBuf [mgmBlockSize]byte
	x := new(big.Int).SetBytes(xBuf)
	y := new(big.Int).SetBytes(yBuf)
	z := new(big.Int).SetInt64(0)

	for y.BitLen() != 0 {
		if y.Bit(0) == 1 {
			z.Xor(z, x)
		}
		if x.Bit(mgmMaxBit) == 1 {
			x.SetBit(x, mgmMaxBit, 0)
			x.Lsh(x, 1)
			x.Xor(x, r128)
		} else {
			x.Lsh(x, 1)
		}
		y.Rsh(y, 1)
	}
	zBytes := z.Bytes()
	rem := len(xBuf) - len(zBytes)
	for i := 0; i < rem; i++ {
		mulBuf[i] = 0
	}
	copy(mulBuf[rem:], zBytes)
	return mulBuf[:]
}
