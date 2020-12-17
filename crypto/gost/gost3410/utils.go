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

package gost3410

import (
	"math/big"
)

func bytes2big(d []byte) *big.Int {
	return big.NewInt(0).SetBytes(d)
}

func reverse(d []byte) {
	for i, j := 0, len(d)-1; i < j; i, j = i+1, j-1 {
		d[i], d[j] = d[j], d[i]
	}
}

func Reversed(d []byte) []byte {
	e := make([]byte, len(d))
	for i := 0; i < len(d); i++ {
		e[i] = d[len(d)-i-1]
	}
	return e
}

func pad(d []byte, size int) []byte {
	return append(make([]byte, size-len(d)), d...)
}

func PointSize(p *big.Int) int {
	if p.BitLen() > 256 {
		return 64
	}
	return 32
}
