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
	"math/big"
)

func NewUKM(raw []byte) *big.Int {
	t := make([]byte, len(raw))
	for i := 0; i < len(t); i++ {
		t[i] = raw[len(raw)-i-1]
	}
	return bytes2big(t)
}
