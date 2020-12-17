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

// GOST R 34.11-2012 256-bit hash function.
// RFC 6986.
package gost34112012256

import (
	"hash"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/internal/gost34112012"
)

const (
	BlockSize = gost34112012.BlockSize
	Size      = 32
)

/*
func init() {
	crypto.RegisterHash(crypto.GOSTR34112012256, New)
}
*/

func New() hash.Hash {
	return gost34112012.New(32)
}
