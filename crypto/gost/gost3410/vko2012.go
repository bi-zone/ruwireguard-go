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

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012256"
	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost34112012512"
)

// RFC 7836 VKO GOST R 34.10-2012 256-bit key agreement function.
// UKM is user keying material, also called VKO-factor.
func (prv *PrivateKey) KEK2012256(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	key, err := prv.KEK(pub, ukm)
	if err != nil {
		return nil, err
	}
	h := gost34112012256.New()
	if _, err = h.Write(key); err != nil {
		return nil, err
	}
	return h.Sum(key[:0]), nil
}

// RFC 7836 VKO GOST R 34.10-2012 512-bit key agreement function.
// UKM is user keying material, also called VKO-factor.
func (prv *PrivateKey) KEK2012512(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	key, err := prv.KEK(pub, ukm)
	if err != nil {
		return nil, err
	}
	h := gost34112012512.New()
	if _, err = h.Write(key); err != nil {
		return nil, err
	}
	return h.Sum(key[:0]), nil
}
