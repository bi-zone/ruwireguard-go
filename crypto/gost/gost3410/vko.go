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

func (prv *PrivateKey) KEK(pub *PublicKey, ukm *big.Int) ([]byte, error) {
	keyX, keyY, err := prv.C.Exp(prv.Key, pub.X, pub.Y)
	if err != nil {
		return nil, err
	}
	u := big.NewInt(0).Set(ukm).Mul(ukm, prv.C.Co)
	if u.Cmp(bigInt1) != 0 {
		keyX, keyY, err = prv.C.Exp(u, keyX, keyY)
		if err != nil {
			return nil, err
		}
	}
	pk := PublicKey{prv.C, keyX, keyY}
	return pk.Raw(), nil
}
