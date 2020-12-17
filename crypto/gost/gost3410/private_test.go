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
	"crypto"
	"crypto/rand"
	"testing"
)

func TestSignerInterface(t *testing.T) {
	prvRaw := make([]byte, 32)
	rand.Read(prvRaw)
	prv, err := NewPrivateKey(CurveIdGostR34102001TestParamSet(), prvRaw)
	if err != nil {
		t.FailNow()
	}
	var _ crypto.Signer = prv
}
