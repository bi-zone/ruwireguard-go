// GOSTHopper
// Main: gosthopper.go
//
// 17/02/2019
// "Pure" Go implementation of cipher block operations, for platforms, other
// than amd64.
// This is VERY SLOW, but works. For amd64 we have assembly in docipher_amd64.s
//
// Alexander Venedioukhin
//
// Modified Copyright (c) 2020 BI.ZONE LLC.
//
// +build !amd64

package gosthopper

func DoEncrypt(block [16]uint8, rkeys [10][16]uint8) [16]uint8 {
	// This is a spare, SLOW Go implementation of cipher. This code
	// should be only compiled for target platforms different from amd64.

	var r [16]uint8
	ct := block
	// Encryption process follows.
	for i := 0; i < 9; i++ { // We have nine basic rounds.
		for k := range ct {
			ct[k] = ct[k] ^ rkeys[i][k] // XOR with current round key.
		}
		for k := range r {
			r[k] = LSEncLookup[0][ct[0]][k] // Prepare for lookup.
		}
		for j := 1; j <= 15; j++ {
			// There are 15 values from lookup table to XOR.
			// Calculate XOR with lookup table elements. Each element corresponds
			// to particular value of byte at current block position (ct[j]).
			for k := range r {
				r[k] = r[k] ^ LSEncLookup[j][ct[j]][k]
			}
		}
		ct = r
	}
	for k := range ct {
		ct[k] = ct[k] ^ rkeys[9][k]
	} // XOR with the last round key.

	return ct
}

func DoEncryptCounter(nonce [16]uint8, block [16]uint8, rkeys [10][16]uint8) [16]uint8 {
	// Routine for counter mode. Almost the same as DoEncrypt().

	var r [16]uint8
	ct := nonce
	// Encryption process follows.
	for i := 0; i < 9; i++ { // We have nine basic rounds.
		for k := range ct {
			ct[k] = ct[k] ^ rkeys[i][k] // XOR with current round key.
		}
		for k := range r {
			r[k] = LSEncLookup[0][ct[0]][k] // Prepare for lookup.
		}
		for j := 1; j <= 15; j++ {
			// There are 15 values from lookup table to XOR.
			// Calculate XOR with lookup table elements. Each element corresponds
			// to particular value of byte at current block position (ct[j]).
			for k := range r {
				r[k] = r[k] ^ LSEncLookup[j][ct[j]][k]
			}
		}
		ct = r
	}
	for k := range ct {
		ct[k] = ct[k] ^ rkeys[9][k]
	} // XOR with the last round key.
	for k := range ct {
		ct[k] = ct[k] ^ block[k]
	} // XOR with plain text.
	return ct
}

func DoDecrypt(block [16]uint8, rkeys [10][16]uint8) [16]uint8 {
	// This is a spare, SLOW Go implementation of cipher. This code
	// should be only compiled for target platforms different from amd64.
	var r [16]uint8

	pt := block
	// First - apply inverse L using lookup table.
	for k := range r {
		r[k] = LInvLookup[0][pt[0]][k]
	}
	for j := 1; j <= 15; j++ {
		for k := range r {
			r[k] = r[k] ^ LInvLookup[j][pt[j]][k]
		}
	}
	pt = r

	for i := 9; i > 1; i-- {
		// XOR with current round key (inversed).
		for k := range pt {
			pt[k] = pt[k] ^ rkeys[i][k]
		}
		// Apply SL transformations using lookup table.
		for k := range r {
			r[k] = SLDecLookup[0][pt[0]][k]
		}
		for j := 1; j <= 15; j++ {
			for k := range r {
				r[k] = r[k] ^ SLDecLookup[j][pt[j]][k]
			}
		}
		pt = r
	}

	for k := range pt {
		pt[k] = pt[k] ^ rkeys[1][k]   // XOR with K_2
		pt[k] = PiInverseTable[pt[k]] // Inverse Pi
		pt[k] = pt[k] ^ rkeys[0][k]   // XOR with K_1
	}
	return pt // Plain text.
}
