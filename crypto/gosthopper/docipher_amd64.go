// ~=  GOSTHopper  =~
// Kuznechik cipher, GOST R 34.12-2015
// Main: gosthopper.go
//
// 17/02/2019
// Declarations for assembly low level functions, implementing cipher.
// Actual code - in docipher_amd64.s file.
//
// Alexander Venedioukhin
//
// Modified Copyright (c) 2020 BI.ZONE LLC.

package gosthopper

//go:noescape
//go:nosplit
func DoEncrypt(block [16]uint8, rkeys [10][16]uint8) [16]uint8

//go:noescape
//go:nosplit
func DoEncryptCounter(nonce [16]uint8, block [16]uint8, rkeys [10][16]uint8) [16]uint8

//go:noescape
//go:nosplit
func DoDecrypt(block [16]uint8, rkeys [10][16]uint8) [16]uint8

// NOTE:
// For DoDecrypt() under rkeys inversed round keys are expected.
// To get inverse keys use - GetDecryptRoundKeys().
