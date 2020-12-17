package wgtypes_test

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/bi-zone/ruwireguard-go/crypto/gost/gost3410"
	"github.com/bi-zone/ruwireguard-go/wgctrl/wgtypes"
)

func TestPreparedKeys(t *testing.T) {
	// Keys generated via "wg key" and "wg pubkey" for comparison
	// with this Go implementation.
	const (
		private = "2CQIavBMaPlK2Ey/yH5ehqcRNuCLFmjSCvhL9uRnvBo="
		public  = "Ahu2XTXZWb1GJUpiASebdl1hJA2ZfUkhFz/aSqBZhwrf"
	)

	priv, err := wgtypes.ParseKey(private)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	if diff := cmp.Diff(private, priv.String()); diff != "" {
		t.Fatalf("unexpected private key (-want +got):\n%s", diff)
	}

	pub := priv.PublicKey()
	if diff := cmp.Diff(public, pub.String()); diff != "" {
		t.Fatalf("unexpected public key (-want +got):\n%s", diff)
	}
}

func TestKeyExchange(t *testing.T) {
	privA, pubA := mustKeyPair()
	privB, pubB := mustKeyPair()

	// Perform ECDH key exhange: https://cr.yp.to/ecdh.html.
	ukm := big.NewInt(1)
	sharedA, err := privA.KEK(pubB, ukm)
	if err != nil {
		t.Fatalf("failed to perform KEK A: %v", err)
	}

	ukm = big.NewInt(1)
	sharedB, err := privB.KEK(pubA, ukm)
	if err != nil {
		t.Fatalf("failed to perform KEK B: %v", err)
	}

	if diff := cmp.Diff(sharedA, sharedB); diff != "" {
		t.Fatalf("unexpected shared secret (-want +got):\n%s", diff)
	}
}

func TestBadKeys(t *testing.T) {
	// Adapt to fit the signature used in the test table.
	parseKey := func(b []byte) (wgtypes.Key, error) {
		return wgtypes.ParseKey(string(b))
	}

	tests := []struct {
		name string
		b    []byte
		fn   func(b []byte) (wgtypes.Key, error)
	}{
		{
			name: "bad base64",
			b:    []byte("xxx"),
			fn:   parseKey,
		},
		{
			name: "short base64",
			b:    []byte("aGVsbG8="),
			fn:   parseKey,
		},
		{
			name: "short key",
			b:    []byte("xxx"),
			fn:   wgtypes.NewKey,
		},
		{
			name: "long base64",
			b:    []byte("ZGVhZGJlZWZkZWFkYmVlZmRlYWRiZWVmZGVhZGJlZWZkZWFkYmVlZg=="),
			fn:   parseKey,
		},
		{
			name: "long bytes",
			b:    bytes.Repeat([]byte{0xff}, 40),
			fn:   wgtypes.NewKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn(tt.b)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			t.Logf("OK error: %v", err)
		})
	}
}

func mustKeyPair() (private *gost3410.PrivateKey, public *gost3410.PublicKey) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		panicf("failed to generate private key: %v", err)
	}

	privateKey, _ := gost3410.NewPrivateKey(wgtypes.Curve, priv)
	publicKey, _ := privateKey.PublicKey()

	return privateKey, publicKey
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
