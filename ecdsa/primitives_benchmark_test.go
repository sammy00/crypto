package ecdsa_test

import (
	"crypto/rand"
	"testing"

	"github.com/sammy00/crypto/ecdsa"
	"github.com/sammy00/crypto/elliptic"
)

func BenchmarkKeyGeneration(b *testing.B) {
	b.ResetTimer()
	curve := elliptic.P256k1()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ecdsa.GenerateKey(curve, rand.Reader)
		}
	})
}

func BenchmarkVerifySECP256k1(b *testing.B) {
	b.ResetTimer()
	curve := elliptic.P256k1()

	digest := []byte("testing")
	priv, _ := ecdsa.GenerateKey(curve, rand.Reader)
	r, s, _ := ecdsa.Sign(rand.Reader, priv, digest)

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			ecdsa.Verify(&priv.PublicKey, digest, r, s)
		}
	})
}
