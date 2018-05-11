package secp256k1_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/sammy00/crypto/ecdsa"
	"github.com/sammy00/crypto/elliptic"
)

func BenchmarkGenerateKey(b *testing.B) {
	b.Run("BTC", func(bb *testing.B) {
		curve := btcec.S256()
		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				btcec.NewPrivateKey(curve)
			}
		})
	})

	b.Run("Local", func(bb *testing.B) {
		curve := elliptic.P256k1()
		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				ecdsa.GenerateKey(curve, rand.Reader)
			}
		})
	})
}

func BenchmarkSign(b *testing.B) {
	msg := "test message"
	digest := sha256.Sum256([]byte(msg))

	b.Run("BTC", func(bb *testing.B) {
		priv, err := btcec.NewPrivateKey(btcec.S256())
		if nil != err {
			b.Fatal(err)
		}

		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				priv.Sign(digest[:])
			}
		})
	})

	b.Run("Local", func(bb *testing.B) {
		priv, err := ecdsa.GenerateKey(elliptic.P256k1(), rand.Reader)
		if nil != err {
			b.Fatal(err)
		}

		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				ecdsa.Sign(rand.Reader, priv, digest[:])
			}
		})
	})
}

func BenchmarkVerify(b *testing.B) {
	msg := "test message"
	digest := sha256.Sum256([]byte(msg))

	b.Run("BTC", func(bb *testing.B) {
		priv, err := btcec.NewPrivateKey(btcec.S256())
		if nil != err {
			b.Fatal(err)
		}
		sig, err := priv.Sign(digest[:])
		if nil != err {
			b.Fatal(err)
		}
		pub := priv.PubKey()

		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				sig.Verify(digest[:], pub)
			}
		})
	})

	b.Run("Local", func(bb *testing.B) {
		priv, err := ecdsa.GenerateKey(elliptic.P256k1(), rand.Reader)
		if nil != err {
			b.Fatal(err)
		}
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if nil != err {
			b.Fatal(err)
		}
		pub := &priv.PublicKey

		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				ecdsa.Verify(pub, digest[:], r, s)
			}
		})
	})
}
