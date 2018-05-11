package elliptic_test

import (
	"testing"

	"github.com/btcec"
	"github.com/sammy00/crypto/elliptic"
)

func BenchmarkAdd(b *testing.B) {
	koblitzBTC := btcec.S256()
	Gx, Gy := koblitzBTC.Gx, koblitzBTC.Gy

	b.Run("BTC", func(bb *testing.B) {
		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				koblitzBTC.Add(Gx, Gy, Gx, Gy)
			}
		})
	})
	b.Run("Local", func(bb *testing.B) {
		koblitzLocal := elliptic.P256k1()

		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				koblitzLocal.Add(Gx, Gy, Gx, Gy)
			}
		})
	})
}

func BenchmarkDouble(b *testing.B) {
	koblitzBTC := btcec.S256()
	Gx, Gy := koblitzBTC.Gx, koblitzBTC.Gy

	b.Run("BTC", func(bb *testing.B) {
		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				koblitzBTC.Double(Gx, Gy)
			}
		})
	})
	b.Run("Local", func(bb *testing.B) {
		koblitzLocal := elliptic.P256k1()

		bb.ResetTimer()
		bb.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				koblitzLocal.Double(Gx, Gy)
			}
		})
	})
}
