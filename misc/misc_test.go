package misc_test

import (
	"crypto/rand"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/sammy00/crypto/misc"
)

func fakeRandSlice(ell int32) []byte {
	out := make([]byte, ell)
	rand.Read(out)

	return out
}
func TestReverseCopy(t *testing.T) {
	t.Run("Longer Destination", func(t *testing.T) {
		dstLen := mrand.Int31n(64) + 2
		srcLen := mrand.Int31n(dstLen-1) + 1

		src := fakeRandSlice(srcLen)
		dst := fakeRandSlice(dstLen)

		misc.ReverseCopy(dst, src)

		if !strings.HasSuffix(string(dst), string(src)) {
			t.Errorf("destination (%x) should have suffix as %x\n", dst, src)
		}
	})
	t.Run("Equal Size", func(t *testing.T) {
		ell := mrand.Int31n(64) + 1

		src := fakeRandSlice(ell)
		dst := fakeRandSlice(ell)

		misc.ReverseCopy(dst, src)

		if string(dst) != string(src) {
			t.Errorf("invalid destination: got %x, want %x\n", dst, src)
		}
	})

	t.Run("Shorter Destination", func(t *testing.T) {
		srcLen := mrand.Int31n(64) + 2
		dstLen := mrand.Int31n(srcLen-1) + 1

		src := fakeRandSlice(srcLen)
		dst := fakeRandSlice(dstLen)

		misc.ReverseCopy(dst, src)

		if !strings.HasSuffix(string(src), string(dst)) {
			t.Errorf("destination (%x) should be the suffix of %x\n", dst, src)
		}
	})
}
