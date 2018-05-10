package ecdsa_test

import (
	"crypto/rand"
	mrand "math/rand"
	"strings"
	"testing"

	"github.com/sammy00/crypto/ecdsa"
	"github.com/sammy00/crypto/elliptic"
)

func fakeRandSlice(ell int32) []byte {
	out := make([]byte, ell)
	rand.Read(out)

	return out
}

func testPubKeyEquality(pub1, pub2 *ecdsa.PublicKey, t *testing.T) {
	if 0 != pub1.X.Cmp(pub2.X) {
		t.Fatalf("invalid X: got %x, want %x", pub2.X.Bytes(), pub1.X.Bytes())
	}
	if 0 != pub1.Y.Cmp(pub2.Y) {
		t.Fatalf("invalid Y: got %x, want %x", pub2.Y.Bytes(), pub1.Y.Bytes())
	}
}

func TestReverseCopy(t *testing.T) {
	t.Run("Longer Destination", func(t *testing.T) {
		dstLen := mrand.Int31n(64) + 2
		srcLen := mrand.Int31n(dstLen-1) + 1

		src := fakeRandSlice(srcLen)
		dst := fakeRandSlice(dstLen)

		ecdsa.ReverseCopy(dst, src)

		if !strings.HasSuffix(string(dst), string(src)) {
			t.Errorf("destination (%x) should have suffix as %x\n", dst, src)
		}
	})
	t.Run("Equal Size", func(t *testing.T) {
		ell := mrand.Int31n(64) + 1

		src := fakeRandSlice(ell)
		dst := fakeRandSlice(ell)

		ecdsa.ReverseCopy(dst, src)

		if string(dst) != string(src) {
			t.Errorf("invalid destination: got %x, want %x\n", dst, src)
		}
	})

	t.Run("Shorter Destination", func(t *testing.T) {
		srcLen := mrand.Int31n(64) + 2
		dstLen := mrand.Int31n(srcLen-1) + 1

		src := fakeRandSlice(srcLen)
		dst := fakeRandSlice(dstLen)

		ecdsa.ReverseCopy(dst, src)

		if !strings.HasSuffix(string(src), string(dst)) {
			t.Errorf("destination (%x) should be the suffix of %x\n", dst, src)
		}
	})
}

func TestPubKeyCompress(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256k1(), rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	pub := &priv.PublicKey
	data, err := pub.Compress()
	if nil != err {
		t.Fatal(err)
	}

	pubDec := new(ecdsa.PublicKey)
	if err := pubDec.Decompress(pub.Curve, data); nil != err {
		t.Fatal(err)
	}

	if 0 != pub.X.Cmp(pubDec.X) {
		t.Fatalf("invalid X: got %x, want %x", pubDec.X.Bytes(), pub.X.Bytes())
	}
	if 0 != pub.Y.Cmp(pubDec.Y) {
		t.Fatalf("invalid Y: got %x, want %x", pubDec.Y.Bytes(), pub.Y.Bytes())
	}
}

func TestPubKeyParsing(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256k1(), rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	pub := &priv.PublicKey

	t.Run("Compressed Form", func(t *testing.T) {
		data, err := pub.UncompressedEncode()
		if nil != err {
			t.Fatal(err)
		}

		pubDec := new(ecdsa.PublicKey)
		if err := pubDec.Parse(pub.Curve, data); nil != err {
			t.Fatal(err)
		}

		testPubKeyEquality(pub, pubDec, t)
	})
	t.Run("Uncompressed Form", func(t *testing.T) {
		data, err := pub.Compress()
		if nil != err {
			t.Fatal(err)
		}

		pubDec := new(ecdsa.PublicKey)
		if err := pubDec.Parse(pub.Curve, data); nil != err {
			t.Fatal(err)
		}

		testPubKeyEquality(pub, pubDec, t)
	})
}

func TestPubKeyUncompressedEncoding(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256k1(), rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	pub := &priv.PublicKey
	data, err := pub.UncompressedEncode()
	if nil != err {
		t.Fatal(err)
	}

	//t.Logf("%+v\n", pub)
	//t.Logf("   X: %x\n", pub.X.Bytes())
	//t.Logf("   Y: %x\n", pub.Y.Bytes())
	//t.Logf("data: %x\n", data)

	pubDec := new(ecdsa.PublicKey)
	if err := pubDec.UncompressedDecode(pub.Curve, data); nil != err {
		t.Fatal(err)
	}

	if 0 != pub.X.Cmp(pubDec.X) {
		t.Fatalf("invalid X: got %x, want %x", pubDec.X.Bytes(), pub.X.Bytes())
	}
	if 0 != pub.Y.Cmp(pubDec.Y) {
		t.Fatalf("invalid Y: got %x, want %x", pubDec.Y.Bytes(), pub.Y.Bytes())
	}
}
