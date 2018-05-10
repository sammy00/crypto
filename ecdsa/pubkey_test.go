package ecdsa_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/sammy00/crypto/ecdsa"
	"github.com/sammy00/crypto/elliptic"
)

func testPubKeyEquality(pub1, pub2 *ecdsa.PublicKey, t *testing.T) {
	if 0 != pub1.X.Cmp(pub2.X) {
		t.Fatalf("invalid X: got %x, want %x", pub2.X.Bytes(), pub1.X.Bytes())
	}
	if 0 != pub1.Y.Cmp(pub2.Y) {
		t.Fatalf("invalid Y: got %x, want %x", pub2.Y.Bytes(), pub1.Y.Bytes())
	}
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

func TestPubKeyParsing2(t *testing.T) {
	secp256k1Curve := elliptic.P256k1()
	for i, v := range pubKeyTestVec {
		pub := new(ecdsa.PublicKey)
		if err := pub.Parse(secp256k1Curve, v.key); nil != err {
			if v.isValid {
				t.Errorf("#%d: '%s' failure due to: %s\n", i, v.name, err)
			}
			continue
		}
		if !v.isValid {
			t.Errorf("#%d should fail\n", i)
			continue
		}

		var err error
		var data []byte
		switch v.format {
		case PubKeyCompressed:
			data, err = pub.UncompressedEncode()
		case PubKeyUncompressed:
			data, err = pub.Compress()
		}

		if nil != err {
			t.Errorf("#%d fail due to %s\n", i, err)
			continue
		}

		if bytes.Equal(v.key, data) {
			t.Errorf("invalid data: got %x, want %x\n", data, v.key)
		}
	}
}

func TestPubKeyParsing1(t *testing.T) {
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
