package secp256k1_test

import (
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec"
	"github.com/sammy00/crypto/ecdsa"
	"github.com/sammy00/crypto/elliptic"
)

func publicKeyFromBTC2Local(priv *btcec.PublicKey) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: elliptic.P256k1(),
		X:     priv.X,
		Y:     priv.Y,
	}
}

func publicKeyFromLocal2BTC(pub *ecdsa.PublicKey) *btcec.PublicKey {
	return &btcec.PublicKey{
		Curve: btcec.S256(),
		X:     pub.X,
		Y:     pub.Y,
	}
}

func TestBTCSecp256k1(t *testing.T) {
	priv, err := btcec.NewPrivateKey(btcec.S256())
	if nil != err {
		t.Fatal(err)
	}

	msg := "test message"
	digest := sha256.Sum256([]byte(msg))

	sig, err := priv.Sign(digest[:])
	if nil != err {
		t.Fatal(err)
	}

	pub := btcec.PublicKey(priv.PublicKey)
	if !sig.Verify(digest[:], &pub) {
		t.Fatal("Verification failed")
	}
}

// TestSecp256k1LocalAgainstBTC1 check if the local
// secp256k1 can verify the signature by btcec
func TestSecp256k1LocalAgainstBTC1(t *testing.T) {
	numItr := (1 << 16)
	if testing.Short() {
		numItr = 256
	}

	for i := numItr; i >= 0; i-- {
		privBTC, err := btcec.NewPrivateKey(btcec.S256())
		if nil != err {
			t.Fatal(err)
		}

		msg := "test message"
		digest := sha256.Sum256([]byte(msg))

		sig, err := privBTC.Sign(digest[:])
		if nil != err {
			t.Fatal(err)
		}

		pubLocal := publicKeyFromBTC2Local(privBTC.PubKey())
		if !ecdsa.Verify(pubLocal, digest[:], sig.R, sig.S) {
			t.Fatal("Signature by the secp256k1 if the btcec package" +
				" cannot be verified by that of local ECDSA package ")
		}
	}
}

// TestSecp256k1LocalAgainstBTC1 check if the secp256k1
// by the official btcec package can verify the signature
// by our local secp256k1
func TestSecp256k1LocalAgainstBTC2(t *testing.T) {
	numItr := (1 << 16)
	if testing.Short() {
		numItr = 256
	}

	koblitzCurve := elliptic.P256k1()
	msg := "test message"
	digest := sha256.Sum256([]byte(msg))

	for i := numItr; i >= 0; i-- {
		privLocal, err := ecdsa.GenerateKey(koblitzCurve, rand.Reader)
		if nil != err {
			t.Fatal(err)
		}

		r, s, err := ecdsa.Sign(rand.Reader, privLocal, digest[:])
		if nil != err {
			t.Fatal(err)
		}

		sig := &btcec.Signature{
			R: r,
			S: s,
		}

		pubBTC := publicKeyFromLocal2BTC(&privLocal.PublicKey)
		if !sig.Verify(digest[:], pubBTC) {
			t.Fatal("Signature by secp256k1 of the local ECDSA package" +
				" cannot be verified by that of the btcec package")
		}
	}
}
