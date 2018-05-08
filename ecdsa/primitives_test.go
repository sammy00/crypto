package ecdsa_test

import (
	"crypto/rand"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/sammy00/crypto/ecdsa"
	"github.com/sammy00/crypto/elliptic"
	"golang.org/x/crypto/sha3"
)

// ecdsaSig serves for testing ANS1 marshaling in signing/verification with private keys
type ecdsaSig struct {
	R, S *big.Int
}

func TestSECP256K1(t *testing.T) {
	t.Run("secp256k1", func(t *testing.T) {
		testKeyGeneration(t, elliptic.P256k1())
	})
}

func TestSignAndVerify(t *testing.T) {
	t.Run("secp256k1", func(t *testing.T) {
		testSignAndVerify(t, elliptic.P256k1())
	})
}

func TestSignAndVerifyWithASN1(t *testing.T) {
	// configure the parameters for curves
	curve := elliptic.P256k1()
	// generate the priv-pub key pairs
	privKey, err := ecdsa.GenerateKey(curve, rand.Reader)

	msg := []byte("Hello World")
	// get the message digest, a.k.a. its digest
	digest := sha3.Sum256(msg)

	// sign the message with the key and
	// get the signature encoded according to ASN1
	asn1Sig, err := privKey.Sign(rand.Reader, digest[:], nil)
	if nil != err {
		t.Fatal(err)
	}

	// unmarshal the signature for verification
	var decodedSig ecdsaSig
	if _, err := asn1.Unmarshal(asn1Sig, &decodedSig); nil != err {
		t.Fatal(err)
	}

	// verify the signature (r,s) on the digest
	// by the corresponding public key
	if !ecdsa.Verify(&privKey.PublicKey, digest[:], decodedSig.R, decodedSig.S) {
		t.Fatal("the signature should be valid")
	}
}

func TestZeroHashSignature(t *testing.T) {
	zeros := make([]byte, 64)

	curves := map[string]elliptic.Curve{
		"secp256k1": elliptic.P256k1(),
	}

	for k, v := range curves {
		t.Run(k, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(v, rand.Reader)
			if nil != err {
				t.Fatal(err)
			}

			// signa a digest consisting of all 0
			r, s, err := ecdsa.Sign(rand.Reader, priv, zeros)
			if nil != err {
				t.Fatal(err)
			}

			// confirm the signature can be verified
			if !ecdsa.Verify(&priv.PublicKey, zeros, r, s) {
				t.Errorf("signature for zero digest verfication failed for %s", k)
			}
		})
	}
}

func testKeyGeneration(t *testing.T, c elliptic.Curve) {
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	if !c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y) {
		t.Error("The generate public key should be on curve")
	}
}

func testSignAndVerify(t *testing.T, c elliptic.Curve) {
	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if nil != err {
		t.Fatal(err)
	}

	msg := []byte("testing")
	r, s, err := ecdsa.Sign(rand.Reader, priv, msg)
	if nil != err {
		t.Fatal(err)
	}

	if !ecdsa.Verify(&priv.PublicKey, msg, r, s) {
		t.Fatal("verification should pass")
	}

	msg[0] = ^msg[0]
	if ecdsa.Verify(&priv.PublicKey, msg, r, s) {
		t.Fatal("verification should fail")
	}
}
