// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm.
package ecdsa

// The main purpose of this reimplementation is for decoupling the
// elliptic.Curve from the standard golang library.

// References:
//   [NSA]: Suite B implementer's guide to FIPS 186-3,
//     http://www.nsa.gov/ia/_files/ecdsa.pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf

import (
	"crypto"
	"encoding/asn1"
	"io"
	"math/big"

	"github.com/sammy00/crypto/elliptic"
)

// one is the identity element in the field
var one = new(big.Int).SetInt64(1)

// PrivateKey represents an ECDSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int // private scalar
}

// ecdsaSignature assists in marshaling the signature
type ecdsaSignature struct {
	R, S *big.Int
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Sign signs digest with priv, reading randomness from rand. The opts argument
// is not currently used but, in keeping with the crypto.Signer interface,
// should be the hash function used to digest the message.
//
// This method implements crypto.Signer, which is an interface to support keys
// where the private part is kept in, for example, a hardware module. Common
// uses should use the Sign function in this package directly.
func (priv *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	r, s, err := Sign(rand, priv, digest)
	if nil != err {
		return nil, err
	}

	return asn1.Marshal(ecdsaSignature{r, s})
}

// GenerateKey generates a public and private key pair.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	k, err := randFieldElement(c, rand)
	if nil != err {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	// pub = k*G
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())

	return priv, nil
}

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	c := priv.PublicKey.Curve
	N := c.Params().N

	var k, kInv *big.Int
	for {
		for {
			k, err = randFieldElement(c, rand)
			if nil != err {
				r, s = nil, nil
				return
			}

			//kInv = new(big.Int).ModInverse(k, N)
			kInv = fermatInverse(k, N)
			r, _ = c.ScalarBaseMult(k.Bytes())
			r.Mod(r, N)
			if 0 != r.Sign() {
				break
			}
		}

		// e = H(m)
		e := hashToInt(hash, c)
		// s = k^{-1}*(e+r*d)
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kInv)
		s.Mod(s, N)

		if 0 != s.Sign() {
			break
		}
	}

	return r, s, nil
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	// ensure r,s in [1,n-1]
	if (r.Sign() <= 0) || (s.Sign() <= 0) {
		return false
	}
	if (r.Cmp(N) >= 0) || (s.Cmp(N) >= 0) {
		return false
	}

	// e = H(m)
	e := hashToInt(hash, c)
	// w = s^{-1}
	w := new(big.Int).ModInverse(s, N)
	// u1 = e*w
	u1 := e.Mul(e, w)
	u1.Mod(u1, N)
	// u2 = r*w
	u2 := w.Mul(r, w)
	u2.Mod(u2, N)

	x1, y1 := c.ScalarBaseMult(u1.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())

	x, y := c.Add(x1, y1, x2, y2)
	if x.Sign() == 0 && y.Sign() == 0 {
		// (x,y) is the point in the infinity
		return false
	}
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// randFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func randFieldElement(c elliptic.Curve, rand io.Reader) (*big.Int, error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	if _, err := io.ReadFull(rand, b); nil != err {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)

	return k, nil
}
