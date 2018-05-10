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
	"io"
	"math/big"

	"github.com/sammy00/crypto/elliptic"
)

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
