package elliptic

// Copyright 2010 The Go Authors. All rights reserved.
// Copyright 2018 sammy00. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package operates, internally, on Jacobian coordinates. For a given
// (x, y) position on the curve, the Jacobian coordinates are (x1, y1, z1)
// where x = x1/z1^2 and y = y1/z1^3. The greatest speedups come when the whole
// calculation can be performed within the transform (as in ScalarMult and
// ScalarBaseMult). But even for Add and Double, it's faster to apply and
// reverse the transform than to operate in affine coordinates.

// References:
//   [NSA]: Suite B implementer's guide to FIPS 186-3,
//     http://www.nsa.gov/ia/_files/ecdsa.pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf
//   [SECG]: SECG, SEC2
// 		 http://www.secg.org/sec2-v2.pdf
//   [hyperelliptic.org]
//		 http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html

import (
	"errors"
	"math/big"
	"sync"

	"github.com/sammy00/crypto/misc"
)

var (
	// koblitzInitOncer serves for one-time-only initialization of
	// all internal KoblitzCurve instances
	koblitzInitOncer sync.Once
	// secp256k1 is an unexported KoblitzCurve which can be captured by P256k1()
	secp256k1 *KoblitzCurve
)

// KoblitzCurve embeds the parameters of an elliptic curve and
// also provides a generic, non-constant time implementation of Curve.
// The detail of implementation refers to http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
type KoblitzCurve struct {
	*CurveParams
}

// Add calculates (x1,y1)+(x2,y2) over the curve
func (curve *KoblitzCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	z1 := zForAffine(x1, y1)
	z2 := zForAffine(x2, y2)

	return curve.affineFromJacobian(curve.addJacobian(x1, y1, z1, x2, y2, z2))
}

// DecompressPoint estimates the Y coordinate for the given X coordinate
func (curve *KoblitzCurve) DecompressPoint(x *big.Int, yOdd bool) (*big.Int, error) {
	params := curve.Params()

	// Y = +-sqrt(x^3+B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, params.B)
	x3.Mod(x3, params.P) // normalize x3

	y := new(big.Int).ModSqrt(x3, params.P)

	if misc.IsOdd(y) != yOdd {
		y.Sub(params.P, y)
	}
	if misc.IsOdd(y) != yOdd {
		return nil, errors.New("oddness of y is wrong")
	}

	// check against on curve???

	return y, nil
}

// Double calculates 2*(x,y)
func (curve *KoblitzCurve) Double(x, y *big.Int) (xOut, yOut *big.Int) {
	z := zForAffine(x, y)
	return curve.affineFromJacobian(curve.doubleJacobian(x, y, z))
}

// IsOnCurve checks if the given point (x,y) is on the curve
func (curve *KoblitzCurve) IsOnCurve(x, y *big.Int) bool {
	// y^2 = x^3 + b

	// y^2
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	// rhs = x^3+b
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	rhs.Add(rhs, curve.B)
	rhs.Mod(rhs, curve.P)

	return 0 == rhs.Cmp(y2)
}

// Params returns the parameters specification for this curve
func (curve *KoblitzCurve) Params() *CurveParams {
	return curve.CurveParams
}

// ScalarBaseMult calculates k*G
func (curve *KoblitzCurve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

// ScalarMult estimates k*(x1,y1)
func (curve *KoblitzCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	z1 := new(big.Int).SetInt64(1)
	xx, yy, zz := new(big.Int), new(big.Int), new(big.Int)

	for _, b := range k {
		for i := 0; i < 8; i++ {
			xx, yy, zz = curve.doubleJacobian(xx, yy, zz)
			if 0x80 == (b & 0x80) {
				xx, yy, zz = curve.addJacobian(x1, y1, z1, xx, yy, zz)
			}
			b <<= 1
		}
	}

	//x, y = curve.affineFromJacobian(xx, yy, zz)
	return curve.affineFromJacobian(xx, yy, zz)
}

// addJacobian estimate the sum of two Jacobian point (x1,y1,z1) and (x2,y2,z2)
func (curve *KoblitzCurve) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (x, y, z *big.Int) {
	// http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl
	x, y, z = new(big.Int), new(big.Int), new(big.Int)
	// P + O = P
	if 0 == z1.Sign() {
		x.Set(x2)
		y.Set(y2)
		z.Set(z2)
		return
	}
	if 0 == z2.Sign() {
		x.Set(x1)
		y.Set(y1)
		z.Set(z1)
		return
	}

	// z1^2
	z12 := new(big.Int).Mul(z1, z1)
	z12.Mod(z12, curve.P)
	// z2^2
	z22 := new(big.Int).Mul(z2, z2)
	z22.Mod(z22, curve.P)

	// u1 = x1*z2^2
	u1 := new(big.Int).Mul(x1, z22)
	u1.Mod(u1, curve.P)
	// u2 = x2*z1^2
	u2 := new(big.Int).Mul(x2, z12)
	u2.Mod(u2, curve.P)
	// s1 = y1*z2^3
	s1 := new(big.Int).Mul(y1, z22)
	s1.Mul(s1, z2)
	s1.Mod(s1, curve.P)
	// s2 = y2*z1^3
	s2 := new(big.Int).Mul(y2, z12)
	s2.Mul(s2, z1)
	s2.Mod(s2, curve.P)

	// h = u2-u1
	h := new(big.Int).Sub(u2, u1)
	if -1 == h.Sign() {
		h.Add(h, curve.P) // normalise the field value
	}
	// i = (2*H)^2
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	i.Mod(i, curve.P)
	// j = h*i
	j := new(big.Int).Mul(h, i)
	j.Mod(j, curve.P)
	// r = 2*(s2-s1)
	r := new(big.Int).Sub(s2, s1)
	if -1 == r.Sign() {
		r.Add(r, curve.P)
	}
	r.Lsh(r, 1)
	// v = u1*i
	v := new(big.Int).Mul(u1, i)

	// (x,y,z)
	// x = r^2-j-2*v
	x.Mul(r, r)
	x.Sub(x, j)
	x.Sub(x, v)
	x.Sub(x, v)
	x.Mod(x, curve.P)
	// y = r*(v-x3)-2*s1*j
	v.Sub(v, x)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y.Mul(r, v)
	y.Sub(y, s1)
	y.Mod(y, curve.P)
	// z = ((z1+z2)^2-z1^2-z2^2)*h
	z.Add(z1, z2)
	z.Mul(z, z)
	z.Sub(z, z12)
	z.Sub(z, z22)
	z.Mul(z, h)
	z.Mod(z, curve.P)

	return
}

// affineFromJacobian reverses the Jacobian transform. See the comment at the
// top of the file. In case of point at the infinity, it returns (0,0).
func (curve *KoblitzCurve) affineFromJacobian(x, y, z *big.Int) (xOut, yOut *big.Int) {
	xOut, yOut = new(big.Int), new(big.Int)
	// (z,y,z) is the point at the infinity
	if 0 == z.Sign() {
		return
	}

	zInv := new(big.Int).ModInverse(z, curve.P)
	zInv2 := new(big.Int).Mul(zInv, zInv)

	// xOut = x/z^2
	xOut.Mul(x, zInv2)
	xOut.Mod(xOut, curve.P)
	// yOut = y/z^3
	zInv2.Mul(zInv2, zInv)
	yOut.Mul(y, zInv2)
	yOut.Mod(yOut, curve.P)

	return xOut, yOut
}

// doubleJacobian takes a point in Jacobian coordinates, (x, y, z), and
// returns its double, also in Jacobian form.
func (curve *KoblitzCurve) doubleJacobian(x, y, z *big.Int) (xOut, yOut, zOut *big.Int) {
	// see http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
	// A = x^2
	A := new(big.Int).Mul(x, x)
	A.Mod(A, curve.P)
	// B = y^2
	B := new(big.Int).Mul(y, y)
	B.Mod(B, curve.P)
	// CC = B^2 (duplicate C to avoid strange warning)
	CC := new(big.Int).Mul(B, B)
	CC.Mod(CC, curve.P)

	// D = 2*((x+B)^2-A-CC)
	D := new(big.Int).Add(x, B)
	D.Mul(D, D)
	D.Sub(D, A)
	D.Sub(D, CC)
	D.Lsh(D, 1)
	if -1 == D.Sign() {
		D.Add(D, curve.P)
	}
	D.Mod(D, curve.P)
	// E = 3*A
	E := new(big.Int).Lsh(A, 1)
	E.Add(E, A)
	E.Mod(E, curve.P)
	// F = E^2
	F := new(big.Int).Mul(E, E)
	F.Mod(F, curve.P)

	// (xOut,yOut,zOut)
	// xOut = F-2*D
	xOut = new(big.Int).Sub(F, D)
	xOut.Sub(xOut, D)
	xOut.Mod(xOut, curve.P)
	// yOut = E*(D-X3)-8*C
	yOut = new(big.Int).Sub(D, xOut)
	yOut.Mul(E, yOut)
	yOut.Sub(yOut, CC.Lsh(CC, 3))
	yOut.Mod(yOut, curve.P)
	// zOut = 2*y*z
	zOut = new(big.Int).Mul(y, z)
	zOut.Lsh(zOut, 1)
	zOut.Mod(zOut, curve.P)

	return
}

// P256k1 returns the handle of secp256k1
func P256k1() Curve {
	koblitzInitOncer.Do(initAll)
	return secp256k1
}

func initAll() {
	initP256K1()
}

func initP256K1() {
	secp256k1 = new(KoblitzCurve)

	params := &CurveParams{
		Name: "secp256k1",
	}
	params.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	params.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	params.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	params.Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	params.Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	params.BitSize = 256

	secp256k1.CurveParams = params
}

// zForAffine returns a Jacobian Z value for the affine point (x, y). If x and
// y are zero, it assumes that they represent the point at infinity because (0,
// 0) is not on the any of the curves handled here.
func zForAffine(x, y *big.Int) *big.Int {
	z := new(big.Int)
	// (x,y) isn't the point at the infinity
	if (0 != x.Sign()) || (0 != y.Sign()) {
		z.SetInt64(1)
	}

	return z
}
