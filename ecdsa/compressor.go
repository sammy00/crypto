package ecdsa

import (
	"errors"
	"math/big"

	"github.com/sammy00/crypto/elliptic"
)

const (
	PublicKeyCompressedLen   = 33
	PublicKeyUncompressedLen = 65
)

const (
	pubKeyCompressed   byte = 0x02 // y bit + x coord
	pubKeyUncompressed byte = 0x04 // x_coord + y_coord
)

type PublicKeyCompressor interface {
	Compress() ([]byte, error)
	Decompress(elliptic.Curve, []byte) error
}

type PublicKeyParser interface {
	Parse(elliptic.Curve, []byte) error
}

type PublicKeyUncompressedCodec interface {
	UncompressedEncode() ([]byte, error)
	UncompressedDecode(elliptic.Curve, []byte) error
}

func IsPublicKeyCompressed(pubKey []byte) bool {
	return (len(pubKey) == PublicKeyCompressedLen) &&
		((pubKey[0] & 0xfe) == pubKeyCompressed)
}

func DecompressPoint(curve elliptic.Curve, x *big.Int, yOdd bool) (*big.Int, error) {
	// only support Koblitz curve now
	//if _, ok := curve.(*elliptic.KoblitzCurve); !ok {
	//	return nil, errors.New("Not supported curve")
	//}

	params := curve.Params()

	// Y = +-sqrt(x^3+B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, params.B)
	x3.Mod(x3, params.P) // normalize x3

	y := new(big.Int).ModSqrt(x3, params.P)

	if isOdd(y) != yOdd {
		y.Sub(params.P, y)
	}
	if isOdd(y) != yOdd {
		return nil, errors.New("oddness of y is wrong")
	}

	return y, nil
}
