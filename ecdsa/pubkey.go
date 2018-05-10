package ecdsa

import (
	"errors"
	"math/big"

	"github.com/sammy00/crypto/elliptic"
)

// PublicKey represents an ECDSA public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

func (pub *PublicKey) Compress() ([]byte, error) {
	buf := make([]byte, PublicKeyCompressedLen)

	// 1st byte tells the sign of Y
	buf[0] = pubKeyCompressed
	if isOdd(pub.Y) {
		buf[0] |= 0x01 // make it 3 for an odd Y
	}
	ReverseCopy(buf[1:], pub.X.Bytes())

	return buf, nil
}

func (pub *PublicKey) Decompress(curve elliptic.Curve, data []byte) error {
	if len(data) != PublicKeyCompressedLen {
		return errors.New("Invalid data length")
	}

	if (data[0] & 0xfe) != pubKeyCompressed {
		return errors.New("Invalid format tag")
	}
	yOdd := ((data[0] & 0x01) == 0x01)

	pub.Curve = curve

	pub.X = new(big.Int).SetBytes(data[1:])
	var err error
	pub.Y, err = DecompressPoint(curve, pub.X, yOdd)

	return err
}

func (pub *PublicKey) UncompressedDecode(curve elliptic.Curve, data []byte) error {
	if len(data) != PublicKeyUncompressedLen {
		return errors.New("Invalid data length")
	}

	if pubKeyUncompressed != (data[0] & 0xfe) {
		return errors.New("Invalid format tag")
	}

	pub.Curve = curve

	ell := (PublicKeyUncompressedLen - 1) / 2
	offset := 1
	pub.X = new(big.Int).SetBytes(data[offset:(offset + ell)])
	offset += ell
	pub.Y = new(big.Int).SetBytes(data[offset:])

	return nil
}

func (pub *PublicKey) UncompressedEncode() ([]byte, error) {
	buf := make([]byte, PublicKeyUncompressedLen)
	buf[0] = pubKeyUncompressed

	ell := (PublicKeyUncompressedLen - 1) / 2

	offset := 1
	ReverseCopy(buf[offset:(offset+ell)], pub.X.Bytes())
	offset += ell
	ReverseCopy(buf[offset:(offset+ell)], pub.Y.Bytes())

	return buf, nil
}

func (pub *PublicKey) Parse(curve elliptic.Curve, data []byte) error {
	if len(data) < PublicKeyCompressedLen {
		return errors.New("Invalid data length")
	}

	var err error
	switch data[0] & 0xfe {
	case pubKeyCompressed:
		err = pub.Decompress(curve, data)
	case pubKeyUncompressed:
		err = pub.UncompressedDecode(curve, data)
	default:
		err = errors.New("Invalid format tag")
	}

	if nil == err {
		if !curve.IsOnCurve(pub.X, pub.Y) {
			err = errors.New("The parsed point is off curve")
		}
	}

	return err
}

func ReverseCopy(dst, src []byte) {
	offset := len(dst) - len(src)
	if offset >= 0 {
		copy(dst[offset:], src)
	} else {
		copy(dst, src[-offset:])
	}
}

func isOdd(n *big.Int) bool {
	return 1 == n.Bit(0)
}
