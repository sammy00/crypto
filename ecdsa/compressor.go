package ecdsa

import (
	"github.com/sammy00/crypto/elliptic"
)

const (
	// PublicKeyCompressedLen specifies the length in bytes of pubkey in compressed form
	PublicKeyCompressedLen = 33
	// PublicKeyUncompressedLen specifies the length in bytes of pubkey in uncompressed form
	PublicKeyUncompressedLen = 65
)

const (
	pubKeyCompressed   byte = 0x02 // prefix of the compressed pubkey: y bit + x coord
	pubKeyUncompressed byte = 0x04 // prefix of the uncompressed pubkey: x_coord + y_coord
)

// PublicKeyCompressor specifies the compression/uncompression interface for
// our ecdsa.PublicKey
type PublicKeyCompressor interface {
	// Compress returns a byte slice representing the compression of the
	// receiver (i.e., a PublicKey) for transmission, usually of the same
	// concrete type.
	Compress() ([]byte, error)
	// Decompress overwrites the receiver, which must be a pointer,
	// by parsing the value represented by the byte slice, which was written
	// by Compress(), usually for the same concrete type,
	// and the elliptic curve will be initialised with the elliptic.Curve provided
	Decompress(elliptic.Curve, []byte) error
}

// PublicKeyParser specifies a parser for public key,
// which can take in a byte sequence corresponding to some compressed
// or uncompressed public key
type PublicKeyParser interface {
	// Parse overwrites the receiver, which must be a pointer,
	// by parsing the value represented by the byte slice, which was written
	// by PublicKeyCompressor.Compress() or
	// PublicKeyUncompressedCodec.UncompressedEncode, usually for the
	// same concrete type.
	// And the elliptic curve of the receiver will be initialised with the
	// elliptic.Curve provided, which will helps to valid if the parsed point
	// is on the curve
	Parse(elliptic.Curve, []byte) error
}

// PublicKeyUncompressedCodec specifies a common api for encoding/decoding
// ecdsa.PublicKey into uncompressed form
type PublicKeyUncompressedCodec interface {
	// UncompressedEncode returns a byte slice representing the EC point of the
	// receiver (i.e., a PublicKey) for transmission, usually of the same
	// concrete type.
	UncompressedEncode() ([]byte, error)
	// UncompressedDecode overwrites the receiver, which must be a pointer,
	// by parsing the value represented by the byte slice, which was written
	// by UncompressedEncode(), usually for the same concrete type.
	// And the elliptic curve of the receiver will be initialised with the
	// elliptic.Curve provided
	UncompressedDecode(elliptic.Curve, []byte) error
}

// IsPublicKeyCompressed checks if a byte sequence representing
// a public key in compressed form
func IsPublicKeyCompressed(pubKey []byte) bool {
	return (len(pubKey) == PublicKeyCompressedLen) &&
		((pubKey[0] & 0xfe) == pubKeyCompressed)
}
