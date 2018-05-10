package ecdsa

import (
	"crypto"
	"encoding/asn1"
	"io"
	"math/big"
)

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
