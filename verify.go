package goidentity

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
)

func (i Identity) Verify(data []byte, signature []byte) error {
	publicKey := i.getPublicKey()
	switch i.KeyType {
	case "ed25519":
		ed25519PublicKey := publicKey.(ed25519.PublicKey)
		valid := ed25519.Verify(ed25519PublicKey, data, signature)
		if !valid {
			return errors.New("invalid signature")
		}
		return nil
	case "p256", "p384", "p521":
		if ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey); !ok {
			if ecdhPublicKey, ok := publicKey.(*ecdh.PublicKey); !ok {
				return errors.New("key with type " + i.KeyType + " is not an *ecdsa.PublicKey or *ecdh.PublicKey")
			} else {
				ecdsaPublicKey := new(ecdsa.PublicKey)
				switch i.KeyType {
				case "p256":
					ecdsaPublicKey.Curve = elliptic.P256()
				case "p384":
					ecdsaPublicKey.Curve = elliptic.P384()
				case "p521":
					ecdsaPublicKey.Curve = elliptic.P521()
				}
				size := (len(ecdhPublicKey.Bytes()) - 1) / 2
				x := new(big.Int).SetBytes(ecdhPublicKey.Bytes()[1 : size+1])
				y := new(big.Int).SetBytes(ecdhPublicKey.Bytes()[size+1:])
				ecdsaPublicKey.X = x
				ecdsaPublicKey.Y = y

				hashed := sha256.Sum256(data)
				valid := ecdsa.VerifyASN1(ecdsaPublicKey, hashed[:], signature)
				if !valid {
					return errors.New("invalid signature")
				}
				return nil
			}
		} else {
			hashed := sha256.Sum256(data)
			valid := ecdsa.VerifyASN1(ecdsaPublicKey, hashed[:], signature)
			if !valid {
				return errors.New("invalid signature")
			}
		}
	default:
		return errors.New("unsupported key type")
	}
	return errors.New("unexpected error")
}
