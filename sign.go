package goidentity

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
)

func (p Profile) Sign(data []byte) ([]byte, error) {
	privateKey := p.getPrivateKey()
	switch p.KeyType {
	case "ed25519":
		edPrivateKey, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("key with type ed25519 is not an ed25519.PrivateKey")
		}
		signature := ed25519.Sign(edPrivateKey, data)
		return signature, nil
	case "p256", "p384", "p521":
		ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			ecdhPrivateKey, ok := privateKey.(*ecdh.PrivateKey)
			if !ok {
				return nil, errors.New("key with type " + p.KeyType + " is not an *ecdsa.PrivateKey or *ecdh.PrivateKey")
			}
			switch p.KeyType {
			case "p256":
				ecdsaPrivateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				case "p384":
				ecdsaPrivateKey, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				case "p521":
				ecdsaPrivateKey, _ = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			}
			ecdsaPrivateKey.D.SetBytes(ecdhPrivateKey.Bytes())
		}
		hashed := sha256.Sum256(data)
		signature, err := ecdsa.SignASN1(rand.Reader, ecdsaPrivateKey, hashed[:])
		if err != nil {
			return nil, err
		}
		return signature, nil
	default:
		return nil, errors.New("unsupported key type")
	}
}
