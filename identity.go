package goidentity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path"
)

type Credentials struct {
	DefaultProfileName string
	CredentialsFile    string
}

func NewCredentials(packageName string) *Credentials {
	return &Credentials{
		DefaultProfileName: "default",
		CredentialsFile:    path.Join("."+packageName, "credentials.json"),
	}
}

func (c *Credentials) CreateKey(profileName string, keyType string) (*Profile, error) {
	if profileName == "" {
		profileName = c.DefaultProfileName
	}

	var privateKey crypto.PrivateKey
	var err error

	switch keyType {
	case "ed25519":
		_, privateKey, err = ed25519.GenerateKey(rand.Reader)
	case "p256":
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, errors.New("unsupported key type, expected one of: ed25519, p256, p384, p521")
	}
	if err != nil {
		return nil, err
	}

	// TODO: Encryption

	var privateKeyBytes []byte
	if ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey); ok {
		privateKeyBytes = []byte(ed25519PrivateKey)
	} else if ecdsaPrivateKey, ok := privateKey.(*ecdsa.PrivateKey); ok {
		privateKeyBytes = ecdsaPrivateKey.D.Bytes()
	}

	profile := &Profile{
		KeyType:    keyType,
		Name:       profileName,
		PrivateKey: privateKeyBytes,
	}

	if err := c.saveProfile(profile); err != nil {
		return nil, err
	}

	return profile, nil
}

func (c *Credentials) LoadKey(profileName string) (*Profile, error) {
	if profileName == "" {
		profileName = c.DefaultProfileName
	}

	profile, err := c.loadProfile(profileName)
	if err != nil {
		return nil, err
	}

	// TODO: Decryption

	return profile, nil
}

func (c *Credentials) ListProfiles() ([]string, error) {
	profilesMap, err := c.loadProfiles()
	if err != nil {
		return nil, err
	}

	var profileNames []string
	for profileName := range profilesMap {
		profileNames = append(profileNames, profileName)
	}

	return profileNames, nil
}

func (c *Credentials) GetKeyPair(profileName string) (crypto.PrivateKey, crypto.PublicKey, error) {
	profile, err := c.LoadKey(profileName)
	if err != nil {
		return nil, nil, err
	}
	return profile.getPrivateKey(), profile.getPublicKey(), nil
}
