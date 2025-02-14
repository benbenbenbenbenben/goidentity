package goidentity

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type KeyBytes []byte

type Identity struct {
	PublicKey KeyBytes `json:"public_key"` // Raw public key
	KeyType   string   `json:"key_type"`   // Key type (e.g., "ed25519", "p256")
}

func (i *Identity) getPublicKey() crypto.PublicKey {
	if i.KeyType == "ed25519" {
		return ed25519.PublicKey(i.PublicKey)
	}
	switch i.KeyType {
	case "p256":
		if publicKey, err := ecdh.P256().NewPublicKey(i.PublicKey); err == nil {
			return publicKey
		}
	case "p384":
		if publicKey, err := ecdh.P384().NewPublicKey(i.PublicKey); err == nil {
			return publicKey
		}
	case "p521":
		if publicKey, err := ecdh.P521().NewPublicKey(i.PublicKey); err == nil {
			return publicKey
		}
	}
	panic("unsupported key type: " + i.KeyType)
}

type Profile struct {
	Name       string   `json:"name"`        // Profile name
	KeyType    string   `json:"key_type"`    // Key type (e.g., "ed25519", "p256")
	PrivateKey KeyBytes `json:"private_key"` // Raw private key
}

func (p *Profile) Identity() *Identity {
	publicKey := p.getPublicKeyBytes()
	return &Identity{
		KeyType:   p.KeyType,
		PublicKey: publicKey,
	}
}

func (p *Profile) getPublicKey() crypto.PublicKey {
	privateKey := p.getPrivateKey()
	switch p.KeyType {
	case "ed25519":
		return privateKey.(ed25519.PrivateKey).Public()
	case "p256", "p384", "p521":
		ecdsa, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			ecdh, ok := privateKey.(*ecdh.PrivateKey)
			if !ok {
				panic("key with type " + p.KeyType + " is not an *ecdsa.PrivateKey or *ecdh.PrivateKey")
			}
			return ecdh.Public()
		}
		return ecdsa.PublicKey
	}
	panic("unsupported key type: " + p.KeyType)
}

func (p *Profile) getPublicKeyBytes() KeyBytes {
	publicKey := p.getPublicKey()
	switch p.KeyType {
	case "ed25519":
		bytes, ok := publicKey.(ed25519.PublicKey)
		if ok {
			return KeyBytes(bytes)
		}
	case "p256", "p384", "p521":
		if ec, ok := publicKey.(*ecdsa.PublicKey); ok {
			return KeyBytes(ec.X.Bytes())
		}
		if ecdh, ok := publicKey.(*ecdh.PublicKey); ok {
			return KeyBytes(ecdh.Bytes())
		}
		panic("key with type " + p.KeyType + " is not an *ecdsa.PublicKey or *ecdh.PublicKey")
	}
	panic("unsupported key type: " + p.KeyType)
}

func (p *Profile) getPrivateKey() crypto.PrivateKey {
	if p.KeyType == "ed25519" {
		return ed25519.PrivateKey(p.PrivateKey)
	}

	// we need to reconstruct the private key
	var privateKey crypto.PrivateKey
	var err error
	switch p.KeyType {
	case "p256":
		privateKeyFixedWidth := make([]byte, 32)
		copy(privateKeyFixedWidth, p.PrivateKey)
		privateKey, err = ecdh.P256().NewPrivateKey(privateKeyFixedWidth)
	case "p384":
		privateKeyFixedWidth := make([]byte, 48)
		copy(privateKeyFixedWidth, p.PrivateKey)
		privateKey, err = ecdh.P384().NewPrivateKey(privateKeyFixedWidth)
	case "p521":
		privateKeyFixedWidth := make([]byte, 66)
		copy(privateKeyFixedWidth, p.PrivateKey)
		privateKey, err = ecdh.P521().NewPrivateKey(privateKeyFixedWidth)
	default:
		panic("unsupported key type: " + p.KeyType)
	}
	if err != nil {
		panic(err)
	}
	return privateKey
}

func (c *Credentials) credentialsPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, c.CredentialsFile), nil
}

func (c *Credentials) saveProfile(profile *Profile) error {
	path, err := c.credentialsPath()
	if err != nil {
		return err
	}

	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		os.MkdirAll(filepath.Dir(path), 0700)
	}

	profiles, err := c.loadProfiles()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if profiles == nil {
		profiles = make(map[string]*Profile)
	}

	profiles[profile.Name] = profile

	data, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func (c *Credentials) loadProfile(profileName string) (*Profile, error) {
	profiles, err := c.loadProfiles()
	if err != nil {
		return nil, err
	}

	profile, ok := profiles[profileName]
	if !ok {
		return nil, errors.New("profile not found")
	}

	return profile, nil
}

func (c *Credentials) loadProfiles() (map[string]*Profile, error) {
	path, err := c.credentialsPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var profiles = make(map[string]*Profile)
	err = json.Unmarshal(data, &profiles)
	if err != nil {
		return nil, err
	}

	return profiles, nil
}
