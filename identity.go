package goidentity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path"
	"path/filepath"
)

type Credentials struct {
	DefaultProfileName string
	CredentialsFile    string
}

type Profile struct {
	Name       string `json:"name"`        // Profile name
	PrivateKey []byte `json:"private_key"` // Encoded private key
	PublicKey  []byte `json:"public_key"`  // Encoded public key (optional, can be derived from private key)
	KeyType    string `json:"key_type"`    // Key type (e.g., "ed25519", "p256")
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
	case "p224":
		privateKey, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	case "p256":
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "p384":
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "p521":
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	default:
		return nil, errors.New("unsupported key type, expected one of: ed25519, p224, p256, p384, p521")
	}
	if err != nil {
		return nil, err
	}

	// TODO: Encryption

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)

	var publicKeyBytes []byte
	switch keyType {
	case "ed25519":
		publicKey := privateKey.(ed25519.PrivateKey).Public()
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(publicKey)
	case "p224":
	case "p256":
	case "p384":
	case "p521":
		publicKey := privateKey.(*ecdsa.PrivateKey).Public()
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(publicKey)
	}
	if err != nil {
		return nil, err
	}

	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)

	profile := &Profile{
		Name:       profileName,
		PrivateKey: privateKeyPEM,
		PublicKey:  publicKeyPEM,
		KeyType:    keyType,
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

	block, _ := pem.Decode(profile.PrivateKey)
	if block == nil {
		return nil, nil, errors.New("failed to parse PEM block containing the private key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	var publicKey crypto.PublicKey
	block, _ = pem.Decode(profile.PublicKey)
	if block == nil {
		return nil, nil, errors.New("failed to parse PEM block containing the public key")
	}

	publicKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
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
