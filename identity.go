package goidentity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path"
	"path/filepath"
	"time"
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

func (profile *Profile) GenerateCertificate() (*x509.Certificate, error) {
	privateKeyBlock, _ := pem.Decode(profile.PrivateKey)
	if privateKeyBlock == nil {
		return nil, errors.New("failed to decode private key PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	publicKeyBlock, _ := pem.Decode(profile.PublicKey)
	if publicKeyBlock == nil {
		return nil, errors.New("failed to decode public key PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.Unix()),
		Subject: pkix.Name{
			Organization: []string{"GoIdentity"},
			CommonName:   profile.Name,
		},
		Issuer: pkix.Name{
			Organization: []string{"GoIdentity"},
			CommonName:   "GoIdentity Root CA", // Or make it configurable
		},
		NotBefore:             now.Add(-time.Hour * 24 * 30), // Valid from 30 days ago
		NotAfter:              now.Add(time.Hour * 24 * 365 * 5),  // Valid for 5 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true, // For now, making it a CA for simplicity
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
