package main

import (
	"os"
	"path"
	"testing"
)

func TestNewCredentials(t *testing.T) {
	t.Cleanup(func() {
		h, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.RemoveAll(path.Join(h, ".acme-test-package")); err != nil {
			t.Fatal(err)
		}
	})
	packageName := "acme-test-package"
	creds := NewCredentials(packageName)

	if creds.CredentialsFile != ".acme-test-package/credentials.json" {
		t.Errorf("NewCredentials(%q) CredentialsFile = %q, want %q", packageName, creds.CredentialsFile, "acme-test-package/credentials.json")
	}

	if creds.DefaultProfileName != "default" {
		t.Errorf("NewCredentials(%q) DefaultProfileName = %q, want %q", packageName, creds.DefaultProfileName, "default")
	}

	if _, err := creds.loadProfile("default"); err == nil {
		t.Errorf("loadProfile(%q) = nil, want error", "default")
	}

	if _, err := creds.loadProfile("nonexistent"); err == nil {
		t.Errorf("loadProfile(%q) = nil, want error", "nonexistent")
	}

	if _, err := creds.ListProfiles(); err == nil {
		t.Errorf("ListProfiles() = nil, want error")
	}

	// Now install

	validKeyTypes := []string{"ed25519", "p224", "p256", "p384", "p521"}
	for _, keyType := range validKeyTypes {
		if _, err := creds.CreateKey(keyType, keyType); err != nil {
			t.Errorf("CreateKey(%q) = %v, want nil", keyType, err)
		}
	}

	invalidKeyTypes := []string{"rsa", "dsa", "ecdsa", "ed448"}
	for _, keyType := range invalidKeyTypes {
		if _, err := creds.CreateKey(keyType, keyType); err == nil {
			t.Errorf("CreateKey(%q) = nil, want error", keyType)
		}
	}

	// Now list

	profiles, err := creds.ListProfiles()
	if err != nil {
		t.Errorf("ListProfiles() = %v, want nil", err)
	}
	if profiles == nil {
		t.Errorf("ListProfiles() = nil, want non-nil")
	}
	if len(profiles) != len(validKeyTypes) {
		t.Errorf("ListProfiles() = %d, want %d", len(profiles), len(validKeyTypes))
	}
}
