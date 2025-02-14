package goidentity

import (
	"encoding/hex"
	"os"
	"path"
	"testing"
)

func TestSignAndVerify(t *testing.T) {

	t.Cleanup(func() {
		h, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		if err = os.RemoveAll(path.Join(h, ".acme-test-package-signverify")); err != nil {
			t.Fatal(err)
		}
	})

	var alices []*Profile
	var bobs []*Profile
	cred := NewCredentials("acme-test-package-signverify")
	for _, keyType := range []string{"ed25519", "p256", "p384", "p521"} {
		alice, _ := cred.CreateKey(keyType+"_alice", keyType)
		bob, _ := cred.CreateKey(keyType+"_bob", keyType)
		alices = append(alices, alice)
		bobs = append(bobs, bob)
	}

	for i, alice := range alices {
		bob := bobs[i]

		data := []byte("hello, world")

		signature, err := alice.Sign(data)
		if err != nil {
			t.Fatal("key type:", alice.KeyType, "unexpected error:", err)
		}

		hexSignature := hex.EncodeToString(signature)
		t.Log("key type:", alice.KeyType, "signature:", hexSignature)
		err = alice.Identity().Verify(data, signature)
		if err != nil {
			t.Fatal("key type:", alice.KeyType, "unexpected error:", err)
		}

		err = bob.Identity().Verify(data, signature)
		if err == nil {
			t.Fatal("expected error, but alice signed and bob verified")
		}
	}

}
