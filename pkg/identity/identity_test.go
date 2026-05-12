package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}
	if len(id.PublicKey) == 0 {
		t.Error("public key is empty")
	}
	if len(id.PrivateKey) == 0 {
		t.Error("private key is empty")
	}
}

func TestSaveAndLoadIdentity(t *testing.T) {
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("failed to generate identity: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "pnet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	keyPath := filepath.Join(tmpDir, "id.key")
	if err := SaveIdentity(id, keyPath); err != nil {
		t.Fatalf("failed to save identity: %v", err)
	}

	loadedId, err := LoadIdentity(keyPath)
	if err != nil {
		t.Fatalf("failed to load identity: %v", err)
	}

	if id.Fingerprint() != loadedId.Fingerprint() {
		t.Errorf("fingerprint mismatch: expected %s, got %s", id.Fingerprint(), loadedId.Fingerprint())
	}
}
