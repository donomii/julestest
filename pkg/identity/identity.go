package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func GenerateIdentity() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}

func (id *Identity) Fingerprint() string {
	return hex.EncodeToString(id.PublicKey)
}

func SaveIdentity(id *Identity, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	privHex := hex.EncodeToString(id.PrivateKey)
	return os.WriteFile(path, []byte(privHex), 0600)
}

func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	privBytes, err := hex.DecodeString(string(data))
	if err != nil {
		return nil, err
	}

	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size")
	}

	priv := ed25519.PrivateKey(privBytes)
	pub := priv.Public().(ed25519.PublicKey)

	return &Identity{
		PrivateKey: priv,
		PublicKey:  pub,
	}, nil
}
