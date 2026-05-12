package pairing

import (
	"crypto/ed25519"
	"fmt"
	"personal-net/pkg/identity"
	"testing"
	"time"
)

func TestPairing(t *testing.T) {
	id1, _ := identity.GenerateIdentity()
	id2, _ := identity.GenerateIdentity()
	code := "testcode"
	port := 9999

	errCh := make(chan error, 1)
	var remotePub2 ed25519.PublicKey

	go func() {
		pubs, err := HandlePairing(id1, code, port)
		if err != nil {
			errCh <- err
			return
		}
		remotePub2 = pubs[0]
		errCh <- nil
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	remotePub1, err := JoinPairing(id2, code, fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatalf("JoinPairing failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("HandlePairing failed: %v", err)
	}

	if !id1.PublicKey.Equal(remotePub1) {
		t.Errorf("public key mismatch for id1")
	}

	if !id2.PublicKey.Equal(remotePub2) {
		t.Errorf("public key mismatch for id2")
	}
}
