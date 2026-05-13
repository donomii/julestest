package pairing

import (
	"fmt"
	"personal-net/pkg/identity"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
)

func TestPairing(t *testing.T) {
	id1, _ := identity.GenerateIdentity()
	id2, _ := identity.GenerateIdentity()
	code := "testcode"
	port := 9999

	errCh := make(chan error, 1)
	var remotePeer2 peer.ID

	go func() {
		peers, err := HandlePairing(id1, code, port)
		if err != nil {
			errCh <- err
			return
		}
		remotePeer2 = peers[0].PeerID
		errCh <- nil
	}()

	// Wait for server to start
	time.Sleep(100 * time.Millisecond)

	pinfo, err := JoinPairing(id2, code, fmt.Sprintf("localhost:%d", port))
	if err != nil {
		t.Fatalf("JoinPairing failed: %v", err)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("HandlePairing failed: %v", err)
	}

	// Calculate expected PeerIDs
	priv1, _ := id1.Libp2pPrivKey()
	pid1, _ := peer.IDFromPublicKey(priv1.GetPublic())

	priv2, _ := id2.Libp2pPrivKey()
	pid2, _ := peer.IDFromPublicKey(priv2.GetPublic())

	if pid1 != pinfo.PeerID {
		t.Errorf("peer ID mismatch for id1: expected %s, got %s", pid1, pinfo.PeerID)
	}

	if pid2 != remotePeer2 {
		t.Errorf("peer ID mismatch for id2: expected %s, got %s", pid2, remotePeer2)
	}
}
