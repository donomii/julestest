package discovery

import (
	"context"
	"testing"
	"time"
)

func TestDiscovery(t *testing.T) {
	id := "test-node"
	port := 12345

	server, err := Advertise(id, port)
	if err != nil {
		t.Fatalf("failed to advertise: %v", err)
	}
	defer server.Shutdown()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodeCh, err := Discover(ctx)
	if err != nil {
		t.Fatalf("failed to start discovery: %v", err)
	}

	select {
	case node := <-nodeCh:
		if node.ID != id {
			t.Errorf("expected ID %s, got %s", id, node.ID)
		}
		if node.Port != port {
			t.Errorf("expected port %d, got %d", port, node.Port)
		}
	case <-ctx.Done():
		t.Error("timed out waiting for discovery")
	}
}
