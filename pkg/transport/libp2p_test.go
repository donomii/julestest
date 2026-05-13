package transport

import (
	"context"
	"personal-net/pkg/identity"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
)

func TestLibp2pHost(t *testing.T) {
	id1, _ := identity.GenerateIdentity()
	id2, _ := identity.GenerateIdentity()

	h1, err := CreateHost(id1, 0)
	if err != nil {
		t.Fatalf("failed to create host 1: %v", err)
	}
	defer h1.Close()

	h2, err := CreateHost(id2, 0)
	if err != nil {
		t.Fatalf("failed to create host 2: %v", err)
	}
	defer h2.Close()

	proto := protocol.ID("/test/1.0.0")
	h2.SetStreamHandler(proto, func(s network.Stream) {
		buf := make([]byte, 4)
		s.Read(buf)
		s.Write([]byte("pong"))
		s.Close()
	})

	// Connect h1 to h2
	h1.Peerstore().AddAddrs(h2.ID(), h2.Addrs(), time.Hour)
	if err := h1.Connect(context.Background(), peer.AddrInfo{ID: h2.ID()}); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	s, err := h1.NewStream(context.Background(), h2.ID(), proto)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer s.Close()

	s.Write([]byte("ping"))
	resp := make([]byte, 4)
	s.Read(resp)

	if string(resp) != "pong" {
		t.Errorf("expected pong, got %s", string(resp))
	}
}
