package transport

import (
	"context"
	"fmt"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/p2p/discovery/mdns"
	"personal-net/pkg/identity"
)

type PNetHost struct {
	host.Host
}

type discoveryNotifee struct {
	h host.Host
}

func (n *discoveryNotifee) HandlePeerFound(pi peer.AddrInfo) {
	fmt.Printf("Discovered peer: %s\n", pi.ID.String())
	n.h.Connect(context.Background(), pi)
}

func CreateHost(id *identity.Identity, port int) (*PNetHost, error) {
	priv, err := id.Libp2pPrivKey()
	if err != nil {
		return nil, err
	}

	h, err := libp2p.New(
		libp2p.Identity(priv),
		libp2p.ListenAddrStrings(
			fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", port),
			fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", port),
		),
	)
	if err != nil {
		return nil, err
	}

	dn := &discoveryNotifee{h: h}
	s := mdns.NewMdnsService(h, "pnet-pan", dn)
	if err := s.Start(); err != nil {
		return nil, err
	}

	return &PNetHost{h}, nil
}
