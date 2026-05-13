package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"personal-net/pkg/identity"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/skip2/go-qrcode"
)

type PeerInfo struct {
	PublicKey ed25519.PublicKey
	PeerID    peer.ID
}

func GenerateLinkCode() (string, error) {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func DisplayQRCode(data string) {
	q, err := qrcode.New(data, qrcode.Medium)
	if err != nil {
		fmt.Printf("Failed to generate QR code: %v\n", err)
		return
	}
	fmt.Println(q.ToSmallString(false))
}

func HandlePairing(id *identity.Identity, code string, port int) ([]PeerInfo, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	defer ln.Close()

	conn, err := ln.Accept()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 1. Receive code
	receivedCode := make([]byte, len(code))
	if _, err := io.ReadFull(conn, receivedCode); err != nil {
		return nil, err
	}
	if string(receivedCode) != code {
		return nil, fmt.Errorf("invalid link code")
	}

	// 2. Exchange public keys
	if _, err := conn.Write(id.PublicKey); err != nil {
		return nil, err
	}

	remotePubBytes := make([]byte, ed25519.PublicKeySize)
	if _, err := io.ReadFull(conn, remotePubBytes); err != nil {
		return nil, err
	}
	remotePub := ed25519.PublicKey(remotePubBytes)

	// Derive PeerID
	libp2pPub, err := libp2pcrypto.UnmarshalEd25519PublicKey(remotePub)
	if err != nil {
		return nil, err
	}
	pid, err := peer.IDFromPublicKey(libp2pPub)
	if err != nil {
		return nil, err
	}

	return []PeerInfo{{PublicKey: remotePub, PeerID: pid}}, nil
}

func JoinPairing(id *identity.Identity, code string, addr string) (*PeerInfo, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 1. Send code
	if _, err := conn.Write([]byte(code)); err != nil {
		return nil, err
	}

	// 2. Exchange public keys
	remotePubBytes := make([]byte, ed25519.PublicKeySize)
	if _, err := io.ReadFull(conn, remotePubBytes); err != nil {
		return nil, err
	}
	remotePub := ed25519.PublicKey(remotePubBytes)

	if _, err := conn.Write(id.PublicKey); err != nil {
		return nil, err
	}

	// Derive PeerID
	libp2pPub, err := libp2pcrypto.UnmarshalEd25519PublicKey(remotePub)
	if err != nil {
		return nil, err
	}
	pid, err := peer.IDFromPublicKey(libp2pPub)
	if err != nil {
		return nil, err
	}

	return &PeerInfo{PublicKey: remotePub, PeerID: pid}, nil
}
