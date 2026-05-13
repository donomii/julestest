package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"personal-net/pkg/identity"

	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/nacl/secretbox"
)

type PeerInfo struct {
	PublicKey ed25519.PublicKey
	PeerID    peer.ID
}

func GenerateLinkCode() (string, error) {
	b := make([]byte, 8) // Longer code for better security
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

	// Derive a 32-byte key from the link code
	key := sha256.Sum256([]byte(code))

	// Receive encrypted public key from peer
	remotePub, err := receiveEncrypted(conn, &key)
	if err != nil {
		return nil, err
	}

	// Send our encrypted public key
	if err := sendEncrypted(conn, &key, id.PublicKey); err != nil {
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

	return []PeerInfo{{PublicKey: remotePub, PeerID: pid}}, nil
}

func JoinPairing(id *identity.Identity, code string, addr string) (*PeerInfo, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	key := sha256.Sum256([]byte(code))

	// Send our encrypted public key
	if err := sendEncrypted(conn, &key, id.PublicKey); err != nil {
		return nil, err
	}

	// Receive encrypted public key from peer
	remotePub, err := receiveEncrypted(conn, &key)
	if err != nil {
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

func sendEncrypted(w io.Writer, key *[32]byte, data []byte) error {
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}

	out := secretbox.Seal(nonce[:], data, &nonce, key)
	_, err := w.Write(out)
	return err
}

func receiveEncrypted(r io.Reader, key *[32]byte) ([]byte, error) {
	// secretbox.Overhead is 16. ed25519.PublicKeySize is 32. Nonce is 24.
	// Total expected: 24 + 32 + 16 = 72
	buf := make([]byte, 72)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	var nonce [24]byte
	copy(nonce[:], buf[:24])

	decrypted, ok := secretbox.Open(nil, buf[24:], &nonce, key)
	if !ok {
		return nil, fmt.Errorf("decryption failed (likely invalid link code)")
	}
	return decrypted, nil
}
