package pairing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"personal-net/pkg/identity"

	"github.com/skip2/go-qrcode"
)

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

func HandlePairing(id *identity.Identity, code string, port int) ([]ed25519.PublicKey, error) {
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

	remotePub := make([]byte, ed25519.PublicKeySize)
	if _, err := io.ReadFull(conn, remotePub); err != nil {
		return nil, err
	}

	return []ed25519.PublicKey{ed25519.PublicKey(remotePub)}, nil
}

func JoinPairing(id *identity.Identity, code string, addr string) (ed25519.PublicKey, error) {
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
	remotePub := make([]byte, ed25519.PublicKeySize)
	if _, err := io.ReadFull(conn, remotePub); err != nil {
		return nil, err
	}

	if _, err := conn.Write(id.PublicKey); err != nil {
		return nil, err
	}

	return ed25519.PublicKey(remotePub), nil
}
