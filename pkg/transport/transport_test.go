package transport

import (
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"personal-net/pkg/identity"
	"testing"
)

func TestSecureTransport(t *testing.T) {
	id1, _ := identity.GenerateIdentity()
	id2, _ := identity.GenerateIdentity()

	conf1, _ := GenerateTLSConfig(id1.PrivateKey, []ed25519.PublicKey{id2.PublicKey})
	conf2, _ := GenerateTLSConfig(id2.PrivateKey, []ed25519.PublicKey{id1.PublicKey})

	ln, err := tls.Listen("tcp", "127.0.0.1:0", conf1)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()

		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			errCh <- err
			return
		}

		msg, err := ReceiveMessage(tlsConn)
		if err != nil {
			errCh <- err
			return
		}

		if string(msg) != "hello" {
			errCh <- fmt.Errorf("expected hello, got %s", string(msg))
			return
		}

		errCh <- SendMessage(tlsConn, []byte("world"))
	}()

	conn, err := tls.Dial("tcp", addr, conf2)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	if err := SendMessage(conn, []byte("hello")); err != nil {
		t.Fatalf("failed to send: %v", err)
	}

	msg, err := ReceiveMessage(conn)
	if err != nil {
		t.Fatalf("failed to receive: %v", err)
	}

	if string(msg) != "world" {
		t.Errorf("expected world, got %s", string(msg))
	}

	if err := <-errCh; err != nil {
		t.Fatalf("server error: %v", err)
	}
}
