package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"personal-net/pkg/discovery"
	"personal-net/pkg/identity"
	"personal-net/pkg/pairing"
	"personal-net/pkg/transport"
)

type Config struct {
	TrustedNodes map[string]string `json:"trusted_nodes"` // fingerprint -> public_key_hex
}

func main() {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".pnet")
	keyPath := filepath.Join(configDir, "id.key")
	configPath := filepath.Join(configDir, "config.json")

	if len(os.Args) < 2 {
		fmt.Println("Usage: pnet <command> [args]")
		fmt.Println("Commands: init, start, pair-host, pair-join, list, ping")
		return
	}

	cmd := os.Args[1]

	switch cmd {
	case "init":
		id, err := identity.GenerateIdentity()
		if err != nil {
			log.Fatal(err)
		}
		if err := identity.SaveIdentity(id, keyPath); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Identity initialized. Fingerprint: %s\n", id.Fingerprint())
		saveConfig(configPath, &Config{TrustedNodes: make(map[string]string)})

	case "start":
		id, conf := loadIdAndConfig(keyPath, configPath)
		port := 8000

		// Start mDNS advertising
		server, err := discovery.Advertise(id.Fingerprint(), port)
		if err != nil {
			log.Fatal(err)
		}
		defer server.Shutdown()

		fmt.Printf("Node started. Fingerprint: %s, listening on :%d\n", id.Fingerprint(), port)

		// Discover others
		go func() {
			nodeCh, _ := discovery.Discover(context.Background())
			for node := range nodeCh {
				if _, ok := conf.TrustedNodes[node.ID]; ok {
					fmt.Printf("Discovered trusted node: %s at %s:%d\n", node.ID, node.IP, node.Port)
				}
			}
		}()

		// Listen for incoming secure connections
		trustedPubs := []ed25519.PublicKey{}
		for _, pubHex := range conf.TrustedNodes {
			pubBytes, _ := hex.DecodeString(pubHex)
			trustedPubs = append(trustedPubs, ed25519.PublicKey(pubBytes))
		}

		tlsConf, err := transport.GenerateTLSConfig(id.PrivateKey, trustedPubs)
		if err != nil {
			log.Fatal(err)
		}

		ln, err := tls.Listen("tcp", fmt.Sprintf(":%d", port), tlsConf)
		if err != nil {
			log.Fatal(err)
		}
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go handleConnection(conn)
		}

	case "pair-host":
		id, conf := loadIdAndConfig(keyPath, configPath)
		code, err := pairing.GenerateLinkCode()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Pairing code: %s\n", code)
		pairing.DisplayQRCode(code)

		pubs, err := pairing.HandlePairing(id, code, 9000)
		if err != nil {
			log.Fatal(err)
		}
		for _, pub := range pubs {
			fp := hex.EncodeToString(pub)
			conf.TrustedNodes[fp] = fp
			fmt.Printf("Paired with: %s\n", fp)
		}
		saveConfig(configPath, conf)

	case "pair-join":
		id, conf := loadIdAndConfig(keyPath, configPath)
		if len(os.Args) < 4 {
			fmt.Println("Usage: pnet pair-join <addr> <code>")
			return
		}
		addr := os.Args[2]
		code := os.Args[3]
		pub, err := pairing.JoinPairing(id, code, addr)
		if err != nil {
			log.Fatal(err)
		}
		fp := hex.EncodeToString(pub)
		conf.TrustedNodes[fp] = fp
		fmt.Printf("Successfully paired with: %s\n", fp)
		saveConfig(configPath, conf)

	case "list":
		_, conf := loadIdAndConfig(keyPath, configPath)
		fmt.Println("Trusted nodes:")
		for fp := range conf.TrustedNodes {
			fmt.Println("- ", fp)
		}

	case "ping":
		id, conf := loadIdAndConfig(keyPath, configPath)
		if len(os.Args) < 3 {
			fmt.Println("Usage: pnet ping <addr>")
			return
		}
		addr := os.Args[2]

		trustedPubs := []ed25519.PublicKey{}
		for _, pubHex := range conf.TrustedNodes {
			pubBytes, _ := hex.DecodeString(pubHex)
			trustedPubs = append(trustedPubs, ed25519.PublicKey(pubBytes))
		}

		tlsConf, err := transport.GenerateTLSConfig(id.PrivateKey, trustedPubs)
		if err != nil {
			log.Fatal(err)
		}

		conn, err := tls.Dial("tcp", addr, tlsConf)
		if err != nil {
			log.Fatal(err)
		}
		defer conn.Close()

		transport.SendMessage(conn, []byte("ping"))
		resp, _ := transport.ReceiveMessage(conn)
		fmt.Printf("Received: %s\n", string(resp))

	default:
		fmt.Println("Unknown command")
	}
}

func loadIdAndConfig(keyPath, configPath string) (*identity.Identity, *Config) {
	id, err := identity.LoadIdentity(keyPath)
	if err != nil {
		log.Fatal("Identity not initialized. Run 'pnet init' first.")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return id, &Config{TrustedNodes: make(map[string]string)}
	}
	var conf Config
	json.Unmarshal(data, &conf)
	if conf.TrustedNodes == nil {
		conf.TrustedNodes = make(map[string]string)
	}
	return id, &conf
}

func saveConfig(path string, conf *Config) {
	data, _ := json.MarshalIndent(conf, "", "  ")
	os.WriteFile(path, data, 0600)
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	msg, err := transport.ReceiveMessage(conn)
	if err != nil {
		return
	}
	if string(msg) == "ping" {
		transport.SendMessage(conn, []byte("pong"))
	}
}
