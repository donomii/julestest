package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"personal-net/pkg/identity"
	"personal-net/pkg/pairing"
	"personal-net/pkg/transport"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const ProtocolID = "/pnet/1.0.0"

type Config struct {
	TrustedNodes map[string]string `json:"trusted_nodes"` // fingerprint -> peerID
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
		h, err := transport.CreateHost(id, 8000)
		if err != nil {
			log.Fatal(err)
		}
		defer h.Close()

		fmt.Printf("Node started. PeerID: %s\n", h.ID().String())
		fmt.Printf("Listening on:\n")
		for _, addr := range h.Addrs() {
			fmt.Printf("  %s/p2p/%s\n", addr, h.ID())
		}

		h.SetStreamHandler(ProtocolID, func(s network.Stream) {
			remotePeer := s.Conn().RemotePeer()
			isTrusted := false
			for _, trustedID := range conf.TrustedNodes {
				if trustedID == remotePeer.String() {
					isTrusted = true
					break
				}
			}

			if !isTrusted {
				fmt.Printf("Unrecognized peer attempted to connect: %s\n", remotePeer)
				s.Reset()
				return
			}

			fmt.Printf("Received message from: %s\n", remotePeer)
			buf := make([]byte, 4)
			if _, err := io.ReadFull(s, buf); err == nil {
				if string(buf) == "ping" {
					s.Write([]byte("pong"))
				}
			}
			s.Close()
		})

		select {}

	case "pair-host":
		id, conf := loadIdAndConfig(keyPath, configPath)
		code, err := pairing.GenerateLinkCode()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Pairing code: %s\n", code)
		pairing.DisplayQRCode(code)

		peers, err := pairing.HandlePairing(id, code, 9000)
		if err != nil {
			log.Fatal(err)
		}
		for _, p := range peers {
			fp := hex.EncodeToString(p.PublicKey)
			conf.TrustedNodes[fp] = p.PeerID.String()
			fmt.Printf("Paired with: %s (PeerID: %s)\n", fp, p.PeerID)
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
		p, err := pairing.JoinPairing(id, code, addr)
		if err != nil {
			log.Fatal(err)
		}
		fp := hex.EncodeToString(p.PublicKey)
		conf.TrustedNodes[fp] = p.PeerID.String()
		fmt.Printf("Successfully paired with: %s (PeerID: %s)\n", fp, p.PeerID)
		saveConfig(configPath, conf)

	case "list":
		_, conf := loadIdAndConfig(keyPath, configPath)
		fmt.Println("Trusted nodes:")
		for fp, pid := range conf.TrustedNodes {
			fmt.Printf("- %s (PeerID: %s)\n", fp, pid)
		}

	case "ping":
		id, _ := loadIdAndConfig(keyPath, configPath)
		if len(os.Args) < 3 {
			fmt.Println("Usage: pnet ping <multiaddr>")
			return
		}
		targetAddr := os.Args[2]

		h, err := transport.CreateHost(id, 0)
		if err != nil {
			log.Fatal(err)
		}
		defer h.Close()

		maddr, err := multiaddr.NewMultiaddr(targetAddr)
		if err != nil {
			log.Fatal(err)
		}

		info, err := peer.AddrInfoFromP2pAddr(maddr)
		if err != nil {
			log.Fatal(err)
		}

		if err := h.Connect(context.Background(), *info); err != nil {
			log.Fatal(err)
		}

		s, err := h.NewStream(context.Background(), info.ID, ProtocolID)
		if err != nil {
			log.Fatal(err)
		}
		defer s.Close()

		s.Write([]byte("ping"))
		resp := make([]byte, 4)
		io.ReadFull(s, resp)
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
