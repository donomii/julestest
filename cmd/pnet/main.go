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
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
)

const ProtocolID = "/pnet/1.0.0"

type Config struct {
	TrustedNodes map[string]*NodeRecord `json:"trusted_nodes"` // fingerprint -> NodeRecord
}

type NodeRecord struct {
	PeerID    string   `json:"peer_id"`
	Addresses []string `json:"addresses"`
}

var (
	configLock sync.Mutex
)

func main() {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".pnet")
	keyPath := filepath.Join(configDir, "id.key")
	configPath := filepath.Join(configDir, "config.json")

	if len(os.Args) < 2 {
		printUsage()
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
		fmt.Printf("✅ Identity initialized.\nFingerprint: %s\n", id.Fingerprint())
		saveConfig(configPath, &Config{TrustedNodes: make(map[string]*NodeRecord)})

	case "start":
		id, conf := loadIdAndConfig(keyPath, configPath)
		h, err := transport.CreateHost(id, 8000)
		if err != nil {
			log.Fatal(err)
		}
		defer h.Close()

		fmt.Printf("🚀 Node started.\nPeerID: %s\nFingerprint: %s\n", h.ID().String(), id.Fingerprint())
		fmt.Printf("\nListening on:\n")
		for _, addr := range h.Addrs() {
			fmt.Printf("  %s/p2p/%s\n", addr, h.ID())
		}

		// Background discovery listener
		go func() {
			for {
				time.Sleep(5 * time.Second)
				peers := h.Network().Peers()
				for _, p := range peers {
					addrs := h.Peerstore().Addrs(p)
					updatePeerAddresses(configPath, p.String(), addrs)
				}
			}
		}()

		h.SetStreamHandler(ProtocolID, func(s network.Stream) {
			remotePeer := s.Conn().RemotePeer()
			isTrusted := false
			configLock.Lock()
			for _, record := range conf.TrustedNodes {
				if record.PeerID == remotePeer.String() {
					isTrusted = true
					break
				}
			}
			configLock.Unlock()

			if !isTrusted {
				fmt.Printf("⚠️  Unrecognized peer attempted to connect: %s\n", remotePeer)
				s.Reset()
				return
			}

			fmt.Printf("📩 Received message from: %s\n", remotePeer)
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
		fmt.Printf("🔑 Pairing code: %s\n", code)
		fmt.Println("Scan the QR code below on the joining device:")
		pairing.DisplayQRCode(code)

		peers, err := pairing.HandlePairing(id, code, 9000)
		if err != nil {
			log.Fatal(err)
		}
		for _, p := range peers {
			fp := hex.EncodeToString(p.PublicKey)
			conf.TrustedNodes[fp] = &NodeRecord{
				PeerID: p.PeerID.String(),
			}
			fmt.Printf("🤝 Paired with: %s\n(PeerID: %s)\n", fp, p.PeerID)
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
		conf.TrustedNodes[fp] = &NodeRecord{
			PeerID: p.PeerID.String(),
		}
		fmt.Printf("✨ Successfully paired with: %s\n(PeerID: %s)\n", fp, p.PeerID)
		saveConfig(configPath, conf)

	case "list":
		_, conf := loadIdAndConfig(keyPath, configPath)
		fmt.Println("📜 Trusted nodes:")
		if len(conf.TrustedNodes) == 0 {
			fmt.Println("  (No trusted nodes yet. Run 'pair-host' or 'pair-join' to add some.)")
		}
		for fp, record := range conf.TrustedNodes {
			fmt.Printf("- %s\n    PeerID: %s\n", fp, record.PeerID)
			for _, addr := range record.Addresses {
				fmt.Printf("    📍 %s\n", addr)
			}
		}

	case "revoke":
		_, conf := loadIdAndConfig(keyPath, configPath)
		if len(os.Args) < 3 {
			fmt.Println("Usage: pnet revoke <fingerprint>")
			return
		}
		fp := os.Args[2]
		if _, ok := conf.TrustedNodes[fp]; ok {
			delete(conf.TrustedNodes, fp)
			saveConfig(configPath, conf)
			fmt.Printf("🗑️  Revoked node: %s\n", fp)
		} else {
			fmt.Printf("❌ Node not found: %s\n", fp)
		}

	case "ping":
		id, conf := loadIdAndConfig(keyPath, configPath)
		if len(os.Args) < 3 {
			fmt.Println("Usage: pnet ping <fingerprint|peerID|multiaddr>")
			return
		}
		target := os.Args[2]

		h, err := transport.CreateHost(id, 0)
		if err != nil {
			log.Fatal(err)
		}
		defer h.Close()

		var info *peer.AddrInfo

		if record, ok := conf.TrustedNodes[target]; ok {
			pid, _ := peer.Decode(record.PeerID)
			info = &peer.AddrInfo{ID: pid}
			for _, a := range record.Addresses {
				m, _ := multiaddr.NewMultiaddr(a)
				info.Addrs = append(info.Addrs, m)
			}
		} else {
			pid, err := peer.Decode(target)
			if err == nil {
				info = &peer.AddrInfo{ID: pid}
				for _, record := range conf.TrustedNodes {
					if record.PeerID == target {
						for _, a := range record.Addresses {
							m, _ := multiaddr.NewMultiaddr(a)
							info.Addrs = append(info.Addrs, m)
						}
						break
					}
				}
			} else {
				maddr, err := multiaddr.NewMultiaddr(target)
				if err != nil {
					log.Fatal("Invalid target. Must be fingerprint, PeerID, or Multiaddr.")
				}
				info, err = peer.AddrInfoFromP2pAddr(maddr)
				if err != nil {
					log.Fatal(err)
				}
			}
		}

		if len(info.Addrs) == 0 {
			fmt.Printf("🔍 PeerID %s found, but no addresses known. Trying discovery...\n", info.ID)
		}

		fmt.Printf("📡 Connecting to %s...\n", info.ID)
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
		fmt.Printf("🔔 Received: %s\n", string(resp))

	case "status":
		id, _ := loadIdAndConfig(keyPath, configPath)
		fmt.Printf("👤 Local Fingerprint: %s\n", id.Fingerprint())
		fmt.Println("\nStatus command requires a running node. Use 'start' to see live activity.")

	case "help":
		printUsage()

	default:
		fmt.Printf("❓ Unknown command: %s\n", cmd)
		printUsage()
	}
}

func printUsage() {
	fmt.Println("pnet - Personal Area Network Manager")
	fmt.Println("\nUsage:")
	fmt.Println("  pnet <command> [args]")
	fmt.Println("\nCommands:")
	fmt.Println("  init             Initialize local device identity")
	fmt.Println("  start            Start node and discovery")
	fmt.Println("  pair-host        Accept a new device (displays QR code)")
	fmt.Println("  pair-join        Join an existing network")
	fmt.Println("  list             List trusted devices")
	fmt.Println("  revoke <fp>      Remove a trusted device")
	fmt.Println("  ping <target>    Test connection to a trusted device")
	fmt.Println("  status           Show local device info")
	fmt.Println("  help             Show this help message")
}

func loadIdAndConfig(keyPath, configPath string) (*identity.Identity, *Config) {
	id, err := identity.LoadIdentity(keyPath)
	if err != nil {
		log.Fatal("Identity not initialized. Run 'pnet init' first.")
	}

	configLock.Lock()
	defer configLock.Unlock()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return id, &Config{TrustedNodes: make(map[string]*NodeRecord)}
	}
	var conf Config
	json.Unmarshal(data, &conf)
	if conf.TrustedNodes == nil {
		conf.TrustedNodes = make(map[string]*NodeRecord)
	}
	return id, &conf
}

func saveConfig(path string, conf *Config) {
	configLock.Lock()
	defer configLock.Unlock()
	data, _ := json.MarshalIndent(conf, "", "  ")
	os.WriteFile(path, data, 0600)
}

func updatePeerAddresses(configPath string, pid string, addrs []multiaddr.Multiaddr) {
	configLock.Lock()
	defer configLock.Unlock()
	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}
	var conf Config
	json.Unmarshal(data, &conf)

	updated := false
	for _, record := range conf.TrustedNodes {
		if record.PeerID == pid {
			addrMap := make(map[string]bool)
			for _, a := range record.Addresses {
				addrMap[a] = true
			}
			for _, a := range addrs {
				s := a.String()
				if !addrMap[s] {
					record.Addresses = append(record.Addresses, s)
					updated = true
				}
			}
			break
		}
	}

	if updated {
		data, _ := json.MarshalIndent(conf, "", "  ")
		os.WriteFile(configPath, data, 0600)
	}
}
