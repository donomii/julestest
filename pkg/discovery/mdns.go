package discovery

import (
	"context"
	"net"
	"strings"

	"github.com/hashicorp/mdns"
)

const (
	serviceName = "_pnet._tcp"
)

type NodeInfo struct {
	ID   string
	IP   net.IP
	Port int
}

func getLocalIPs() []net.IP {
	var ips []net.IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP)
			}
		}
	}
	return ips
}

func Advertise(id string, port int) (*mdns.Server, error) {
	ips := getLocalIPs()
	service, err := mdns.NewMDNSService(id, serviceName, "", "", port, ips, []string{"id=" + id})
	if err != nil {
		return nil, err
	}

	server, err := mdns.NewServer(&mdns.Config{Zone: service})
	if err != nil {
		return nil, err
	}

	return server, nil
}

func Discover(ctx context.Context) (<-chan NodeInfo, error) {
	entriesCh := make(chan *mdns.ServiceEntry, 100)
	nodeCh := make(chan NodeInfo, 100)

	go func() {
		defer close(nodeCh)
		for {
			select {
			case <-ctx.Done():
				return
			case entry, ok := <-entriesCh:
				if !ok {
					return
				}
				id := ""
				for _, field := range entry.InfoFields {
					if strings.HasPrefix(field, "id=") {
						id = strings.TrimPrefix(field, "id=")
						break
					}
				}
				if id != "" {
					nodeCh <- NodeInfo{
						ID:   id,
						IP:   entry.AddrV4,
						Port: entry.Port,
					}
				}
			}
		}
	}()

	params := &mdns.QueryParam{
		Service: serviceName,
		Domain:  "local",
		Timeout: 0,
		Entries: entriesCh,
	}

	go func() {
		mdns.Query(params)
		close(entriesCh)
	}()

	return nodeCh, nil
}
