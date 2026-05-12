# pnet - Personal Area Network

A secure, decentralized personal area network (PAN) for cross-platform device communication.

## Features

- **PKI-based Identity**: Every device has a unique Ed25519 identity.
- **mDNS Discovery**: Automatic device discovery on the local network.
- **Secure Pairing**: Easy device linking via QR codes or link codes.
- **Encrypted Transport**: mTLS-secured communication between trusted devices.
- **Cross-Platform**: Works on Mac, Linux, Windows, and Android (via Go build).

## Getting Started

### Installation

Requires Go 1.22+.

```bash
make build
```

### Setup

On each device, initialize its identity:

```bash
./pnet init
```

### Pairing Devices

1.  **On the host device:**
    ```bash
    ./pnet pair-host
    ```
    This will display a pairing code and a QR code.

2.  **On the joining device:**
    ```bash
    ./pnet pair-join <host-ip>:9000 <pairing-code>
    ```

### Running the Node

Start the node to listen for connections and discover trusted peers:

```bash
./pnet start
```

### Testing Communication

Ping a trusted device:

```bash
./pnet ping <device-ip>:8000
```

## Commands

- `init`: Generate a new device identity.
- `start`: Start the mDNS advertiser and secure listener.
- `pair-host`: Put device in pairing mode to accept new devices.
- `pair-join`: Connect to a host in pairing mode.
- `list`: List all trusted device fingerprints.
- `ping`: Send a test message to a peer.

## Architecture

- **Identity**: Ed25519 keys stored in `~/.pnet/id.key`.
- **Discovery**: mDNS service `_pnet._tcp`.
- **Transport**: Mutual TLS (mTLS) where each peer verifies the other's certificate against a local trust store (`~/.pnet/config.json`).
