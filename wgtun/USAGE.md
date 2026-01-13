# wgtun Usage Guide

A self-contained WireGuard tunnel CLI implemented in Rust using the boringtun library.

## Overview

wgtun provides a complete WireGuard VPN implementation without requiring the kernel module or `wg`/`wg-quick` tools. It handles:

- TUN device creation and management
- IP address and route configuration via netlink
- WireGuard protocol encryption/decryption
- Standard WireGuard `.conf` file parsing

## Project Structure

```
wgtun/
├── Cargo.toml                 # Dependencies and project config
├── src/
│   ├── main.rs                # Entry point and logging setup
│   ├── lib.rs                 # Library root exports
│   ├── error.rs               # Error types (WgError, ConfigError, etc.)
│   ├── cli/
│   │   ├── mod.rs
│   │   ├── args.rs            # Clap CLI definitions
│   │   └── commands.rs        # Command implementations
│   ├── config/
│   │   ├── mod.rs
│   │   ├── types.rs           # WgConfig, PeerConfig, TunnelMode
│   │   └── parser.rs          # WireGuard .conf parsing
│   ├── tunnel/
│   │   ├── mod.rs
│   │   ├── peer.rs            # PeerSession (wraps boringtun::Tunn)
│   │   └── router.rs          # AllowedIPs routing table
│   ├── platform/
│   │   ├── mod.rs
│   │   ├── traits.rs          # NetworkManager, TunDevice traits
│   │   └── linux/
│   │       ├── mod.rs
│   │       ├── netlink.rs     # IP/route config via rtnetlink
│   │       └── tun.rs         # TUN device via tokio-tun
│   ├── runtime/
│   │   ├── mod.rs
│   │   └── event_loop.rs      # Main async packet loop
│   └── network/
│       └── mod.rs
```

## Building

```bash
cargo build --release
```

The binary will be at `target/release/wgtun`.

## CLI Commands

### Global Options

```
-v, --verbose    Increase log verbosity (can be repeated)
                 -v   = info
                 -vv  = debug
                 -vvv = trace
```

### `wgtun up` - Bring up a tunnel

```bash
wgtun up -c <CONFIG> [OPTIONS]
```

Options:
- `-c, --config <PATH>` - Path to WireGuard config file (required)
- `-i, --interface <NAME>` - Interface name (overrides config, default: kernel-assigned)
- `-p, --port <PORT>` - Listen port (overrides config)
- `--server` - Run as server (accept connections without endpoint)
- `-f, --foreground` - Run in foreground

Examples:
```bash
# Client mode
sudo wgtun up -c client.conf -v

# Server mode
sudo wgtun up -c server.conf --server -v

# Custom interface name
sudo wgtun up -c config.conf -i wg0 -p 51820 -v
```

### `wgtun down` - Bring down a tunnel

```bash
wgtun down <INTERFACE>
```

Example:
```bash
sudo wgtun down wg0
```

### `wgtun status` - Show interface status

```bash
wgtun status [INTERFACE]
```

Shows status for a specific interface, or all interfaces if omitted.

### `wgtun genkey` - Generate private key

```bash
wgtun genkey
```

Outputs a base64-encoded private key to stdout.

### `wgtun pubkey` - Derive public key

```bash
wgtun pubkey < private.key
# or
echo "<private-key>" | wgtun pubkey
```

Reads a private key from stdin and outputs the corresponding public key.

### `wgtun show-config` - Show example config

```bash
wgtun show-config
```

Prints a documented example configuration file.

## Configuration File Format

Standard WireGuard INI format with `[Interface]` and `[Peer]` sections.

### [Interface] Section

| Field | Required | Description |
|-------|----------|-------------|
| `PrivateKey` | Yes | Base64-encoded 32-byte private key |
| `Address` | No | Comma-separated IP addresses with CIDR (e.g., `10.0.0.2/24`) |
| `ListenPort` | No | UDP listen port (random if omitted) |
| `DNS` | No | DNS servers (informational, not applied) |
| `MTU` | No | TUN MTU (default: 1420) |
| `FwMark` | No | Firewall mark for routing (decimal or hex `0xCAFE`) |

### [Peer] Sections

| Field | Required | Description |
|-------|----------|-------------|
| `PublicKey` | Yes | Base64-encoded 32-byte public key |
| `Endpoint` | No* | Remote address (`host:port` or `[ipv6]:port`) |
| `AllowedIPs` | No | Comma-separated CIDR networks |
| `PresharedKey` | No | Base64-encoded 32-byte symmetric key |
| `PersistentKeepalive` | No | Keepalive interval in seconds |

*Endpoint is required for client mode, optional for server mode.

### Example Client Config

```ini
[Interface]
PrivateKey = <your-private-key>
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = <server-public-key>
Endpoint = server.example.com:51820
AllowedIPs = 10.0.0.0/24, 192.168.1.0/24
PersistentKeepalive = 25
```

### Example Server Config

```ini
[Interface]
PrivateKey = <server-private-key>
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <client-public-key>
AllowedIPs = 10.0.0.2/32
```

## Key Generation

Generate a keypair:
```bash
# Generate private key
wgtun genkey > private.key

# Derive public key
wgtun pubkey < private.key > public.key
```

## Architecture

### Packet Flow

```
┌─────────────────────────────────────────────────────────┐
│                     Event Loop                          │
│                                                         │
│  ┌─────────┐    ┌──────────────┐    ┌─────────────┐    │
│  │   TUN   │───▶│ AllowedIPs   │───▶│ PeerSession │    │
│  │ Reader  │    │   Router     │    │ (boringtun) │    │
│  └─────────┘    └──────────────┘    └──────┬──────┘    │
│       ▲                                     │          │
│       │                                     ▼          │
│  ┌─────────┐                          ┌─────────┐      │
│  │   TUN   │◀────────────────────────│   UDP   │      │
│  │ Writer  │                          │ Socket  │      │
│  └─────────┘                          └─────────┘      │
└─────────────────────────────────────────────────────────┘
```

1. **Outbound**: TUN → Router lookup → Encrypt (boringtun) → UDP send
2. **Inbound**: UDP recv → Decrypt (boringtun) → TUN write
3. **Timer**: Periodic keepalives and handshake maintenance (250ms tick)

### Key Components

- **PeerSession** (`tunnel/peer.rs`): Wraps `boringtun::Tunn`, handles encrypt/decrypt, tracks statistics
- **AllowedIpsRouter** (`tunnel/router.rs`): Longest-prefix-match routing to find peer for destination IP
- **SessionManager** (`runtime/event_loop.rs`): Manages all peer sessions, handles packet dispatch
- **LinuxNetworkManager** (`platform/linux/netlink.rs`): Configures addresses and routes via netlink
- **LinuxTunDevice** (`platform/linux/tun.rs`): Creates and manages TUN devices

### Error Types

```
WgError
├── Config(ConfigError)     # Config parsing errors
├── Network(NetworkError)   # TUN/netlink failures
├── Tunnel(TunnelError)     # Protocol errors
├── Io(io::Error)           # I/O errors
└── Other(String)           # Misc errors
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `boringtun` | WireGuard protocol implementation |
| `tokio-tun` | Async TUN device I/O |
| `rtnetlink` | Network configuration via netlink |
| `x25519-dalek` | Key exchange |
| `clap` | CLI argument parsing |
| `tokio` | Async runtime |
| `tracing` | Logging |

## Development Notes

### Running Tests

```bash
cargo test
```

### Testing Locally

Requires root for TUN device creation:
```bash
cargo build --release
sudo ./target/release/wgtun up -c test.conf -vv
```

### Adding Platform Support

1. Implement traits in `platform/traits.rs`:
   - `NetworkManager` for IP/route configuration
   - `TunDevice` for device I/O
2. Add platform module under `platform/`
3. Update `platform/mod.rs` with conditional compilation

### Current Limitations

- Linux only (platform traits exist for future portability)
- Status command shows placeholder (IPC mechanism needed)
- Pre/Post up/down commands stored but not executed
- No daemonization (use systemd or similar)
- No rate limiting on handshakes

## Troubleshooting

### Permission Denied

TUN device creation requires root or `CAP_NET_ADMIN`:
```bash
sudo wgtun up -c config.conf
# or
sudo setcap cap_net_admin+ep ./target/release/wgtun
```

### Interface Already Exists

The kernel auto-assigns interface names. Use `-i` to specify a unique name:
```bash
sudo wgtun up -c config.conf -i wg1
```

### Connection Issues

Enable verbose logging:
```bash
sudo wgtun up -c config.conf -vvv
```

Check:
- Firewall allows UDP on listen port
- Endpoint is reachable
- Keys match between peers
- AllowedIPs are configured correctly

## License

MIT
