use base64::Engine;
use std::io::{self, BufRead};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::config::parse_config_file;
use crate::config::parser::{derive_public_key, encode_key, generate_private_key};
use crate::error::Result;
use crate::platform::linux::{create_tun_split, LinuxNetworkManager};
use crate::platform::NetworkManager;
use crate::runtime::run_tunnel;

/// Execute the 'up' command
pub async fn cmd_up(
    config_path: Option<PathBuf>,
    interface: Option<String>,
    port: Option<u16>,
    server: bool,
    foreground: bool,
) -> Result<()> {
    // Load configuration
    let mut config = if let Some(path) = config_path {
        parse_config_file(&path)?
    } else {
        return Err(crate::error::WgError::Other(
            "Config file required. Use -c/--config to specify.".to_string(),
        ));
    };

    // Override with CLI arguments
    if let Some(name) = interface {
        config.interface.interface_name = Some(name);
    }
    if let Some(p) = port {
        config.interface.listen_port = Some(p);
    }

    let iface_name = config.interface.interface_name.clone();

    tracing::info!("Starting WireGuard tunnel");

    // Create TUN device
    let (tun_reader, tun_writer, tun_name, tun_index) =
        create_tun_split(iface_name.as_deref(), config.interface.mtu).await?;

    tracing::info!("Created TUN device: {}", tun_name);

    // Create network manager for IP/route configuration
    let netmgr = LinuxNetworkManager::new().await?;

    // Assign IP addresses
    for addr in &config.interface.addresses {
        netmgr.add_address(tun_index, *addr).await?;
        tracing::info!("Added address {} to {}", addr, tun_name);
    }

    // Bring interface up
    netmgr.set_link_up(tun_index).await?;

    // Set MTU if specified
    if let Some(mtu) = config.interface.mtu {
        netmgr.set_mtu(tun_index, mtu).await?;
    }

    // Create UDP socket
    let listen_port = config.interface.listen_port.unwrap_or(0);
    let udp = create_udp_socket(listen_port).await?;
    let local_addr = udp.local_addr()?;
    tracing::info!("Listening on UDP {}", local_addr);

    // Add routes for AllowedIPs
    for peer in &config.peers {
        for allowed_ip in &peer.allowed_ips {
            // Skip routes for the interface's own addresses
            let skip = config.interface.addresses.iter().any(|a| {
                a.network_address() == allowed_ip.network_address()
            });

            if !skip {
                if let Err(e) = netmgr.add_route(*allowed_ip, tun_index, None).await {
                    tracing::warn!("Failed to add route for {}: {}", allowed_ip, e);
                } else {
                    tracing::info!("Added route {} via {}", allowed_ip, tun_name);
                }
            }
        }
    }

    // Set up signal handlers
    let shutdown = CancellationToken::new();
    let shutdown_clone = shutdown.clone();

    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Received SIGINT, shutting down...");
        shutdown_clone.cancel();
    });

    // Log peer information
    let public_key = derive_public_key(&config.interface.private_key);
    tracing::info!(
        "Interface public key: {}",
        encode_key(public_key.as_bytes())
    );

    for (i, peer) in config.peers.iter().enumerate() {
        tracing::info!(
            "Peer {}: {} (endpoint: {:?})",
            i,
            encode_key(peer.public_key.as_bytes()),
            peer.endpoint
        );
    }

    // Run the event loop
    let udp = Arc::new(udp);
    run_tunnel(config, tun_reader, tun_writer, udp, shutdown).await?;

    // Cleanup
    tracing::info!("Cleaning up...");

    // Remove routes (best effort)
    // Routes are typically cleaned up when the interface is deleted

    // Interface will be cleaned up when TUN device is dropped

    Ok(())
}

/// Execute the 'down' command
pub async fn cmd_down(interface: String) -> Result<()> {
    let netmgr = LinuxNetworkManager::new().await?;

    // Get interface index
    let index = netmgr.get_interface_index(&interface).await?;

    // Bring interface down
    netmgr.set_link_down(index).await?;

    tracing::info!("Interface {} is down", interface);

    Ok(())
}

/// Execute the 'status' command
pub async fn cmd_status(interface: Option<String>) -> Result<()> {
    // For now, just show that the command is not fully implemented
    // A full implementation would query the running tunnel via IPC or shared state

    if let Some(iface) = interface {
        println!("Interface: {}", iface);
        println!("  Status: (status query not yet implemented)");
    } else {
        println!("(status query not yet implemented)");
        println!("Hint: specify an interface name to check");
    }

    Ok(())
}

/// Execute the 'genkey' command
pub fn cmd_genkey() {
    let private_key = generate_private_key();
    let encoded = encode_key(&private_key.to_bytes());
    println!("{}", encoded);
}

/// Execute the 'pubkey' command
pub fn cmd_pubkey() -> Result<()> {
    let stdin = io::stdin();
    let mut line = String::new();

    stdin.lock().read_line(&mut line).map_err(|e| {
        crate::error::WgError::Other(format!("Failed to read from stdin: {}", e))
    })?;

    let line = line.trim();
    let bytes = base64::prelude::BASE64_STANDARD.decode(line).map_err(|e| {
        crate::error::WgError::Other(format!("Invalid base64: {}", e))
    })?;

    if bytes.len() != 32 {
        return Err(crate::error::WgError::Other(format!(
            "Private key must be 32 bytes, got {}",
            bytes.len()
        )));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    let private_key = x25519_dalek::StaticSecret::from(key_bytes);
    let public_key = derive_public_key(&private_key);

    println!("{}", encode_key(public_key.as_bytes()));

    Ok(())
}

/// Show example configuration
pub fn cmd_show_config() {
    let example = r#"[Interface]
# Your private key (generate with: wgtun genkey)
PrivateKey = <base64-encoded-private-key>

# IP address(es) for this interface
Address = 10.0.0.2/24

# UDP listen port (optional, random if not specified)
ListenPort = 51820

# DNS servers (informational only, not applied)
# DNS = 1.1.1.1, 8.8.8.8

# MTU (optional, default 1420)
# MTU = 1420

[Peer]
# Peer's public key
PublicKey = <base64-encoded-public-key>

# Peer's endpoint (required for client mode)
Endpoint = server.example.com:51820

# IPs allowed through this peer
AllowedIPs = 10.0.0.0/24, 192.168.1.0/24

# Optional preshared key for additional security
# PresharedKey = <base64-encoded-preshared-key>

# Keepalive interval in seconds (useful behind NAT)
PersistentKeepalive = 25
"#;

    println!("{}", example);
}

/// Create a UDP socket for WireGuard traffic
async fn create_udp_socket(port: u16) -> Result<UdpSocket> {
    // Try to bind to both IPv4 and IPv6
    // First try dual-stack (IPv6 with IPv4 mapped)
    let addr_v6 = SocketAddr::from((Ipv6Addr::UNSPECIFIED, port));
    if let Ok(socket) = UdpSocket::bind(addr_v6).await {
        return Ok(socket);
    }

    // Fall back to IPv4 only
    let addr_v4 = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    UdpSocket::bind(addr_v4)
        .await
        .map_err(|e| crate::error::WgError::Io(e))
}
