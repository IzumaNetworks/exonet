use boringtun::noise::TunnResult;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::{PeerConfig, WgConfig};
use crate::error::{Result, TunnelError, WgError};
use crate::platform::linux::{TunReader, TunWriter};
use crate::tunnel::{extract_dest_ip, extract_src_ip, AllowedIpsRouter, PeerSession};

/// Maximum packet size (MTU + some overhead)
const MAX_PACKET_SIZE: usize = 65536;

/// Timer interval for keepalives/handshakes
const TIMER_INTERVAL_MS: u64 = 250;

/// Session manager containing all peer sessions
pub struct SessionManager {
    /// Peer sessions indexed by their index
    sessions: HashMap<u32, RwLock<PeerSession>>,
    /// Map from public key to session index
    key_to_index: HashMap<PublicKey, u32>,
    /// AllowedIPs router
    router: AllowedIpsRouter,
}

impl SessionManager {
    /// Create a new session manager from configuration
    pub fn new(config: &WgConfig) -> Result<Self> {
        let mut sessions = HashMap::new();
        let mut key_to_index = HashMap::new();

        for (idx, peer_config) in config.peers.iter().enumerate() {
            let idx = idx as u32;
            let session = PeerSession::new(
                &config.interface.private_key,
                Arc::new(peer_config.clone()),
                idx,
            )?;

            key_to_index.insert(peer_config.public_key, idx);
            sessions.insert(idx, RwLock::new(session));
        }

        let router = AllowedIpsRouter::new(&config.peers);

        Ok(Self {
            sessions,
            key_to_index,
            router,
        })
    }

    /// Get a session by index
    pub fn get(&self, index: u32) -> Option<&RwLock<PeerSession>> {
        self.sessions.get(&index)
    }

    /// Get a session by public key
    pub fn get_by_key(&self, key: &PublicKey) -> Option<&RwLock<PeerSession>> {
        self.key_to_index.get(key).and_then(|idx| self.get(*idx))
    }

    /// Find peer for destination IP
    pub fn find_peer_for_dest(&self, dest: std::net::IpAddr) -> Option<(u32, &RwLock<PeerSession>)> {
        self.router.lookup(dest).and_then(|idx| {
            self.sessions
                .get(&(idx as u32))
                .map(|s| (idx as u32, s))
        })
    }

    /// Iterate over all sessions
    pub fn iter(&self) -> impl Iterator<Item = (&u32, &RwLock<PeerSession>)> {
        self.sessions.iter()
    }
}

/// Run the main tunnel event loop
pub async fn run_tunnel(
    config: WgConfig,
    mut tun_reader: TunReader,
    mut tun_writer: TunWriter,
    udp: Arc<UdpSocket>,
    shutdown: CancellationToken,
) -> Result<()> {
    let sessions = Arc::new(SessionManager::new(&config)?);

    // Buffers for packet processing
    let mut tun_buf = vec![0u8; MAX_PACKET_SIZE];
    let mut udp_buf = vec![0u8; MAX_PACKET_SIZE];
    let mut out_buf = vec![0u8; MAX_PACKET_SIZE];

    // Timer for keepalives
    let mut timer = tokio::time::interval(Duration::from_millis(TIMER_INTERVAL_MS));

    // Initiate handshakes for peers with endpoints
    initiate_handshakes(&sessions, &udp, &mut out_buf).await?;

    tracing::info!("Event loop started");

    loop {
        tokio::select! {
            biased;

            // Shutdown signal
            _ = shutdown.cancelled() => {
                tracing::info!("Shutdown requested");
                break;
            }

            // TUN device read (outbound: tunnel -> network)
            result = tun_reader.recv(&mut tun_buf) => {
                match result {
                    Ok(n) if n > 0 => {
                        if let Err(e) = handle_tun_packet(
                            &tun_buf[..n],
                            &sessions,
                            &udp,
                            &mut out_buf,
                        ).await {
                            tracing::warn!("Error handling TUN packet: {}", e);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("TUN read error: {}", e);
                    }
                }
            }

            // UDP socket read (inbound: network -> tunnel)
            result = udp.recv_from(&mut udp_buf) => {
                match result {
                    Ok((n, src_addr)) if n > 0 => {
                        if let Err(e) = handle_udp_packet(
                            &udp_buf[..n],
                            src_addr,
                            &sessions,
                            &mut tun_writer,
                            &udp,
                            &mut out_buf,
                        ).await {
                            tracing::warn!("Error handling UDP packet from {}: {}", src_addr, e);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::error!("UDP read error: {}", e);
                    }
                }
            }

            // Timer tick for keepalives/handshakes
            _ = timer.tick() => {
                if let Err(e) = handle_timers(&sessions, &udp, &mut out_buf).await {
                    tracing::warn!("Timer error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Initiate handshakes for all peers with known endpoints
async fn initiate_handshakes(
    sessions: &SessionManager,
    udp: &UdpSocket,
    out_buf: &mut [u8],
) -> Result<()> {
    for (idx, session_lock) in sessions.iter() {
        let mut session = session_lock.write().await;
        let endpoint = session.endpoint().await;

        if let Some(endpoint) = endpoint {
            // Try to initiate a handshake
            match session.encapsulate(&[], out_buf) {
                TunnResult::WriteToNetwork(data) => {
                    tracing::debug!(
                        "Initiating handshake with peer {} at {}",
                        idx,
                        endpoint
                    );
                    if let Err(e) = udp.send_to(data, endpoint).await {
                        tracing::warn!("Failed to send handshake to {}: {}", endpoint, e);
                    }
                }
                TunnResult::Done => {}
                TunnResult::Err(e) => {
                    tracing::warn!("Handshake initiation error for peer {}: {:?}", idx, e);
                }
                _ => {}
            }
        }
    }

    Ok(())
}

/// Handle a packet from the TUN device (outbound)
async fn handle_tun_packet(
    packet: &[u8],
    sessions: &SessionManager,
    udp: &UdpSocket,
    out_buf: &mut [u8],
) -> Result<()> {
    // Extract destination IP to find the right peer
    let dest_ip = extract_dest_ip(packet).ok_or_else(|| {
        TunnelError::InvalidPacket("Cannot extract destination IP".to_string())
    })?;

    // Find the peer for this destination
    let (idx, session_lock) = sessions.find_peer_for_dest(dest_ip).ok_or_else(|| {
        TunnelError::NoPeerForDestination(dest_ip.to_string())
    })?;

    let mut session = session_lock.write().await;
    let endpoint = session.endpoint().await;

    tracing::trace!(
        "TUN -> peer {}: {} (endpoint: {:?})",
        idx,
        PeerSession::format_packet(packet),
        endpoint
    );

    // Encapsulate the packet
    match session.encapsulate(packet, out_buf) {
        TunnResult::WriteToNetwork(data) => {
            if let Some(endpoint) = endpoint {
                udp.send_to(data, endpoint).await?;
            } else {
                tracing::debug!("No endpoint for peer {}, packet queued", idx);
            }
        }
        TunnResult::Done => {
            // Packet was queued (handshake in progress)
            tracing::trace!("Packet queued for peer {} (handshake pending)", idx);
        }
        TunnResult::Err(e) => {
            tracing::warn!("Encapsulation error for peer {}: {:?}", idx, e);
        }
        _ => {
            tracing::warn!("Unexpected TunnResult from encapsulate");
        }
    }

    Ok(())
}

/// Handle a packet from the UDP socket (inbound)
async fn handle_udp_packet(
    packet: &[u8],
    src_addr: SocketAddr,
    sessions: &SessionManager,
    tun_writer: &mut TunWriter,
    udp: &UdpSocket,
    out_buf: &mut [u8],
) -> Result<()> {
    // WireGuard packet format: first 4 bytes contain type and receiver index
    if packet.len() < 4 {
        return Err(TunnelError::InvalidPacket("Packet too short".to_string()).into());
    }

    let packet_type = packet[0];

    // For data packets (type 4), the receiver index is at bytes 4-7
    // For handshake packets, we need to try all peers
    let receiver_index = if packet_type == 4 && packet.len() >= 8 {
        let idx = u32::from_le_bytes([packet[4], packet[5], packet[6], packet[7]]);
        Some(idx)
    } else {
        None
    };

    // Try to find the peer either by index or by trying all peers
    if let Some(idx) = receiver_index {
        // Data packet - use receiver index
        if let Some(session_lock) = sessions.get(idx) {
            let mut session = session_lock.write().await;

            // Update endpoint if it changed
            session.set_endpoint(src_addr).await;

            process_peer_packet(
                packet,
                src_addr,
                &mut session,
                tun_writer,
                udp,
                out_buf,
            )
            .await?;
        } else {
            tracing::debug!("Unknown receiver index {} from {}", idx, src_addr);
        }
    } else {
        // Handshake packet - try all peers
        for (idx, session_lock) in sessions.iter() {
            let mut session = session_lock.write().await;

            match session.decapsulate(Some(src_addr.ip()), packet, out_buf) {
                TunnResult::WriteToNetwork(response) => {
                    // Update endpoint
                    session.set_endpoint(src_addr).await;
                    udp.send_to(response, src_addr).await?;
                    tracing::debug!("Handshake response sent to peer {} at {}", idx, src_addr);
                    return Ok(());
                }
                TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                    // Verify source IP is allowed
                    if let Some(src_ip) = extract_src_ip(data) {
                        if !session.is_allowed_ip(src_ip) {
                            tracing::warn!(
                                "Dropping packet from {} - source IP {} not in AllowedIPs",
                                src_addr,
                                src_ip
                            );
                            return Ok(());
                        }
                    }

                    session.set_endpoint(src_addr).await;
                    tun_writer.send(data).await?;
                    return Ok(());
                }
                TunnResult::Done => {
                    // This peer accepted the packet
                    session.set_endpoint(src_addr).await;
                    return Ok(());
                }
                TunnResult::Err(_) => {
                    // Try next peer
                    continue;
                }
            }
        }

        tracing::debug!("No peer accepted handshake packet from {}", src_addr);
    }

    Ok(())
}

/// Process a packet for a specific peer
async fn process_peer_packet(
    packet: &[u8],
    src_addr: SocketAddr,
    session: &mut PeerSession,
    tun_writer: &mut TunWriter,
    udp: &UdpSocket,
    out_buf: &mut [u8],
) -> Result<()> {
    match session.decapsulate(Some(src_addr.ip()), packet, out_buf) {
        TunnResult::WriteToNetwork(response) => {
            udp.send_to(response, src_addr).await?;
        }
        TunnResult::WriteToTunnelV4(data, src_ip) => {
            // Verify source IP is allowed
            if !session.is_allowed_ip(std::net::IpAddr::V4(src_ip)) {
                tracing::warn!(
                    "Dropping packet - source IP {} not in AllowedIPs",
                    src_ip
                );
                return Ok(());
            }

            tracing::trace!(
                "UDP -> TUN: {}",
                PeerSession::format_packet(data)
            );
            tun_writer.send(data).await?;
        }
        TunnResult::WriteToTunnelV6(data, src_ip) => {
            // Verify source IP is allowed
            if !session.is_allowed_ip(std::net::IpAddr::V6(src_ip)) {
                tracing::warn!(
                    "Dropping packet - source IP {} not in AllowedIPs",
                    src_ip
                );
                return Ok(());
            }

            tracing::trace!(
                "UDP -> TUN: {}",
                PeerSession::format_packet(data)
            );
            tun_writer.send(data).await?;
        }
        TunnResult::Done => {
            // Nothing to do
        }
        TunnResult::Err(e) => {
            tracing::debug!("Decapsulation error: {:?}", e);
        }
    }

    Ok(())
}

/// Handle timer events for all peers
async fn handle_timers(
    sessions: &SessionManager,
    udp: &UdpSocket,
    out_buf: &mut [u8],
) -> Result<()> {
    for (idx, session_lock) in sessions.iter() {
        let mut session = session_lock.write().await;
        let endpoint = session.endpoint().await;

        // Process timer events
        loop {
            match session.update_timers(out_buf) {
                TunnResult::WriteToNetwork(data) => {
                    if let Some(endpoint) = endpoint {
                        if let Err(e) = udp.send_to(data, endpoint).await {
                            tracing::debug!(
                                "Failed to send timer packet to peer {} at {}: {}",
                                idx,
                                endpoint,
                                e
                            );
                        }
                    }
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    tracing::trace!("Timer error for peer {}: {:?}", idx, e);
                    break;
                }
                _ => break,
            }
        }
    }

    Ok(())
}
