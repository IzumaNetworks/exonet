use base64::Engine;
use boringtun::noise::{Tunn, TunnResult};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::config::PeerConfig;
use crate::error::{Result, TunnelError};

/// Statistics for a peer session
#[derive(Debug, Default)]
pub struct PeerStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
}

impl PeerStats {
    pub fn record_sent(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_received(&self, bytes: usize) {
        self.bytes_received
            .fetch_add(bytes as u64, Ordering::Relaxed);
        self.packets_received.fetch_add(1, Ordering::Relaxed);
    }
}

/// Wrapper around boringtun's Tunn with additional state management
pub struct PeerSession {
    /// The boringtun tunnel instance
    tunn: Tunn,
    /// Peer's public key
    public_key: PublicKey,
    /// Current known endpoint for this peer
    endpoint: RwLock<Option<SocketAddr>>,
    /// Allowed IPs for this peer (reference to config)
    config: Arc<PeerConfig>,
    /// Session statistics
    stats: Arc<PeerStats>,
    /// Time of last handshake completion
    last_handshake: RwLock<Option<Instant>>,
    /// Peer index (unique identifier within the tunnel)
    index: u32,
}

impl PeerSession {
    /// Create a new peer session
    pub fn new(
        local_private_key: &StaticSecret,
        peer_config: Arc<PeerConfig>,
        index: u32,
    ) -> Result<Self> {
        let tunn = Tunn::new(
            local_private_key.clone(),
            peer_config.public_key,
            peer_config.preshared_key,
            peer_config.persistent_keepalive,
            index,
            None, // rate_limiter - we may add this later
        )
        .map_err(|e| TunnelError::WireGuard(e.to_string()))?;

        Ok(Self {
            tunn,
            public_key: peer_config.public_key,
            endpoint: RwLock::new(peer_config.endpoint),
            config: peer_config,
            stats: Arc::new(PeerStats::default()),
            last_handshake: RwLock::new(None),
            index,
        })
    }

    /// Get the peer's public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Get the peer's current endpoint
    pub async fn endpoint(&self) -> Option<SocketAddr> {
        *self.endpoint.read().await
    }

    /// Update the peer's endpoint (e.g., after roaming)
    pub async fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write().await;
        if *endpoint != Some(addr) {
            tracing::debug!(
                "Peer {} endpoint changed: {:?} -> {}",
                base64::prelude::BASE64_STANDARD.encode(self.public_key.as_bytes()),
                *endpoint,
                addr
            );
            *endpoint = Some(addr);
        }
    }

    /// Get the peer index
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get the peer configuration
    pub fn config(&self) -> &PeerConfig {
        &self.config
    }

    /// Get statistics
    pub fn stats(&self) -> &Arc<PeerStats> {
        &self.stats
    }

    /// Encrypt an IP packet for transmission to this peer
    ///
    /// The output buffer must be at least src.len() + 32 bytes (for WireGuard overhead)
    /// or 148 bytes for handshake initiation.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let result = self.tunn.encapsulate(src, dst);

        if let TunnResult::WriteToNetwork(data) = &result {
            self.stats.record_sent(data.len());
        }

        result
    }

    /// Decrypt an incoming WireGuard packet
    ///
    /// The output buffer should be at least the size of the incoming packet.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<std::net::IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        let result = self.tunn.decapsulate(src_addr, datagram, dst);

        match &result {
            TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                self.stats.record_received(data.len());
            }
            _ => {}
        }

        result
    }

    /// Process timer events (keepalive, rekey, etc.)
    ///
    /// Should be called periodically (e.g., every 250ms).
    /// Returns packets that need to be sent to the peer.
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.update_timers(dst)
    }

    /// Record that a handshake completed successfully
    pub async fn record_handshake(&self) {
        let mut last_handshake = self.last_handshake.write().await;
        *last_handshake = Some(Instant::now());
    }

    /// Get time since last handshake
    pub async fn time_since_handshake(&self) -> Option<std::time::Duration> {
        self.last_handshake.read().await.map(|t| t.elapsed())
    }

    /// Check if this peer is allowed to send/receive traffic for the given IP
    pub fn is_allowed_ip(&self, addr: std::net::IpAddr) -> bool {
        for allowed in &self.config.allowed_ips {
            if allowed.contains(addr) {
                return true;
            }
        }
        false
    }

    /// Format packet for logging
    pub fn format_packet(data: &[u8]) -> String {
        if data.len() < 20 {
            return format!("{} bytes (too short)", data.len());
        }

        let version = (data[0] >> 4) & 0xf;
        match version {
            4 => {
                let src = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
                let dst = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
                let proto = data[9];
                format!("IPv4 {} -> {} proto={} len={}", src, dst, proto, data.len())
            }
            6 => {
                if data.len() < 40 {
                    return format!("IPv6 {} bytes (truncated)", data.len());
                }
                format!("IPv6 {} bytes", data.len())
            }
            _ => format!("{} bytes (unknown version {})", data.len(), version),
        }
    }
}
