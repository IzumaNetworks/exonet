use ip_network::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use x25519_dalek::{PublicKey, StaticSecret};

/// Complete WireGuard configuration
#[derive(Clone)]
pub struct WgConfig {
    pub interface: InterfaceConfig,
    pub peers: Vec<PeerConfig>,
}

impl std::fmt::Debug for WgConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgConfig")
            .field("interface", &"<InterfaceConfig>")
            .field("peers", &self.peers)
            .finish()
    }
}

/// [Interface] section configuration
#[derive(Clone)]
pub struct InterfaceConfig {
    /// Private key for this interface
    pub private_key: StaticSecret,
    /// IP addresses to assign to the interface (e.g., 10.0.0.1/24)
    pub addresses: Vec<IpNetwork>,
    /// UDP listen port (None = random port selection)
    pub listen_port: Option<u16>,
    /// DNS servers (informational - not applied by this tool)
    pub dns: Vec<IpAddr>,
    /// MTU setting (None = auto-detect)
    pub mtu: Option<u32>,
    /// Interface name (None = kernel-assigned)
    pub interface_name: Option<String>,
    /// Firewall mark for advanced routing
    pub fwmark: Option<u32>,
    /// Pre-up command (not executed, stored for reference)
    pub pre_up: Option<String>,
    /// Post-up command (not executed, stored for reference)
    pub post_up: Option<String>,
    /// Pre-down command (not executed, stored for reference)
    pub pre_down: Option<String>,
    /// Post-down command (not executed, stored for reference)
    pub post_down: Option<String>,
}

impl std::fmt::Debug for InterfaceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceConfig")
            .field("addresses", &self.addresses)
            .field("listen_port", &self.listen_port)
            .field("mtu", &self.mtu)
            .field("interface_name", &self.interface_name)
            .finish_non_exhaustive()
    }
}

impl Default for InterfaceConfig {
    fn default() -> Self {
        Self {
            private_key: StaticSecret::random_from_rng(rand::rngs::OsRng),
            addresses: Vec::new(),
            listen_port: None,
            dns: Vec::new(),
            mtu: None,
            interface_name: None,
            fwmark: None,
            pre_up: None,
            post_up: None,
            pre_down: None,
            post_down: None,
        }
    }
}

/// [Peer] section configuration
#[derive(Debug, Clone)]
pub struct PeerConfig {
    /// Public key of this peer
    pub public_key: PublicKey,
    /// Optional preshared key for additional symmetric encryption
    pub preshared_key: Option<[u8; 32]>,
    /// Remote endpoint (required for initiating connections)
    pub endpoint: Option<SocketAddr>,
    /// IP ranges allowed through this peer (routing + ACL)
    pub allowed_ips: Vec<IpNetwork>,
    /// Keepalive interval in seconds
    pub persistent_keepalive: Option<u16>,
}

impl PeerConfig {
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            preshared_key: None,
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: None,
        }
    }
}

/// Runtime mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Client mode: initiates connections to peers
    #[default]
    Client,
    /// Server mode: listens for incoming connections
    Server,
}

impl WgConfig {
    /// Get all AllowedIPs across all peers (for route setup)
    pub fn all_allowed_ips(&self) -> impl Iterator<Item = &IpNetwork> {
        self.peers.iter().flat_map(|p| p.allowed_ips.iter())
    }

    /// Find peer by public key
    pub fn find_peer(&self, public_key: &PublicKey) -> Option<&PeerConfig> {
        self.peers.iter().find(|p| &p.public_key == public_key)
    }
}
