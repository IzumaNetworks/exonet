use base64::Engine;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use std::net::IpAddr;

use crate::config::PeerConfig;

/// Routes packets to peers based on AllowedIPs
///
/// Uses longest-prefix matching to determine which peer should handle
/// traffic for a given destination IP address.
pub struct AllowedIpsRouter {
    /// Routing table mapping destination IPs to peer indices
    table: IpNetworkTable<usize>,
}

impl AllowedIpsRouter {
    /// Create a new router from peer configurations
    pub fn new(peers: &[PeerConfig]) -> Self {
        let mut table = IpNetworkTable::new();

        for (idx, peer) in peers.iter().enumerate() {
            for allowed_ip in &peer.allowed_ips {
                table.insert(*allowed_ip, idx);
                tracing::debug!(
                    "Route {} -> peer {} ({})",
                    allowed_ip,
                    idx,
                    base64::prelude::BASE64_STANDARD.encode(peer.public_key.as_bytes())
                );
            }
        }

        Self { table }
    }

    /// Look up which peer should handle a packet to the given destination
    ///
    /// Returns the peer index if found, None otherwise.
    pub fn lookup(&self, dest: IpAddr) -> Option<usize> {
        self.table.longest_match(dest).map(|(_, idx)| *idx)
    }

    /// Check if any peer can handle the given destination
    pub fn has_route(&self, dest: IpAddr) -> bool {
        self.lookup(dest).is_some()
    }

    /// Get all networks in the routing table
    pub fn networks(&self) -> impl Iterator<Item = (IpNetwork, &usize)> {
        self.table.iter()
    }

    /// Add a new route
    pub fn add_route(&mut self, network: IpNetwork, peer_index: usize) {
        self.table.insert(network, peer_index);
    }

    /// Remove a route
    pub fn remove_route(&mut self, network: IpNetwork) -> Option<usize> {
        self.table.remove(network)
    }
}

/// Extract destination IP address from an IP packet
pub fn extract_dest_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0x0f;

    match version {
        4 => {
            // IPv4 - destination is at offset 16
            if packet.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )))
        }
        6 => {
            // IPv6 - destination is at offset 24
            if packet.len() < 40 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Extract source IP address from an IP packet
pub fn extract_src_ip(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    let version = (packet[0] >> 4) & 0x0f;

    match version {
        4 => {
            // IPv4 - source is at offset 12
            if packet.len() < 20 {
                return None;
            }
            Some(IpAddr::V4(std::net::Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )))
        }
        6 => {
            // IPv6 - source is at offset 8
            if packet.len() < 40 {
                return None;
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_dest_ip_v4() {
        // Minimal IPv4 header with dst = 10.0.0.1
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // Version 4, IHL 5
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;

        let dest = extract_dest_ip(&packet).unwrap();
        assert_eq!(dest, IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_extract_src_ip_v4() {
        // Minimal IPv4 header with src = 192.168.1.1
        let mut packet = [0u8; 20];
        packet[0] = 0x45;
        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 1;
        packet[15] = 1;

        let src = extract_src_ip(&packet).unwrap();
        assert_eq!(src, IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_router_lookup() {
        use x25519_dalek::PublicKey;

        let peer = PeerConfig {
            public_key: PublicKey::from([0u8; 32]),
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
            persistent_keepalive: None,
        };

        let router = AllowedIpsRouter::new(&[peer]);

        assert_eq!(
            router.lookup(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))),
            Some(0)
        );
        assert_eq!(
            router.lookup(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))),
            None
        );
    }
}
