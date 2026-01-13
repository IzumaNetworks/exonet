use crate::error::{ConfigError, Result, WgError};
use base64::prelude::*;
use ini::Ini;
use ip_network::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};

use super::types::{InterfaceConfig, PeerConfig, WgConfig};

/// Parse a WireGuard configuration file
pub fn parse_config_file<P: AsRef<Path>>(path: P) -> Result<WgConfig> {
    let ini = Ini::load_from_file(path).map_err(|e| ConfigError::Parse(e.to_string()))?;

    let mut interface: Option<InterfaceConfig> = None;
    let mut peers: Vec<PeerConfig> = Vec::new();

    for (section, props) in ini.iter() {
        match section {
            Some("Interface") => {
                interface = Some(parse_interface_section(props)?);
            }
            Some("Peer") => {
                peers.push(parse_peer_section(props)?);
            }
            _ => {
                // Ignore unknown sections
            }
        }
    }

    let interface = interface.ok_or(ConfigError::MissingField("Interface section"))?;

    Ok(WgConfig { interface, peers })
}

fn parse_interface_section(props: &ini::Properties) -> Result<InterfaceConfig> {
    let private_key = props
        .get("PrivateKey")
        .ok_or(ConfigError::MissingField("PrivateKey"))?;
    let private_key = decode_private_key(private_key)?;

    let addresses = props
        .get("Address")
        .map(|s| parse_address_list(s))
        .transpose()?
        .unwrap_or_default();

    let listen_port = props
        .get("ListenPort")
        .map(|s| {
            s.parse::<u16>()
                .map_err(|_| ConfigError::InvalidPort(s.to_string()))
        })
        .transpose()?;

    let dns = props
        .get("DNS")
        .map(|s| parse_dns_list(s))
        .transpose()?
        .unwrap_or_default();

    let mtu = props
        .get("MTU")
        .map(|s| {
            s.parse::<u32>()
                .map_err(|_| ConfigError::Parse(format!("Invalid MTU: {}", s)))
        })
        .transpose()?;

    let fwmark = props
        .get("FwMark")
        .map(|s| parse_fwmark(s))
        .transpose()?;

    Ok(InterfaceConfig {
        private_key,
        addresses,
        listen_port,
        dns,
        mtu,
        interface_name: None,
        fwmark,
        pre_up: props.get("PreUp").map(String::from),
        post_up: props.get("PostUp").map(String::from),
        pre_down: props.get("PreDown").map(String::from),
        post_down: props.get("PostDown").map(String::from),
    })
}

fn parse_peer_section(props: &ini::Properties) -> Result<PeerConfig> {
    let public_key = props
        .get("PublicKey")
        .ok_or(ConfigError::MissingField("PublicKey"))?;
    let public_key = decode_public_key(public_key)?;

    let preshared_key = props
        .get("PresharedKey")
        .map(|s| decode_preshared_key(s))
        .transpose()?;

    let endpoint = props
        .get("Endpoint")
        .map(|s| parse_endpoint(s))
        .transpose()?;

    let allowed_ips = props
        .get("AllowedIPs")
        .map(|s| parse_address_list(s))
        .transpose()?
        .unwrap_or_default();

    let persistent_keepalive = props
        .get("PersistentKeepalive")
        .map(|s| {
            s.parse::<u16>()
                .map_err(|_| ConfigError::Parse(format!("Invalid PersistentKeepalive: {}", s)))
        })
        .transpose()?;

    Ok(PeerConfig {
        public_key,
        preshared_key,
        endpoint,
        allowed_ips,
        persistent_keepalive,
    })
}

/// Decode a base64-encoded private key
fn decode_private_key(s: &str) -> Result<StaticSecret> {
    let bytes = BASE64_STANDARD
        .decode(s.trim())
        .map_err(|e| ConfigError::InvalidKey(format!("Invalid base64: {}", e)))?;

    if bytes.len() != 32 {
        return Err(ConfigError::InvalidKey(format!(
            "Private key must be 32 bytes, got {}",
            bytes.len()
        ))
        .into());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(StaticSecret::from(key_bytes))
}

/// Decode a base64-encoded public key
fn decode_public_key(s: &str) -> Result<PublicKey> {
    let bytes = BASE64_STANDARD
        .decode(s.trim())
        .map_err(|e| ConfigError::InvalidKey(format!("Invalid base64: {}", e)))?;

    if bytes.len() != 32 {
        return Err(ConfigError::InvalidKey(format!(
            "Public key must be 32 bytes, got {}",
            bytes.len()
        ))
        .into());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(PublicKey::from(key_bytes))
}

/// Decode a base64-encoded preshared key
fn decode_preshared_key(s: &str) -> Result<[u8; 32]> {
    let bytes = BASE64_STANDARD
        .decode(s.trim())
        .map_err(|e| ConfigError::InvalidKey(format!("Invalid base64: {}", e)))?;

    if bytes.len() != 32 {
        return Err(ConfigError::InvalidKey(format!(
            "Preshared key must be 32 bytes, got {}",
            bytes.len()
        ))
        .into());
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);
    Ok(key_bytes)
}

/// Parse a comma-separated list of IP addresses/networks
fn parse_address_list(s: &str) -> Result<Vec<IpNetwork>> {
    s.split(',')
        .map(|addr| {
            let addr = addr.trim();
            // Handle addresses without CIDR notation
            if !addr.contains('/') {
                // Assume /32 for IPv4 and /128 for IPv6
                let ip: IpAddr = addr
                    .parse()
                    .map_err(|_| ConfigError::InvalidAddress(addr.to_string()))?;
                let prefix = if ip.is_ipv4() { 32 } else { 128 };
                return IpNetwork::new(ip, prefix)
                    .map_err(|_| ConfigError::InvalidAddress(addr.to_string()).into());
            }
            addr.parse::<IpNetwork>()
                .map_err(|_| ConfigError::InvalidAddress(addr.to_string()).into())
        })
        .collect()
}

/// Parse a comma-separated list of DNS servers
fn parse_dns_list(s: &str) -> Result<Vec<IpAddr>> {
    s.split(',')
        .map(|addr| {
            addr.trim()
                .parse::<IpAddr>()
                .map_err(|_| ConfigError::InvalidAddress(addr.to_string()).into())
        })
        .collect()
}

/// Parse an endpoint (host:port)
fn parse_endpoint(s: &str) -> Result<SocketAddr> {
    let s = s.trim();

    // Handle IPv6 addresses in brackets
    if s.starts_with('[') {
        // IPv6 format: [host]:port
        let close_bracket = s
            .find(']')
            .ok_or_else(|| ConfigError::InvalidEndpoint(s.to_string()))?;
        let colon = s[close_bracket..]
            .find(':')
            .ok_or_else(|| ConfigError::InvalidEndpoint(s.to_string()))?;
        let port_str = &s[close_bracket + colon + 1..];
        let host_str = &s[1..close_bracket];

        let host: IpAddr = host_str
            .parse()
            .map_err(|_| ConfigError::InvalidEndpoint(s.to_string()))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| ConfigError::InvalidEndpoint(s.to_string()))?;

        Ok(SocketAddr::new(host, port))
    } else {
        // Try to parse as host:port
        // First try direct parse (works for IP:port)
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(addr);
        }

        // Try hostname resolution (simplified - just split on last colon)
        let last_colon = s
            .rfind(':')
            .ok_or_else(|| ConfigError::InvalidEndpoint(s.to_string()))?;
        let host_str = &s[..last_colon];
        let port_str = &s[last_colon + 1..];

        let host: IpAddr = host_str
            .parse()
            .map_err(|_| ConfigError::InvalidEndpoint(format!("Cannot resolve hostname: {}", s)))?;
        let port: u16 = port_str
            .parse()
            .map_err(|_| ConfigError::InvalidEndpoint(s.to_string()))?;

        Ok(SocketAddr::new(host, port))
    }
}

/// Parse fwmark (supports decimal and hex with 0x prefix)
fn parse_fwmark(s: &str) -> Result<u32> {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u32::from_str_radix(&s[2..], 16)
            .map_err(|_| ConfigError::Parse(format!("Invalid FwMark: {}", s)).into())
    } else {
        s.parse::<u32>()
            .map_err(|_| ConfigError::Parse(format!("Invalid FwMark: {}", s)).into())
    }
}

/// Encode a key to base64
pub fn encode_key(key: &[u8; 32]) -> String {
    BASE64_STANDARD.encode(key)
}

/// Generate a new private key
pub fn generate_private_key() -> StaticSecret {
    StaticSecret::random_from_rng(rand::rngs::OsRng)
}

/// Derive public key from private key
pub fn derive_public_key(private_key: &StaticSecret) -> PublicKey {
    PublicKey::from(private_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_address_list() {
        let addrs = parse_address_list("10.0.0.1/24, 192.168.1.0/24").unwrap();
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_parse_address_without_cidr() {
        let addrs = parse_address_list("10.0.0.1").unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].netmask(), 32);
    }

    #[test]
    fn test_parse_endpoint_ipv4() {
        let endpoint = parse_endpoint("192.168.1.1:51820").unwrap();
        assert_eq!(endpoint.port(), 51820);
    }

    #[test]
    fn test_parse_endpoint_ipv6() {
        let endpoint = parse_endpoint("[::1]:51820").unwrap();
        assert_eq!(endpoint.port(), 51820);
    }

    #[test]
    fn test_parse_fwmark_decimal() {
        let mark = parse_fwmark("12345").unwrap();
        assert_eq!(mark, 12345);
    }

    #[test]
    fn test_parse_fwmark_hex() {
        let mark = parse_fwmark("0xCAFE").unwrap();
        assert_eq!(mark, 0xCAFE);
    }
}
