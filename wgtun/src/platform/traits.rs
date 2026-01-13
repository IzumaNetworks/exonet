use async_trait::async_trait;
use ip_network::IpNetwork;
use std::net::IpAddr;

use crate::error::Result;

/// Platform-agnostic network configuration operations
#[async_trait]
pub trait NetworkManager: Send + Sync {
    /// Add an IP address to the interface
    async fn add_address(&self, iface_index: u32, addr: IpNetwork) -> Result<()>;

    /// Remove an IP address from the interface
    async fn del_address(&self, iface_index: u32, addr: IpNetwork) -> Result<()>;

    /// Add a route through the interface
    async fn add_route(
        &self,
        dest: IpNetwork,
        iface_index: u32,
        gateway: Option<IpAddr>,
    ) -> Result<()>;

    /// Remove a route
    async fn del_route(&self, dest: IpNetwork, iface_index: u32) -> Result<()>;

    /// Bring interface up
    async fn set_link_up(&self, iface_index: u32) -> Result<()>;

    /// Bring interface down
    async fn set_link_down(&self, iface_index: u32) -> Result<()>;

    /// Set interface MTU
    async fn set_mtu(&self, iface_index: u32, mtu: u32) -> Result<()>;

    /// Get interface index by name
    async fn get_interface_index(&self, name: &str) -> Result<u32>;
}

/// Platform-agnostic TUN device operations
#[async_trait]
pub trait TunDevice: Send + Sync {
    /// Read a packet from the TUN device
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;

    /// Write a packet to the TUN device
    async fn send(&self, buf: &[u8]) -> Result<usize>;

    /// Get the interface name
    fn name(&self) -> &str;

    /// Get the interface index
    fn index(&self) -> u32;

    /// Get the MTU
    fn mtu(&self) -> u32;
}
