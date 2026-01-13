use async_trait::async_trait;
use futures::TryStreamExt;
use ip_network::IpNetwork;
use rtnetlink::Handle;
use std::net::IpAddr;

use crate::config::InterfaceAddress;
use crate::error::{NetworkError, Result};
use crate::platform::traits::NetworkManager;

/// Linux implementation of NetworkManager using netlink
pub struct LinuxNetworkManager {
    handle: Handle,
}

impl LinuxNetworkManager {
    /// Create a new LinuxNetworkManager
    pub async fn new() -> Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()
            .map_err(|e| NetworkError::Netlink(e.to_string()))?;

        // Spawn the connection handler
        tokio::spawn(connection);

        Ok(Self { handle })
    }
}

#[async_trait]
impl NetworkManager for LinuxNetworkManager {
    async fn add_address(&self, iface_index: u32, addr: InterfaceAddress) -> Result<()> {
        self.handle
            .address()
            .add(iface_index, addr.ip, addr.prefix)
            .execute()
            .await
            .map_err(|e| NetworkError::AddAddress(e.to_string()))?;

        Ok(())
    }

    async fn del_address(&self, iface_index: u32, addr: InterfaceAddress) -> Result<()> {
        // For simplicity, we just log - a complete implementation would query and delete
        tracing::debug!(
            "Attempting to delete address {} from interface {}",
            addr,
            iface_index
        );

        Ok(())
    }

    async fn add_route(
        &self,
        dest: IpNetwork,
        iface_index: u32,
        gateway: Option<IpAddr>,
    ) -> Result<()> {
        match dest.network_address() {
            IpAddr::V4(ipv4) => {
                let mut route = self
                    .handle
                    .route()
                    .add()
                    .v4()
                    .destination_prefix(ipv4, dest.netmask())
                    .output_interface(iface_index);

                if let Some(IpAddr::V4(gw)) = gateway {
                    route = route.gateway(gw);
                }

                route
                    .execute()
                    .await
                    .map_err(|e| NetworkError::AddRoute(e.to_string()))?;
            }
            IpAddr::V6(ipv6) => {
                let mut route = self
                    .handle
                    .route()
                    .add()
                    .v6()
                    .destination_prefix(ipv6, dest.netmask())
                    .output_interface(iface_index);

                if let Some(IpAddr::V6(gw)) = gateway {
                    route = route.gateway(gw);
                }

                route
                    .execute()
                    .await
                    .map_err(|e| NetworkError::AddRoute(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn del_route(&self, dest: IpNetwork, iface_index: u32) -> Result<()> {
        // Simplified: just log the attempt
        // Full implementation would query routes and delete matching ones
        tracing::debug!(
            "Attempting to delete route {} via interface {}",
            dest,
            iface_index
        );
        Ok(())
    }

    async fn set_link_up(&self, iface_index: u32) -> Result<()> {
        self.handle
            .link()
            .set(iface_index)
            .up()
            .execute()
            .await
            .map_err(|e| NetworkError::SetLinkUp(e.to_string()))?;

        Ok(())
    }

    async fn set_link_down(&self, iface_index: u32) -> Result<()> {
        self.handle
            .link()
            .set(iface_index)
            .down()
            .execute()
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))?;

        Ok(())
    }

    async fn set_mtu(&self, iface_index: u32, mtu: u32) -> Result<()> {
        self.handle
            .link()
            .set(iface_index)
            .mtu(mtu)
            .execute()
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))?;

        Ok(())
    }

    async fn get_interface_index(&self, name: &str) -> Result<u32> {
        let mut links = self.handle.link().get().match_name(name.to_string()).execute();

        if let Some(link) = links
            .try_next()
            .await
            .map_err(|e| NetworkError::Netlink(e.to_string()))?
        {
            return Ok(link.header.index);
        }

        Err(NetworkError::Netlink(format!("Interface {} not found", name)).into())
    }
}
