use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tun::Tun;

use crate::error::{NetworkError, Result};
use crate::platform::traits::TunDevice;

/// Linux TUN device implementation
pub struct LinuxTunDevice {
    tun: Tun,
    name: String,
    index: u32,
    mtu: u32,
}

impl LinuxTunDevice {
    /// Create a new TUN device
    pub async fn new(name: Option<&str>, mtu: Option<u32>) -> Result<Self> {
        let mtu_val = mtu.unwrap_or(1420); // Default WireGuard MTU

        let tun = tokio_tun::Tun::builder()
            .name(name.unwrap_or(""))
            .tap(false)
            .packet_info(false)
            .mtu(mtu_val as i32)
            .up()
            .try_build()
            .map_err(|e| NetworkError::TunCreation(e.to_string()))?;

        let tun_name = tun.name().to_string();

        // Get the interface index
        let index = Self::get_tun_index(&tun_name).await?;

        tracing::info!(
            "Created TUN device {} (index={}, mtu={})",
            tun_name,
            index,
            mtu_val
        );

        Ok(Self {
            tun,
            name: tun_name,
            index,
            mtu: mtu_val,
        })
    }

    async fn get_tun_index(name: &str) -> Result<u32> {
        use std::ffi::CString;

        let name_cstr =
            CString::new(name).map_err(|e| NetworkError::TunCreation(e.to_string()))?;

        let index = unsafe { libc::if_nametoindex(name_cstr.as_ptr()) };

        if index == 0 {
            return Err(NetworkError::TunCreation(format!(
                "Failed to get interface index for {}",
                name
            ))
            .into());
        }

        Ok(index)
    }

    /// Get the underlying Tun for direct access if needed
    pub fn inner(&self) -> &Tun {
        &self.tun
    }
}

#[async_trait]
impl TunDevice for LinuxTunDevice {
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        // tokio_tun's Tun doesn't have async recv, we need to use the fd directly
        // For now, we'll use a workaround with try_recv or blocking in spawn_blocking
        // Actually, tokio_tun implements AsyncRead

        // We need to use a different approach since Tun implements AsyncRead
        // but we only have &self, not &mut self

        // For proper async I/O, we'd need interior mutability or a different design
        // For now, let's use the raw fd with tokio's async fd

        Err(crate::error::WgError::Other(
            "recv not implemented - use split approach".to_string(),
        ))
    }

    async fn send(&self, buf: &[u8]) -> Result<usize> {
        Err(crate::error::WgError::Other(
            "send not implemented - use split approach".to_string(),
        ))
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn index(&self) -> u32 {
        self.index
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }
}

/// Split TUN device into read and write halves for use with tokio::select!
pub struct TunReader {
    reader: tokio::io::ReadHalf<Tun>,
}

pub struct TunWriter {
    writer: tokio::io::WriteHalf<Tun>,
}

impl TunReader {
    pub async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buf).await
    }
}

impl TunWriter {
    pub async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writer.write(buf).await
    }
}

/// Create a TUN device and split it into reader/writer halves
pub async fn create_tun_split(
    name: Option<&str>,
    mtu: Option<u32>,
) -> Result<(TunReader, TunWriter, String, u32)> {
    let mtu_val = mtu.unwrap_or(1420);

    let tun = tokio_tun::Tun::builder()
        .name(name.unwrap_or(""))
        .tap(false)
        .packet_info(false)
        .mtu(mtu_val as i32)
        .up()
        .try_build()
        .map_err(|e| NetworkError::TunCreation(e.to_string()))?;

    let tun_name = tun.name().to_string();
    let index = LinuxTunDevice::get_tun_index(&tun_name).await?;

    tracing::info!(
        "Created TUN device {} (index={}, mtu={})",
        tun_name,
        index,
        mtu_val
    );

    let (reader, writer) = tokio::io::split(tun);

    Ok((TunReader { reader }, TunWriter { writer }, tun_name, index))
}
