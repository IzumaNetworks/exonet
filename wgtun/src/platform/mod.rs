pub mod traits;

#[cfg(target_os = "linux")]
pub mod linux;

pub use traits::{NetworkManager, TunDevice};

#[cfg(target_os = "linux")]
pub use linux::{LinuxNetworkManager, LinuxTunDevice};
