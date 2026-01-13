pub mod parser;
pub mod types;

pub use parser::parse_config_file;
pub use types::{InterfaceConfig, Mode, PeerConfig, WgConfig};
