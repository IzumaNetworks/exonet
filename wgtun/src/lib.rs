//! wgtun - Self-contained WireGuard tunnel CLI
//!
//! This library provides the core functionality for creating WireGuard tunnels
//! using the boringtun library for the WireGuard protocol implementation.
//!
//! # Features
//!
//! - TUN device creation and management
//! - IP address and route configuration via netlink
//! - WireGuard protocol handling (encryption, handshakes, keepalives)
//! - Support for multiple peers with AllowedIPs routing
//!
//! # Example
//!
//! ```no_run
//! use wgtun::config::parse_config_file;
//!
//! let config = parse_config_file("wg0.conf").unwrap();
//! println!("Loaded {} peers", config.peers.len());
//! ```

pub mod cli;
pub mod config;
pub mod error;
pub mod network;
pub mod platform;
pub mod runtime;
pub mod tunnel;

pub use error::{Result, WgError};
