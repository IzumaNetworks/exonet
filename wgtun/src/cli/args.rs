use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "wgtun", about = "Self-contained WireGuard tunnel CLI", version)]
pub struct Cli {
    /// Increase verbosity (-v for info, -vv for debug, -vvv for trace)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Bring up a WireGuard interface
    Up {
        /// Path to WireGuard config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Interface name (overrides config)
        #[arg(short, long)]
        interface: Option<String>,

        /// Listen port (overrides config)
        #[arg(short, long)]
        port: Option<u16>,

        /// Run as server (accept incoming connections without endpoint)
        #[arg(long)]
        server: bool,

        /// Run in foreground (don't daemonize)
        #[arg(short, long)]
        foreground: bool,
    },

    /// Bring down a WireGuard interface
    Down {
        /// Interface name
        interface: String,
    },

    /// Show interface status
    Status {
        /// Interface name (shows all if omitted)
        interface: Option<String>,
    },

    /// Generate a new private key
    Genkey,

    /// Derive public key from private key (reads from stdin)
    Pubkey,

    /// Show example configuration file
    ShowConfig,
}

impl Cli {
    pub fn log_level(&self) -> tracing::Level {
        match self.verbose {
            0 => tracing::Level::WARN,
            1 => tracing::Level::INFO,
            2 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        }
    }
}
