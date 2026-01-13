use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

mod cli;
mod config;
mod error;
mod network;
mod platform;
mod runtime;
mod tunnel;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(match cli.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        })
    });

    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let result = match cli.command {
        Commands::Up {
            config,
            interface,
            port,
            server,
            foreground,
        } => {
            cli::commands::cmd_up(config, interface, port, server, foreground).await
        }
        Commands::Down { interface } => cli::commands::cmd_down(interface).await,
        Commands::Status { interface } => cli::commands::cmd_status(interface).await,
        Commands::Genkey => {
            cli::commands::cmd_genkey();
            Ok(())
        }
        Commands::Pubkey => cli::commands::cmd_pubkey(),
        Commands::ShowConfig => {
            cli::commands::cmd_show_config();
            Ok(())
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
