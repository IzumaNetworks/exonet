use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WgError {
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    #[error("Tunnel error: {0}")]
    Tunnel(#[from] TunnelError),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("{0}")]
    Other(String),
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing required field: {0}")]
    MissingField(&'static str),

    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid port: {0}")]
    InvalidPort(String),

    #[error("Invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("File error: {0}")]
    File(#[from] io::Error),
}

#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Failed to create TUN device: {0}")]
    TunCreation(String),

    #[error("Failed to add address: {0}")]
    AddAddress(String),

    #[error("Failed to add route: {0}")]
    AddRoute(String),

    #[error("Failed to set interface up: {0}")]
    SetLinkUp(String),

    #[error("Netlink error: {0}")]
    Netlink(String),

    #[error("Socket error: {0}")]
    Socket(#[from] io::Error),
}

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("WireGuard error: {0}")]
    WireGuard(String),

    #[error("No peer found for destination: {0}")]
    NoPeerForDestination(String),

    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid packet: {0}")]
    InvalidPacket(String),
}

pub type Result<T> = std::result::Result<T, WgError>;
