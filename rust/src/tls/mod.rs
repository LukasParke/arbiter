//! TLS interception subsystem (W1): CA management, dynamic leaf certificates,
//! CONNECT handling.
//!
//! Layout:
//! - [`ca`]: root-CA generation/loading/persistence (`arbiter ca` backing).
//! - [`leaf`]: per-host dynamic leaf certificates behind a fixed-cap cache.
//! - [`acceptor`]: rustls [`rustls::ServerConfig`] assembly for interception
//!   and static-cert downstream TLS.
//!
//! Resolution contract: CA resolution is lazy — never on the socket-bind path
//! (startup bar < 100 ms). RSA-2048 keygen and other CPU-heavy crypto runs on
//! the blocking pool via `tokio::task::spawn_blocking`.

pub mod acceptor;
pub mod ca;
pub mod leaf;

use crate::error::Result;

/// Errors surfaced by TLS interception. Foundation contract: `arbiter::Error`
/// carries this via `#[from]`; variants may only be extended by tls owners.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("CA generation failed: {0}")]
    CaGeneration(String),
    #[error("failed to load certificate/key: {0}")]
    KeyMaterial(String),
    #[error("leaf certificate for {host}: {msg}")]
    Leaf { host: String, msg: String },
    #[error("TLS handshake failed for {host}: {source}")]
    Handshake {
        host: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl TlsError {
    /// Convenience constructor matching the DX bar: cause line plus context.
    pub fn leaf(host: impl Into<String>, msg: impl Into<String>) -> Self {
        Self::Leaf {
            host: host.into(),
            msg: msg.into(),
        }
    }

    pub fn ca_generation(msg: impl Into<String>) -> Self {
        Self::CaGeneration(msg.into())
    }

    pub fn key_material(msg: impl Into<String>) -> Self {
        Self::KeyMaterial(msg.into())
    }
}

pub type TlsResult<T> = Result<T>;

/// Installed once at first use; reqwest's rustls already installs ring, so
/// installation is skipped when a process-wide provider already exists.
pub(crate) fn init_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        // Failure means another thread won the race; either way a default
        // exists afterwards, which is all callers need.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}
