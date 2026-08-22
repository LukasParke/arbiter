//! TLS interception subsystem (W1): CA management, dynamic leaf certificates,
//! CONNECT handling. Implementation lands in the proxy-parity wave.

use crate::error::Result;

/// Errors surfaced by TLS interception. Foundation contract: `arbiter::Error`
/// carries this via `#[from]`; variants may only be extended by tls owners.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("CA generation failed: {0}")]
    CaGeneration(String),
    #[error("failed to load certificate/key: {0}")]
    KeyMaterial(String),
    #[error("TLS handshake failed for {host}: {source}")]
    Handshake {
        host: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Placeholder wiring so foundation compiles; replaced by the W1 wave.
pub fn ca_available() -> bool {
    false
}

pub type TlsResult<T> = Result<T>;
