use std::fmt;

use crate::secret_scan::SecretFinding;

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Unified error surface. Mirrors the TS error classes
/// (`BundleValidationError`, `SecretFindingError`, `BodyLimitExceededError`)
/// plus transport and storage failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid bundle: {location}: {problem}")]
    BundleValidation { location: String, problem: String },

    #[error("Bundle digest mismatch: exchanges.ndjson does not match manifest")]
    DigestMismatch,

    #[error("Manifest exchangeCount {declared} does not match {actual} exchanges")]
    ExchangeCountMismatch { declared: u64, actual: usize },

    #[error("{0}")]
    SecretFindings(#[from] SecretFindingError),

    #[error("Body limit exceeded: {0}")]
    BodyLimitExceeded(String),

    #[error("Refusing to write through symlinked path: {0}")]
    SymlinkedPath(String),

    #[error("Unsafe path segment: {0}")]
    UnsafePath(String),

    #[error("{context}: {source}")]
    Io {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{context}: {source}")]
    Json {
        context: String,
        #[source]
        source: serde_json::Error,
    },

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("TLS error: {0}")]
    Tls(#[from] crate::tls::TlsError),

    #[error(
        "exchange {seq} carries a WebSocket stream and cannot be replayed via HTTP replay modes"
    )]
    WebsocketNotReplayable { seq: u64 },

    #[error("{0}")]
    Other(String),
}

impl Error {
    pub fn bundle_validation(location: impl Into<String>, problem: impl Into<String>) -> Self {
        Error::BundleValidation {
            location: location.into(),
            problem: problem.into(),
        }
    }

    pub fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        Error::Io {
            context: context.into(),
            source,
        }
    }

    pub fn other(msg: impl Into<String>) -> Self {
        Error::Other(msg.into())
    }
}

/// Fail-closed secret-scan failure carrying every finding; findings never
/// contain the full secret value.
#[derive(Debug)]
pub struct SecretFindingError {
    pub findings: Vec<SecretFinding>,
}

impl fmt::Display for SecretFindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.findings.first() {
            Some(first) => write!(
                f,
                "Secret scan failed: {} finding(s). First: {} at {}",
                self.findings.len(),
                first.kind,
                first.location
            ),
            None => write!(f, "Secret scan failed with no findings"),
        }
    }
}

impl std::error::Error for SecretFindingError {}
