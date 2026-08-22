//! Arbiter — API proxy, exact capture/replay, OpenAPI generation, HAR export.
//!
//! Rust rewrite of the TypeScript implementation in the repository root.
//! The canonical data model lives in [`types`]; deterministic serialization
//! and digesting in [`json`] and [`bundle`].

pub mod auth;
pub mod bundle;
pub mod capture;
pub mod cli;
pub mod diff;
pub mod error;
pub mod gateway;
pub mod generate_spec;
pub mod headers;
pub mod infer;
pub mod json;
pub mod middleware;
pub mod redaction;
pub mod replay;
pub mod secret_scan;
pub mod server;
pub mod sse;
pub mod storage;
pub mod store;
pub mod types;
pub mod validation;
pub mod version;
