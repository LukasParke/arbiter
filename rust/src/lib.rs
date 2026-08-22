//! Arbiter — API proxy, exact capture/replay, OpenAPI generation, HAR export.
//!
//! Rust rewrite of the TypeScript implementation in the repository root.
//! The canonical data model lives in [`types`]; deterministic serialization
//! and digesting in [`json`] and [`bundle`].

pub mod auth;
pub mod bundle;
pub mod capture;
pub mod cli;
pub mod config;
pub mod diff;
pub mod error;
pub mod gateway;
pub mod generate_spec;
pub mod headers;
pub mod infer;
pub mod json;
pub mod llm;
pub mod middleware;
pub mod mock;
pub mod redaction;
pub mod replay;
pub mod rules;
pub mod secret_scan;
pub mod server;
pub mod sse;
pub mod storage;
pub mod store;
pub mod tls;
pub mod tui;
pub mod types;
pub mod validation;
pub mod version;
pub mod ws;
