//! Canonical capture bundle format: deterministic manifest, NDJSON
//! exchanges, content-addressed bodies, fail-closed validation.

pub mod derive;
pub mod sanitize;
pub mod store;
pub mod validate;

pub use store::{
    bundle_digest, is_sha256_hex, load_bundle, make_captured_body, safe_join, sha256_hex,
    write_bundle, CaptureBundle, WriteBundleOptions, INLINE_BODY_LIMIT,
};
pub use validate::{validate_exchange, validate_manifest, validate_sequence_order, BundleLimits};
