//! Capture module: body sinks, the capture-session reverse proxy, and
//! re-exports of the analysis primitives the TS `capture/index.ts` surfaces.

pub mod body_sink;
pub mod session;

pub use crate::error::SecretFindingError;
pub use crate::redaction::{
    redacted_query_names, RedactionPolicy, RedactionPolicyOptions, REDACTED_VALUE,
};
pub use crate::sse::{parse_sse_body, terminal_marker_for, SseEvent, SseParser};
pub use body_sink::{
    BodyLimitPolicy, BodySink, SunkBody, DEFAULT_MAX_BODY_BYTES, MAX_SPILLED_BODY_BYTES,
};
pub use session::{
    start_capture_session, CaptureSession, CaptureSessionOptions, ExportOptions, ExportResult,
};

// `capture/index.ts` also re-exports headers helpers and `export * from types`.
pub use crate::headers::{
    capture_headers, forwardable_headers, headers_from_raw, is_hop_by_hop, HOP_BY_HOP_HEADERS,
};
pub use crate::types::*;
