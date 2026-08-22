//! Runtime validation for untrusted bundle input. JSON parsing alone proves
//! nothing about shape; every manifest and exchange field is checked here
//! before the rest of the loader trusts it.

use serde_json::Value;

use crate::error::Error;
use crate::types::{
    BodyStorage, CaptureFailure, CaptureManifest, CaptureMode, CapturedBody, CapturedExchange,
    CapturedHeaders, CapturedRequest, CapturedResponse, HeaderMapValues, RedactionPolicySummary,
    StreamState, ValidationSummary, WsOpcode, WsStream, EXCHANGE_SCHEMA_VERSION,
};

/// Bounds applied before parsing/allocating untrusted input.
pub struct BundleLimits;

impl BundleLimits {
    pub const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
    pub const MAX_NDJSON_LINE_BYTES: u64 = 64 * 1024 * 1024;
    pub const MAX_EXCHANGES: usize = 100_000;
    pub const MAX_DECLARED_BODY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
    pub const MAX_HEADER_ENTRIES: usize = 512;
    pub const MAX_HEADER_VALUE_BYTES: usize = 64 * 1024;
    pub const MAX_STRING_BYTES: usize = 64 * 1024;
}

/// Hard bound on captured websocket messages per exchange (matches the
/// recorder's `MAX_WS_MESSAGES_PER_STREAM`).
const MAX_WS_MESSAGES: usize = 100_000;
/// Close reason is UTF-8 and at most 128 bytes after validation.
const MAX_WS_CLOSE_REASON_BYTES: usize = 128;

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

const BASE64_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const STREAM_KINDS: [&str; 3] = ["buffered", "sse", "other-stream"];
const FAILURE_STAGES: [&str; 4] = [
    "request-capture",
    "upstream-connect",
    "response-capture",
    "persistence",
];

fn fail(location: &str, problem: impl Into<String>) -> Error {
    Error::bundle_validation(location, problem)
}

fn as_record<'a>(
    value: &'a Value,
    location: &str,
) -> Result<&'a serde_json::Map<String, Value>, Error> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(fail(location, "expected an object")),
    }
}

fn as_string(value: &Value, location: &str, max_bytes: usize) -> Result<String, Error> {
    let Value::String(s) = value else {
        return Err(fail(location, "expected a string"));
    };
    if s.len() > max_bytes {
        return Err(fail(location, format!("string exceeds {max_bytes} bytes")));
    }
    Ok(s.clone())
}

fn as_bounded_int(value: &Value, location: &str, max: f64) -> Result<f64, Error> {
    let Value::Number(n) = value else {
        return Err(fail(location, "expected a finite integer"));
    };
    let Some(v) = n.as_f64() else {
        return Err(fail(location, "expected a finite integer"));
    };
    if !v.is_finite() || v.fract() != 0.0 {
        return Err(fail(location, "expected a finite integer"));
    }
    if !(0.0..=max).contains(&v) {
        return Err(fail(location, format!("out of bounds (0..{max})")));
    }
    Ok(v)
}

fn as_u64(value: &Value, location: &str, max: f64) -> Result<u64, Error> {
    Ok(as_bounded_int(value, location, max)? as u64)
}

fn as_finite_non_negative(value: &Value, location: &str) -> Result<f64, Error> {
    let Value::Number(n) = value else {
        return Err(fail(location, "expected a finite non-negative number"));
    };
    let v = n
        .as_f64()
        .ok_or_else(|| fail(location, "expected a finite non-negative number"))?;
    if !v.is_finite() || v < 0.0 {
        return Err(fail(location, "expected a finite non-negative number"));
    }
    Ok(v)
}

fn as_iso_date(value: &Value, location: &str) -> Result<String, Error> {
    let text = as_string(value, location, 128)?;
    // JS Date.parse accepts ISO-8601; require an RFC 3339-compatible form.
    if chrono::DateTime::parse_from_rfc3339(&text).is_err() {
        return Err(fail(location, "expected an ISO-8601 timestamp"));
    }
    Ok(text)
}

fn as_string_array(
    value: &Value,
    location: &str,
    max_entries: usize,
) -> Result<Vec<String>, Error> {
    let Value::Array(items) = value else {
        return Err(fail(location, "expected an array"));
    };
    if items.len() > max_entries {
        return Err(fail(location, format!("more than {max_entries} entries")));
    }
    items
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            as_string(
                entry,
                &format!("{location}[{i}]"),
                BundleLimits::MAX_STRING_BYTES,
            )
        })
        .collect()
}

pub fn validate_manifest(raw: &Value) -> Result<CaptureManifest, Error> {
    let m = as_record(raw, "manifest")?;
    let observed_manifest_version = m.get("schemaVersion").and_then(Value::as_u64);
    if !matches!(observed_manifest_version, Some(1) | Some(2)) {
        return Err(fail(
            "manifest.schemaVersion",
            format!(
                "unsupported value {}",
                m.get("schemaVersion")
                    .map(describe)
                    .unwrap_or_else(|| "missing".into())
            ),
        ));
    }
    let mode_str = as_string(m.get("mode").unwrap_or(&Value::Null), "manifest.mode", 64)?;
    let mode = match mode_str.as_str() {
        "observe" => CaptureMode::Observe,
        "exact" => CaptureMode::Exact,
        other => return Err(fail("manifest.mode", format!("unknown mode {other}"))),
    };
    let bundle_digest = as_string(
        m.get("bundleDigest").unwrap_or(&Value::Null),
        "manifest.bundleDigest",
        128,
    )?;
    if !is_sha256_hex(&bundle_digest) {
        return Err(fail("manifest.bundleDigest", "not a sha256 hex digest"));
    }
    let target_origin = as_string(
        m.get("targetOrigin").unwrap_or(&Value::Null),
        "manifest.targetOrigin",
        2048,
    )?;
    if url::Url::parse(&target_origin).is_err() {
        return Err(fail("manifest.targetOrigin", "not a valid URL"));
    }
    let redaction = as_record(
        m.get("redaction").unwrap_or(&Value::Null),
        "manifest.redaction",
    )?;
    let metadata = match m.get("metadata") {
        None | Some(Value::Null) => None,
        Some(v) => {
            let record = as_record(v, "manifest.metadata")?;
            let mut out = std::collections::BTreeMap::new();
            for (key, value) in record {
                out.insert(
                    as_string(&Value::String(key.clone()), "manifest.metadata key", 1024)?,
                    as_string(
                        value,
                        &format!("manifest.metadata.{key}"),
                        BundleLimits::MAX_STRING_BYTES,
                    )?,
                );
            }
            Some(out)
        }
    };
    Ok(CaptureManifest {
        schema_version: observed_manifest_version.unwrap_or(1),
        arbiter_version: as_string(
            m.get("arbiterVersion").unwrap_or(&Value::Null),
            "manifest.arbiterVersion",
            128,
        )?,
        mode,
        target_origin,
        started_at: as_iso_date(
            m.get("startedAt").unwrap_or(&Value::Null),
            "manifest.startedAt",
        )?,
        completed_at: as_iso_date(
            m.get("completedAt").unwrap_or(&Value::Null),
            "manifest.completedAt",
        )?,
        exchange_count: as_u64(
            m.get("exchangeCount").unwrap_or(&Value::Null),
            "manifest.exchangeCount",
            BundleLimits::MAX_EXCHANGES as f64,
        )?,
        bundle_digest,
        redaction: RedactionPolicySummary {
            redact_headers: as_string_array(
                redaction.get("redactHeaders").unwrap_or(&Value::Null),
                "manifest.redaction.redactHeaders",
                1024,
            )?,
            allow_query: as_string_array(
                redaction.get("allowQuery").unwrap_or(&Value::Null),
                "manifest.redaction.allowQuery",
                1024,
            )?,
        },
        metadata,
    })
}

fn validate_headers(raw: &Value, location: &str) -> Result<CapturedHeaders, Error> {
    let h = as_record(raw, location)?;
    let values_record = as_record(
        h.get("values").unwrap_or(&Value::Null),
        &format!("{location}.values"),
    )?;
    let mut values: HeaderMapValues = Default::default();
    let mut entries = 0usize;
    for (name, header_values) in values_record {
        if *name != name.to_lowercase() {
            return Err(fail(
                &format!("{location}.values"),
                format!("header name not lowercased: {name}"),
            ));
        }
        let Value::Array(list) = header_values else {
            return Err(fail(
                &format!("{location}.values.{name}"),
                "expected an array of values",
            ));
        };
        entries += list.len();
        if entries > BundleLimits::MAX_HEADER_ENTRIES {
            return Err(fail(
                &format!("{location}.values"),
                format!(
                    "more than {} header values",
                    BundleLimits::MAX_HEADER_ENTRIES
                ),
            ));
        }
        let mapped: Result<Vec<String>, Error> = list
            .iter()
            .enumerate()
            .map(|(i, v)| {
                as_string(
                    v,
                    &format!("{location}.values.{name}[{i}]"),
                    BundleLimits::MAX_HEADER_VALUE_BYTES,
                )
            })
            .collect();
        values.insert(name.clone(), mapped?);
    }
    Ok(CapturedHeaders {
        values,
        redacted: as_string_array(
            h.get("redacted").unwrap_or(&Value::Null),
            &format!("{location}.redacted"),
            BundleLimits::MAX_HEADER_ENTRIES,
        )?,
    })
}

fn validate_body(raw: &Value, location: &str) -> Result<CapturedBody, Error> {
    let b = as_record(raw, location)?;
    let sha256 = as_string(
        b.get("sha256").unwrap_or(&Value::Null),
        &format!("{location}.sha256"),
        128,
    )?;
    if !is_sha256_hex(&sha256) {
        return Err(fail(
            &format!("{location}.sha256"),
            "not a sha256 hex digest",
        ));
    }
    let size = as_u64(
        b.get("size").unwrap_or(&Value::Null),
        &format!("{location}.size"),
        BundleLimits::MAX_DECLARED_BODY_BYTES as f64,
    )?;
    let storage_record = as_record(
        b.get("storage").unwrap_or(&Value::Null),
        &format!("{location}.storage"),
    )?;
    let kind = storage_record
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("");
    let storage = match kind {
        "inline-base64" => {
            let value = as_string(
                storage_record.get("value").unwrap_or(&Value::Null),
                &format!("{location}.storage.value"),
                // base64 expansion of the inline limit, with slack for padding
                64 * 1024 * 1024,
            )?;
            let valid_chars = value
                .bytes()
                .all(|b| BASE64_CHARS.contains(b as char) || b == b'=');
            if !valid_chars || value.len() % 4 != 0 {
                return Err(fail(
                    &format!("{location}.storage.value"),
                    "malformed base64",
                ));
            }
            // Cheap pre-decode size check: base64 length must be consistent
            // with the declared body size, so a tampered size cannot force
            // overallocation.
            let decoded_upper_bound = value.len().div_ceil(4) * 3;
            if (decoded_upper_bound as u64) < size || decoded_upper_bound as u64 > size + 3 {
                return Err(fail(
                    &format!("{location}.storage.value"),
                    "base64 length inconsistent with declared size",
                ));
            }
            BodyStorage::InlineBase64 { value }
        }
        "blob" => {
            let blob_path = as_string(
                storage_record.get("path").unwrap_or(&Value::Null),
                &format!("{location}.storage.path"),
                512,
            )?;
            if blob_path != format!("bodies/{sha256}.bin") {
                return Err(fail(
                    &format!("{location}.storage.path"),
                    "not content-addressed",
                ));
            }
            BodyStorage::Blob { path: blob_path }
        }
        other => {
            return Err(fail(
                &format!("{location}.storage.kind"),
                format!("unknown kind {other}"),
            ))
        }
    };
    let media_type = match b.get("mediaType") {
        None | Some(Value::Null) => None,
        Some(v) => Some(as_string(v, &format!("{location}.mediaType"), 1024)?),
    };
    let content_encoding = match b.get("contentEncoding") {
        None | Some(Value::Null) => None,
        Some(v) => Some(as_string(v, &format!("{location}.contentEncoding"), 256)?),
    };
    Ok(CapturedBody {
        sha256,
        size,
        media_type,
        content_encoding,
        storage,
    })
}

fn validate_stream(raw: &Value, location: &str) -> Result<StreamState, Error> {
    let s = as_record(raw, location)?;
    let kind = as_string(
        s.get("kind").unwrap_or(&Value::Null),
        &format!("{location}.kind"),
        64,
    )?;
    if !STREAM_KINDS.contains(&kind.as_str()) {
        return Err(fail(
            &format!("{location}.kind"),
            format!("unknown kind {kind}"),
        ));
    }
    let boolean = |key: &str| -> Result<bool, Error> {
        match s.get(key) {
            Some(Value::Bool(b)) => Ok(*b),
            _ => Err(fail(&format!("{location}.{key}"), "expected a boolean")),
        }
    };
    let terminal_marker = match s.get("terminalMarker") {
        None | Some(Value::Null) => None,
        Some(v) => Some(as_string(v, &format!("{location}.terminalMarker"), 256)?),
    };
    let error = match s.get("error") {
        None | Some(Value::Null) => None,
        Some(v) => Some(as_string(v, &format!("{location}.error"), 4096)?),
    };
    Ok(StreamState {
        kind,
        completed: boolean("completed")?,
        client_aborted: boolean("clientAborted")?,
        upstream_aborted: boolean("upstreamAborted")?,
        terminal_marker,
        error,
    })
}

fn validate_failure(raw: Option<&Value>, location: &str) -> Result<Option<CaptureFailure>, Error> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.is_null() {
        return Ok(None);
    }
    let f = as_record(raw, location)?;
    let stage = as_string(
        f.get("stage").unwrap_or(&Value::Null),
        &format!("{location}.stage"),
        64,
    )?;
    if !FAILURE_STAGES.contains(&stage.as_str()) {
        return Err(fail(
            &format!("{location}.stage"),
            format!("unknown stage {stage}"),
        ));
    }
    Ok(Some(CaptureFailure {
        stage,
        message: as_string(
            f.get("message").unwrap_or(&Value::Null),
            &format!("{location}.message"),
            4096,
        )?,
    }))
}

fn validate_validation_summary(
    raw: Option<&Value>,
    location: &str,
) -> Result<Option<ValidationSummary>, Error> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.is_null() {
        return Ok(None);
    }
    let v = as_record(raw, location)?;
    let valid = match v.get("valid") {
        Some(Value::Bool(b)) => *b,
        _ => return Err(fail(&format!("{location}.valid"), "expected a boolean")),
    };
    Ok(Some(ValidationSummary {
        valid,
        violation_count: as_u64(
            v.get("violationCount").unwrap_or(&Value::Null),
            &format!("{location}.violationCount"),
            1_000_000.0,
        )?,
    }))
}

pub fn validate_exchange(raw: &Value, index: usize) -> Result<CapturedExchange, Error> {
    let location = format!("exchange[{index}]");
    let e = as_record(raw, &location)?;
    if e.get("schemaVersion").and_then(Value::as_u64) != Some(EXCHANGE_SCHEMA_VERSION) {
        return Err(fail(
            &format!("{location}.schemaVersion"),
            format!(
                "unsupported value {}",
                e.get("schemaVersion")
                    .map(describe)
                    .unwrap_or_else(|| "missing".into())
            ),
        ));
    }
    let request = as_record(
        e.get("request").unwrap_or(&Value::Null),
        &format!("{location}.request"),
    )?;
    let response = as_record(
        e.get("response").unwrap_or(&Value::Null),
        &format!("{location}.response"),
    )?;
    let request = CapturedRequest {
        method: as_string(
            request.get("method").unwrap_or(&Value::Null),
            &format!("{location}.request.method"),
            64,
        )?,
        path: as_string(
            request.get("path").unwrap_or(&Value::Null),
            &format!("{location}.request.path"),
            16 * 1024,
        )?,
        http_version: as_string(
            request.get("httpVersion").unwrap_or(&Value::Null),
            &format!("{location}.request.httpVersion"),
            32,
        )?,
        headers: validate_headers(
            request.get("headers").unwrap_or(&Value::Null),
            &format!("{location}.request.headers"),
        )?,
        body: validate_body(
            request.get("body").unwrap_or(&Value::Null),
            &format!("{location}.request.body"),
        )?,
    };
    let status = match response.get("status") {
        Some(Value::Number(n)) => {
            n.as_u64()
                .filter(|s| (1..=599).contains(s))
                .ok_or_else(|| {
                    fail(
                        &format!("{location}.response.status"),
                        "out of bounds (1..599)",
                    )
                })?
        }
        _ => {
            return Err(fail(
                &format!("{location}.response.status"),
                "expected a finite integer",
            ))
        }
    };
    let stream = validate_stream(
        response.get("stream").unwrap_or(&Value::Null),
        &format!("{location}.response.stream"),
    )?;
    let response = CapturedResponse {
        status: status as u16,
        status_text: as_string(
            response.get("statusText").unwrap_or(&Value::Null),
            &format!("{location}.response.statusText"),
            512,
        )?,
        http_version: as_string(
            response.get("httpVersion").unwrap_or(&Value::Null),
            &format!("{location}.response.httpVersion"),
            32,
        )?,
        headers: validate_headers(
            response.get("headers").unwrap_or(&Value::Null),
            &format!("{location}.response.headers"),
        )?,
        body: validate_body(
            response.get("body").unwrap_or(&Value::Null),
            &format!("{location}.response.body"),
        )?,
        stream,
    };
    let failure = validate_failure(e.get("failure"), &format!("{location}.failure"))?;
    let validation =
        validate_validation_summary(e.get("validation"), &format!("{location}.validation"))?;
    let sequence = as_u64(
        e.get("sequence").unwrap_or(&Value::Null),
        &format!("{location}.sequence"),
        u64::MAX as f64,
    )?;
    let tunnel = as_optional_ext(e, "tunnel", &format!("{location}.tunnel"))?;
    let tls = as_optional_ext(e, "tls", &format!("{location}.tls"))?;
    let ws: Option<WsStream> = as_optional_ext(e, "ws", &format!("{location}.ws"))?;
    if let Some(ws) = &ws {
        validate_ws_stream(ws, &format!("{location}.ws"))?;
    }
    let llm = as_optional_ext(e, "llm", &format!("{location}.llm"))?;
    Ok(CapturedExchange {
        schema_version: EXCHANGE_SCHEMA_VERSION,
        sequence,
        started_at: as_iso_date(
            e.get("startedAt").unwrap_or(&Value::Null),
            &format!("{location}.startedAt"),
        )?,
        duration_ms: as_finite_non_negative(
            e.get("durationMs").unwrap_or(&Value::Null),
            &format!("{location}.durationMs"),
        )?,
        request,
        response,
        tls,
        failure,
        validation,
        tunnel,
        ws,
        llm,
    })
}

/// Upper bound applied to each optional v2 extension block before decoding,
/// preserving the bounded-allocation loader posture for untrusted input.
const MAX_EXTENSION_BLOCK_BYTES: usize = 8 * 1024 * 1024;

fn as_optional_ext<T: serde::de::DeserializeOwned>(
    e: &serde_json::Map<String, Value>,
    key: &str,
    location: &str,
) -> Result<Option<T>, Error> {
    match e.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            if v.to_string().len() > MAX_EXTENSION_BLOCK_BYTES {
                return Err(fail(location, "extension block exceeds permitted size"));
            }
            serde_json::from_value(v.clone())
                .map(Some)
                .map_err(|err| fail(location, format!("invalid structure: {err}")))
        }
    }
}

/// Structural checks on a decoded WsStream that serde cannot express:
/// bounded message count, per-message size/offset bounds, opcode/payload
/// consistency, base64 validity, and close-reason length.
fn validate_ws_stream(ws: &WsStream, location: &str) -> Result<(), Error> {
    if ws.messages.len() > MAX_WS_MESSAGES {
        return Err(fail(
            &format!("{location}.messages"),
            format!("more than {MAX_WS_MESSAGES} messages"),
        ));
    }
    if let Some(protocol) = &ws.protocol {
        if protocol.len() > BundleLimits::MAX_STRING_BYTES {
            return Err(fail(
                &format!("{location}.protocol"),
                "string exceeds 65536 bytes",
            ));
        }
    }
    for (index, message) in ws.messages.iter().enumerate() {
        let message_location = format!("{location}.messages[{index}]");
        validate_ws_message(message, &message_location)?;
    }
    if let Some(reason) = &ws.close_reason {
        if reason.len() > MAX_WS_CLOSE_REASON_BYTES {
            return Err(fail(
                &format!("{location}.closeReason"),
                format!("exceeds {MAX_WS_CLOSE_REASON_BYTES} bytes"),
            ));
        }
    }
    Ok(())
}

fn validate_ws_message(message: &crate::types::WsMessage, location: &str) -> Result<(), Error> {
    if message.size > BundleLimits::MAX_DECLARED_BODY_BYTES {
        return Err(fail(
            &format!("{location}.size"),
            format!(
                "out of bounds (0..{})",
                BundleLimits::MAX_DECLARED_BODY_BYTES
            ),
        ));
    }
    if !message.offset_ms.is_finite() || message.offset_ms < 0.0 {
        return Err(fail(
            &format!("{location}.offsetMs"),
            "expected a finite non-negative number",
        ));
    }
    match message.opcode {
        WsOpcode::Text => match (&message.text, &message.data_base64) {
            (Some(text), None) => {
                if text.len() as u64 != message.size {
                    return Err(fail(
                        &format!("{location}.size"),
                        "does not match text length",
                    ));
                }
            }
            _ => {
                return Err(fail(
                    &format!("{location}.text"),
                    "text messages carry text only",
                ))
            }
        },
        WsOpcode::Close => {
            // Close frames may carry a reason, raw bytes, or nothing.
            if let Some(data) = &message.data_base64 {
                check_base64_payload(data, message.size, location)?;
            } else if message.text.is_none() && message.size > 2 {
                return Err(fail(
                    &format!("{location}.size"),
                    "empty close frame exceeds 2 bytes",
                ));
            }
        }
        WsOpcode::Binary | WsOpcode::Ping | WsOpcode::Pong => {
            match (&message.data_base64, &message.text) {
                (Some(data), None) => {
                    check_base64_payload(data, message.size, location)?;
                }
                _ => {
                    return Err(fail(
                        &format!("{location}.dataBase64"),
                        "expected dataBase64 payload for non-text opcode",
                    ))
                }
            }
        }
    }
    Ok(())
}

fn check_base64_payload(value: &str, size: u64, location: &str) -> Result<(), Error> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| fail(&format!("{location}.dataBase64"), "malformed base64"))?;
    if decoded.len() as u64 != size {
        return Err(fail(
            &format!("{location}.size"),
            "does not match decoded payload length",
        ));
    }
    Ok(())
}
pub fn validate_sequence_order(exchanges: &[CapturedExchange]) -> Result<(), Error> {
    for pair in exchanges.windows(2) {
        if pair[1].sequence <= pair[0].sequence {
            return Err(Error::bundle_validation(
                "exchanges.ndjson",
                format!(
                    "sequence {} does not strictly increase (previous {})",
                    pair[1].sequence, pair[0].sequence
                ),
            ));
        }
    }
    Ok(())
}

fn describe(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod ws_validation_tests {
    use super::*;
    use serde_json::json;

    use base64::Engine;

    /// Minimal valid HTTP-shaped exchange line, matching the writer's
    /// canonical serialization.
    fn base_exchange() -> Value {
        let body = |value: &str| {
            json!({
                "sha256": sha256_hex_for(value),
                "size": value.len(),
                "mediaType": null,
                "contentEncoding": null,
                "storage": {"kind": "inline-base64", "value": base64_of(value)}
            })
        };
        json!({
            "schemaVersion": 1,
            "sequence": 1,
            "startedAt": "2026-08-21T00:00:00.000Z",
            "durationMs": 5.0,
            "request": {
                "method": "GET", "path": "/x", "httpVersion": "1.1",
                "headers": {"values": {}, "redacted": []}, "body": body("")
            },
            "response": {
                "status": 200, "statusText": "OK", "httpVersion": "1.1",
                "headers": {"values": {}, "redacted": []}, "body": body(""),
                "stream": {"kind": "buffered", "completed": true,
                           "clientAborted": false, "upstreamAborted": false,
                           "terminalMarker": null, "error": null}
            },
            "failure": null, "validation": null,
            "tunnel": null, "tls": null, "ws": null, "llm": null
        })
    }

    fn sha256_hex_for(value: &str) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(value.as_bytes()))
    }

    fn base64_of(value: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(value)
    }

    fn valid_ws_json() -> Value {
        let payload = base64_of("hello");
        json!({
            "protocol": null,
            "messages": [{
                "direction": "client-to-server",
                "opcode": "binary",
                "dataBase64": payload,
                "size": 5,
                "offsetMs": 1.5
            }],
            "completed": true,
            "closeCode": 1000,
            "closeReason": "done"
        })
    }

    fn exchange_with(ws: Value) -> Value {
        let mut raw = base_exchange();
        raw["ws"] = ws;
        raw
    }

    #[test]
    fn accepts_wellformed_ws_stream() {
        let parsed = validate_exchange(&exchange_with(valid_ws_json()), 0).unwrap();
        assert_eq!(parsed.ws.unwrap().messages.len(), 1);
    }

    #[test]
    fn rejects_excess_message_count() {
        // Built structurally: 100_001 tiny messages would exceed the 8 MiB
        let make = || crate::types::WsMessage {
            direction: crate::types::WsDirection::ClientToServer,
            opcode: crate::types::WsOpcode::Text,
            text: Some(String::new()),
            data_base64: None,
            size: 0,
            offset_ms: 0.0,
        };
        let ws = WsStream {
            protocol: None,
            messages: (0..=MAX_WS_MESSAGES).map(|_| make()).collect(),
            completed: true,
            close_code: None,
            close_reason: None,
        };
        let err = validate_ws_stream(&ws, "exchange[0].ws").unwrap_err();
        assert!(err.to_string().contains("more than"), "{err}");

        let at_cap = WsStream {
            messages: (0..MAX_WS_MESSAGES).map(|_| make()).collect(),
            ..ws
        };
        assert!(validate_ws_stream(&at_cap, "exchange[0].ws").is_ok());
    }

    #[test]
    fn rejects_negative_or_non_finite_offset() {
        for bad in [-1.0, f64::NAN] {
            let mut ws = valid_ws_json();
            ws["messages"][0]["offsetMs"] = json!(bad);
            // JSON cannot carry NaN; only the negative case is representable.
            if !bad.is_nan() {
                assert!(validate_exchange(&exchange_with(ws), 0).is_err());
            }
        }
    }

    #[test]
    fn rejects_size_base64_mismatch() {
        let mut ws = valid_ws_json();
        ws["messages"][0]["size"] = json!(6);
        assert!(validate_exchange(&exchange_with(ws), 0).is_err());
    }

    #[test]
    fn rejects_text_opcode_without_text_payload() {
        let mut ws = valid_ws_json();
        ws["messages"][0]["opcode"] = json!("text");
        ws["messages"][0]["text"] = Value::Null;
        assert!(validate_exchange(&exchange_with(ws), 0).is_err());
    }

    #[test]
    fn rejects_oversized_close_reason_and_bad_direction() {
        let mut ws = valid_ws_json();
        ws["closeReason"] = json!("x".repeat(129));
        assert!(validate_exchange(&exchange_with(ws), 0).is_err());

        let mut ws = valid_ws_json();
        ws["messages"][0]["direction"] = json!("sideways");
        assert!(validate_exchange(&exchange_with(ws), 0).is_err());
    }
}
