//! Canonical capture bundle storage.
//!
//! ```text
//! capture/
//!   manifest.json        deterministic manifest with bundle digest
//!   exchanges.ndjson     one stable-JSON exchange per line, ordered by sequence
//!   bodies/<sha256>.bin  content-addressed body bytes
//!   validation.ndjson    optional structured violations
//! ```

use std::collections::HashMap;
use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::bundle::validate::{
    validate_exchange, validate_manifest, validate_sequence_order, BundleLimits,
};
use crate::error::{Error, Result};
use crate::json::stable_stringify;
use crate::types::{
    BodyStorage, CaptureManifest, CapturedBody, CapturedExchange, BUNDLE_SCHEMA_VERSION,
};

pub const INLINE_BODY_LIMIT: usize = 8 * 1024;

const SHA256_HEX_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct CaptureBundle {
    pub root: PathBuf,
    pub manifest: CaptureManifest,
    pub exchanges: Vec<CapturedExchange>,
    body_cache: HashMap<String, Vec<u8>>,
}

impl CaptureBundle {
    /// Read and verify the bytes for a captured body. Inline bodies decode
    /// from base64; blobs are read from disk with containment checks.
    pub fn read_body(&mut self, body: &CapturedBody) -> Result<Vec<u8>> {
        let bytes = match &body.storage {
            BodyStorage::InlineBase64 { value } => crate::secret_scan::base64_decode(value)
                .map_err(|_| {
                    Error::bundle_validation(
                        "body.storage.value",
                        "malformed base64 in inline body",
                    )
                })?,
            BodyStorage::Blob { .. } => match self.body_cache.get(&body.sha256) {
                Some(bytes) => bytes.clone(),
                None => {
                    if !is_sha256_hex(&body.sha256) {
                        return Err(Error::other(format!(
                            "Invalid body digest: {}",
                            body.sha256
                        )));
                    }
                    let expected = format!("bodies/{}.bin", body.sha256);
                    if let BodyStorage::Blob { path } = &body.storage {
                        if path != &expected {
                            return Err(Error::other(format!(
                                "Blob path {} is not content-addressed",
                                path
                            )));
                        }
                    }
                    let bytes = read_contained_file(
                        &self.root,
                        &["bodies", &format!("{}.bin", body.sha256)],
                        body.size,
                    )?;
                    self.body_cache.insert(body.sha256.clone(), bytes.clone());
                    bytes
                }
            },
        };
        if bytes.len() as u64 != body.size {
            return Err(Error::other(format!(
                "Body size mismatch for {}",
                body.sha256
            )));
        }
        let digest = sha256_hex(&bytes);
        if digest != body.sha256 {
            return Err(Error::other(format!(
                "Body digest mismatch for {}",
                body.sha256
            )));
        }
        Ok(bytes)
    }

    /// Read all referenced blob bodies into memory (bounded by declared
    /// sizes, which are validated on load).
    pub fn read_all_bodies(&mut self) -> Result<HashMap<String, Vec<u8>>> {
        let mut out: HashMap<String, Vec<u8>> = HashMap::new();
        for exchange in &self.exchanges.clone() {
            for body in [&exchange.request.body, &exchange.response.body] {
                if matches!(body.storage, BodyStorage::Blob { .. })
                    && !out.contains_key(&body.sha256)
                {
                    out.insert(body.sha256.clone(), self.read_body(body)?);
                }
            }
        }
        Ok(out)
    }
}

pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Digest over normalized exchange content. Timing provenance (`startedAt`,
/// `durationMs`) is excluded so semantically identical captures compare equal.
pub fn bundle_digest(exchanges: &[CapturedExchange]) -> String {
    let mut hash = Sha256::new();
    for exchange in exchanges {
        let value = serde_json::to_value(exchange).expect("exchange serializes");
        if let Value::Object(map) = &value {
            let mut view = map.clone();
            view.remove("startedAt");
            view.remove("durationMs");
            hash.update(stable_stringify(&Value::Object(view)));
        }
        hash.update(b"\n");
    }
    hex::encode(hash.finalize())
}

#[derive(Debug, Clone)]
pub struct WriteBundleOptions {
    /// Manifest fields except `schemaVersion`, `exchangeCount`, `bundleDigest`
    /// which are derived here.
    pub manifest: CaptureManifest,
    pub exchanges: Vec<CapturedExchange>,
    pub bodies: HashMap<String, Vec<u8>>,
    pub validation: Option<Vec<Value>>,
}

/// Write a deterministic bundle. The output directory is created with
/// owner-only permissions; blob files are content-addressed by sha256.
pub fn write_bundle(output_dir: &Path, options: WriteBundleOptions) -> Result<CaptureManifest> {
    std::fs::create_dir_all(output_dir)
        .map_err(|e| Error::io(format!("create output dir {:?}", output_dir), e))?;
    set_dir_permissions(output_dir, 0o700)?;
    // Never write through a symlinked output root (symlink-overwrite hardening).
    let root = output_dir
        .canonicalize()
        .map_err(|e| Error::io("realpath output root", e))?;
    let bodies_dir = root.join("bodies");
    std::fs::create_dir_all(&bodies_dir).map_err(|e| Error::io("create bodies dir", e))?;
    set_dir_permissions(&bodies_dir, 0o700)?;
    if std::fs::symlink_metadata(&bodies_dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(Error::SymlinkedPath(bodies_dir.display().to_string()));
    }

    let mut exchanges = options.exchanges;
    exchanges.sort_by_key(|e| e.sequence);

    let mut referenced: Vec<String> = vec![];
    for exchange in &exchanges {
        for body in [&exchange.request.body, &exchange.response.body] {
            if let BodyStorage::Blob { path } = &body.storage {
                let expected = format!("bodies/{}.bin", body.sha256);
                if *path != expected {
                    return Err(Error::other(format!(
                        "Body blob path {path} is not content-addressed (expected {expected})"
                    )));
                }
                if !referenced.contains(&body.sha256) {
                    referenced.push(body.sha256.clone());
                }
            }
        }
    }
    referenced.sort();

    for digest in &referenced {
        let Some(bytes) = options.bodies.get(digest) else {
            return Err(Error::other(format!(
                "Missing body bytes for referenced blob {digest}"
            )));
        };
        if sha256_hex(bytes) != *digest {
            return Err(Error::other(format!(
                "Body bytes do not match digest {digest}"
            )));
        }
        write_file_atomic(bodies_dir.join(format!("{digest}.bin")), bytes)?;
    }

    let ndjson = exchanges
        .iter()
        .map(|e| stable_stringify(&serde_json::to_value(e).expect("exchange serializes")))
        .collect::<Vec<_>>()
        .join("\n");
    write_file_atomic(
        root.join("exchanges.ndjson"),
        format!("{ndjson}\n").as_bytes(),
    )?;

    if let Some(validation) = &options.validation {
        if !validation.is_empty() {
            let lines = validation
                .iter()
                .map(stable_stringify)
                .collect::<Vec<_>>()
                .join("\n");
            write_file_atomic(
                root.join("validation.ndjson"),
                format!("{lines}\n").as_bytes(),
            )?;
        }
    }

    // Stamp manifest schemaVersion 1 for HTTP-only captures (byte-identical
    // to TS writer output — frozen interchange) and 2 only when v2 extension
    // content (tunnel/tls/ws/llm) is present.
    let needs_v2 = exchanges
        .iter()
        .any(|e| e.tunnel.is_some() || e.tls.is_some() || e.ws.is_some() || e.llm.is_some());
    let manifest = CaptureManifest {
        schema_version: if needs_v2 { BUNDLE_SCHEMA_VERSION } else { 1 },
        exchange_count: exchanges.len() as u64,
        bundle_digest: bundle_digest(&exchanges),
        ..options.manifest
    };
    write_file_atomic(
        root.join("manifest.json"),
        format!(
            "{}\n",
            stable_stringify(&serde_json::to_value(&manifest).expect("manifest serializes"))
        )
        .as_bytes(),
    )?;
    Ok(manifest)
}

fn set_dir_permissions(path: &Path, mode: u32) -> Result<()> {
    let meta =
        std::fs::metadata(path).map_err(|e| Error::io(format!("stat {}", path.display()), e))?;
    let mut perms = meta.permissions();
    perms.set_mode(mode);
    std::fs::set_permissions(path, perms)
        .map_err(|e| Error::io(format!("chmod {}", path.display()), e))
}

fn write_file_atomic(file_path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    let file_path = file_path.as_ref();
    let tmp = file_path.with_extension("tmp");
    {
        let mut f = std::fs::File::create(&tmp).map_err(|e| Error::io("atomic create", e))?;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io("atomic chmod", e))?;
        f.write_all(data)
            .map_err(|e| Error::io("atomic write", e))?;
        f.sync_all().ok();
    }
    std::fs::rename(&tmp, file_path).map_err(|e| Error::io("atomic rename", e))
}

/// Load and verify a bundle. Every field is runtime-validated with bounded
/// sizes before allocation, sequences must be strictly increasing, digests
/// are verified, and all file reads are confined to the bundle root with
/// symlinks rejected at every path component. Untrusted bundles are safe to
/// load.
pub fn load_bundle(bundle_dir: &Path) -> Result<CaptureBundle> {
    let root = bundle_dir
        .canonicalize()
        .map_err(|e| Error::io("resolve bundle root", e))?;

    let manifest_raw =
        read_contained_file(&root, &["manifest.json"], BundleLimits::MAX_MANIFEST_BYTES)?;
    let manifest_parsed: Value =
        serde_json::from_slice(&manifest_raw).map_err(|e| Error::Json {
            context: "manifest.json is not valid JSON".into(),
            source: e,
        })?;
    let manifest = validate_manifest(&manifest_parsed)?;

    let exchanges_raw = read_contained_file(
        &root,
        &["exchanges.ndjson"],
        (BundleLimits::MAX_EXCHANGES as u64).saturating_mul(BundleLimits::MAX_NDJSON_LINE_BYTES),
    )?;
    let text = String::from_utf8(exchanges_raw)
        .map_err(|_| Error::bundle_validation("exchanges.ndjson", "not valid UTF-8"))?;
    let mut exchanges: Vec<CapturedExchange> = vec![];
    for line in text.split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        if line.len() as u64 > BundleLimits::MAX_NDJSON_LINE_BYTES {
            return Err(Error::bundle_validation(
                format!("exchange[{}]", exchanges.len()),
                format!(
                    "NDJSON line exceeds {} bytes",
                    BundleLimits::MAX_NDJSON_LINE_BYTES
                ),
            ));
        }
        if exchanges.len() >= BundleLimits::MAX_EXCHANGES {
            return Err(Error::bundle_validation(
                "exchanges.ndjson",
                format!("more than {} exchanges", BundleLimits::MAX_EXCHANGES),
            ));
        }
        let parsed: Value = serde_json::from_str(line).map_err(|e| Error::Json {
            context: format!("exchange[{}] is not valid JSON", exchanges.len()),
            source: e,
        })?;
        exchanges.push(validate_exchange(&parsed, exchanges.len())?);
    }
    validate_sequence_order(&exchanges)?;

    if exchanges.len() as u64 != manifest.exchange_count {
        return Err(Error::ExchangeCountMismatch {
            declared: manifest.exchange_count,
            actual: exchanges.len(),
        });
    }
    let digest = bundle_digest(&exchanges);
    if digest != manifest.bundle_digest {
        return Err(Error::DigestMismatch);
    }

    Ok(CaptureBundle {
        root,
        manifest,
        exchanges,
        body_cache: HashMap::new(),
    })
}

/// Join path segments under root, rejecting traversal and absolute segments.
pub fn safe_join(root: &Path, segments: &[&str]) -> Result<PathBuf> {
    for segment in segments {
        if segment.starts_with('/')
            || segment
                .split(['/', '\\'])
                .any(|p| p == ".." || p.is_empty() && false)
        {
            return Err(Error::UnsafePath((*segment).to_string()));
        }
        if segment.split(['/', '\\']).any(|p| p == "..") {
            return Err(Error::UnsafePath((*segment).to_string()));
        }
    }
    let mut joined = root.to_path_buf();
    for segment in segments {
        joined.push(segment);
    }
    let relative = joined
        .strip_prefix(root)
        .map_err(|_| Error::UnsafePath(segments.join("/")))?;
    if relative.starts_with("..") {
        return Err(Error::UnsafePath(segments.join("/")));
    }
    Ok(joined)
}

/// Read a file strictly contained under `root` (which must already be a
/// realpath): every intermediate component is lstat-checked so a symlinked
/// directory (e.g. bodies/ -> /etc) cannot escape, the leaf must be a regular
/// non-symlink file, its realpath must remain under root, and its size must
/// not exceed `max_bytes` before any allocation happens.
fn read_contained_file(root: &Path, segments: &[&str], max_bytes: u64) -> Result<Vec<u8>> {
    let file_path = safe_join(root, segments)?;

    // Reject symlinks at every path component between root and the leaf.
    let mut current = root.to_path_buf();
    for segment in segments {
        current.push(segment);
        let meta: std::fs::Metadata = std::fs::symlink_metadata(&current)
            .map_err(|e| Error::io(format!("lstat {}", current.display()), e))?;
        if meta.file_type().is_symlink() {
            return Err(Error::SymlinkedPath(current.display().to_string()));
        }
    }

    let meta = std::fs::symlink_metadata(&file_path)
        .map_err(|e| Error::io(format!("lstat {}", file_path.display()), e))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(Error::other(format!(
            "Not a regular file: {}",
            file_path.display()
        )));
    }
    if meta.len() > max_bytes {
        return Err(Error::other(format!(
            "File exceeds permitted size ({} > {max_bytes}): {}",
            meta.len(),
            file_path.display()
        )));
    }

    // Defense in depth against TOCTOU swaps: the resolved path of what we
    // actually open must still live under the bundle root.
    let real = file_path
        .canonicalize()
        .map_err(|e| Error::io("realpath", e))?;
    if real != file_path && !real.starts_with(root) {
        return Err(Error::other(format!(
            "Bundle file escapes root after resolution: {}",
            file_path.display()
        )));
    }
    std::fs::read(&file_path).map_err(|e| Error::io(format!("read {}", file_path.display()), e))
}

/// Build a CapturedBody, inlining small payloads and blobbing large ones.
/// Large bodies are written immediately to `<bodies_dir>/<sha256>.bin`.
pub fn make_captured_body(
    bytes: &[u8],
    media_type: Option<&str>,
    content_encoding: Option<&str>,
    bodies_dir: Option<&Path>,
) -> Result<CapturedBody> {
    let digest = sha256_hex(bytes);
    if bytes.len() <= INLINE_BODY_LIMIT || bodies_dir.is_none() {
        use base64::Engine;
        return Ok(CapturedBody {
            sha256: digest,
            size: bytes.len() as u64,
            media_type: media_type.map(|m| m.to_string()),
            content_encoding: content_encoding.map(|c| c.to_string()),
            storage: BodyStorage::InlineBase64 {
                value: base64::engine::general_purpose::STANDARD.encode(bytes),
            },
        });
    }
    let bodies_dir = bodies_dir.unwrap();
    std::fs::create_dir_all(bodies_dir).map_err(|e| Error::io("bodies dir", e))?;
    let path = bodies_dir.join(format!("{digest}.bin"));
    write_file_atomic(&path, bytes)?;
    Ok(CapturedBody {
        sha256: digest.clone(),
        size: bytes.len() as u64,
        media_type: media_type.map(|m| m.to_string()),
        content_encoding: content_encoding.map(|c| c.to_string()),
        storage: BodyStorage::Blob {
            path: format!("bodies/{digest}.bin"),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redaction::RedactionPolicy;
    use crate::types::{
        CaptureMode, CapturedHeaders, CapturedRequest, CapturedResponse, StreamState,
    };
    use std::collections::BTreeMap;

    fn empty_headers() -> CapturedHeaders {
        CapturedHeaders {
            values: BTreeMap::new(),
            redacted: vec![],
        }
    }

    fn minimal_exchange(seq: u64, body_bytes: &[u8]) -> CapturedExchange {
        let body = make_captured_body(body_bytes, Some("text/plain"), None, None).unwrap();
        CapturedExchange {
            schema_version: 1,
            sequence: seq,
            started_at: "2026-08-21T00:00:00.000Z".into(),
            duration_ms: 5.0,
            request: CapturedRequest {
                method: "GET".into(),
                path: "/x".into(),
                http_version: "1.1".into(),
                headers: empty_headers(),
                body: body.clone(),
            },
            response: CapturedResponse {
                status: 200,
                status_text: "OK".into(),
                http_version: "1.1".into(),
                headers: empty_headers(),
                body,
                stream: StreamState {
                    kind: "buffered".into(),
                    completed: true,
                    client_aborted: false,
                    upstream_aborted: false,
                    terminal_marker: None,
                    error: None,
                },
            },
            failure: None,
            validation: None,
            tunnel: None,
            tls: None,
            ws: None,
            llm: None,
        }
    }

    /// Like [`minimal_exchange`] but with blob-backed request/response bodies.
    fn minimal_exchange_blob(seq: u64, body_bytes: &[u8]) -> CapturedExchange {
        let mut e = minimal_exchange(seq, body_bytes);
        let digest = sha256_hex(body_bytes);
        let blob_body = CapturedBody {
            sha256: digest.clone(),
            size: body_bytes.len() as u64,
            media_type: Some("text/plain".into()),
            content_encoding: None,
            storage: BodyStorage::Blob {
                path: format!("bodies/{digest}.bin"),
            },
        };
        e.request.body = blob_body.clone();
        e.response.body = blob_body;
        e
    }

    fn manifest_options(mode: CaptureMode) -> WriteBundleOptions {
        WriteBundleOptions {
            manifest: CaptureManifest {
                schema_version: BUNDLE_SCHEMA_VERSION,
                arbiter_version: "1.1.0".into(),
                mode,
                target_origin: "https://api.example.com".into(),
                started_at: "2026-08-21T00:00:00.000Z".into(),
                completed_at: "2026-08-21T00:00:01.000Z".into(),
                exchange_count: 0,
                bundle_digest: "0".repeat(64),
                redaction: RedactionPolicy::default().summary(),
                metadata: None,
            },
            exchanges: vec![],
            bodies: HashMap::new(),
            validation: None,
        }
    }

    #[test]
    fn write_then_load_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("capture");
        let mut options = manifest_options(CaptureMode::Exact);
        options.exchanges = vec![
            minimal_exchange(2, b"second"),
            minimal_exchange(1, b"first"),
        ];
        let manifest = write_bundle(&out, options).unwrap();
        assert_eq!(manifest.exchange_count, 2);

        let bundle = load_bundle(&out).unwrap();
        assert_eq!(bundle.exchanges.len(), 2);
        assert_eq!(bundle.exchanges[0].sequence, 1); // sorted
        let bytes = bundle
            .exchanges
            .clone()
            .first()
            .map(|e| e.request.body.clone())
            .unwrap();
        let mut b2 = bundle;
        assert_eq!(b2.read_body(&bytes).unwrap(), b"first");
    }

    #[test]
    fn digest_excludes_timing_provenance() {
        let mut a = minimal_exchange(1, b"payload");
        let mut b = a.clone();
        a.duration_ms = 9999.9;
        b.started_at = "2020-01-01T00:00:00.000Z".into();
        let _ = &mut a;
        assert_eq!(bundle_digest(&[a]), bundle_digest(&[b]));
    }

    #[test]
    fn tampered_exchange_fails_digest_check() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("capture");
        let mut options = manifest_options(CaptureMode::Observe);
        options.exchanges = vec![minimal_exchange(1, b"x")];
        write_bundle(&out, options).unwrap();
        // Tamper with exchanges.ndjson.
        let p = out.join("exchanges.ndjson");
        let raw = std::fs::read_to_string(&p)
            .unwrap()
            .replace("\"path\":\"/x\"", "\"path\":\"/y\"");
        std::fs::write(&p, raw).unwrap();
        assert!(load_bundle(&out).is_err());
    }

    #[test]
    fn wrong_exchange_count_fails() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("capture");
        let mut options = manifest_options(CaptureMode::Observe);
        options.exchanges = vec![minimal_exchange(1, b"x")];
        let manifest = write_bundle(&out, options).unwrap();
        // Drop the only exchange line; count mismatch must fail the load.
        std::fs::write(out.join("exchanges.ndjson"), "").unwrap();
        let err = load_bundle(&out);
        match err {
            Err(Error::ExchangeCountMismatch { declared, actual }) => {
                assert_eq!((declared, actual), (manifest.exchange_count, 0));
            }
            other => panic!("expected count mismatch, got {other:?}"),
        }
    }
    #[test]
    fn symlinked_body_component_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("capture");
        // Blob-backed body: exceeds the inline limit so write_bundle spills it.
        let big = vec![9u8; INLINE_BODY_LIMIT + 1];
        let mut options = manifest_options(CaptureMode::Observe);
        options.bodies.insert(sha256_hex(&big), big.clone());
        options.exchanges = vec![minimal_exchange_blob(1, &big)];
        write_bundle(&out, options).unwrap();

        // Replace bodies/ with a symlink pointing outside the bundle.
        let outside = tempfile::tempdir().unwrap();
        std::fs::remove_dir_all(out.join("bodies")).unwrap();
        std::os::unix::fs::symlink(outside.path(), out.join("bodies")).unwrap();

        // load_bundle reads only manifest+ndjson and succeeds; the blob read
        // must fail closed on the symlinked path component.
        let mut bundle = load_bundle(&out).unwrap();
        let body = bundle.exchanges[0].request.body.clone();
        assert!(matches!(body.storage, BodyStorage::Blob { .. }));
        assert!(bundle.read_body(&body).is_err());
    }

    #[test]
    fn unsafe_join_rejects_traversal() {
        let root = Path::new("/tmp/bundle-root");
        assert!(safe_join(root, &["bodies", "abc.bin"]).is_ok());
        assert!(safe_join(root, &["..", "escape"]).is_err());
        assert!(safe_join(root, &["/absolute"]).is_err());
        assert!(safe_join(root, &["a/../b"]).is_err());
    }

    #[test]
    fn large_bodies_blob_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let bodies = dir.path().join("bodies");
        let big = vec![7u8; INLINE_BODY_LIMIT + 1];
        let body = make_captured_body(&big, None, None, Some(&bodies)).unwrap();
        assert!(matches!(body.storage, BodyStorage::Blob { .. }));
        assert_eq!(body.size, (INLINE_BODY_LIMIT + 1) as u64);
        assert!(bodies.join(format!("{}.bin", body.sha256)).exists());

        let small = make_captured_body(b"tiny", None, None, Some(&bodies)).unwrap();
        assert!(matches!(small.storage, BodyStorage::InlineBase64 { .. }));
    }

    /// Locks wire compatibility with the TypeScript implementation: this
    /// manifest + NDJSON are byte-for-byte what `writeBundle` in
    /// `src/bundle/index.ts` emits for the same exchange. The Rust loader
    /// must accept it and recompute the identical digest — any serde shape
    /// drift (field renames, key ordering, number formatting) breaks this.
    #[test]
    fn loads_bundle_written_by_typescript_implementation() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("ts-bundle");
        std::fs::create_dir_all(root.join("bodies")).unwrap();
        std::fs::write(
            root.join("manifest.json"),
            concat!(
                r#"{"arbiterVersion":"1.1.0","bundleDigest":"a3088d3e4cf799031ff83ac25ca3b34cf55b5c9477ced4b6b1e15cb20fee23fd","#,
                r#""completedAt":"2026-08-21T12:00:01.000Z","exchangeCount":1,"mode":"exact","#,
                r#""redaction":{"allowQuery":[],"redactHeaders":["authorization"]},"schemaVersion":1,"targetOrigin":"https://api.example.com","#,
                r#""startedAt":"2026-08-21T12:00:00.000Z"}"#,
                "\n",
            ),
        )
        .unwrap();
        std::fs::write(
            root.join("exchanges.ndjson"),
            concat!(
                r#"{"schemaVersion":1,"sequence":1,"startedAt":"2026-08-21T12:00:00.000Z","durationMs":42.5,"#,
                r#""request":{"method":"POST","path":"/v1/x?q=__redacted__","httpVersion":"1.1","headers":{"values":{"content-type":["application/json"]},"redacted":["authorization"]},"body":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0,"mediaType":null,"contentEncoding":null,"storage":{"kind":"inline-base64","value":""}}},"#,
                r#""response":{"status":200,"statusText":"OK","httpVersion":"1.1","headers":{"values":{},"redacted":[]},"body":{"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","size":0,"mediaType":null,"contentEncoding":null,"storage":{"kind":"inline-base64","value":""}},"stream":{"kind":"buffered","completed":true,"clientAborted":false,"upstreamAborted":false,"terminalMarker":null,"error":null}},"#,
                r#""failure":null,"validation":{"valid":true,"violationCount":0}}"#,
                "\n",
            ),
        )
        .unwrap();

        let bundle = load_bundle(&root).expect("TS bundle loads");
        assert_eq!(bundle.exchanges.len(), 1);
        assert_eq!(
            bundle.manifest.bundle_digest,
            bundle_digest(&bundle.exchanges),
            "digest recomputation matches the TS manifest"
        );
    }

    #[test]
    fn sequence_order_must_increase() {
        let a = minimal_exchange(2, b"a");
        let mut b = minimal_exchange(2, b"b");
        b.response.status_text = "also-two".into();
        assert!(validate_sequence_order(&[a.clone(), b]).is_err());
        let c = minimal_exchange(3, b"c");
        assert!(validate_sequence_order(&[a, c]).is_ok());
    }

    #[test]
    fn output_root_gets_owner_only_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("capture");
        write_bundle(&out, manifest_options(CaptureMode::Observe)).unwrap();
        let mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(&out).unwrap().permissions(),
        );
        assert_eq!(mode & 0o777, 0o700);
        let manifest_mode = std::os::unix::fs::PermissionsExt::mode(
            &std::fs::metadata(out.join("manifest.json"))
                .unwrap()
                .permissions(),
        );
        assert_eq!(manifest_mode & 0o777, 0o600);
    }
}
