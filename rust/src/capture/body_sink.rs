//! Incremental body capture with inline threshold, spill-to-temp-file, and
//! SHA-256 + size accounting.
//!
//! Below the limit bytes stay in memory; crossing it either spills to a
//! restricted temporary file or fails the exchange — never silently truncates.
//! Port of `src/capture/bodySink.ts`.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Hard ceiling for spilled bodies: spill moves storage to disk, it does not
/// remove limits entirely. 4 GiB default.
pub const MAX_SPILLED_BODY_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default in-memory threshold before spill/fail (TS `DEFAULT_MAX_BODY_BYTES`).
pub const DEFAULT_MAX_BODY_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BodyLimitPolicy {
    /// Crossing the in-memory limit spills to a restricted temporary file.
    Spill,
    /// Crossing the in-memory limit fails the exchange outright.
    Fail,
}

/// The finalized content of a [`BodySink`]: full bytes plus digest and size.
///
/// When the sink spilled, `temp_path` points at the (already read-out)
/// temporary file; call [`SunkBody::dispose`] to remove it.
#[derive(Debug, Clone)]
pub struct SunkBody {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub size: u64,
    pub spilled: bool,
    pub temp_path: Option<PathBuf>,
}

impl SunkBody {
    /// Remove the backing temporary file, if any. Idempotent.
    pub fn dispose(&self) {
        if let Some(path) = &self.temp_path {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn body_limit_error(limit: u64) -> Error {
    Error::BodyLimitExceeded(format!("Body exceeded configured limit of {limit} bytes"))
}

/// Accumulates raw body bytes with incremental SHA-256.
#[derive(Debug)]
pub struct BodySink {
    policy: BodyLimitPolicy,
    inline_limit: u64,
    spill_limit: u64,
    spill_dir: PathBuf,
    hash: Sha256,
    chunks: Vec<Vec<u8>>,
    byte_count: u64,
    spill_file: Option<(PathBuf, std::fs::File)>,
    finished: bool,
}

impl BodySink {
    /// Create a sink with the default in-memory threshold and spill directory.
    ///
    /// `max_spilled_bytes` is the hard disk-backed ceiling; crossing it is a
    /// hard failure under either policy (`MAX_SPILLED_BODY_BYTES` default).
    pub fn new(policy: BodyLimitPolicy, max_spilled_bytes: u64) -> Self {
        Self::with_options(
            policy,
            DEFAULT_MAX_BODY_BYTES,
            max_spilled_bytes,
            &std::env::temp_dir(),
        )
    }

    /// Full control over thresholds and spill location (mirrors the TS
    /// constructor's optional `limit` / `spillDir` / `spillLimit` arguments).
    pub fn with_options(
        policy: BodyLimitPolicy,
        inline_limit: u64,
        max_spilled_bytes: u64,
        spill_dir: &Path,
    ) -> Self {
        Self {
            policy,
            inline_limit,
            spill_limit: max_spilled_bytes,
            spill_dir: spill_dir.to_path_buf(),
            hash: Sha256::new(),
            chunks: Vec::new(),
            byte_count: 0,
            spill_file: None,
            finished: false,
        }
    }

    pub fn write(&mut self, chunk: &[u8]) -> Result<()> {
        if self.finished {
            return Err(Error::other("BodySink already finished"));
        }
        self.hash.update(chunk);
        self.byte_count += chunk.len() as u64;
        if let Some((_, file)) = self.spill_file.as_mut() {
            // Spill changes the storage medium, not the contract: crossing
            // the spill ceiling is still a hard failure, never truncation.
            if self.byte_count > self.spill_limit {
                let error = body_limit_error(self.spill_limit);
                self.abort();
                return Err(error);
            }
            std::io::Write::write_all(file, chunk)
                .map_err(|e| Error::io("write spilled body chunk", e))?;
            return Ok(());
        }
        self.chunks.push(chunk.to_vec());
        if self.byte_count > self.inline_limit {
            if self.policy == BodyLimitPolicy::Fail {
                return Err(body_limit_error(self.inline_limit));
            }
            if self.byte_count > self.spill_limit {
                let error = body_limit_error(self.spill_limit);
                self.abort();
                return Err(error);
            }
            self.spill()?;
        }
        Ok(())
    }

    pub fn size(&self) -> u64 {
        self.byte_count
    }

    fn spill(&mut self) -> Result<()> {
        std::fs::create_dir_all(&self.spill_dir).map_err(|e| Error::io("create spill dir", e))?;
        set_owner_only_permissions(&self.spill_dir)?;
        let path = self
            .spill_dir
            .join(format!("arbiter-spill-{}", hex::encode(rand_bytes())));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode_600();
        let mut file = options
            .open(&path)
            .map_err(|e| Error::io("open spill file", e))?;
        for chunk in std::mem::take(&mut self.chunks) {
            std::io::Write::write_all(&mut file, chunk.as_slice())
                .map_err(|e| Error::io("write spilled body chunk", e))?;
        }
        self.spill_file = Some((path, file));
        Ok(())
    }

    /// Finalize and return the digest plus the full bytes.
    pub fn finish(mut self) -> Result<SunkBody> {
        self.finished = true;
        let sha256 = hex::encode(std::mem::take(&mut self.hash).finalize());
        let size = self.byte_count;
        if let Some((spill_path, file)) = self.spill_file.take() {
            drop(file);
            let bytes =
                std::fs::read(&spill_path).map_err(|e| Error::io("read spilled body", e))?;
            return Ok(SunkBody {
                bytes,
                sha256,
                size,
                spilled: true,
                temp_path: Some(spill_path),
            });
        }
        let mut chunks = std::mem::take(&mut self.chunks);
        let bytes = if chunks.len() == 1 {
            chunks.pop().unwrap_or_default()
        } else {
            let mut bytes = Vec::with_capacity(size as usize);
            for chunk in chunks.drain(..) {
                bytes.extend_from_slice(&chunk);
            }
            bytes
        };
        Ok(SunkBody {
            bytes,
            sha256,
            size,
            spilled: false,
            temp_path: None,
        })
    }

    /// Discard buffered content and remove any spill file. No-op once
    /// `finish` has transferred ownership.
    pub fn abort(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.chunks.clear();
        if let Some((path, _file)) = self.spill_file.take() {
            drop(_file);
            let _ = std::fs::remove_file(&path);
        }
    }
}

impl Drop for BodySink {
    fn drop(&mut self) {
        // Never leak a spill file when an exchange dies unexpectedly without
        // an explicit abort(); finish()/abort() mark us finished first.
        if !self.finished {
            if let Some((path, _file)) = self.spill_file.take() {
                drop(_file);
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

trait OpenOptionsExt600 {
    fn mode_600(&mut self) -> &mut Self;
}

impl OpenOptionsExt600 for std::fs::OpenOptions {
    #[cfg(unix)]
    fn mode_600(&mut self) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt;
        self.mode(0o600)
    }

    #[cfg(not(unix))]
    fn mode_600(&mut self) -> &mut Self {
        self
    }
}

fn set_owner_only_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path).map_err(|e| Error::io("stat spill dir", e))?;
        let mut permissions = meta.permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(path, permissions)
            .map_err(|e| Error::io("restrict spill dir", e))?;
    }
    let _ = path;
    Ok(())
}

fn rand_bytes() -> [u8; 8] {
    use rand::RngCore;
    let mut buf = [0u8; 8];
    rand::rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn accumulates_bytes_and_computes_sha256() {
        let mut sink = BodySink::new(BodyLimitPolicy::Fail, MAX_SPILLED_BODY_BYTES);
        sink.write(b"hello ").unwrap();
        sink.write(b"world").unwrap();
        assert_eq!(sink.size(), 11);
        let done = sink.finish().unwrap();
        assert_eq!(done.size, 11);
        assert_eq!(done.bytes, b"hello world");
        assert_eq!(done.sha256, crate::bundle::sha256_hex(b"hello world"));
        assert!(!done.spilled);
        assert!(done.temp_path.is_none());
    }

    #[test]
    fn empty_sink_yields_empty_sha256() {
        let done = BodySink::new(BodyLimitPolicy::Fail, MAX_SPILLED_BODY_BYTES)
            .finish()
            .unwrap();
        assert_eq!(done.size, 0);
        assert_eq!(done.sha256, SHA256_EMPTY);
    }

    #[test]
    fn fails_on_limit_crossing_with_fail_policy() {
        let mut sink = BodySink::with_options(
            BodyLimitPolicy::Fail,
            4,
            MAX_SPILLED_BODY_BYTES,
            Path::new("/tmp"),
        );
        let err = sink.write(b"too long").unwrap_err();
        assert!(matches!(err, Error::BodyLimitExceeded(_)));
        assert_eq!(
            err.to_string(),
            "Body limit exceeded: Body exceeded configured limit of 4 bytes"
        );
    }

    #[test]
    fn finish_consumes_the_sink_so_late_writes_cannot_occur() {
        let mut sink = BodySink::new(BodyLimitPolicy::Fail, MAX_SPILLED_BODY_BYTES);
        sink.write(b"done").unwrap();
        let done = sink.finish().unwrap();
        done.dispose();
        assert_eq!(done.bytes, b"done");
    }

    #[test]
    fn spills_to_disk_with_spill_policy_and_preserves_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = BodySink::with_options(
            BodyLimitPolicy::Spill,
            4,
            MAX_SPILLED_BODY_BYTES,
            dir.path(),
        );
        let payload = b"0123456789abcdef";
        sink.write(&payload[..8]).unwrap();
        sink.write(&payload[8..]).unwrap();
        assert!(sink.size() > 4);
        let done = sink.finish().unwrap();
        assert!(done.spilled);
        assert_eq!(done.bytes, payload);
        assert_eq!(done.size, 16);
        assert_eq!(done.sha256, crate::bundle::sha256_hex(payload));
        let temp_path = done.temp_path.clone().unwrap();
        assert!(temp_path.starts_with(dir.path()));
        // The spill file still exists until disposed.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        done.dispose();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn enforces_the_hard_spill_ceiling_instead_of_unbounded_disk_growth() {
        let dir = tempfile::tempdir().unwrap();
        // memory limit 4 bytes, spill ceiling 16 bytes
        let mut sink = BodySink::with_options(BodyLimitPolicy::Spill, 4, 16, dir.path());
        sink.write(b"01234567").unwrap(); // spills
        let err = sink.write(b"89abcdefXX").unwrap_err();
        assert!(matches!(err, Error::BodyLimitExceeded(_)));
        // Ceiling breach also cleans the spill file up.
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn abort_removes_spill_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = BodySink::with_options(
            BodyLimitPolicy::Spill,
            2,
            MAX_SPILLED_BODY_BYTES,
            dir.path(),
        );
        sink.write(b"spill me").unwrap();
        sink.abort();
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn dropping_a_mid_spill_sink_never_leaks_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut sink = BodySink::with_options(
            BodyLimitPolicy::Spill,
            2,
            MAX_SPILLED_BODY_BYTES,
            dir.path(),
        );
        sink.write(b"abandoned").unwrap();
        drop(sink);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
