//! Root-CA generation, persistence and loading (`arbiter ca generate` backing).
//!
//! The CA is resolved lazily — never on the socket-bind path (startup bar
//! < 100 ms). Generation is CPU-heavy (RSA keygen especially) and therefore
//! runs on tokio's blocking pool. On-disk layout under `--ca-dir`
//! (default `~/.arbiter/ca`): `ca.pem` (certificate, PEM) + `key.pem`
//! (PKCS#8 private key, PEM); directory mode 0700, file modes 0600.
//!
//! Algorithms: ECDSA P-256 (default, cheap handshakes) or RSA-2048 for
//! maximum legacy-client compatibility. RSA keys are minted by the `rsa`
//! crate and handed to rcgen's ring-backed [`rcgen::PKCS_RSA_SHA256`] key
//! pair, since rcgen cannot generate RSA keys without its aws-lc backend.
//!
//! Validity: the root lives 10 years; leaves are capped at the
//! Apple-enforced 825-day ceiling (see `leaf.rs`).

use crate::tls::TlsError;
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rsa::pkcs8::EncodePrivateKey;
use rsa::RsaPrivateKey;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::error::{Error, Result};

/// Default CA directory relative to the user's home.
pub const DEFAULT_CA_DIR: &str = ".arbiter/ca";

/// File name of the persisted CA certificate (PEM) inside the CA dir.
pub const CA_CERT_FILE: &str = "ca.pem";

/// File name of the persisted CA key (PKCS#8 PEM) inside the CA dir.
pub const CA_KEY_FILE: &str = "key.pem";

/// Common Name of the generated root CA.
const CA_COMMON_NAME: &str = "Arbiter Proxy Root CA";

/// Root-CA signature algorithm choice (`--ca-alg`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CaAlg {
    /// ECDSA P-256 / SHA-256 (default; fast handshakes).
    #[default]
    EcdsaP256,
    /// RSA 2048 / SHA-256 (legacy-client compatibility).
    Rsa2048,
}

impl CaAlg {
    /// Canonical flag spelling of this algorithm.
    pub fn as_str(&self) -> &'static str {
        match self {
            CaAlg::EcdsaP256 => "ecdsa-p256",
            CaAlg::Rsa2048 => "rsa-2048",
        }
    }
}

impl FromStr for CaAlg {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ecdsa-p256" | "ec256" | "p256" => Ok(CaAlg::EcdsaP256),
            "rsa-2048" | "rsa2048" => Ok(CaAlg::Rsa2048),
            other => Err(Error::other(format!(
                "unknown CA algorithm '{other}'\n  help: --ca-alg accepts 'ecdsa-p256' or 'rsa-2048'"
            ))),
        }
    }
}

impl std::fmt::Display for CaAlg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Handle on the resolved root CA: DER certificate chain plus PKCS#8 key.
///
/// Cheap to clone; every field is owned static data ready to feed rustls.
pub struct CaHandle {
    /// DER-encoded certificate chain (self-signed root only: one element).
    pub cert_chain_der: Vec<CertificateDer<'static>>,
    /// DER-encoded PKCS#8 private key of the root.
    pub key_der: PrivateKeyDer<'static>,
}

/// `PrivateKeyDer` is not `Clone` upstream; our copy is a re-encoded
/// owned PKCS#8 snapshot, which is exactly what rustls consumers need.
impl Clone for CaHandle {
    fn clone(&self) -> Self {
        CaHandle {
            cert_chain_der: self.cert_chain_der.clone(),
            key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                self.key_der.secret_der().to_vec(),
            )),
        }
    }
}

impl std::fmt::Debug for CaHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let alg = match &self.key_der {
            PrivateKeyDer::Pkcs8(_) => "pkcs8",
            PrivateKeyDer::Pkcs1(_) => "pkcs1",
            PrivateKeyDer::Sec1(_) => "sec1",
            _ => "unknown",
        };
        f.debug_struct("CaHandle")
            .field("chain_len", &self.cert_chain_der.len())
            .field("key_encoding", &alg)
            .finish()
    }
}

/// Resolve the root CA: load the existing pair when both files exist,
/// otherwise generate a fresh one with `alg`, persist it (dir 0700 /
/// files 0600) and return it.
pub async fn ensure_ca(
    dir: &Path,
    alg: CaAlg,
    cert_path: &Path,
    key_path: &Path,
) -> Result<CaHandle> {
    if cert_path.is_file() && key_path.is_file() {
        return load_ca(cert_path, key_path);
    }
    generate_ca(dir, alg, cert_path.to_path_buf(), key_path.to_path_buf()).await
}

/// Generate a fresh CA pair and persist it under `cert_path`/`key_path`.
///
/// All crypto work runs behind [`tokio::task::spawn_blocking`].
pub async fn generate_ca(
    dir: &Path,
    alg: CaAlg,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<CaHandle> {
    let dir = dir.to_path_buf();
    let handle = tokio::task::spawn_blocking(move || -> Result<CaHandle> {
        let key_pair = match alg {
            CaAlg::EcdsaP256 => KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .map_err(|e| TlsError::ca_generation(format!("ECDSA P-256 keygen failed: {e}")))?,
            CaAlg::Rsa2048 => rsa_key_pair()?,
        };
        let cert = ca_params()?
            .self_signed(&key_pair)
            .map_err(|e| TlsError::ca_generation(format!("self-sign root CA: {e}")))?;
        persist(
            &dir,
            &cert_path,
            &key_path,
            cert.pem().as_bytes(),
            key_pair.serialize_pem().as_bytes(),
        )?;
        Ok(CaHandle {
            cert_chain_der: vec![cert.der().clone()],
            key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
        })
    })
    .await
    .map_err(|join| Error::other(format!("CA generation task panicked: {join}")))?;
    handle
}

fn rsa_key_pair() -> Result<KeyPair> {
    // rsa 0.9 pins rand_core 0.6; use its re-exported OsRng so the
    // workspace's rand 0.9 never leaks into the trait bounds.
    let mut rng = rsa::rand_core::OsRng;
    let key = RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| TlsError::ca_generation(format!("RSA-2048 keygen failed: {e}")))?;
    let pkcs8 = key
        .to_pkcs8_der()
        .map_err(|e| TlsError::key_material(format!("RSA PKCS#8 encoding failed: {e}")))?;
    KeyPair::from_pkcs8_der_and_sign_algo(
        &PrivatePkcs8KeyDer::from(pkcs8.as_bytes().to_vec()),
        &rcgen::PKCS_RSA_SHA256,
    )
    .map_err(|e| TlsError::key_material(format!("ring rejected RSA PKCS#8 key: {e}")).into())
}

/// Deterministic CA certificate parameters. Shared by generation and leaf
/// issuance so an issuer reconstructed from the loaded key produces the
/// same subject/issuer identity as the persisted root.
fn ca_params() -> Result<CertificateParams> {
    let mut params = CertificateParams::new(Vec::<String>::new()).map_err(ca_generation_error)?;
    params
        .distinguished_name
        .push(DnType::CommonName, CA_COMMON_NAME);
    // Sane 10-year root lifetime (leaves are independently capped at the
    // Apple 825-day ceiling in leaf.rs). Backdated 1 day for clock skew.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(10 * 365);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    Ok(params)
}

fn ca_generation_error(e: rcgen::Error) -> Error {
    Error::from(TlsError::ca_generation(e.to_string()))
}

/// Reconstruct an rcgen issuer certificate for leaf issuance.
///
/// rcgen 0.13 cannot sign with a certificate parsed back from DER (the
/// `Certificate` type has no public constructor from existing DER), so we
/// re-mint a throwaway self-signed certificate from the deterministic CA
/// parameters. It carries the same subject DN and — crucially — the same
/// public key as the persisted root, which is all leaf signing consumes.
/// Leaves are presented together with the REAL root DER, so clients anchor
/// exclusively on what is in their trust store.
pub(crate) fn issuer_certificate(ca_key_pair: &KeyPair) -> Result<rcgen::Certificate> {
    let params = ca_params()?;
    params
        .self_signed(ca_key_pair)
        .map_err(ca_generation_error)
}

/// Persist the pair: directory 0700, files 0600 (permission hardening is a
/// no-op on platforms without unix mode bits).
fn persist(
    dir: &Path,
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<()> {
    fs::create_dir_all(dir)
        .map_err(|e| Error::io(format!("create CA dir {}", dir.display()), e))?;
    #[cfg(unix)]
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| Error::io(format!("chmod 0700 {}", dir.display()), e))?;

    write_private(cert_path, cert_pem)?;
    write_private(key_path, key_pem)?;
    Ok(())
}

fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write;

    #[cfg(unix)]
    {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::io(format!("create {}", parent.display()), e))?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| Error::io(format!("open {} for writing", path.display()), e))?;
        file.write_all(contents)
            .map_err(|e| Error::io(format!("write {}", path.display()), e))?;
        // Enforce even when the file already existed with looser bits.
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::io(format!("chmod 0600 {}", path.display()), e))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, contents).map_err(|e| Error::io(format!("write {}", path.display()), e))
    }
}

/// Load a previously generated CA pair from PEM files via rustls-pemfile.
pub fn load_ca(cert_path: &Path, key_path: &Path) -> Result<CaHandle> {
    let cert_pem = fs::read(cert_path)
        .map_err(|e| Error::io(format!("read CA certificate {}", cert_path.display()), e))?;
    let key_pem = fs::read(key_path)
        .map_err(|e| Error::io(format!("read CA key {}", key_path.display()), e))?;

    let mut cert_reader = std::io::BufReader::new(cert_pem.as_slice());
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| TlsError::key_material(format!("parse {}: {e}", cert_path.display())))?;
    if certs.is_empty() {
        return Err(TlsError::key_material(format!(
            "no CERTIFICATE block in {}\n  help: regenerate with `arbiter ca generate --force`",
            cert_path.display()
        ))
        .into());
    }

    let mut key_reader = std::io::BufReader::new(key_pem.as_slice());
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| TlsError::key_material(format!("parse {}: {e}", key_path.display())))?
        .ok_or_else(|| {
            TlsError::key_material(format!(
                "no private-key block in {}\n  help: regenerate with `arbiter ca generate --force`",
                key_path.display()
            ))
        })?;

    Ok(CaHandle {
        cert_chain_der: certs,
        key_der: key,
    })
}

/// Platform-specific trust-store installation instructions printed after
/// generation (`--install-hint`).
pub fn install_hint() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "Install the root CA in the macOS system trust store:\n  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.arbiter/ca/ca.pem"
    }
    #[cfg(target_os = "windows")]
    {
        "Install the root CA in the Windows system trust store (admin shell):\n  certutil -addstore -f ROOT %USERPROFILE%\\.arbiter\\ca\\ca.pem"
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "Install the root CA in the Linux system trust store:\n  sudo cp ~/.arbiter/ca/ca.pem /usr/local/share/ca-certificates/arbiter-ca.crt && sudo update-ca-certificates\n  (Debian-family path; Fedora uses /etc/pki/ca-trust/source/anchors + update-ca-trust)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_ca_dir(alg: CaAlg) -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path().join("ca");
        let suffix = format!("{alg}");
        let cert = dir.join(format!("ca-{suffix}.pem"));
        let key = dir.join(format!("key-{suffix}.pem"));
        (tmp, dir, cert, key)
    }

    #[tokio::test]
    async fn generate_persist_reload_roundtrip_with_perms() {
        let (_tmp, dir, cert, key) = tmp_ca_dir(CaAlg::EcdsaP256);
        let first = ensure_ca(&dir, CaAlg::EcdsaP256, &cert, &key)
            .await
            .expect("generate");

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                fs::metadata(&dir).unwrap().mode() & 0o777,
                0o700,
                "dir must be 0700"
            );
            assert_eq!(
                fs::metadata(&cert).unwrap().mode() & 0o777,
                0o600,
                "cert must be 0600"
            );
            assert_eq!(
                fs::metadata(&key).unwrap().mode() & 0o777,
                0o600,
                "key must be 0600"
            );
        }

        // Reload straight from disk and via ensure_ca's load path: identical material.
        let reloaded = load_ca(&cert, &key).expect("reload");
        assert_eq!(first.cert_chain_der[0], reloaded.cert_chain_der[0]);
        assert_eq!(first.key_der.secret_der(), reloaded.key_der.secret_der());

        let again = ensure_ca(&dir, CaAlg::EcdsaP256, &cert, &key)
            .await
            .expect("ensure reload");
        assert_eq!(again.cert_chain_der[0], first.cert_chain_der[0]);
    }

    #[tokio::test]
    async fn rsa_roundtrip() {
        let (_tmp, dir, cert, key) = tmp_ca_dir(CaAlg::Rsa2048);
        let generated = generate_ca(&dir, CaAlg::Rsa2048, cert.clone(), key.clone())
            .await
            .expect("generate RSA CA");
        let loaded = load_ca(&cert, &key).expect("load RSA pair");
        assert_eq!(generated.cert_chain_der[0], loaded.cert_chain_der[0]);
        assert_eq!(generated.key_der.secret_der(), loaded.key_der.secret_der());
    }

    #[test]
    fn unknown_algorithm_errors_with_help() {
        let err = CaAlg::from_str("ed25519").unwrap_err().to_string();
        assert!(err.contains("help:"), "error must carry help line: {err}");
        assert_eq!("rsa-2048", CaAlg::from_str("RSA-2048").unwrap().as_str());
    }
}
