//! Per-host dynamic leaf certificates behind a fixed-cap insertion-order
//! cache (AMEND-2: `Mutex<(HashMap, VecDeque)>`, cap 256, no lru crate).
//!
//! Every leaf is signed on the fly by the root CA: CN + SAN DNS = host,
//! with an IP SAN when the host parses as an IP literal (rcgen maps this
//! automatically), EKU serverAuth, ECDSA P-256 key for cheap handshakes.
//! The cache maps host → `Arc<rustls::sign::CertifiedKey>`; eviction is
//! strictly insertion order.
//!
//! CPU work (keygen + signing) runs behind [`tokio::task::spawn_blocking`]
//! via [`LeafCache::cert_for`]. The synchronous twin
//! [`LeafCache::get_or_mint_sync`] exists solely for rustls'
//! `ResolvesServerCert::resolve`, which is a sync API inside the handshake:
//! after first mint a host is a map hit (~ns); cold mints are single-digit
//! milliseconds with P-256.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use rcgen::{CertificateParams, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::CertifiedKey;

use super::ca::{issuer_certificate, CaHandle};
use crate::error::{Error, Result};
use crate::tls::TlsError;

/// Default cache capacity (AMEND-2).
pub const DEFAULT_LEAF_CACHE_SIZE: usize = 256;

/// Cache counters surfaced by [`LeafCache::stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeafStats {
    /// Hosts currently cached.
    pub entries: usize,
    /// Lookups served from the cache.
    pub hits: u64,
    /// Lookups that required a mint.
    pub misses: u64,
}

/// Fixed-cap, insertion-order-evicting leaf certificate cache.
type CertifiedKeyStore = (HashMap<String, Arc<CertifiedKey>>, VecDeque<String>);

pub struct LeafCache {
    inner: Mutex<CertifiedKeyStore>,
    cap: usize,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl LeafCache {
    /// A cache holding at most `cap` leaves (`DEFAULT_LEAF_CACHE_SIZE` in
    /// production wiring). `cap` is clamped to at least 1.
    pub fn new(cap: usize) -> Self {
        LeafCache {
            inner: Mutex::new((HashMap::new(), VecDeque::new())),
            cap: cap.max(1),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Cached leaf for `host`, minting asynchronously on miss.
    pub async fn cert_for(&self, ca: &CaHandle, host: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(hit) = self.lookup(host) {
            return Ok(hit);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let ca = ca.clone();
        let host = host.to_string();
        let host_for_task = host.clone();
        let minted = tokio::task::spawn_blocking(move || mint_leaf(ca, &host_for_task))
            .await
            .map_err(|join| Error::other(format!("leaf generation task panicked: {join}")))??;
        Ok(self.store(&host, minted))
    }
    /// Synchronous get-or-mint. Used only from `ResolvesServerCert::resolve`
    /// (a sync callback inside the TLS handshake); see module docs for why
    /// the inline mint is acceptable there.
    pub fn get_or_mint_sync(&self, ca: &CaHandle, host: &str) -> Result<Arc<CertifiedKey>> {
        if let Some(hit) = self.lookup(host) {
            return Ok(hit);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let minted = mint_leaf(ca.clone(), host)?;
        Ok(self.store(host, minted))
    }

    fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        let guard = self.inner.lock().expect("leaf cache poisoned");
        guard.0.get(host).cloned().inspect(|_hit| {
            self.hits.fetch_add(1, Ordering::Relaxed);
        })
    }

    /// Insert without overwriting a racing insert; evict oldest entries in
    /// insertion order until within capacity. Returns the stored value.
    fn store(&self, host: &str, key: Arc<CertifiedKey>) -> Arc<CertifiedKey> {
        let mut guard = self.inner.lock().expect("leaf cache poisoned");
        if let Some(existing) = guard.0.get(host) {
            return existing.clone();
        }
        while guard.0.len() >= self.cap {
            match guard.1.pop_front() {
                Some(oldest) => {
                    guard.0.remove(&oldest);
                }
                None => break,
            }
        }
        guard.0.insert(host.to_string(), key.clone());
        guard.1.push_back(host.to_string());
        key
    }

    /// Number of cached hosts.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("leaf cache poisoned").0.len()
    }

    /// True when nothing is cached.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True when `host` currently has a cached leaf.
    pub fn contains(&self, host: &str) -> bool {
        self.inner
            .lock()
            .expect("leaf cache poisoned")
            .0
            .contains_key(host)
    }

    /// Drop every cached leaf.
    pub fn clear(&self) {
        let mut guard = self.inner.lock().expect("leaf cache poisoned");
        guard.0.clear();
        guard.1.clear();
    }

    /// Current size and hit/miss counters.
    pub fn stats(&self) -> LeafStats {
        LeafStats {
            entries: self.len(),
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
        }
    }
}

impl Default for LeafCache {
    fn default() -> Self {
        LeafCache::new(DEFAULT_LEAF_CACHE_SIZE)
    }
}

/// Mint a fresh leaf for `host` signed by `ca`. CPU-bound: run behind
/// `spawn_blocking`.
fn mint_leaf(ca: CaHandle, host: &str) -> Result<Arc<CertifiedKey>> {
    let ca_key_pair = KeyPair::try_from(&ca.key_der)
        .map_err(|e| TlsError::key_material(format!("reload CA key for leaf signing: {e}")))?;
    let issuer = issuer_certificate(&ca_key_pair)?;

    // CertificateParams::new maps IP-literal hosts to an IP SAN and
    // everything else to a DNS SAN — exactly the contract we need.
    let mut params = CertificateParams::new(vec![host.to_string()])
        .map_err(|e| TlsError::leaf(host, format!("certificate parameters: {e}")))?;
    params.distinguished_name.push(DnType::CommonName, host);
    // Apple-enforced ceiling: leaves longer than 825 days lose iOS/macOS
    // trust. Backdate slightly so clock skew never yields a not-yet-valid
    // cert.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(825);
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| TlsError::leaf(host, format!("P-256 keygen: {e}")))?;
    let cert = params
        .signed_by(&leaf_key, &issuer, &ca_key_pair)
        .map_err(|e| TlsError::leaf(host, format!("issuance failed: {e}")))?;

    // Bridge the rcgen-generated PKCS#8 key into a rustls SigningKey via the
    // process-wide ring provider's key loader.
    let signing_key = rustls::crypto::ring::default_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()),
        ))
        .map_err(|e| TlsError::leaf(host, format!("leaf key loading: {e}")))?;

    // Present [leaf, real-root] so clients can chain up to the anchor they
    // trust (the reconstructed issuer handle above never goes on the wire).
    let mut chain = vec![cert.der().clone()];
    chain.extend(ca.cert_chain_der.iter().cloned());
    Ok(Arc::new(CertifiedKey::new(chain, signing_key)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca::{ensure_ca, CaAlg};

    async fn test_ca(dir: &std::path::Path) -> CaHandle {
        ensure_ca(
            dir,
            CaAlg::EcdsaP256,
            &dir.join("ca.pem"),
            &dir.join("key.pem"),
        )
        .await
        .expect("test CA")
    }

    #[tokio::test]
    async fn caches_hits_and_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = test_ca(tmp.path()).await;
        let cache = LeafCache::new(8);

        assert!(cache.is_empty());
        let a = cache.cert_for(&ca, "example.com").await.unwrap();
        let b = cache.cert_for(&ca, "example.com").await.unwrap();
        assert!(Arc::ptr_eq(&a, &b), "second lookup must be a cache hit");

        let s = cache.stats();
        assert_eq!((s.entries, s.hits, s.misses), (1, 1, 1));

        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(
            cache.stats(),
            LeafStats {
                entries: 0,
                hits: 1,
                misses: 1
            }
        );
    }

    #[tokio::test]
    async fn evicts_in_insertion_order() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = test_ca(tmp.path()).await;
        let cache = LeafCache::new(3);

        for host in ["h1.test", "h2.test", "h3.test", "h4.test"] {
            cache.cert_for(&ca, host).await.unwrap();
        }

        assert!(
            !cache.contains("h1.test"),
            "first-inserted host must be evicted"
        );
        for host in ["h2.test", "h3.test", "h4.test"] {
            assert!(cache.contains(host), "{host} must survive");
        }
        assert_eq!(cache.len(), 3);

        // Re-requesting h2 refreshes nothing about order (insertion-order,
        // not LRU): inserting one more still evicts h2, the oldest entry.
        cache.cert_for(&ca, "h2.test").await.unwrap();
        cache.cert_for(&ca, "h5.test").await.unwrap();
        assert!(!cache.contains("h2.test"), "insertion order, not recency");
        assert!(cache.contains("h5.test"));
    }

    #[tokio::test]
    async fn ip_literal_hosts_mint_cleanly() {
        let tmp = tempfile::tempdir().unwrap();
        let ca = test_ca(tmp.path()).await;
        let cache = LeafCache::new(4);
        for host in ["127.0.0.1", "::1", "example.com"] {
            cache.cert_for(&ca, host).await.expect(host);
        }
        assert_eq!(cache.len(), 3);
    }
}
