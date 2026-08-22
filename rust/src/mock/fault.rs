//! Fault injection (W3) — the SOLE fault implementation for BOTH mock and
//! proxy modes (AMEND-5).
//!
//! One xorshift64* draw per request gates ALL injections atomically: the
//! fraction gate and the injection choice come from the same draw, so a
//! request is never partially faulted. In proxy mode the draw happens BEFORE
//! upstream dispatch (`inject_before_upstream`) so streaming/SSE responses
//! are never corrupted mid-stream.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::error::Result;

/// The kind of hard error a faulted request receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum FaultKind {
    /// Abruptly close the connection without a response.
    Reset,
    /// Accept the request and never answer (client timeout).
    Timeout,
    /// Answer 200 with random garbage bytes.
    Garbage,
}

/// Fault configuration shared by `arbiter mock` and `arbiter start`.
/// `fraction_pct` applies to every enabled injection; `0..=100`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FaultConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<FaultKind>,
    #[serde(default = "default_fraction")]
    pub fraction_pct: u8,
}

fn default_fraction() -> u8 {
    100
}

impl FaultConfig {
    /// Build from CLI parts (AMEND-11 typed-surface constructor) and
    /// validate. Disabled when every knob is absent.
    pub fn from_cli(
        latency_ms: Option<u64>,
        status: Option<u16>,
        error: Option<FaultKind>,
        fraction_pct: u8,
    ) -> Result<Self> {
        let cfg = FaultConfig {
            latency_ms,
            status,
            error,
            fraction_pct,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// True when no fault knob is set — the injector then always passes.
    pub fn is_enabled(&self) -> bool {
        self.latency_ms.is_some() || self.status.is_some() || self.error.is_some()
    }

    /// Fail fast on nonsense values before any socket binds.
    pub fn validate(&self) -> Result<()> {
        if let Some(code) = self.status {
            if !(100..=599).contains(&code) {
                return Err(crate::error::Error::other(format!(
                    "mock: --fault-status {code} is not a valid HTTP status (100..=599)"
                )));
            }
        }
        if self.fraction_pct > 100 {
            return Err(crate::error::Error::other(format!(
                "mock: --fault-fraction {} exceeds 100",
                self.fraction_pct
            )));
        }
        Ok(())
    }
}

/// The outcome of one atomic fault draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultDecision {
    /// No fault — proceed normally.
    None,
    Latency(u64),
    Status(u16),
    Reset,
    Timeout,
    Garbage,
}

impl FaultDecision {
    /// Sleep duration for latency/timeout decisions.
    pub fn delay(&self) -> Option<Duration> {
        match self {
            FaultDecision::Latency(ms) => Some(Duration::from_millis(*ms)),
            // A "timeout" hangs long enough that any realistic client gives
            // up first; bounded so server shutdown is still possible.
            FaultDecision::Timeout => Some(Duration::from_secs(3600)),
            _ => None,
        }
    }

    /// Replacement status for status-injection decisions.
    pub fn status_override(&self) -> Option<u16> {
        match self {
            FaultDecision::Status(code) => Some(*code),
            _ => None,
        }
    }
}

const GOLDEN: u64 = 0x2545_F491_4F6C_DD1D;
const DEFAULT_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// Per-server injector holding the xorshift64* state. Cheap to clone-free
/// share behind an Arc; draws are atomic so concurrent requests stay
/// independent and deterministic under a fixed seed (tests).
pub struct FaultInjector {
    config: FaultConfig,
    state: AtomicU64,
}

impl std::fmt::Debug for FaultInjector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FaultInjector")
            .field("config", &self.config)
            .finish()
    }
}

impl FaultInjector {
    /// Injector seeded from system entropy (production path).
    pub fn new(config: FaultConfig) -> Self {
        let seed = config_seed_entropy();
        FaultInjector::with_seed(config, seed)
    }

    /// Deterministic injector for tests and golden runs. A zero seed is
    /// remapped to a fixed nonzero constant (xorshift must never start at 0).
    pub fn with_seed(config: FaultConfig, seed: u64) -> Self {
        FaultInjector {
            config,
            state: AtomicU64::new(if seed == 0 { DEFAULT_SEED } else { seed }),
        }
    }

    fn next_draw(&self) -> u64 {
        let mut x = self.state.load(Ordering::Relaxed);
        debug_assert_ne!(x, 0, "xorshift state must never be zero");
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state.store(x, Ordering::Relaxed);
        x.wrapping_mul(GOLDEN)
    }

    /// THE single draw per request (AMEND-5). Decides once, atomically:
    /// none | latency | status | reset | timeout | garbage. The fraction
    /// gate and the injection selection both derive from the same draw.
    pub fn roll(&self) -> FaultDecision {
        if !self.config.is_enabled() || self.config.fraction_pct == 0 {
            return FaultDecision::None;
        }
        let candidates: Vec<FaultDecision> = [
            self.config.latency_ms.map(FaultDecision::Latency),
            self.config.status.map(FaultDecision::Status),
            self.config.error.map(|k| match k {
                FaultKind::Reset => FaultDecision::Reset,
                FaultKind::Timeout => FaultDecision::Timeout,
                FaultKind::Garbage => FaultDecision::Garbage,
            }),
        ]
        .into_iter()
        .flatten()
        .collect();
        if candidates.is_empty() {
            return FaultDecision::None;
        }
        let draw = self.next_draw();
        // Low bits: fraction gate (pct=100 always passes).
        if draw % 100 >= self.config.fraction_pct.min(100) as u64 {
            return FaultDecision::None;
        }
        // High bits: which injection fires.
        candidates[((draw >> 32) as usize) % candidates.len()]
    }

    /// Proxy-mode entry point (AMEND-5): draw BEFORE upstream dispatch so a
    /// faulted request never reaches the origin and streamed responses are
    /// never split mid-flight.
    pub fn inject_before_upstream(&self) -> FaultDecision {
        self.roll()
    }

    /// Apply response-shaping decisions (status override / garbage body) to
    /// already-decided response parts. Returns true when the response was
    /// replaced. Latency/reset/timeout are handled by the caller's I/O path.
    pub fn apply_to_response(
        &self,
        decision: &FaultDecision,
        status: &mut u16,
        body: &mut Vec<u8>,
        content_type: &mut String,
    ) -> bool {
        match decision {
            FaultDecision::Status(code) => {
                *status = *code;
                *body = Vec::new();
                true
            }
            FaultDecision::Garbage => {
                *status = 200;
                *body = garbage_bytes(512);
                *content_type = "application/octet-stream".to_string();
                true
            }
            _ => false,
        }
    }
}

fn config_seed_entropy() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(DEFAULT_SEED);
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::rng().fill_bytes(&mut b);
    u64::from_le_bytes(b) ^ nanos.rotate_left(17) | 1
}

/// Random garbage bytes (hex-rendered so bodies stay printable/loggable).
pub fn garbage_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut raw = vec![0u8; len.div_ceil(2)];
    rand::rng().fill_bytes(&mut raw);
    let hex: Vec<u8> = raw
        .iter()
        .flat_map(|b| [HEX[(b >> 4) as usize], HEX[(b & 0xf) as usize]])
        .collect();
    hex.into_iter().take(len).collect()
}

const HEX: &[u8; 16] = b"0123456789abcdef";

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(
        latency: Option<u64>,
        status: Option<u16>,
        error: Option<FaultKind>,
        pct: u8,
    ) -> FaultConfig {
        FaultConfig {
            latency_ms: latency,
            status,
            error,
            fraction_pct: pct,
        }
    }

    #[test]
    fn determinism_matrix_seeded_xorshift() {
        // Two enabled injections so the decision sequence actually depends
        // on the draw bits (single-injection configs are constant streams).
        let cfg = cfg(Some(50), Some(500), None, 100);
        // Same seed => identical decision sequence.
        let a = FaultInjector::with_seed(cfg, 42);
        let b = FaultInjector::with_seed(cfg, 42);
        for _ in 0..200 {
            assert_eq!(a.roll(), b.roll());
        }
        // Different seed => different sequence (overwhelming probability).
        let c = FaultInjector::with_seed(cfg, 43);
        let diffs = (0..50).filter(|_| a.roll() != c.roll()).count();
        assert!(diffs > 0, "distinct seeds produced identical sequences");
    }

    #[test]
    fn fraction_gate_bounds_hold() {
        // pct=0 never faults even with knobs set.
        let off = FaultInjector::with_seed(cfg(None, Some(503), None, 0), 7);
        for _ in 0..500 {
            assert_eq!(off.roll(), FaultDecision::None);
        }
        // pct=100 always faults when a knob is set.
        let on = FaultInjector::with_seed(cfg(None, Some(503), None, 100), 7);
        for _ in 0..500 {
            assert_eq!(on.roll(), FaultDecision::Status(503));
        }
        // pct=50: roughly half faulted over many draws (loose bounds).
        let half = FaultInjector::with_seed(cfg(None, Some(418), None, 50), 99);
        let faulted = (0..10_000)
            .filter(|_| half.roll() != FaultDecision::None)
            .count();
        assert!(
            (4_000..6_000).contains(&faulted),
            "fraction drift: {faulted}/10000"
        );
    }

    #[test]
    fn single_draw_picks_only_enabled_injections() {
        // Only reset configured: every faulted draw is Reset.
        let r = FaultInjector::with_seed(cfg(None, None, Some(FaultKind::Reset), 100), 5);
        for _ in 0..100 {
            assert_eq!(r.roll(), FaultDecision::Reset);
        }
        // Three kinds enabled: all three appear across draws, nothing else.
        let mix = FaultInjector::with_seed(cfg(None, None, Some(FaultKind::Garbage), 100), 11);
        for _ in 0..50 {
            assert_eq!(mix.roll(), FaultDecision::Garbage);
        }
        let multi = FaultInjector::with_seed(cfg(Some(10), Some(500), None, 100), 13);
        let seen: std::collections::HashSet<_> = (0..100).map(|_| multi.roll()).collect();
        assert!(seen.contains(&FaultDecision::Latency(10)));
        assert!(seen.contains(&FaultDecision::Status(500)));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn disabled_config_always_none_and_helpers_map_cleanly() {
        let none = FaultInjector::with_seed(cfg(None, None, None, 100), 1);
        assert_eq!(none.roll(), FaultDecision::None);
        assert!(!cfg(None, None, None, 100).is_enabled());
        assert_eq!(
            FaultDecision::Latency(5).delay(),
            Some(Duration::from_millis(5))
        );
        assert_eq!(FaultDecision::Status(418).status_override(), Some(418));
        assert_eq!(FaultDecision::None.delay(), None);
    }

    #[test]
    fn validate_rejects_bad_values_and_from_cli_round_trips() {
        assert!(cfg(None, Some(99), None, 100).validate().is_err());
        assert!(cfg(None, Some(600), None, 100).validate().is_err());
        assert!(cfg(None, None, None, 101).validate().is_err());
        assert!(FaultConfig::from_cli(Some(250), None, Some(FaultKind::Timeout), 10).is_ok());
        assert!(FaultConfig::from_cli(None, None, None, 100).is_ok());
        assert!(FaultConfig::from_cli(None, Some(42), None, 100).is_err());
    }

    #[test]
    fn zero_seed_is_safe_and_garbage_is_printable() {
        let z = FaultInjector::with_seed(cfg(Some(1), None, None, 100), 0);
        assert_eq!(z.roll(), FaultDecision::Latency(1));
        let g = garbage_bytes(32);
        assert_eq!(g.len(), 32);
        assert!(g.iter().all(|b| b.is_ascii_hexdigit()));
    }
}
