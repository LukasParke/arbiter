//! Replay of capture bundles against a live target (port of src/replay/).

pub mod compare;
pub mod engine;
pub mod legacy;

pub use compare::{compare_exact, compare_semantic_json, compare_semantic_sse, first_json_diff};
pub use engine::{
    replay_capture, ReplayCredentialEnv, ReplayExchangeResult, ReplayMode, ReplayOptions,
    ReplayOutcome, ReplayReport,
};
pub use legacy::{load_legacy_jsonl, LegacyTrafficLine};
