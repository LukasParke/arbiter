//! Purpose-built capture TUI (W5): feed transports, filter grammar, app
//! state machine, and rendering. Entry point lives in `cli/tui.rs`; the
//! HTTP surface the attach transport polls lives in `server/flows_api.rs`.

pub mod app;
pub mod feed;
pub mod filter;
pub mod ui;
