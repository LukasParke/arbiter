//! HTTP middleware ports (`src/middleware/`).

mod har_recorder;

pub use har_recorder::{
    build_har_entry, har_store, render_response_text, HarEntryParts, HarStore, DEFERRED_TEXT,
};
