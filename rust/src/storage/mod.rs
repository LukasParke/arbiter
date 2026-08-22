//! Persistence adapters (SQLite-backed HAR and endpoint storage).

pub mod sqlite;

pub use sqlite::SqliteStore;
