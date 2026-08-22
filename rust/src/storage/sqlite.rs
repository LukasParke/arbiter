//! SQLite storage adapter. Port of `src/storage/sqlite.ts`: WAL journal,
//! identical schema, JSON-serialized HAR request/response rows and endpoint
//! data, silent no-ops when the store is not ready.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::error::{Error, Result};

const CREATE_SCHEMA: &str = "
        CREATE TABLE IF NOT EXISTS har_entries (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          startedDateTime TEXT NOT NULL,
          time INTEGER NOT NULL,
          request TEXT NOT NULL,
          response TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_har_started ON har_entries(startedDateTime);

        CREATE TABLE IF NOT EXISTS endpoints (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          path TEXT NOT NULL,
          method TEXT NOT NULL,
          data TEXT NOT NULL,
          UNIQUE(path, method)
        );
        CREATE INDEX IF NOT EXISTS idx_endpoints_path_method ON endpoints(path, method);
      ";

/// Thread-safe handle around a SQLite connection. The connection is `None`
/// after construction failure semantics mirror the TS adapter (methods become
/// silent no-ops returning empty results).
pub struct SqliteStore {
    connection: Mutex<Option<Connection>>,
    db_path: PathBuf,
}

fn lock_connection(
    guard: &Mutex<Option<Connection>>,
) -> std::sync::MutexGuard<'_, Option<Connection>> {
    // A poisoned mutex means another thread panicked while holding the
    // connection; the data itself stays consistent (SQLite transactions), so
    // recover rather than propagate the poison.
    guard
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl SqliteStore {
    /// Open (creating if needed) the database at `db_path`, create the parent
    /// directory, enable WAL journaling, and ensure the schema exists. On
    /// schema failure the handle is dropped so no bad connection is retained.
    pub fn open(db_path: &Path) -> Result<Self> {
        let resolved = if db_path.is_absolute() {
            db_path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|e| Error::io("resolve current dir", e))?
                .join(db_path)
        };
        if let Some(dir) = resolved.parent() {
            // Directory creation failures are ignored, mirroring the TS
            // try/catch; opening will surface a real error if it matters.
            let _ = std::fs::create_dir_all(dir);
        }

        let conn = Connection::open(&resolved)
            .map_err(|e| Error::Storage(format!("open database {}: {e}", resolved.display())))?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")
            .map_err(|e| Error::Storage(format!("enable WAL journal mode: {e}")))?;
        if let Err(e) = conn.execute_batch(CREATE_SCHEMA) {
            // If schema creation fails, close DB to avoid holding a bad
            // handle.
            return Err(Error::Storage(format!("create schema: {e}")));
        }

        Ok(SqliteStore {
            connection: Mutex::new(Some(conn)),
            db_path: resolved,
        })
    }

    pub fn is_ready(&self) -> bool {
        lock_connection(&self.connection).is_some()
    }

    /// Path the store was opened with (diagnostics/tests).
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn save_har_entry(&self, entry: &Value) -> Result<()> {
        let guard = lock_connection(&self.connection);
        let Some(conn) = guard.as_ref() else {
            return Ok(());
        };
        let Some(started_date_time) = entry.get("startedDateTime").and_then(Value::as_str) else {
            return Ok(());
        };
        let Some(time) = entry.get("time").and_then(Value::as_i64) else {
            return Ok(());
        };
        let request = serialize_field(entry, "request");
        let response = serialize_field(entry, "response");
        conn.execute(
            "INSERT INTO har_entries (startedDateTime, time, request, response) VALUES (?, ?, ?, ?)",
            rusqlite::params![started_date_time, time, request, response],
        )
        .map_err(|e| Error::Storage(format!("save HAR entry: {e}")))?;
        Ok(())
    }

    pub fn get_har_log(&self) -> Result<Value> {
        let guard = lock_connection(&self.connection);
        let Some(conn) = guard.as_ref() else {
            return Ok(empty_har_log());
        };
        let mut stmt = conn
            .prepare(
                "SELECT startedDateTime, time, request, response FROM har_entries ORDER BY id ASC",
            )
            .map_err(|e| Error::Storage(format!("query HAR entries: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(|e| Error::Storage(format!("query HAR entries: {e}")))?;

        let mut entries = Vec::new();
        for row in rows {
            let (started_date_time, time, request, response) =
                row.map_err(|e| Error::Storage(format!("read HAR entry row: {e}")))?;
            entries.push(json!({
                "startedDateTime": started_date_time,
                "time": time,
                "request": parse_json_or_empty(&request),
                "response": parse_json_or_empty(&response),
            }));
        }
        Ok(har_log_with_entries(entries))
    }

    pub fn clear_har(&self) -> Result<()> {
        let mut guard = lock_connection(&self.connection);
        let Some(conn) = guard.as_mut() else {
            return Ok(());
        };
        conn.execute("DELETE FROM har_entries", [])
            .map_err(|e| Error::Storage(format!("clear HAR entries: {e}")))?;
        Ok(())
    }

    pub fn upsert_endpoint(&self, path: &str, method: &str, data: &Value) -> Result<()> {
        let guard = lock_connection(&self.connection);
        let Some(conn) = guard.as_ref() else {
            return Ok(());
        };
        let serialized = if data.is_null() {
            "{}"
        } else {
            &data.to_string()
        };
        conn.execute(
            "INSERT INTO endpoints (path, method, data) VALUES (?, ?, ?)\n         ON CONFLICT(path, method) DO UPDATE SET data=excluded.data",
            rusqlite::params![path, method.to_lowercase(), serialized],
        )
        .map_err(|e| Error::Storage(format!("upsert endpoint: {e}")))?;
        Ok(())
    }

    pub fn get_all_endpoints(&self) -> Result<Vec<(String, String, Value)>> {
        let guard = lock_connection(&self.connection);
        let Some(conn) = guard.as_ref() else {
            return Ok(Vec::new());
        };
        let mut stmt = conn
            .prepare("SELECT path, method, data FROM endpoints")
            .map_err(|e| Error::Storage(format!("query endpoints: {e}")))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|e| Error::Storage(format!("query endpoints: {e}")))?;

        let mut out = Vec::new();
        for row in rows {
            let (path, method, data) =
                row.map_err(|e| Error::Storage(format!("read endpoint row: {e}")))?;
            out.push((path, method, parse_json_or_empty(&data)));
        }
        Ok(out)
    }
}

/// `JSON.stringify(entry.field ?? {})`: explicit null and absence both fall
/// back to `{}`; any other value serializes as-is.
fn serialize_field(entry: &Value, field: &str) -> String {
    match entry.get(field) {
        None | Some(Value::Null) => "{}".to_string(),
        Some(value) => value.to_string(),
    }
}

fn parse_json_or_empty(raw: &str) -> Value {
    serde_json::from_str(raw).unwrap_or_else(|_| json!({}))
}

fn empty_har_log() -> Value {
    har_log_with_entries(Vec::new())
}

fn har_log_with_entries(entries: Vec<Value>) -> Value {
    json!({
        "log": {
            "version": "1.2",
            "creator": { "name": "Arbiter", "version": "1.0.0" },
            "entries": entries,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn open_temp_store(dir: &Path) -> SqliteStore {
        SqliteStore::open(&dir.join("arbiter.db")).expect("open store")
    }

    #[test]
    fn is_ready_after_open() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_temp_store(dir.path());
        assert!(store.is_ready());
    }

    #[test]
    fn creates_parent_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a/b/c/arbiter.db");
        let store = SqliteStore::open(&nested).expect("open nested store");
        assert!(store.is_ready());
        assert!(nested.exists());
    }

    #[test]
    fn har_entry_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_temp_store(dir.path());

        store
            .save_har_entry(&json!({
                "startedDateTime": "2025-01-01T00:00:00.000Z",
                "time": 42,
                "request": { "method": "GET", "url": "https://example.test/v1" },
                "response": { "status": 200 }
            }))
            .expect("save entry");

        let log = store.get_har_log().expect("get log");
        assert_eq!(log["log"]["version"], "1.2");
        assert_eq!(log["log"]["creator"]["name"], "Arbiter");
        assert_eq!(log["log"]["creator"]["version"], "1.0.0");
        let entries = log["log"]["entries"].as_array().expect("entries array");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["startedDateTime"], "2025-01-01T00:00:00.000Z");
        assert_eq!(entries[0]["time"], 42);
        assert_eq!(entries[0]["request"]["method"], "GET");
        assert_eq!(entries[0]["response"]["status"], 200);
    }

    #[test]
    fn missing_har_fields_default_to_empty_objects() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_temp_store(dir.path());
        store
            .save_har_entry(&json!({ "startedDateTime": "t", "time": 1 }))
            .expect("save minimal entry");
        let log = store.get_har_log().expect("get log");
        let entries = log["log"]["entries"].as_array().expect("entries array");
        assert_eq!(entries[0]["request"], json!({}));
        assert_eq!(entries[0]["response"], json!({}));
    }

    #[test]
    fn empty_log_shape_when_no_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_temp_store(dir.path());
        let log = store.get_har_log().expect("get log");
        assert_eq!(
            log,
            json!({
                "log": {
                    "version": "1.2",
                    "creator": { "name": "Arbiter", "version": "1.0.0" },
                    "entries": []
                }
            })
        );
    }

    #[test]
    fn upsert_endpoint_updates_in_place_and_lowercases_method() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_temp_store(dir.path());

        store
            .upsert_endpoint("/v1/a", "POST", &json!({ "statusCodes": [200] }))
            .expect("first upsert");
        // Same (path, method): data replaced, not duplicated; method stored
        // lowercase like the TS adapter.
        store
            .upsert_endpoint("/v1/a", "POST", &json!({ "statusCodes": [200, 404] }))
            .expect("second upsert");
        store
            .upsert_endpoint("/v1/b", "GET", &json!({ "note": "other" }))
            .expect("third upsert");

        let endpoints = store.get_all_endpoints().expect("get all endpoints");
        assert_eq!(endpoints.len(), 2);

        let a = endpoints
            .iter()
            .find(|(path, _, _)| path == "/v1/a")
            .expect("endpoint /v1/a");
        assert_eq!(a.1, "post");
        assert_eq!(a.2, json!({ "statusCodes": [200, 404] }));
    }

    #[test]
    fn clear_har_removes_all_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = open_temp_store(dir.path());
        for i in 0..3 {
            store
                .save_har_entry(&json!({
                    "startedDateTime": format!("t{i}"),
                    "time": i,
                    "request": {},
                    "response": {}
                }))
                .expect("save entry");
        }
        assert_eq!(
            store.get_har_log().expect("log")["log"]["entries"]
                .as_array()
                .expect("entries")
                .len(),
            3
        );
        store.clear_har().expect("clear");
        assert!(store.get_har_log().expect("log")["log"]["entries"]
            .as_array()
            .expect("entries")
            .is_empty());
    }

    #[test]
    fn data_persists_across_reopen() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let store = open_temp_store(dir.path());
            store
                .upsert_endpoint("/v1/persist", "get", &json!({ "ok": true }))
                .expect("upsert");
        }
        let reopened = open_temp_store(dir.path());
        let endpoints = reopened
            .get_all_endpoints()
            .expect("endpoints after reopen");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].0, "/v1/persist");
        assert_eq!(endpoints[0].1, "get");
        assert_eq!(endpoints[0].2, json!({ "ok": true }));
    }
}
