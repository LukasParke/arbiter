# Changelog

All notable changes to Arbiter are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the
npm package (`@parke.dev/arbiter`). The Rust binary (`rust/`) tracks the same
version via `Cargo.toml`.

## [Unreleased]

### Added — Rust implementation (PR #39)

- Complete Rust port of the API proxy: exact capture/replay, OpenAPI 3.1
  generation, HAR export, credential gateway, sanitization, validation,
  SQLite persistence, and the full CLI surface. Wire-compatible bundles with
  the TypeScript implementation.

### Added — Proxy-parity expansion (PR #40)

- TLS interception: `arbiter ca` root-CA management, CONNECT MITM with dynamic
  per-host leaf certificates, `--tls-passthrough` globs, reverse-proxy HTTPS.
- WebSocket relay + per-message capture (bundle format v2 `ws` records).
- Mock/simulate engine: spec-example generation, byte-exact capture replay,
  strongest-match scoring, hot reload.
- Fault injection (latency/status/reset/timeout/garbage) in mock and proxy
  modes.
- Live OpenAPI validation proxy with violations report.
- LLM provider fingerprinting (9 providers), usage-token folding for
  streaming responses, shape fingerprints with drift grouping.
- Purpose-built TUI (`arbiter tui`).
- Header rewrite rules; subprocess/webhook hooks.
- Shell completions, layered config file, global `--json`.
- Nested CONNECT proxy chaining with depth cap.
- HAR-backed flows API on the docs server for TUI attach from proxy mode.
- Shutdown auto-export of HAR + generated OpenAPI from `start`.

### Changed

- Bundle manifest `schemaVersion` is written as **2** only when captures
  contain v2-only content (WebSocket streams); HTTP-only captures remain
  byte-identical to v1 output. Loaders accept both versions.

### Migration notes: bundle format v1 → v2

- **Reading**: both implementations load v1 and v2 manifests transparently;
  no action is required for existing capture directories.
- **Writing**: Rust writers emit v2 manifests only when WebSocket or
  tunnel metadata is present. The TypeScript writer always emits v1; those
  bundles load everywhere.
- **Digests**: the bundle digest algorithm is unchanged for HTTP-only
  exchanges. Exchanges containing WebSocket messages exclude per-message
  timing (`ws.messages[i].offsetMs`) from the digest, so re-captures of the
  same wire content produce identical digests regardless of timing.
- **Tooling**: no migration command is needed. To force v1 output from a
  session that saw WebSocket traffic, replay the HTTP subset through
  `arbiter mock --capture` and re-export, or filter exchanges before export
  in library use.

## [1.1.0] — TypeScript release line

See npm for the TypeScript package history (`@parke.dev/arbiter`).
