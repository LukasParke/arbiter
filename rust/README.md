# Arbiter (Rust port)

Rust implementation of the Arbiter API proxy — exact capture/replay, OpenAPI
3.1 generation, HAR export, credential gateway, and sanitization. This is a
faithful port of the TypeScript implementation in the repository root; the
TypeScript sources remain the behavioral reference until the cutover is
approved.

## Build

```bash
cd rust
cargo build --release          # binary: target/release/arbiter
cargo test                     # unit + loopback integration tests
```

## Layout

| Module | Ported from | Purpose |
|---|---|---|
| `src/types.rs` | `src/capture/types.ts` | Canonical capture model (serde camelCase, wire-compatible) |
| `src/json.rs` | `src/bundle/stableJson.ts` | Deterministic key-sorted JSON + RFC 6901 pointers |
| `src/redaction.rs` | `src/capture/redaction.ts` | Credential header/query redaction policy |
| `src/secret_scan.rs` | `src/capture/secretScan.ts` | Fail-closed secret scanning with decompression bomb guard |
| `src/headers.rs` | `src/capture/headers.ts` | Header normalization, capture redaction, forwarding rules |
| `src/sse.rs` | `src/capture/sse.ts` | Incremental UTF-8/SSE parser, provider terminal markers |
| `src/bundle/` | `src/bundle/*` | Bundle validation (untrusted-input hardened), load/write, HAR/traffic derivation, sanitize |
| `src/capture/` | `src/capture/session.ts`, `bodySink.ts` | Embeddable exact-capture proxy session |
| `src/replay/` | `src/replay/*` | Bundle replay: status-only / exact-byte / semantic-JSON / semantic-SSE comparison |
| `src/gateway/` | `src/gateway/index.ts` | Opaque-token credential gateway |
| `src/store/`, `src/infer.rs` | `src/store/openApiStore.ts`, `src/infer.ts` | OpenAPI 3.1 generation from observed traffic |
| `src/server/` | `src/server.ts` | Standalone proxy + docs servers (Scalar, openapi.json/yaml, /har) |
| `src/validation/` | `src/validation/index.ts`, `src/validate.ts` | Contract validation against an OpenAPI spec |
| `src/storage/` | `src/storage/sqlite.ts` | SQLite persistence (HAR entries, endpoints) |
| `src/diff.rs`, `src/generate_spec.rs` | `src/diff.ts`, `src/generate-spec.ts` | Spec drift tooling |
| `src/cli/` | `src/cli.ts`, `src/commands/*` | Command surface (`arbiter start/capture/replay/gateway/sanitize/validate/...`) |

## Compatibility guarantees

- **Bundle format**: byte-identical manifests and NDJSON exchange encoding
  (stable key-sorted JSON), same sha256 content addressing, same digest
  algorithm excluding timing provenance. Bundles written by the TypeScript
  implementation load in Rust and vice versa.
- **Redaction semantics**: same default header set, same sensitive-name
  pattern, same `__redacted__` query placeholder with verbatim name retention.
- **Secret scanning**: same pattern set, same fail-closed behavior, findings
  never contain the full secret.
- **SSE analysis**: same terminal markers (`[DONE]`, `message_stop`, `error`,
  `response.completed|failed|incomplete`).

## Security model

Unchanged from the TypeScript implementation: bundles are treated as hostile
input on load (bounded sizes before allocation, strictly increasing sequences,
digest verification, symlink rejection at every path component under the
bundle root); exports are secret-scanned fail-closed; bundle directories are
created `0700` and files `0600`; writes never follow a symlinked output root.
