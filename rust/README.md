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

## Proxy-parity expansion (feat/proxy-parity)

Built on the Rust port, this wave closes the functional gap to mitmproxy /
Wiretap / Hoverfly / WireMock / Prism (LiteLLM gateway features excluded):

- **TLS interception (mitmproxy parity)** — `arbiter ca` generates/loads a
  root CA; CONNECT tunnels are intercepted with dynamic per-host leaf certs
  (825-day validity, Apple-trust compatible), or pass through untouched via
  `--tls-passthrough` globs; `--tls-cert/--tls-key` serve reverse-proxy HTTPS;
  ALPN h2 + HTTP/1.1 both directions.
- **WebSocket relay + capture** — upgrades are forwarded transparently,
  messages recorded into bundle-v2 `ws` records (direction, opcode, payload,
  close state); h2c prior-knowledge supported on plaintext listeners.
- **Mock / simulate engine** — `arbiter mock --spec x.yaml` (Prism-parity
  example generation, CORS, hot reload) or `--capture DIR` (byte-exact
  recorded-response replay with strongest-match scoring); fault injection
  (`--fault-status/--fault-latency-ms/--fault-error`) usable in mock AND
  proxy modes; header rewrite rules (`set:/append:/remove:/rename:`).
- **Live validation proxy** — `start --validate-spec x.yaml --report r.json
  --fail-on-violation`: forwards traffic, validates against the spec,
  records structured violations (seq-keyed request/response pairing).
- **Purpose-built TUI** — `arbiter tui [--attach URL | --target URL]`:
  live flow list (100k ring, virtualized), detail viewer with JSON
  highlighting, filter grammar (`method=GET status=2xx path~/v1/*`),
  per-flow replay/delete/HAR-export, LLM columns, saved filters.
- **LLM fingerprinting** — provider detection across anthropic/openai/
  google/xai/mistral/ollama/openrouter/azure/bedrock from path+auth+body
  evidence (redacted-header names count as presence); usage-token folding
  for streaming SSE; types-only shape fingerprints with drift grouping;
  surfaces as exchange metadata, `arbiter fingerprint`, `/__fingerprint`.
- **Hooks & modification** — `--on-request/--on-response` subprocess or
  `--hook-server` webhook (redacted views in, modified-exchange out,
  fail-open on timeout); ordered header rule engine.
- **DX plumbing** — `complete bash|zsh|fish|powershell`, layered config
  file (`config init/show/path`; defaults < file < env < CLI), global
  `--json`, cause+help error lines everywhere.

Perf (measured, release build): startup-to-listening 83–96 ms warm; proxy
overhead ~1–4% vs upstream-bound baseline at c=16 (385 rps local fixture);
recording spills to disk past 32 MiB so memory stays bounded; clippy
-D warnings clean; 441 tests green.

Known follow-ups: nested CONNECT (proxy chaining) rejected by design;
TUI HTTP-attach requires a capture-session surface (embedded mode is the
primary UX); streaming NDJSON responses lack response_shape_fp.

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
