# Arbiter exact capture and replay

Status: Proposed

## Objective

Grow Arbiter into the canonical capture, validation, sanitization, export, and replay module for coding-agent provider contract goldens.

Arbiter must be able to sit between provider-specific coding-agent CLIs and Anthropic, OpenAI, Moonshot, or OpenRouter and produce reviewable artifacts that prove exactly what application-level HTTP traffic crossed the proxy. OpenRouter CI will consume those artifacts to replay the captured conversation through its current skins and adapters.

This is not a special-case test runner inside Arbiter. Arbiter owns the general traffic contract; OpenRouter owns harness launch configuration and router-specific replay.

## Definition of exact

Arbiter guarantees exact **application HTTP body bytes after transport decoding**:

- request body bytes received from the client;
- response body bytes delivered to the client;
- ordered SSE bytes and terminal state;
- request method and path/query;
- response status;
- explicitly selected end-to-end headers.

Arbiter does not claim equality for TLS records, HTTP/2 frames, TCP segmentation, transfer-chunk framing, or provider compression framing. Those are transport implementation details, not API contract bytes.

## Current gaps

| Gap | Current behavior | Required behavior |
|---|---|---|
| Request fidelity | Express body parsers consume requests and `JSON.stringify(req.body)` reconstructs POST/PUT/PATCH bodies | Forward the original bytes unchanged; parsing happens only on a copy after forwarding |
| Response persistence | Live response chunks stream, but export later converts buffers to UTF-8 and sometimes reparses JSON | Persist and export the exact bytes delivered to the client, with encoding metadata |
| SSE completeness | Chunks are concatenated without explicit completion, truncation, cancellation, or stream-error metadata | Record ordered bytes plus completion state and protocol-aware terminal evidence |
| Header safety | Request/response headers, including credentials, are stored and can become OpenAPI examples | Redact values before persistence; retain removed header names as evidence |
| Replay | Replays method and URL only; original request body and non-auth headers are omitted | Replay method, path/query, selected headers, and exact body bytes; verify expected response under declared semantics |
| Storage | SQLite stores JSON blobs but not canonical raw response bytes | Store immutable exchanges and body blobs losslessly |
| Validation | Custom OpenAPI validator only checks a subset of request/response constraints | Keep validation pluggable and emit structured violations without changing recorded bytes |
| Server interface | `startServers` is coupled to process-wide singleton stores and always starts both servers | Add an embeddable capture session with explicit lifecycle and stores |
| Failure handling | Several storage/recording failures are swallowed | Exact mode fails closed and surfaces every capture failure |
| License metadata | README/LICENSE say MIT while `package.json` says ISC | Make package metadata consistently MIT |

## Module design

Arbiter exposes one deep module: `CaptureSession`.

```ts
interface CaptureSessionOptions {
  target: URL;
  listen: { hostname: string; port: number };
  output?: string;
  redaction?: RedactionPolicy;
  validation?: ContractValidation;
  mode?: "observe" | "exact";
}

interface CaptureSession {
  readonly url: URL;
  exchanges(): readonly CapturedExchange[];
  waitForIdle(): Promise<void>;
  export(options: ExportOptions): Promise<ExportResult>;
  close(): Promise<void>;
}

startCaptureSession(options: CaptureSessionOptions): Promise<CaptureSession>
replayCapture(capture: CaptureBundle, options: ReplayOptions): Promise<ReplayReport>
validateCapture(capture: CaptureBundle, contract: ContractSource): Promise<ValidationReport>
```

`startServers` and the CLI become adapters over this module. Middleware capture remains separate because it observes an application after parsing and cannot promise proxy-level byte fidelity.

## Capture model

### Exchange schema

```ts
interface CapturedExchange {
  schemaVersion: 1;
  sequence: number;
  startedAt: string;
  durationMs: number;
  request: {
    method: string;
    path: string;
    httpVersion: string;
    headers: CapturedHeaders;
    body: CapturedBody;
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    headers: CapturedHeaders;
    body: CapturedBody;
    stream: StreamState;
  };
  failure: CaptureFailure | null;
  validation: ValidationSummary | null;
}

interface CapturedBody {
  sha256: string;
  size: number;
  mediaType: string | null;
  contentEncoding: string | null;
  storage: { kind: "inline-base64"; value: string } | { kind: "blob"; path: string };
}

interface CapturedHeaders {
  values: Record<string, string[]>;
  redacted: string[];
}

interface StreamState {
  kind: "buffered" | "sse" | "other-stream";
  completed: boolean;
  clientAborted: boolean;
  upstreamAborted: boolean;
  terminalMarker: string | null;
  error: string | null;
}
```

Header names are lowercased and duplicate values remain arrays. Bodies are bytes, never strings in the canonical model.

### Bundle format

```text
capture/
  manifest.json
  exchanges.ndjson
  bodies/
    <sha256>.bin
  validation.ndjson
```

The manifest records Arbiter version, capture mode, target origin with query values removed, started/completed times, exchange count, bundle digest, redaction policy, and optional caller metadata.

The bundle is deterministic after normalization:

- exchange order by sequence;
- body blobs content-addressed;
- stable JSON serialization;
- no random filenames;
- timestamps retained as provenance but excluded from semantic bundle comparison.

HAR and traffic JSONL become derived exports from the canonical bundle, not independent storage formats.

## Exact proxy path

Replace body-parser-based proxying with a raw streaming path.

### Request

1. Receive `IncomingMessage`.
2. Tee raw request chunks to a bounded capture sink and the upstream request.
3. Preserve chunk order without reconstructing the body.
4. Remove hop-by-hop headers and recompute framing headers only when Node requires it.
5. Record a SHA-256 incrementally.
6. Parse JSON only after capture, from the captured bytes, for OpenAPI inference/validation.
7. Propagate client cancellation upstream and record it.

The default exact mode body limit is configurable. Crossing it does not silently truncate; it either spills to a restricted temporary/blob file or fails the exchange according to policy.

### Response

1. Request `Accept-Encoding: identity` by default in exact mode.
2. Forward upstream status and end-to-end headers.
3. Tee every upstream response chunk to the client and capture sink.
4. Preserve the exact byte sequence sent to the client.
5. Record upstream errors, client cancellation, and whether the stream completed.
6. For `text/event-stream`, incrementally parse a copy only to identify terminal events; never rewrite the stream.
7. Do not report the exchange as complete until the recording sink settles.

If the upstream ignores `identity` and responds compressed, Arbiter forwards and records the compressed application body consistently, records the content encoding, and derives a decoded analysis view separately. Canonical and analysis bodies are never conflated.

## Redaction and secret safety

### Default policy

Redact values for:

- `authorization`
- `proxy-authorization`
- `cookie`
- `set-cookie`
- `x-api-key`
- `x-auth-token`
- `x-goog-api-key`
- header names matching `api[-_]?key|auth|credential|secret|token|cookie|session`

Query values are redacted by default while names are retained. Users may explicitly allow safe query keys.

For exact request replay, redaction creates an explicit limitation: a redacted header is not replayable unless a replay credential provider supplies it. Arbiter never stores the original secret in the capture bundle.

### Secret scanner

Before export succeeds in exact mode:

- scan manifest, headers, paths, parsed JSON/text bodies, and analysis metadata;
- accept caller-supplied exact secret values to reject anywhere;
- detect common API-key, bearer/basic, AWS, Google, JWT, PEM, and cookie patterns;
- produce findings with exchange/field location, never the complete secret;
- fail export on any finding.

Binary bodies are not content-redacted. The caller must mark allowed media types; unexpected binary bodies fail exact export.

## Credential-injecting gateway mode

Add a mode specifically designed for untrusted clients without coupling it to coding agents:

```text
arbiter gateway --policy policy.json --credential-command <command>
```

The client receives an opaque short-lived gateway token. Arbiter:

1. authenticates the token;
2. validates method, path, target, model, request count, expiry, and byte/spend policy;
3. records the client request with the opaque token redacted;
4. obtains the real upstream credential through an injected credential provider;
5. adds the credential only to the upstream request;
6. never exposes it to the client process or capture artifact.

The credential provider can be a callback in library use or a subprocess command in CLI use. Its stdout is consumed as a secret and never logged. Arbiter clears references after constructing the upstream request.

Policy v1:

```ts
interface GatewayPolicy {
  tokenSha256: string;
  expiresAt: string;
  targetOrigin: string;
  methods: string[];
  pathPrefixes: string[];
  models?: string[];
  maxRequests: number;
  maxRequestBytes: number;
  maxResponseBytes: number;
  maxDurationMs: number;
}
```

Cost enforcement that requires provider pricing is an application concern. Arbiter enforces request/token-field ceilings where configured and exposes hooks for a caller-owned budget service.

## Replay

Replay consumes the canonical capture bundle.

### Modes

- `exact-request`: resend method, path/query, safe headers, and body bytes exactly.
- `semantic-json-response`: validate/compare JSON after declared normalization.
- `exact-response-body`: compare response bytes exactly.
- `semantic-sse-response`: compare ordered SSE events and JSON payloads while allowing declared volatile JSON pointers.
- `status-only`: retained for compatibility.

### Credential injection

Replay accepts credentials only through:

- CLI environment-to-header mappings;
- a credential-provider callback;
- gateway mode.

Credentials never update the stored capture.

### Replay report

Each exchange reports independently:

- transport success;
- request digest sent;
- status match;
- response contract validity;
- exact/semantic body result;
- first differing byte offset or JSON pointer/SSE event;
- normalization rules applied;
- duration.

Replay must never ignore parse/comparison failures. Unsupported comparison modes are errors, not skipped checks.

## Validation

Arbiter keeps its generated OpenAPI discovery, but contract validation must be promoted to a first-class adapter.

```ts
interface ContractValidator {
  validateRequest(exchange: CapturedExchange): Promise<Violation[]>;
  validateResponse(exchange: CapturedExchange): Promise<Violation[]>;
}
```

Initial adapters:

1. Existing lightweight validator, renamed `BasicOpenAPIValidator` for compatibility.
2. External-command validator adapter for WireTap or another full validator.
3. Runtime callback adapter so OpenRouter can apply curated Zod schemas for providers without official OpenAPI.

Validation runs on parsed analysis views, never canonical bytes. Violations include authority/source/revision metadata.

## CLI

### Capture

```text
arbiter capture \
  --target https://api.anthropic.com \
  --output ./capture \
  --port 8080 \
  --exact \
  --spec ./anthropic.openapi.yaml \
  --fail-on-validation
```

Flags:

- `--output <dir>` required for exact capture;
- `--exact` fail-closed capture semantics;
- `--redact-header <glob>` repeatable;
- `--allow-query <name>` repeatable;
- `--reject-secret <value-env-name>` repeatable without placing secret values in argv;
- `--max-body-bytes`;
- `--idle-timeout`;
- `--proxy-only` and `--docs-only` must actually work;
- `--ready-file <path>` writes connection metadata atomically for process orchestration;
- `--report <path>` writes a final machine-readable report on shutdown.

`arbiter start` remains compatible and defaults to observe mode.

### Replay

```text
arbiter replay ./capture \
  --target http://127.0.0.1:8787 \
  --mode semantic-sse-response \
  --credential-env OPENROUTER_API_KEY:authorization:Bearer
```

### Validate

```text
arbiter validate ./capture --spec ./openapi.yaml --strict --report report.json
```

### Sanitize

```text
arbiter sanitize ./capture --output ./sanitized --reject-secret-env ANTHROPIC_API_KEY
```

Sanitize revalidates an untrusted capture and emits a new deterministic bundle. It never edits in place.

## Programmatic integration

New package exports:

```json
{
  "./capture": "./dist/src/capture/index.js",
  "./replay": "./dist/src/replay/index.js",
  "./validation": "./dist/src/validation/index.js",
  "./bundle": "./dist/src/bundle/index.js"
}
```

OpenRouter imports Arbiter's schemas and bundle loader. It does not import Arbiter's Express docs server or global stores.

## Compatibility and migration

1. Build the canonical exchange/bundle model alongside current HAR/OpenAPI stores.
2. Route proxy capture into the canonical store.
3. Derive HAR, traffic JSONL, and OpenAPI observations from canonical exchanges.
4. Replace replay's legacy traffic reader with a bundle reader; retain legacy JSONL input behind an explicit compatibility flag.
5. Migrate SQLite to canonical exchanges and content-addressed body blobs. Add schema versioning and migrations.
6. Remove the request-body map, body-parser dependency from the proxy path, and `_rawResponseBuffer` deferred model.
7. Keep `harRecorder` but document that middleware mode offers semantic capture, not proxy exactness.

## Testing strategy

### Unit tests

- raw JSON whitespace/key-order request bytes survive unchanged;
- arbitrary text and binary request bytes survive unchanged;
- duplicate headers and query values are represented correctly;
- default and custom redaction policies;
- exact-secret scanning without leaking findings;
- bundle serialization is deterministic;
- path traversal and symlink rejection;
- SSE terminal detection for Anthropic Messages, OpenAI Responses, and Chat Completions;
- stream truncation, client abort, upstream abort, and in-stream error metadata;
- first byte/JSON pointer/SSE event diff reporting;
- gateway policy enforcement and credential-provider secrecy;
- body-limit spill/failure behavior.

### Integration tests

Use local byte-echo and streaming upstreams:

- request bytes received upstream equal client bytes;
- response bytes received by client equal captured bytes;
- SSE chunks are delivered before upstream completion;
- compressed response handling keeps canonical and analysis views distinct;
- recording failures cause exact mode to fail;
- replay sends the recorded body bytes and safe headers;
- generated HAR round-trips body bytes through base64 where required;
- SQLite restart preserves exact bundles;
- docs-only/proxy-only modes bind only requested listeners.

### Golden end-to-end fixtures

Add provider-shaped local fixtures for:

- Anthropic Messages request/SSE;
- OpenAI Responses request/SSE;
- OpenAI Chat Completions request/SSE;
- auxiliary token-count/model calls.

These are synthetic local protocol fixtures. Real coding-harness traffic belongs in the consuming OpenRouter repository, not Arbiter's own tests.

## CI and release

Required checks:

- build;
- typecheck;
- lint;
- unit/integration tests;
- package export smoke test;
- CLI capture/replay smoke test;
- secret scan over committed fixtures;
- Linux and macOS test matrix for filesystem/body persistence behavior.

Release work:

- reconcile the project to MIT in `package.json`;
- bump a minor version because the new APIs are additive;
- publish from a reviewed tag or protected main workflow;
- attach JSON schemas for the capture bundle to the release;
- update README with exactness limits and security model.

## Implementation phases

### Phase 1: canonical bundle and raw capture

- add schemas/types;
- content-addressed byte storage;
- raw request and response tee;
- SSE completion metadata;
- deterministic export;
- fail-closed exact mode;
- derive HAR/JSONL from the bundle.

Exit: local byte-echo and SSE integration tests prove client/upstream/capture equality.

### Phase 2: redaction and sanitization

- redaction policy;
- exact-secret and pattern scanner;
- safe query/header handling;
- restricted output permissions;
- sanitize command;
- path/symlink/size gates.

Exit: fixtures containing credentials cannot be exported, persisted, or replayed without explicit injection.

### Phase 3: exact replay and comparison

- canonical bundle replay;
- exact request bytes;
- semantic JSON/SSE and exact response comparison;
- focused diffs;
- credential-provider interface;
- legacy replay compatibility.

Exit: replay integration tests prove original bodies and safe headers are resent.

### Phase 4: credential gateway

- token policy;
- target/path/model/request limits;
- credential provider callback/command;
- gateway CLI;
- signed final manifest hook for external orchestrators.

Exit: an untrusted subprocess completes a provider-shaped run without possessing the real upstream key.

### Phase 5: validation adapters and polish

- validator interface;
- structured full OpenAPI adapter integration;
- report formats;
- actual docs-only/proxy-only support;
- storage migration;
- README, schemas, and release.

Exit: Arbiter is the only traffic recorder needed by the OpenRouter coding-agent contract system.

## Acceptance criteria

- The upstream receives byte-for-byte the request body the client sent.
- The capture stores byte-for-byte the response body the client received.
- SSE streams remain live and record terminal/truncation/error state.
- Credential values never appear in canonical captures, HAR, JSONL, OpenAPI examples, logs, reports, or SQLite.
- Exact mode surfaces recording and persistence failures.
- Capture bundles are deterministic, versioned, path-safe, and independently consumable.
- Replay resends original request bodies and selected headers.
- Replay supports exact bytes, semantic JSON, and semantic SSE with explicit normalization.
- An untrusted client can use gateway mode without access to the upstream credential.
- Programmatic APIs do not require global singleton stores or docs servers.
- Current OpenAPI discovery and interactive docs remain available as derived views.
- OpenRouter's contract package consumes Arbiter artifacts without implementing another proxy.

## Non-goals

- running coding-agent CLIs;
- understanding OpenRouter model routing;
- defining provider pricing;
- proving undocumented provider cache-key behavior;
- transparent HTTPS MITM for clients that cannot configure a base URL;
- reproducing TLS/HTTP2/TCP framing;
- mutating captured bodies to make them valid.
