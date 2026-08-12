<p align="center">
  <img src="ArbiterLogo.png" alt="Arbiter Logo" width="250">
</p>

# Arbiter

Arbiter is a powerful API proxy and documentation generator that automatically creates OpenAPI specifications and HAR (HTTP Archive) recordings for any API you access through it.

## Features

- **Exact Capture** - Byte-fidelity capture of application HTTP bodies with deterministic, content-addressed capture bundles
- **Replay & Comparison** - Replay captured bundles with exact-byte, semantic-JSON, or semantic-SSE comparison
- **Redaction & Secret Safety** - Credential headers and query values are redacted before persistence; exports are secret-scanned and fail closed
- **Credential Gateway** - Untrusted clients use short-lived opaque tokens; real upstream credentials are injected server-side and never exposed
- **API Proxy** - Transparently proxies all API requests to the target API 
- **Automatic OpenAPI Generation** - Builds a complete OpenAPI 3.1 specification based on observed traffic
- **HAR Recording** - Records all requests and responses in HAR format for debugging and analysis
- **Interactive API Documentation** - Provides beautiful, interactive API documentation using [Scalar](https://github.com/scalar/scalar)
- **Security Scheme Detection** - Automatically detects and documents API key, Bearer token, and Basic authentication
- **Schema Inference** - Analyzes JSON responses to generate accurate schema definitions
- **Path Parameter Detection** - Intelligently identifies path parameters from multiple requests
- **Support for Complex Content Types** - Handles JSON, XML, form data, and binary content

## Getting Started

### Installation

```bash
npm install -g @parke.dev/arbiter
```

### Basic Usage

Start Arbiter by pointing it to your target API:

```bash
arbiter --target https://api.example.com
# with persistence
arbiter --target https://api.example.com --db-path ./arbiter.db
```

Then send requests through the proxy:

```bash
curl http://localhost:8080/users
```

And view the automatically generated documentation:

```bash
open http://localhost:9000/docs
```

### Docker Usage

You can run Arbiter using Docker:

```bash
# Build the Docker image
docker build -t arbiter .

# Run the container (ephemeral)
docker run -p 8080:8080 -p 9000:9000 arbiter --target https://api.example.com

# Run the container with persistent storage
docker run -p 8080:8080 -p 9000:9000 \
  -v $(pwd)/data:/data \
  arbiter --target https://api.example.com --db-path /data/arbiter.db
```

The container exposes:
- Port 8080 for the proxy server
- Port 9000 for the documentation server

You can customize the ports and other options:

```bash
docker run -p 3000:3000 -p 3001:3001 arbiter \
  --target https://api.example.com \
  --port 3000 \
  --docs-port 3001 \
  --db-path /data/arbiter.db \
  --verbose
```

## Usage Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t, --target <url>` | Target API URL to proxy to | (required) |
| `-p, --port <number>` | Port to run the proxy server on | 8080 |
| `-d, --docs-port <number>` | Port to run the documentation server on | 9000 |
| `--db-path <path>` | Path to SQLite database file for persistence | (disabled) |
| `--docs-only` | Run only the documentation server | false |
| `--proxy-only` | Run only the proxy server | false |
| `-v, --verbose` | Enable verbose logging | false |

## API Documentation

After using the API through the proxy, you can access:

- Interactive API docs: `http://localhost:9000/docs`
- OpenAPI JSON: `http://localhost:9000/openapi.json`
- OpenAPI YAML: `http://localhost:9000/openapi.yaml`
- HAR Export: `http://localhost:9000/har`

## Exact Capture and Replay

Arbiter's canonical capture path guarantees **exact application HTTP body bytes after transport decoding**:

- request body bytes received from the client;
- response body bytes delivered to the client;
- ordered SSE bytes and terminal state (`message_stop`, `[DONE]`, `response.completed`, …);
- request method and path/query, response status, and selected end-to-end headers.

Arbiter does **not** claim equality for TLS records, HTTP/2 frames, TCP segmentation, transfer-chunk framing, or provider compression framing — those are transport details, not API contract bytes. If an upstream compresses despite `Accept-Encoding: identity`, the compressed bytes are recorded canonically with their `content-encoding`, and analysis views are derived separately.

### Capture

```bash
arbiter capture \
  --target https://api.anthropic.com \
  --output ./capture \
  --exact \
  --reject-secret ANTHROPIC_API_KEY \
  --ready-file ./ready.json \
  --report ./report.json
```

`--exact` enables fail-closed semantics: any recording, persistence, body-limit, or secret-scan failure fails the export. On shutdown (SIGINT/SIGTERM or `--idle-timeout`), a deterministic bundle is written:

```text
capture/
  manifest.json        # version, mode, target origin, bundle digest, redaction policy
  exchanges.ndjson     # one stable-JSON exchange per line, ordered by sequence
  bodies/<sha256>.bin  # content-addressed body bytes
  validation.ndjson    # optional structured violations
```

Bundles are safe to load from untrusted sources: digests are verified, symlinks and path traversal are rejected.

### Replay

```bash
arbiter replay ./capture \
  --target http://127.0.0.1:8787 \
  --mode semantic-sse-response \
  --credential-env OPENROUTER_API_KEY:authorization:Bearer \
  --ignore-pointer /id \
  --fail-on-diff
```

Modes: `status-only`, `exact-response-body` (first differing byte offset), `semantic-json-response` (first differing JSON pointer), `semantic-sse-response` (ordered events with declared volatile pointers; non-SSE exchanges fail loudly rather than matching vacuously). Replay resends the recorded method, path/query, safe headers, and exact body bytes. Redacted credentials are only re-injected through `--credential-env` or a credential-provider callback — never stored.

**Redaction limits replayability by design.** A query value redacted at capture is not replayable: Arbiter never sends invented placeholder values to a target. Such exchanges fail as unreplayable unless a replacement is supplied via `--query-env NAME:ENV_VAR` (or a `queryValueProvider` callback in library use). The same applies to redacted headers and `--credential-env`. Legacy traffic JSONL replays remain available via `--legacy-jsonl` (or by passing a file path).

### Sanitize and validate

```bash
arbiter sanitize ./capture --output ./sanitized --reject-secret-env ANTHROPIC_API_KEY
arbiter validate ./capture --spec ./openapi.yaml --strict --report report.json
```

Sanitize reloads an untrusted bundle with full verification, re-applies redaction, secret-scans everything, and emits a new deterministic bundle. It never edits in place.

### Credential gateway

```bash
arbiter gateway --policy policy.json --credential-command 'op read op://vault/anthropic/key' \
  --capture-output ./gateway-capture
```

The policy pins a sha256 of an opaque client token plus expiry, target origin, methods, path prefixes, optional models, and request/byte/duration ceilings. The client never sees the upstream credential; the credential command's stdout is consumed as a secret and never logged. Oversized requests receive a clean `413` JSON response.

With `--capture-output` (or `capture: {}` in library use), allowed gateway traffic is routed through an exact `CaptureSession` and exported as a deterministic bundle on shutdown. The gateway fails closed if the injected credential header is not covered by the capture redaction policy, so neither the gateway token nor the upstream credential can reach the bundle.

### Library usage

```typescript
import { startCaptureSession } from '@parke.dev/arbiter/capture';
import { loadBundle } from '@parke.dev/arbiter/bundle';
import { replayCapture } from '@parke.dev/arbiter/replay';
import { validateCapture, BasicOpenAPIValidator, CallbackValidator } from '@parke.dev/arbiter/validation';
import { startGateway } from '@parke.dev/arbiter/gateway';

const session = await startCaptureSession({ target: 'https://api.anthropic.com', mode: 'exact' });
// point your client at session.url …
await session.waitForIdle();
const { bundle } = await session.export({ output: './capture' });
await session.close();

const report = await replayCapture(loadBundle('./capture'), {
  target: 'http://127.0.0.1:8787',
  mode: 'semantic-sse-response',
  normalization: { ignorePointers: ['/id'] },
});
```

### Security model

- Default redaction removes values for `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-goog-api-key`, and any header matching `api[-_]?key|auth|credential|secret|token|cookie|session`; redacted names are kept as evidence.
- Query parameter values are redacted by default; names are retained. Allow specific keys with `--allow-query`.
- Exact exports secret-scan the manifest, headers, paths, and textual bodies for caller-supplied exact values (`--reject-secret ENV_NAME`) and common credential patterns (Anthropic/OpenAI/OpenRouter keys, GitHub tokens, AWS key ids, Google API keys, JWTs, PEM keys, Bearer/Basic values). Any finding fails the export; findings never contain the full secret.
- Unexpected binary bodies fail exact export unless their media type is explicitly allowed.
- Bundle output directories are created `0700`, files `0600`; output roots are realpath-resolved so writes never follow a symlinked directory.
- `loadBundle` treats bundles as hostile input: every manifest/exchange field is runtime-validated with bounded sizes before allocation, sequences must be strictly increasing, base64 must be well-formed and consistent with declared sizes, digests are verified, and file reads reject symlinks at every path component under the bundle root.

## How It Works

### Proxy Server

Arbiter creates a proxy server that forwards all requests to your target API, preserving headers, method, body, and other request details. Responses are returned unmodified to the client, while Arbiter records the exchange in the background.

### OpenAPI Generation

As requests flow through the proxy, Arbiter:

1. Records endpoints, methods, and path parameters
2. Analyzes request bodies and generates request schemas
3. Processes response bodies and generates response schemas
4. Detects query parameters and headers
5. Identifies security schemes based on authentication headers
6. Combines multiple observations to create a comprehensive specification

### Schema Generation

Arbiter uses sophisticated algorithms to generate accurate JSON schemas:

- Object property types are inferred from values
- Array item schemas are derived from sample items
- Nested objects and arrays are properly represented
- Path parameters are identified from URL patterns
- Query parameters are extracted and documented
- Security requirements are automatically detected

### HAR Recording

All requests and responses are recorded in HAR (HTTP Archive) format, providing:

- Complete request details (method, URL, headers, body)
- Complete response details (status, headers, body)
- Timing information
- Content size and type

## Advanced Features

### Structure Analysis

Arbiter can analyze the structure of JSON-like text that isn't valid JSON:

- Detects array-like structures (`[{...}, {...}]`)
- Identifies object-like structures (`{"key": "value"}`)
- Extracts field names from malformed JSON
- Provides fallback schemas for unstructured content

### Content Processing

Arbiter handles various content types:

- **JSON** - Parsed and converted to schemas with proper types
- **XML** - Recognized and documented with appropriate schema format
- **Form Data** - Processed and documented as form parameters
- **Binary Data** - Handled with appropriate binary format schemas
- **Compressed Content** - Automatically decompressed (gzip support)

## Middleware Usage

Arbiter can also be used as middleware in your own application. Note that middleware mode observes the application *after* parsing and offers semantic capture only — proxy-level byte exactness requires `arbiter capture`:

```typescript
import express from 'express';
import { harRecorder } from '@parke.dev/arbiter/middleware';
import { openApiStore } from '@parke.dev/arbiter/store';

const app = express();

// Add Arbiter middleware
app.use(harRecorder(openApiStore));

// Your routes
app.get('/users', (req, res) => {
  res.json([{ id: 1, name: 'User' }]);
});

app.listen(3000);
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Publishing (maintainers)

This repo auto-publishes to npm on push to `main` if the version in `package.json` is newer than the version on npm.

Setup (one-time):
- On npmjs.com → `@parke.dev/arbiter` → Settings → Trusted Publisher, add GitHub Actions:
  - Organization or user: `LukasParke`
  - Repository: `arbiter`
  - Workflow filename: `publish.yml`

Manual run:
- You can also trigger the workflow manually from the Actions tab (workflow_dispatch).

## License

This project is licensed under the MIT License - see the LICENSE file for details.
