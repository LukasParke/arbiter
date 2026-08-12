# Arbiter exact-capture implementation progress

Branch: `agent/exact-capture` (worktree `/Users/luke/.herdr/worktrees/arbiter/agent-exact-capture`)
Plan: `PLAN.md`
Tracking issue: https://github.com/LukasParke/arbiter/issues/32
PR: https://github.com/LukasParke/arbiter/pull/33

## Phase status

- [x] Phase 1 — canonical bundle + raw capture
  - `src/capture/types.ts` exchange/bundle schemas (v1)
  - `src/capture/session.ts` raw streaming proxy (`startCaptureSession`), request/response byte tee, SSE state, fail-closed exact mode
  - `src/capture/bodySink.ts` incremental sha256 + spill/fail body limits
  - `src/bundle/` deterministic bundle write/load, content-addressed blobs, stable JSON, digest verify, path/symlink safety
  - `src/bundle/derive.ts` HAR + traffic JSONL derived views
- [x] Phase 2 — redaction and sanitization
  - `src/capture/redaction.ts` default policy + globs + query allowlist
  - `src/capture/secretScan.ts` exact-value + pattern scanner, binary gating, decoded analysis views
  - `src/bundle/sanitize.ts` + `arbiter sanitize` (never in place, deterministic output)
  - legacy observe path (`startServers`) also redacts credential header values before HAR/OpenAPI/SQLite
- [x] Phase 3 — replay and comparison
  - `src/replay/` bundle replay: exact request bytes + safe headers; modes status-only / exact-response-body / semantic-json-response / semantic-sse-response
  - first-diff byte offset / JSON pointer / SSE event reporting; volatile pointer normalization
  - credential injection via provider callback or ENV:header:prefix mapping; capture never mutated
  - legacy JSONL replay preserved (`--legacy-jsonl` / file input)
- [x] Phase 4 — credential gateway
  - `src/gateway/` sha256-pinned opaque tokens (timing-safe), expiry/duration/count/method/path/model/byte ceilings
  - credential provider callback + subprocess command (stdout consumed as secret, never logged)
  - `arbiter gateway --policy --credential-command`
- [x] Phase 5 — validation adapters, CLI, docs, license
  - `src/validation/` ContractValidator: BasicOpenAPIValidator (existing lightweight), CommandValidator (external), CallbackValidator (Zod-style)
  - `arbiter capture/replay/validate/sanitize/gateway` CLI commands; `--ready-file`, `--report`, `--reject-secret`, `--idle-timeout`
  - real `--proxy-only` / `--docs-only` (only requested listeners bound)
  - package.json: MIT, v1.1.0, exports ./capture ./replay ./validation ./bundle ./gateway
  - README security model + exactness limits; `schemas/capture-bundle.schema.json`

## Verification

- `pnpm build` green (tsc strict)
- `pnpm lint` green, `pnpm format:check` green
- 189 tests passing across 20 files:
  - unit: redaction, sse (Anthropic/Responses/ChatCompletions terminals, truncation, chunk splits), secretScan, bodySink, bundle determinism/tamper/path-safety, compare (bytes/JSON/SSE), sanitize, validation adapters
  - integration: byte fidelity (JSON whitespace/binary), SSE live-streaming before upstream completion, upstream abort metadata, identity encoding, compressed canonical bytes, duplicate headers, redaction e2e, fail-closed export, spill, secret rejection, 502 failure, HAR/JSONL derivation + base64 round-trip, replay (bytes/headers/credentials/diffs), gateway policy suite, provider-shaped golden fixtures, proxy-only/docs-only binding
  - CLI smoke: capture → sanitize → replay end-to-end via dist/cli.js, secret-rejection exit codes
- package export smoke: all five new subpath exports load from dist

## Post-PR

- Clean-context security review run; C1–C5/H2/H3 hardened (generic client-facing errors, spill cleanup on abnormal death, credential ref dropped in finally) — commit e065bc1
- CI workflow was broken repo-wide (pnpm 11 via version:latest needs Node >= 22.13; every matrix job failed at install). Fixed: pnpm pinned to 10, lint once on Node 22, new build job with export/CLI smoke, tests on ubuntu+macos × Node 20/22/24 — commit 1f15767
- CI fully green (lint, build+export smoke, tests on ubuntu+macos × Node 20/22/24) as of 363a9a5
- CommandValidator stdin EPIPE race fixed (Linux CI caught it; validator exiting before reading stdin)
- CodeRabbit rate-limited; retriggering when the limit resets, then driving threads to zero

## Parent-review remediation (post-PR)

All 8 false-green/high items plus the gateway capture gap addressed:

1. semantic-sse mode rejects non-SSE/empty bodies (`compareSemanticSse`) and replay marks non-SSE exchanges as failures instead of vacuous passes; provider fixture asserts 3 pass / 2 loud failures
2. upstream destroy AND bare socket close both set `upstreamAborted: true` + error evidence (new `close`-without-`end` handling in session); two truncation tests
3. exported request bytes asserted byte-exact in bundle round-trip + provider fixture
4. replay path/query asserted exact, including an allowed-query (`page=7&limit=25`) exact-value test
5. end-to-end test: capture with redacted `x-api-key` → bundle holds neither key → replay reinjects a different key, target receives only the new one
6. determinism test compares content-addressed `bodies/*.bin` names and bytes across two writes
7. secret-free export test walks every bundle file plus derived HAR/JSONL for four planted secrets (auth header, query value, client cookie, set-cookie)
8. gateway oversized requests: clean `413` JSON + `connection: close`, no socket destroy; gateway stays usable afterwards

Blocking gap fixed: **gateway now composes with CaptureSession**. `GatewayOptions.capture` routes upstream traffic through an exact capture session (`GatewayServer.capture` exposes it; CLI `--capture-output` exports on shutdown). Fails closed if the injected credential header is not covered by the capture redaction policy. Tests prove byte-exact client traffic recorded with neither the gateway token nor the real credential in any artifact.

197 tests passing (was 189).

## Second parent audit remediation (trust boundaries)

1. `loadBundle` now treats bundles as hostile input: `src/bundle/validate.ts` runtime-validates every manifest/exchange/body/header/stream/failure field with typed errors; rejects non-finite/negative/out-of-range numbers, duplicate/out-of-order sequences, malformed or size-inconsistent base64, uppercase header names, unknown enum values; bounded manifest size, NDJSON line size, exchange count, and declared body sizes enforced before parsing/allocation
2. Path containment hardened: `readContainedFile` lstat-rejects symlinks at every path component (symlinked intermediate `bodies/` dir escape closed), leaf realpath must remain under root, file size checked against declared bound before read; `writeBundle` realpaths the output root and refuses symlinked bodies dirs. 21 malicious-bundle tests added
3. Replay never sends `__redacted__` placeholders: exchanges with capture-redacted query values fail as unreplayable unless a `queryValueProvider` (library) / `--query-env NAME:ENV` (CLI) supplies replacements. README exactness/replayability claims updated
4. Gateway path allowlisting by path-segment semantics (`pathAllowed`): `/v1secrets` no longer matches `/v1`; encoded traversal, backslashes, control chars, malformed percent-encoding, and non-normalized methods rejected; unit + end-to-end tests
5. PR body verification counts updated

223 tests passing (was 197).

## Blockers

- none

## Notes

- better-sqlite3 bumped 12.2.0 → 12.11.1 (12.2.0 has no prebuilds for newer Node; compile fails locally on Node 26)
