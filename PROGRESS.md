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
- Monitoring CI + reviews via sentinel `arbiter-pr33-ci`

## Blockers

- none

## Notes

- better-sqlite3 bumped 12.2.0 → 12.11.1 (12.2.0 has no prebuilds for newer Node; compile fails locally on Node 26)
