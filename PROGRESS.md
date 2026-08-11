# Arbiter exact-capture implementation progress

Branch: `agent/exact-capture` (worktree `/Users/luke/.herdr/worktrees/arbiter/agent-exact-capture`)
Plan: `PLAN.md` (copied from feat/coding-agent-capture worktree)
Tracking issue: https://github.com/LukasParke/arbiter/issues/32
PR: (pending)

## Phase status

- [x] Phase 1 — canonical bundle + raw capture
  - `src/capture/types.ts` exchange/bundle schemas (v1)
  - `src/capture/session.ts` raw streaming proxy (`startCaptureSession`), tee request/response bytes, SSE state, fail-closed exact mode
  - `src/capture/bodySink.ts` incremental sha256 + spill/fail body limits
  - `src/bundle/` deterministic bundle write/load, content-addressed blobs, stable JSON, digest verify, path/symlink safety
  - `src/bundle/derive.ts` HAR + traffic JSONL derived views
- [x] Phase 2 — redaction and sanitization (core)
  - `src/capture/redaction.ts` default policy + globs + query allowlist
  - `src/capture/secretScan.ts` exact-value + pattern scanner, binary gating, decoded analysis views
  - sanitize CLI: pending
- [ ] Phase 3 — replay and comparison
- [ ] Phase 4 — credential gateway
- [ ] Phase 5 — validation adapters, CLI, docs, license

## Tests

- `pnpm build` green
- 71 tests passing (unit: redaction/sse/secretScan/bodySink/bundle; integration: byte fidelity, SSE live streaming, spill, fail-closed, secret rejection, HAR round-trip)

## Blockers

- better-sqlite3@12.2.0 does not compile on local Node 26; bumped to 12.11.1 (prebuilds available). CI matrix uses Node 20–24.
