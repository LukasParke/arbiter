# Arbiter — Critical DX/UX/TUI Review (2026-08-22)

Method: five perspective-diverse reviewer agents ran the release/debug binary
against live fixtures (help dumps in /tmp/ux-audit/, common-mistake transcripts,
README quickstarts executed verbatim); every blocker/major finding was then
adversarially re-verified by a second agent prompted to refute it; a
completeness critic audited lens coverage. Findings that failed reproduction
were excluded. Machine-readable data: local://ux-findings.json.

## Blockers (data loss / dead core flows)

B1  Ctrl-C during an in-flight request hangs `capture` forever; the only escape
    (SIGKILL) destroys the entire recording. Fix: export partial bundles on
    signal with a hard deadline + truncated marker.
B2  `capture` silently overwrites an existing --output directory on re-run
    (reproduced: pre-existing manifest.json replaced). sanitize refuses
    non-empty dirs; capture must too (--force to override).
B3  Ctrl-C on `arbiter start` destroys all recorded traffic: no export path
    exists at all, no summary, no hint. Fix: auto-export HAR+OpenAPI on
    shutdown.
B4  Attach-mode DELETE splices the flows Vec; every later sequence shifts while
    TUI cursors go stale. Fix: tombstones or cursor reset.
B5  Detail-view bodies cannot be scrolled: scroll actions exist but no
    keybinding produces them. Fix: bind PgUp/PgDn/j/k + n/m indicator.
B6  `w` HAR export silently overwrites an existing file without confirmation.

## First-run journey (4 breaks)

F1  Bare `arbiter` errors with required --target; no pointer to `start`.
F2  `arbiter help <subcommand>` fails for EVERY subcommand ("unrecognized
    subcommand") because the default-command config disables clap help routing.
    Reproduced directly.
F3  HTTPS targets via `start` silently generate a CA and never print trust
    instructions (`ca generate` does); first interception fails opaquely.
F4  README quickstart installs the TS npm package; rust/README has no
    quickstart for the binary at all.

## CLI grammar & POSIX

G1  -t collision: --target everywhere except `diff` where -t = --traffic.
G2  Input-path drift: positional BUNDLE vs -i/--input vs -t/--traffic vs
    --input across replay/diff/generate-spec/generate-traffic.
G3  mock help EXAMPLES reference a nonexistent flag (--match strongest) -
    copy-paste from your own help fails verbatim.
G4  Global --json advertised but most commands ignore it; reports fixed-format.
G5  Per-subcommand -V disabled (replay -V errors); generate-spec --version
    collides semantically with version discovery elsewhere.
G6  Port drift on EADDRINUSE is silent (walks to next free port).
G7  Exit-code inconsistency: config init overwrite-refusal prints error, exits 0.

## TUI friction

T1  Ctrl+C swallowed as "close overlay" instead of quitting.
T2  Saved filters lost on exit despite README advertising persistence.
T3  Embedded mode hides where to send traffic until after first paint.
T4  Attached instance death freezes the UI on stale data (low-vis indicator).
T5  Filter grammar has no user-facing reference outside filter.rs source.

## Docs & non-interactive gaps

D1  No bundle inspection command (inspect/show/list) anywhere.
D2  Gateway policy JSON schema undocumented.
D3  Config layering only read by `start`; [capture]/[mock]/[replay] sections
    silently ignored by their subcommands.
D4  JSON reports unversioned; library API (~25 pub mods) has no stability
    declaration.
D5  No CHANGELOG; bundle v1->v2 has no migration story or tooling.

## What works well

Cause+help error lines where present (fingerprint missing-bundle is exemplary);
filter grammar design; byte-exact mock replay; spill-bounded recording;
completions; the contains_id verbose panic caught by an earlier internal wave.

## Prioritized fixes

1  Signal-safe partial export (B1,B3)          M
2  Refuse non-empty capture output w/o --force (B2)  S
3  Tombstone deletes / cursor reset (B4)       S
4  Detail scroll keybindings + indicator (B5,B6)  S
5  Restore clap help routing; bare-arbiter hint  S
6  CA hint from start; kill silent flags        M
7  Flag grammar unification (-t, input paths, ghost examples)  M
8  Real global --json; report schemas; per-subcmd -V  M
9  `arbiter inspect <bundle>`                   M
10 Config layering honored everywhere (or documented otherwise)  M

Critic additions: unversioned reports/API surface, --version story gaps,
v1/v2 migration tooling, packaging/CHANGELOG/platform notes - folded into
D4/D5 and fix list item 8.
