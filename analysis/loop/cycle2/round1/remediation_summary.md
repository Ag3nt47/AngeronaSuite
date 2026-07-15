# Cycle 2 / Round 1 — Remediation Summary

Date: 2026-07-14. Scope: minimal defensive fixes for C2-R1-01 through
C2-R1-05 in the current shared tree. Claude's concurrent ARIA additions and
all pre-existing user changes were preserved. `rules/_active_combined.yar`,
host ACLs, secrets, and external state were not touched.

## Applied fixes

### C2-R1-01 — path-aware process trust

- A basename-only policy row now applies only to telemetry that genuinely has
  no executable path. If an event supplies a path, suppression requires an
  exact normalized path match.
- Memory Injection Scanner no longer skips opening/scanning a PID from its
  basename alone. It evaluates trust only after suspicious memory is found and
  the executable path has been enriched.
- The exact-path Proton entries retain their existing behavior. The pathless
  fallback remains available for legacy/pathless events.

### C2-R1-02 — deterministic AAR correlation

- Removed basename-in-message and bare-PID matching. Artifact evidence now
  requires an exact normalized full path. Process evidence requires both an
  expected PID and the opaque per-spawn red-team correlation token.
- Red Team history now records those opaque correlation tokens.
- Each step has a bounded time window; a detection/remediation event can be
  consumed by only one verdict.
- Remediation preferentially binds to the exact triggering event timestamp.
  SOAR Automation now includes `trigger_ts` and `trigger_module` on completed
  suspend/terminate actions.

### C2-R1-03 — severity-aware bounded retention

- The ledger still has the same hard `MAX_ROWS` bound and query interface.
- Pruning now removes oldest INFO/LOW/MEDIUM telemetry before HIGH/CRITICAL
  evidence. If protected evidence alone exceeds the cap, its oldest rows are
  retired so disk use remains bounded.
- Added a `(severity, id)` index for the bounded prune path.

### C2-R1-04 — scoped emergency shutdown

- `kill-all-angerona.bat` now terminates only Python processes whose executable
  path or command line belongs to the canonical Angerona installation root.
- Graceful llama3 unload remains.
- Removed the image-wide `ollama_llama_server.exe` fallback, so other Ollama
  users/models are not forcibly terminated.

### C2-R1-05 — ARIA off switch fails closed

- Disabled ARIA refuses READ invocation, WRITE staging, confirmation, and
  proactive trigger evaluation before callbacks can run.
- Disabling an enabled assistant clears all pending confirmation tokens.
- `Assistant.self_test()` now proves zero callbacks for disabled reads, writes,
  confirmation, and proactive paths.

## Focused gates

- `py_compile`: PASS for all 9 changed Python/test files.
- Focused unit tests: PASS, 7/7.
- `Assistant.self_test()`: PASS, including disabled-state zero-callback checks.
- `git diff --check`: PASS (line-ending notices only).
- Static shutdown review: no image-wide Python or Ollama runner kill remains;
  graceful llama3 unload is retained.

## Files changed in this remediation phase

- `src/angerona/core/process_allowlist.py`
- `src/angerona/modules/mem_inject_scanner.py`
- `src/angerona/shark/aar_report.py`
- `src/angerona/shark/red_team.py`
- `src/angerona/modules/soar.py`
- `src/angerona/core/storage.py`
- `src/angerona/core/assistant.py`
- `kill-all-angerona.bat`
- `tests/test_policy_and_drill_resolution.py`
- `tests/test_cycle2_round1_remediation.py`
- `analysis/loop/cycle2/round1/remediation_summary.md`
- `analysis/loop/cycle2/LOOP_LOG.md`

## Deferred hardening

- Authenticode/hash-bound process trust would strengthen exact-path policy but
  requires certificate lifecycle and executable-update UX design.
- A separate signed cold evidence archive and explicit retirement ledger record
  remain useful future additions; this round keeps the existing hard hot-ledger
  bound while protecting serious evidence from ordinary telemetry floods.
- Persisted PID/start-time ownership tokens could supplement the shutdown
  script's canonical-root validation, but are not required for the safety fix.

Round 1 remediation status: all five findings have safe defensive mitigations
applied and focused gates pass. Bug-test should independently verify the full
combined tree.
