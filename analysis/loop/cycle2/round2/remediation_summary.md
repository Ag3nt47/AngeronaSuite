# Cycle 2 / Round 2 — Remediation Summary

Date: 2026-07-14. Scope: minimal defensive fixes for C2-R2-01 through
C2-R2-04 in the current shared tree. Concurrent user/Claude/agent edits were
preserved. No GUI was launched, no processes were killed, and
`rules/_active_combined.yar` was not modified.

## Applied fixes

### C2-R2-01 — reliable Stop & clean

- Both Red Team engines now use a dedicated cancellation event, interruptible
  jitter, and cancellation checks before/after each phase and stage.
- Red Team process-spawn spacing and Shark CPU/file-churn, stale-cleanup, burst,
  and held-connection waits now observe cancellation.
- Stop performs only a 250 ms bounded worker join, then scoped cleanup. A worker
  still exiting performs final cleanup itself. A new run is refused while the
  prior worker remains alive.
- Cancelled Shark runs do not invoke the completion/AAR callback; cancelled runs
  do not announce normal completion or schedule delayed cleanup.

### C2-R2-02 — strict emergency-shutdown ownership

- `kill-all-angerona.bat` now delegates ownership decisions to a pure PowerShell
  predicate instead of substring/prefix matching.
- Ownership requires the exact suite virtual-environment interpreter, or the
  first parsed Python script entry point to resolve beneath the canonical repo
  root with a directory boundary. A later argument merely mentioning a repo
  file is not ownership.
- Sibling-prefix installations, unrelated readers, mixed-case valid paths, and
  PID reuse with a different executable are covered by deterministic cases.
  Image-wide Python/Ollama termination remains absent.

### C2-R2-03 — confirmation binds the exact ARIA action

- Tool registrations have monotonically increasing versions; replacing or
  unregistering a tool revokes pending previews for that name.
- A pending write stores the original WRITE callback, version/kind, immutable
  recursive argument snapshot, exact preview, expiry, and integrity digest.
- Confirmation rejects callback/version/kind/integrity changes and executes the
  bound callback with reconstructed snapshot values. Tokens remain single-use,
  expire, and are cleared across disable/re-enable.

### C2-R2-04 — research egress requires confirmation

- `research` is now a local-only READ that classifies the indicator and returns
  vetted source URLs without calling an injected fetcher or browser opener.
- Browser opening is the separate `open_research_sources` WRITE action. Its
  preview includes source count, named destinations, and a redacted indicator;
  opening occurs only after confirmation. Browser opening now defaults off.

## Focused gates

- Warning-as-error `py_compile`: **5/5 changed Python/test files passed**.
- Focused deterministic regressions: **4/4 passed** (including both drill
  engines and a six-case PowerShell ownership matrix).
- Affected module self-tests: **2/2 passed** (`Assistant`, research fetchers).
- `git diff --check`: PASS; only existing Windows line-ending notices appeared.

## Files changed in this phase

- `src/angerona/shark/red_team.py`
- `src/angerona/shark/shark_attack.py`
- `src/angerona/core/assistant.py`
- `src/angerona/connectors/research_fetchers.py`
- `kill-all-angerona.bat`
- `tools/angerona_process_owner.ps1`
- `tests/test_cycle2_round2_remediation.py`

Round 2 remediation status: all four findings have defensive mitigations and
focused gates pass. The independent bug-test phase should run the combined-tree
compile/import/discovery/self-check gates.
