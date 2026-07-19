# Cycle 2 / Round 3 - Red-Team Findings

Date: 2026-07-14. Scope: final read-only convergence audit of the current
combined tree after all Cycle 2 Round 1/2 remediation, QA, performance, and
visionary work. All earlier Cycle 2 reports and the prior-findings ledger were
reviewed first. Source, tests, rules, configuration, runtime data, secrets, and
host state were not modified; `rules/_active_combined.yar` was not touched.

## C2-R3-01 - A confirmation-token collision can replace the action the operator previewed

- **Severity:** LOW (ARIA remains opt-in/unwired; ordinary operator use has a
  very low collision rate)
- **Components:** `src/angerona/core/assistant.py:206-218,220-247`.
- **Evidence:** WRITE confirmations use only the first eight hexadecimal
  characters of a UUID (32 bits). The token is inserted directly into
  `_pending` without checking whether that key already exists. A collision
  therefore replaces the older `StagedAction`. `confirm(token)` correctly
  validates the action now stored under the key, but it has no way to know that
  the operator may be responding to the earlier preview carrying the identical
  visible token.
- **Deterministic proof:** A read-only probe replaced the UUID source with two
  identical UUID values, staged `first('reviewed-A')`, then staged
  `second('different-B')`. Both previews returned token `deadbeef`, `_pending`
  contained one entry, and confirming the token returned success while the only
  callback executed was `second('different-B')`. This does not defeat Round
  2's callback/version/argument digest; it demonstrates a key-allocation flaw
  before that binding is selected.
- **Exploitability / impact:** Accidental collision is negligible at normal
  human use, but the 32-bit birthday bound is about 77,000 live tokens for a
  50% collision chance, and the existing performance test showed tens of
  thousands can be staged within the five-minute TTL. A future in-process ARIA
  integration able to invoke tools repeatedly could deliberately create token
  pressure. An operator confirming an older displayed token could then execute
  the newer, individually valid action instead. ARIA is presently opt-in and
  unwired, so this is LOW rather than MEDIUM.
- **Exact remediation:** Generate at least 128 bits of visible token entropy
  (the full `uuid4().hex` is sufficient) and allocate with a collision-retry
  loop under the same lock used for pending-action mutation. Never overwrite a
  live token. Add a deterministic regression whose token source collides once,
  proving the second stage receives a different token and each preview confirms
  only its own immutable action. If ARIA becomes multi-threaded, protect
  register/invoke/confirm/cancel/prune with one re-entrant lock.

## Final convergence decision

**Not yet converged in the Round 3 red-team gate:** one new LOW, dormant/opt-in
ARIA confirmation finding remains. No new MEDIUM, HIGH, or CRITICAL finding was
established. The Response Safety Kernel MVP itself preserved its stated shadow
boundary: production-wide searches found `ShadowDecision`, `allowed`,
`aligned`, `shadow_decision`, and `evaluate_shadow` consumed only inside the
pure evaluator and Assistant's bounded audit record, never by confirmation,
SOAR, Resolve Center, drill cleanup, shutdown, or another host-action branch.

Once C2-R3-01 is remediated and its focused/full gates pass, the defensive
surfaces audited here are suitable for a final convergence recheck.

## Verified without a new regression

- **Shadow policy invariants:** deterministic bounded canonicalization; missing,
  malformed, non-finite, stale-process, protected-process, and extension-error
  inputs fail closed inside shadow data. The audit metadata contains a digest
  and fixed diagnostics only, is held in the existing bounded conversation
  deque, and has no authoritative consumer.
- **Drill cancellation:** both engines use cancellation events, interruptible
  waits, checks at phase/stage boundaries, bounded joins, final cleanup, and no
  cancelled Shark completion callback. The Round 2 deterministic jitter-race
  regression and 100-cycle performance probes established zero later stages or
  surviving workers. A currently executing OS primitive can still take up to
  its existing timeout to return, but it does not start a later stage.
- **Emergency shutdown:** the parser rejects sibling-prefix roots, arbitrary
  later repo arguments, non-Python entry points, and changed executables; it
  accepts the exact suite interpreter or the first canonical Python entry point
  beneath a directory-bounded root. The remaining architectural preference for
  persisted PID/start-time ownership is already deferred and was not re-filed.
- **Research:** `research` constructs a local allow-listed plan only.
  `open_research_sources` is a separately confirmed WRITE, browser opening
  defaults off, and the READ regression performs zero opener/fetch calls.
- **Trust, drills, and evidence:** path-rich events require exact-path trust;
  AAR correlation uses exact paths or PID plus opaque drill token, bounded
  windows, single-use evidence, and trigger timestamps; run-scoped resolution
  and severity-aware hard-bounded retention remain present.
- **D-drive storage and responsiveness:** production and direct self-check temp
  paths resolve under `<install-folder>\runtime-data`.
  Drill/verification markers default to its sandbox. Deception canaries remain
  intentionally tiny tripwires in protected user locations rather than runtime
  databases/reports. Current crash/watchdog logs contain no new application
  crash after 15:58 and no new production freeze signature after the historical
  16:07 Resolve Center trace; later watchdog entries are documented headless
  self-check artifacts. Diagnostic rotation remains bounded at about 4 MiB.

## Files and evidence reviewed

- `analysis/loop/RUNBOOK.md`, `analysis/loop/PRIOR_FINDINGS.md`, every Cycle 2
  Round 1/2 report, the innovation proposal, and `cycle2/LOOP_LOG.md`.
- `core/action_policy.py`, `core/assistant.py`, ARIA dispatch/routines/HUD and
  research connectors, plus Round 2 remediation/visionary tests.
- Both red-team engines and console lifecycle, AAR, drill resolution, SOAR,
  trusted-process policy and consumers, storage/data paths, Eco wake-up,
  shutdown/Ollama helpers, and relevant focused/performance tests.
- `diagnostics/crash.log`, both watchdog logs, self-test failures, remediation
  records, current runtime-data inventory, and source-wide authority/path
  searches.
