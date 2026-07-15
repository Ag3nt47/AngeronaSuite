# Angerona Improvement Loop — Cycle 2

## Round 1 — Red Team

- Read-only audit completed against the current combined 193-file tree; source,
  runtime data, host state, configs, and `rules/_active_combined.yar` were not
  modified.
- Prior findings were reviewed first and were not duplicated. Known deferred
  trust-root, ledger-key, Remote Bridge, and PowerShell work remains deferred.
- New findings: **5 total** — **4 MEDIUM active**, **1 LOW dormant**.
  - C2-R1-01: basename-only process trust can suppress MEMI, posture, and SOAR.
  - C2-R1-02: AAR PID/path fuzzy correlation can create false passes.
  - C2-R1-03: newest-only row retention can evict critical audit evidence.
  - C2-R1-04: emergency shutdown kills unrelated Python/Ollama workloads.
  - C2-R1-05: ARIA's disabled flag is not enforced by its action gate.
- Convergence: **NO**; remediation and verification are required before the
  round can be considered clean.

## Round 1 — Remediation

- Applied defensive fixes for all five new findings.
- Path-rich process events now require exact-path trust; basename rows are a
  pathless-telemetry fallback and no longer skip memory scanning.
- AAR correlation now uses exact full paths or PID plus an opaque drill token,
  bounded step windows, single-use evidence, and trigger-timestamp remediation
  binding.
- Event pruning remains hard-bounded but retires lower-severity telemetry before
  HIGH/CRITICAL evidence.
- Emergency shutdown filters Python ownership to the Angerona root, keeps
  graceful llama3 unload, and no longer image-kills every Ollama runner.
- ARIA disabled state now blocks reads, writes, confirmations, and proactive
  callbacks and clears pending confirmation tokens.
- Gates: changed-file compile PASS; focused tests 7/7 PASS;
  `Assistant.self_test()` PASS; diff check PASS.
- Deferred enhancements (not required for these minimal fixes): certificate/hash
  trust binding, signed cold evidence archive/retirement records, and persisted
  PID/start-time shutdown tokens.

## Round 1 — Innovation Research

- Completed the cycle's one web-research pass using authoritative primary
  technical sources from Microsoft, Cedar, NIST, Google Research,
  OpenTelemetry, and W3C.
- Compared proposals against current ARIA, EventBus/storage, module lifecycle,
  SOAR, Remote Bridge, behavioral tuning, ELAT, TECT, and prior visionary work;
  previously proposed replay, ledger-chain, mutation, and novelty-sketch ideas
  were not repackaged as new.
- Ranked three defensive, privacy-preserving candidates:
  1. **Response Safety Kernel** — recommended shadow-mode MVP for one uniform,
     immutable, default-deny action policy boundary.
  2. **Angerona Sensor Cells** — least-privileged process isolation, starting
     with one read-only untrusted-input parser.
  3. **Collective Baseline Exchange** — secure aggregation plus differential
     privacy; research-only until cohort, poisoning, privacy-budget, and consent
     requirements are fully specified.
- No code, rule, runtime configuration, or host state was changed.

## Round 1 — Bug Test / QA

- Final compile gate passed **194/194** Python files; conflict and diff-integrity
  scans passed.
- Module validation passed: **62/62 imports**, **61/61 discovered**, no import,
  discovery, constructor, duplicate-name, or duplicate-CODE failures.
- Focused remediation and policy/drill regressions passed **7/7**; scoped
  shutdown and ARIA disabled-state enforcement also passed static/self-test
  review.
- ARIA passed **12/12** standalone self-tests after fixing its runner's Windows
  CP1252 Unicode-output crash.
- Full application self-check passed twice; final result **26/26**, with the raw
  module drill at **47 pass, 15 expected stopped/idle/Ollama skips, 0 genuine
  failures**. The benign live drill completed 30 steps over two phases and
  cleaned its marker.
- Fixed a second QA-only issue: the headless self-check now stops the production
  UI watchdog after constructing `MainWindow`, so long test phases no longer
  create false freeze diagnostics. The gated rerun left the watchdog log
  unchanged.
- Diagnostic review found zero current self-test failures and no new application
  crash. **New production bugs: 0.**

## Round 1 — Performance

- Cached unchanged 500-row SOAR queue parses by path/mtime/size/limit; 400
  representative reads fell from **434.287 ms to 32.436 ms** (**92.5% less**),
  with fresh-list and append-invalidation checks passing.
- Suppressed identical dashboard card text/style mutations; 400 steady updates
  fell from **400+400 Qt calls to 1+1**, while changed values still rendered.
- Direct `tools/selfcheck.py` startup now invokes the canonical D-drive runtime
  environment before any temp/Qt work, preventing QA drill/report temp churn in
  the C-profile. Its final combined compile/path gate was interrupted and is
  explicitly left for the coordinator's next full validation.
- `pages.py` compile and offscreen equivalence gates passed. No detector cadence,
  response behavior, event durability, or rule was changed. Remaining live-
  sensor/EventBus optimizations stay proposed pending fidelity/load proof.

## Round 2 — Red Team

- Read-only audit completed after Round 1; fixed/deferred findings were not
  duplicated without new evidence.
- New findings: **4 total** — **2 MEDIUM active**, **2 LOW dormant/opt-in**.
  - C2-R2-01: Stop & clean does not cancel either drill worker.
  - C2-R2-02: emergency shutdown still over-matches sibling-prefix and unrelated
    Python command lines that merely contain the Angerona root.
  - C2-R2-03: ARIA confirmation is not bound to the originally previewed tool
    callback/version or immutable arguments.
  - C2-R2-04: the default ARIA research READ opens external browser sources and
    discloses the indicator without confirmation.
- Exact-path trust, deterministic AAR matching, run-scoped drill resolution,
  bounded severity-aware retention, the disabled ARIA gate, D-drive setup, and
  Round 1 UI caches showed no new regression in this static pass.
- Convergence: **NO**; remediation and independent validation are required.
