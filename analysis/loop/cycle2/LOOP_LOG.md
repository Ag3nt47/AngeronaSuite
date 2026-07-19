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

## Round 2 — Remediation

- Fixed both drill Stop & clean paths with interruptible cancellation, bounded
  join/final cleanup, worker-overlap refusal, and no Shark completion callback
  after cancellation.
- Replaced emergency-shutdown substring ownership with a canonical,
  entry-point-aware predicate; sibling prefixes, unrelated repo-file readers,
  mixed case, quoting, and PID reuse are covered.
- Bound ARIA confirmations to the exact versioned WRITE callback, immutable
  arguments, preview, expiry, and digest; registry changes revoke previews.
- Split local research preview from confirmed browser/indicator egress.
- Gates: **5/5 compile**, **4/4 focused regressions**, **2/2 module self-tests**;
  diff check passed with line-ending notices only. Rules and host state were not
  changed.

## Round 2 — Bug Test / QA

- Full compile passed **201/201** Python files; conflict and diff-integrity
  scans passed.
- Module integrity passed: **62/62 imports**, **61/61 construction/discovery**,
  0 errors, 0 duplicate names, and 0 duplicate non-empty codes.
- With pytest absent, direct repository runners passed **15/15** Round 1,
  Round 2, policy/drill, lifecycle, storage-path, and shutdown regressions.
- ARIA/research self-tests passed **12/12**.
- Full offscreen application self-check passed **26/26**; raw module result was
  **47 pass, 15 expected stopped/idle/Ollama skips, 0 genuine failures**. The
  benign live drill completed 30 steps over two phases and cleaned its marker.
- Canonical data and temp paths were asserted under
  `<install-folder>\runtime-data`; the current self-check
  produced no new crash or watchdog record, and the self-test failure ledger is
  empty.
- **New production bugs: 0; code changes in this phase: 0.** Round 2 QA is
  converged; the scheduled performance/visionary and Round 3 gates remain.

## Round 2 - Performance

- Found one proven long-session retention defect in ARIA's newly bound WRITE
  confirmations: expired, abandoned action snapshots were never retired. A
  20,000-action probe retained **20,001 records / 30.129 MiB** after expiry.
- Added TTL cleanup before another WRITE is staged, with an efficient oldest-
  edge hot path and full expiry scans only for registry mutation/operator
  inspection. Still-valid tokens and every confirmation safety binding remain
  unchanged.
- The identical post-fix probe retained **1 record / 0.403 MiB**, releasing
  **98.7%** of traced retained memory. Normal binding cost remained about
  **260 us/action** versus **255 us/action** before.
- Repeated actual cancellation left **0** Red Team/Shark worker threads after
  100 runs each (p95 **0.650/0.302 ms**). Five thousand research reads plus
  5,000 staged/cancelled previews left **0 pending** and **0.009 MiB** current
  traced memory. The emergency shutdown helper is not resident during normal
  operation; Round 1 caches are constant-size.
- Gates: full compile helper **194/194**, affected compile **5/5**, direct Round
  2 regressions **5/5**, ARIA **12/12**, diff integrity PASS. No visible GUI,
  detector cadence, response durability, rules, or host process state changed.
- Performance convergence: **YES** for the measured Round 2 scope.

## Round 2 - Visionary

- Scored the three Round 1 concepts against the post-remediation architecture.
  Response Safety Kernel remained the only candidate suitable for a bounded
  MVP; Sensor Cells remain proposed and Collective Baseline Exchange remains
  research-only.
- Added a dependency-free, pure `core/action_policy.py` shadow evaluator with
  bounded canonical input, deterministic digests/codes, stale-process and
  protected-process checks, argument-binding comparison, and fail-closed shadow
  results for missing context or policy errors.
- Wired only ARIA's already-staged WRITE preview to a digest-only comparison in
  its bounded memory. Confirmation, execution, SOAR containment, rules, host
  actions, network behavior, and visible GUI do not consult the shadow result.
- Focused tests passed **7/7**; action-policy self-test PASS; existing Round 2
  regressions **5/5**; ARIA **12/12**; compile helper **195/195**. A 10,000-call
  preview probe measured approximately **35.309 microseconds/evaluation**.
- Round 3 must prove no production branch consumes the shadow decision, fuzz
  canonicalization, re-check bounded/no-secret audit metadata, and keep SOAR
  unwired unless a separate latency/recursion audit justifies observation only.
## 2026-07-14 21:19 EDT - Round 3 red-team

- Completed the final read-only convergence audit of the combined post-Round-2
  tree, including the Response Safety Kernel shadow boundary, ARIA confirmation
  lifecycle/TTL, research egress, drill cancellation races, shutdown ownership,
  trusted-process/AAR/remediation/retention paths, D-drive storage, performance,
  and current crash/watchdog evidence.
- Verified the new Response Safety Kernel remains shadow-only: its decisions and
  alignment metadata are never consumed by confirmation, SOAR, or another host
  action path.
- Found one new LOW opt-in issue, C2-R3-01: 32-bit ARIA confirmation tokens are
  inserted without collision handling. A deterministic repeated-UUID probe
  proved the older visible token can select a newer staged action.
- No new MEDIUM/HIGH/CRITICAL issue was established. Round 3 red-team is not yet
  converged pending the small token-allocation remediation and independent gates.
- Reports: `round3/redteam_findings.md` and `round3/redteam_findings.json`.

## 2026-07-14 21:26 EDT - Round 3 remediation

- Closed C2-R3-01 with full 128-bit UUID4 hexadecimal confirmation tokens and
  collision-safe allocation that never replaces a live staged action.
- Added one re-entrant state lock around pending confirmation and tool-registry
  mutation; user callbacks and the Response Safety Kernel shadow evaluator
  remain outside the lock.
- Added a deterministic repeated-UUID regression proving both previews retain
  distinct tokens and each confirmation executes only its own immutable bound
  callback and arguments.
- Gates: changed compile **2/2**, forced collision **1/1**, Round 2 remediation
  **5/5**, visionary shadow-policy **7/7**, and ARIA **12/12** all PASS; scoped
  diff-integrity PASS.
- Rules, GUI, runtime configuration, and host state were not changed.
- Report: `round3/remediation_summary.md`.

## 2026-07-14 21:34 EDT - Round 3 final bug test / QA

- Complete combined-tree compile passed **205/205** Python files; the
  production-package helper passed **195/195**. Conflict-marker and diff-
  integrity gates passed.
- Module integrity passed: **62/62 imports**, **61/61 construction/discovery**,
  0 errors, 0 duplicate names, and 0 duplicate non-empty codes.
- All focused Cycle 2 and lifecycle regressions passed **24/24**; ARIA/research
  passed **12/12** and the Response Safety Kernel self-test passed.
- A bounded pending-action probe retained both forced-collision actions,
  produced **480/480 unique concurrent tokens**, executed each exactly once
  while refusing 480 duplicate confirmations, retired 200 expired snapshots,
  and left no stale pending state.
- Full offscreen application self-check passed **26/26**; raw module result was
  **47 pass, 15 expected stopped/idle/Ollama skips, 0 genuine failures**. The
  benign live drill completed 30 steps over two phases and cleaned its marker.
- Canonical data, `TEMP`, `TMP`, and Python temp paths all resolved under the
  D-drive runtime directory. Crash and watchdog logs were unchanged; the new
  self-test ledger contains 0 failures.
- **Final QA convergence: YES. New production bugs: 0; QA code changes: 0.**
- Report: `round3/bugtest_results.md`.

## 2026-07-15 - Round 3 final performance

- Confirmed the 21:39:50 watchdog entry as a valid 5.4-second production stall:
  the GUI was waiting in `DashboardCards.refresh -> FlightRecorder.max_ts ->
  storage._lock` while the machine was awake. Sleep/wake and shutdown happened
  afterward and do not explain that entry.
- Applied a narrow fix: dashboard cards
  and the live alert feed now use a post-commit in-memory ledger revision plus
  immediate-only interactive reads, so the Qt thread keeps its last complete
  view and retries instead of waiting behind SQLite writer/retention work.
- Controlled writer contention: the former blocking query waited **250.407 ms**
  for a 250 ms hold; **10,000** new busy-path probe triplets completed in
  **10.966 ms** (~1.10 us/triplet), with revision reads at **306.4 ns/call**.
- ARIA stage/cancel remained bounded at **663.63 us/action** with memory tracing,
  **0 pending**, and **0.037 MiB** retained; shadow evaluation measured
  **63.46 us/call**. Cancellation, caches, sequential wake-up, retention, and
  diagnostic bounds showed no new regression.
- Gates: changed compile **3/3**, focused storage **1/1**, Cycle 2 regressions
  **16/16**, package compile **195/195**, ARIA/research **12/12**, lifecycle and
  scoped diff integrity all PASS. Final performance convergence: **YES**.
- Report: `round3/performance_summary.md`.

## 2026-07-15 - Round 3 final visionary review

- Final disposition: keep the Response Safety Kernel MVP exactly as a bounded
  shadow experiment; no rollback is warranted and promotion is not authorized.
- Proved the boundary remains unchanged after the token-lock and non-blocking
  storage fixes. Source-wide search found no confirmation, SOAR, Resolve Center,
  drill, shutdown, trust, or storage branch consuming shadow decisions.
- Re-ran the shadow-policy **7/7**, token-collision **1/1**, non-blocking storage
  **1/1**, and changed-file compile **3/3** gates; all passed.
- Re-scored Sensor Cells as a future one-parser lab prototype and Collective
  Baseline Exchange as research-only. Added two proposed-only next-cycle ideas:
  a local Lifecycle Epoch Ledger and an advisory Shadow Differential Review.
- The operator-confirmed sleep/wake/watchdog lifecycle action is treated as
  legitimate evidence, not a new defect or a reason to change the shadow MVP.
- Recorded a six-stage future safety-kernel roadmap with an explicit operator
  approval gate before each scope expansion and before any enforcement.
- Implemented in this phase: report/log only. Proposed items were not shipped.
  Final visionary convergence: **YES**.
- Report: `round3/visionary_summary.md`.

## 2026-07-15 - Documentation / Cycle 2 complete

- Three adversarial/remediation/QA/performance loops completed and converged:
  **10/10 security findings fixed** with no unresolved Cycle 2 finding.
- Final gates: complete-tree compile **205/205**, production package **195/195**,
  module imports **62/62**, discovery **61/61**, focused regressions **24/24**,
  ARIA/research **12/12**, and full self-check **26/26** with **0 genuine
  module failures**.
- Updated both README and llms mirrors plus eight distinct current Word masters;
  published hash-matched current copies to the Desktop analysis folder while
  preserving historical snapshots.
- DOCX structural and accessibility QA passed **8/8**. Pixel/page render QA was
  unavailable because LibreOffice is absent and the installed Word automation
  type library is broken; no page counts were guessed.
- Documentation manifest: `DOCUMENTATION_UPDATE.md`. Cycle 2 state: COMPLETE.
