# Cycle 7 / Round 3 — Adversarial Verification

Audit date: 2026-08-20  
Base commit: `478e65e28cd8` plus the current shared, uncommitted Cycle 7 fixes  
Method: read-only product review plus safe in-memory/process-lifecycle challenge

## Outcome

The re-challenge verified the original destructive Remote Bridge-to-SOAR path,
then found a second-order Evolution Engine policy-mutation bypass. That bypass
and the remaining elevated source-bootstrap hash gap were both remediated and
retested in this round. All six original findings and the new Round-3 finding
are resolved in the current tree. The inherited-data-root and AnalysisWorker
native-thread ordering fixes also survived repeated stress.

## New finding

### C7-R3-01 — Observe-only remote evidence can still mutate local detection policy

- **Severity:** MEDIUM
- **Status:** FIXED IN ROUND 3
- **Component:** `src/angerona/modules/remote_bridge.py:411-449`;
  `src/angerona/core/eventbus.py:75-91`;
  `src/angerona/modules/evolution_engine.py:157-171,334-384`;
  `src/angerona/modules/yara_scanner.py:99-132`

Remote Bridge now owns the local module identity, strips top-level local PID/path
action keys, and overwrites the peer's authority label with
`remote-observe-only`. Both SOAR engines correctly reject that event. The
default-enabled Evolution Engine subscriber does not check that provenance. It
activates whenever event details contain `verified="SUCCESS"` and a syntactically
valid ATT&CK technique ID, both of which remain peer-controlled remote telemetry.

A safe proof bound an Evolution Engine whose `activate()` method only appended to
a list, then republished an authenticated-peer-equivalent payload. The resulting
event was observe-only, its PID and path were stripped, and its local module was
`Remote Bridge`; nevertheless `activate("T1059")` fired. In production this path
can start Ollama/verification work and compile, persist, replace, and activate an
auto-generated YARA rule. A compromised paired sensor can therefore consume
bounded local resources and replace a useful evolved rule with a low-value rule,
even though its telemetry is documented as observation-only.

Existing mutual authentication, disabled-by-default bridge configuration,
technique-ID validation, a two-worker/eight-per-hour evolution cap, and the YARA
compile gate materially limit exploitability. They do not restore the missing
authority boundary.

**Recommendation:** make origin/authority an immutable Event field assigned by
the transport, rather than a mutable detail convention. Centralize a default
deny for every state-mutating subscriber. Evolution must require local-origin
Posture Hardening evidence plus a typed, technique/run-bound verification receipt;
remote telemetry may inform triage but must not activate or replace local rules.
Add an integration test that enumerates every observe-only consumer and proves
none invokes process, firewall, file, rule, policy, plugin, or remediation writes.

**Closure:** Evolution Engine now rejects `is_remote_observe_only(ev)` before it
reads `verified` or `technique`. An authenticated-peer-equivalent regression
produces zero activations and the full Remote Bridge security file passes 4/4.
Immutable Event-level authority and exhaustive mutation-consumer enumeration
remain worthwhile defense in depth, but the demonstrated mutation path is closed.

## Re-challenge matrix

| Target | Result | Evidence |
|---|---|---|
| C7-R1-01 Remote-to-local confused deputy | **RESOLVED** | Eight malicious CRITICAL remote events produced zero SOAR actions. Module identity is receiver-owned, action keys move to `source_*`, and Evolution now rejects observe-only evidence before local rule mutation. |
| C7-R1-02 Staged proposal reported as executed | **RESOLVED** | `apply_fix()` records `staged=True`, `executed=False`, `verified=False`; UI copy says “staged — not executed” and “not verified as fixed”. Result-shape challenge rendered no executed/fixed claim. |
| C7-R1-03 AI/no-fix bulk ignore | **RESOLVED** | AI-unavailable and bulk-ignore callbacks left an empty ignore store. Only a typed, expiring, approved `not_applicable` record suppresses scoring; legacy records fail safe. The evidence remains operator-attested rather than independently proven, but AI/no-fix state is no longer suppression authority. |
| C7-R1-04 Hung in-process sandbox blackout | **RESOLVED** | Opening the editor no longer stops sensors or replaces EventBus publishing. Five 30-second hanging probes were terminated at a 0.15-second deadline (maximum observed 0.389 s) with zero surviving child processes. The child still inherits the operator token, so this is process/deadline isolation rather than an AppContainer security sandbox. |
| C7-R1-05 Unhashed release/build inputs | **RESOLVED** | Tagged-release CI uses a committed wheel hash lock and a SHA-256-verified exact Inno 6.7.1 installer. Both elevated source bootstraps are explicitly CPython 3.12 x64, consume the same lock with `--require-hashes --no-deps`, and have no unhashed fallback. |
| C7-R1-06 Installer downgrade | **RESOLVED for the first public release boundary** | Current Setup reads a persistent HKLM64 high-water mark, fails closed on invalid versions, and rejects lower versions. The [public repository release page](https://github.com/Ag3nt47/AngeronaSuite/releases) currently has no releases, so no pre-gate genuine public Setup exists that can ignore the new check. Do not publish or retain a guardless Setup; the first published release must pass real ISCC/upgrade/downgrade CI. |
| Expanded R4-01 inherited `ANGERONA_DATA` ACL target | **RESOLVED** | `start-angerona.bat`, `start-angerona-guarded.bat`, and `Install-Angerona.bat` overwrite the inherited value before elevation. A command-shell challenge seeded `C:\Windows` and obtained the canonical sibling `D:\local-security-ai\AngeronaData`. The editable-elevated-source boundary remains the already-known C6-R2-03 limitation. |
| AnalysisWorker result/native-finished ordering | **RESOLVED** | `result_ready(dict)` is distinct from native `QThread.finished()`, and cleanup/reaping is connected only to native completion. Fifteen additional fresh-process repetitions of result ordering plus deferred Alert Detail close passed; no post-21:25 Qt crash event/dump appeared. |

## Focused verification results

- Relevant pytest set: **18 passed / 0 failed** in 4.32 seconds.
- Remote destructive-action challenge: **8 events / 0 actions**.
- Remote Evolution bypass proof: **1 observe-only event / 1 unauthorized activation**.
- Hung subprocess challenge: **5/5 terminated**, maximum 0.389 seconds,
  **0 surviving descendants**.
- AnalysisWorker/lifecycle fresh-process stress: **15/15 passed** in this pass,
  in addition to the bug agent's prior 30/30 result.
- Windows crash evidence: the 21:25:17 `Qt6Core.dll` `0xc0000409` event occurred
  during the pre-fix aggregate. No later matching Application Error or dump was
  present after the fix and these additional lifecycle runs.
- The exact SHA-256-verified Inno Setup 6.7.1 compiler installed noninteractively
  and compiled the complete script with placeholder release payloads. Clean
  install, upgrade, and downgrade rejection remain release-CI/VM acceptance gates.

Post-finding remediation added **4/4** passing remote-authority regressions and
**32/32** passing release/source-trust gates. The exact hash-verified Inno 6.7.1
compiler also compiled the full Setup script locally using placeholder release
payloads; clean install/upgrade/downgrade behavior remains a release-CI/VM gate.

## Prior-finding reconciliation

Across C7-R1-01 through C7-R1-06: **6 resolved / 0 open** after in-loop
remediation. C7-R3-01 is also fixed. The expanded R4-01 data-root consequence
and the separate AnalysisWorker lifecycle defect are verified resolved.

## New-finding severity summary

| Severity | Count |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |
