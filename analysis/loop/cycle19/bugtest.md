# Cycle 19 Bug Test — Passes 1, 8–10, 14–15

Date: 2026-08-21  
Scope: baseline, compilation, module/core self-tests, event flood and
backpressure, drill closure, SOAR gates, storage growth, crash isolation, and
thread lifecycle.

## Outcome

- **FIXED — High:** SOAR action sinks did not re-verify the EventBus HMAC after
  publication. `Event` is frozen, but its legacy `details` mapping remains
  mutable; an in-process mutation could therefore alter a signed PID or path
  before containment. `SOARModule` and `ActiveResponseSOAR` now fail closed on
  an invalid event immediately before host response. Active Response also
  rechecks the configured response scope inside the mutation sink rather than
  relying only on its polling loop.
- **REPORTED — Medium performance:** `AsyncFlightRecorder.submit()` is normally
  queue-only, but a saturated queue writes overflow evidence synchronously to
  the DLQ. This preserves evidence but backpressures EventBus publishers during
  a sustained flood.
- **REPORTED — Medium storage:** `dlq_events.json` has no rotation, retention,
  or authenticated replay/re-ingestion policy. Sustained scanner or drill
  pressure can grow it without bound. Performance/remediation owns the bounded
  authenticated spool design because deleting security evidence is not an
  appropriate bug-test-only change.
- No syntax errors, broken imports, duplicate module codes, discovery errors,
  unexpected self-test failures, remediation-closure regression, database
  corruption, crash-supervisor failure, or lifecycle leak was reproduced.

## Baseline and commands

All commands ran from the repository root with `PYTHONPATH=src` and the project
virtual environment.

### Compilation

Walked every `*.py` under `src/angerona` and called
`py_compile.compile(..., doraise=True)`.

- **283 compiled / 0 errors**
- The changed SOAR files and new regression test recompiled after the fix.
- No stale/truncated mount artifact was observed.

### Discovery, registration, and self-tests

`python tools/selfcheck.py`:

- Discovery: **66 modules / 0 errors**
- Module runner: **51 passed / 16 expected environment or lifecycle skips / 0
  unexpected failures**
- Harness phases: **26 passed / 0 failed**

The 16 expected skips were stopped live sensors, opt-in/idle SOAR, local Ollama
timeout, and non-host Linux/macOS modules. These are explicitly classified by
the harness and are not treated as passing functional claims.

Every module-level `core/*.self_test()` was also imported and executed in a
separate bounded child process:

- **18 passed / 0 failed / 0 timed out**

Static/import audit:

- **68** `angerona.modules.*` files imported
- **66** local `BaseModule` subclasses constructed by discovery
- **48** declared module codes, **0 duplicates**
- **0** broken imports and **0** manager discovery errors
- Twelve legacy module files do not expose the optional `register()` convenience
  factory. This is not a runtime defect: current `ModuleManager` deliberately
  discovers `BaseModule` subclasses without registration, all 66 are present,
  and no newly added/changed module introduced a missing factory.

### Focused regression suites

The broad resilience/remediation command covered application startup/shutdown,
fleet lifecycle, GUI and worker backpressure, performance, storage, evidence
retention, drill resolution, purple remediation, remote evidence, SOAR scope,
and tamper-evident ledgers:

- **174 passed / 1 intentional skip / 0 failed** in 17.78 seconds

After the SOAR fix, the changed action path and adjacent security contracts were
rerun:

- `tests/test_cycle19_bugtest.py`
- `tests/test_remote_bridge_security.py`
- `tests/test_cycle4_round1_regressions.py`
- `tests/test_sigma_import_safety.py`
- `tests/test_purple_remediation_e2e.py`
- `tests/test_drill_remediation_lifecycle.py`

Result: **30 passed / 0 failed**. Ruff and `py_compile` also passed on every
changed file.

## Adversarial findings

### C19-BT-01 — Mutable signed response evidence

Severity: **High**  
Status: **FIXED**

**Symptom:** A bus event's HMAC covered `details`, but response code consumed the
mutable mapping without re-verification at the final action boundary.

**Root cause:** The frozen dataclass prevents field reassignment but does not
deep-freeze nested dictionaries. The ring and subscribers share the same mapping
reference.

**Fix:**

- `SOARModule._run_playbook()` now verifies an armed bus signature before
  containment.
- `ActiveResponseSOAR._kill_and_rollback()` now verifies before process/file
  mutation and rechecks response scope in the sink.
- Unarmed development/self-test buses retain their historical behavior; the
  production GUI and headless runtimes arm the bus.

**Gate:** Three new regressions prove that a changed PID/path causes zero
containment/deletion and that a direct private-sink call cannot bypass configured
scope. The adjacent 30-test security set passed.

### C19-BT-02 — Synchronous overflow spill

Severity: **Medium**  
Status: **REPORTED**

Eight concurrent publishers sent **40,000** signed events through a 500-event
ring, a 512-event durable recorder queue, and a 512-event normalized-evidence
queue:

- Publish completion: **33.855 seconds** (about **1,182 events/second**)
- Recorder: **10,856 persisted**, **29,144 overflow-DLQ**, **0 storage-DLQ**,
  **0 failures**
- Normalized read model: **22,209 persisted**, **17,791 intentionally dropped
  on full**, **0 failures**
- All workers drained within their deadlines; no publisher or worker thread hung.
- EventBus ring remained **500** and its revision reached **40,000**.

Evidence was preserved, but each full-queue overflow performed file I/O on the
publisher. A secondary bounded spill writer or equivalent design is required;
that change is outside the safe bug-fix gate.

### C19-BT-03 — Unbounded DLQ growth

Severity: **Medium**  
Status: **REPORTED**

The same flood produced:

- `dlq_events.json`: **29,144/29,144 valid JSON records**, **7,233,622 bytes**
- High-severity conservation: **62 DLQ + 18 SQLite = 80/80** generated HIGH
  events
- Flight-recorder SQLite: **3,104 rows** with a 3,000-row test cap (bounded
  prune/batch slack)
- Normalized-evidence SQLite: exactly **3,000 rows** with a 3,000-row cap

The databases are bounded; the overflow file is not. The recommended remediation
is bounded authenticated segments, explicit retention by size/age, replay with
idempotency, and visible loss/degradation metrics—not silent truncation.

## Drill remediation closure challenge

The initial miss → reviewed detector contract → separate rerun proof sequence
passed:

- An applied action remains `APPLIED` and receives **0% verified-closure credit**.
- The source run cannot self-certify.
- A fresh exact `Purple Remediation Guard` catch on a different run issues an
  authenticated verification receipt.
- The AAR then renders **1/1 verified closure (100%)**.
- Wrong detector, technique, contract digest, stale evidence, tampered state,
  and unsigned AAR paths all fail closed.
- A later miss reopens the verified finding.

No local-AI output is trusted or executed for this closure path; it is
deterministic and proof-bound.

## Crash logs and lifecycle

The repository diagnostic logs are historical (newest workspace crash/hang
records predate this cycle). Their last actionable UI stalls were in synchronous
posture-history reads, alert-row widget construction, and flight-recorder reads.
The current tree already routes HUD reads through zero-wait cached snapshots,
uses bounded/paginated alert tables, and uses a zero-wait UI reader. Their current
regression suites passed. The protected live runtime diagnostics could not be
read by this non-elevated test process because its administrator-only ACL worked
as configured.

A fresh synthetic lifecycle challenge completed:

- **100 start/stop cycles / 100 entries / 0 surviving Cycle 19 threads**
- A crashing module made exactly **3 attempts**, entered `error`/quarantine,
  emitted the expected HIGH/HIGH/CRITICAL sequence, wrote **1 crash snapshot**,
  and exited without hanging.
- Application shutdown tests proved SQLite handles are not closed underneath
  live writers and are closed after successful drains.

## Remaining external gates

- Long elevated live-sensor/Ollama soak with Eco transitions and physical
  sleep/resume.
- Native Linux/macOS frozen-artifact acceptance on their target runners.
- Clean-VM install/upgrade/uninstall and watchdog process-restart testing.
- Bounded authenticated DLQ spool/replay remediation and its disk-full/fault
  injection tests.

