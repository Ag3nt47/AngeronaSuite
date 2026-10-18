# Hardware adaptation and verified self check

Date: 2026-10-18. Maintenance version: 1.13.0. Baseline:
`a5cb7a3b8a2e87d5383ed4319fc5aa450b3c4da0`.

This update reduces unnecessary background and presentation work, extends
routine pacing to memory pressure, and makes the self-check's own failure
detection independently testable. Operator instructions are in the
[hardware and self-check guide](../../docs/hardware-and-selfcheck.md).

## Runtime and older hardware

- The existing cooperative controller accepts RAM percentage and available-byte
  observations from Resource Governor's existing sampler, including when the
  engine runs without a dashboard. At least 85% used or at most 512 MiB
  available requests moderate pacing; at least 92% or at most 256 MiB requests
  severe pacing. Invalid observations retain the last valid signal until its
  bounded expiry. Missing RAM readings no longer relax the governor's own lease.
  Shared CPU feedback uses the same sampler, without a new thread.
- Existing hysteresis, routine opt-in, elapsed-work checkpoints and maximum
  interval addition remain in force. Streaming event delivery, response actions
  and watchdogs keep their cadence. Routine discovery can take longer under
  pressure; an individual native call cannot be preempted.
- PerfGovernor retains its psutil Process object between samples. Recreating
  that object discarded the CPU delta baseline and repeatedly reported zero.
- EntropyWorker blocks until its first queued input instead of periodically
  waking while idle. Nonempty batches retain a bounded flush interval, item
  ordering and capacity. Callback registration no longer deadlocks when called
  from an existing callback. The Python fallback reuses duplicate results only
  within the current batch; NumPy uses a fixed byte histogram instead of sorting.
- Resource Governor's own self-test now exercises bounded lease application,
  exclusion of security-critical modules, restoration and low-RAM pacing on
  inert siblings. The expanded metadata check exposed USB's legacy `darwin`
  declaration; it now uses the canonical `macos` identifier.

## Windows and presentation work

`PresentationTimer` suspends its native Qt timer when its view or containing
window is hidden or minimized. Visibility restores a requested timer; explicit
stop and completed single shots remain stopped. A rejected window close keeps
the visible view refreshing. Owner destruction cancels native callbacks.

Twenty timer sites use this primitive: four dashboard detail dialogs and their shared header, three
Flow timers, three WorldView timers, Attack Heatmap, Operations Center metrics,
Resolve Center, Top Talkers, and five recurring indicator classes. This reaches
ten investigation window/dialog surfaces and the shared indicators. Visible
intervals follow the existing pressure controller, with a maximum 30-second
addition. Job completion, response and collection timers retain their ownership.
The static swords indicator no longer schedules an idle timer, and WorldView's
initial callback now has an owned, cancellable timer.

Shared AsyncSnapshot readers back empty-result polls off from 40 through 80
and 160 to 250 milliseconds, resetting to 40 on a fresh request and stopping
on completion. This changes sustained scheduled polling from 25 to 4 per
second. Results can wait for the next scheduled poll; Qt dispatch can run late.

## Stronger checks and verification

Each selected module receives shared checks for identity, callable diagnostics,
BaseModule metadata and lifecycle entry points, and health-state consistency.
Active tests must return a real boolean and a bounded, nonempty explanation.
A successful classifier fixture cannot conceal a failed live module's health.
Skipped modules still receive safe metadata checks, while live probes stay skipped.

Every module result includes duration and subcheck evidence. Worker admission
uses logical CPU count, available RAM and the existing pressure multiplier.
Actual timed-out callbacks retain both the run's hardware allowance and the
process-wide six-call permit until they exit. Python cannot safely kill an
arbitrary blocked thread. Later calls that cannot be admitted fail explicitly.

Eight controlled canaries challenge success, failure, exceptions, malformed
results, timeout detection, disabled-module skips, platform skips and corrupted
accounting. A ninth check reconciles the requested inventory, individual records,
subchecks and counters. Successful verifier checks are labeled separately and
do not inflate capability success counts. Unknown selections fail visibly.

Schema-2 diagnostic reports use a unique run ID, atomic replacement and exact
JSON readback. The offscreen harness independently rereads that report and
matches the ID, results, verifier state and counts. It also runs 32 inert
modules through a controlled two-worker allowance and records all phase timings.
Final notifications follow verification and readback. Reporting or persistence
faults remain actionable failures. Only an exactly absent optional kernel driver
becomes a skip; protocol errors, crashes and timeouts remain failures.

## Measured and simulated evidence

[Entropy measurements](entropy-benchmark.json) execute the Git baseline and
current Python fallback implementations with inert data. NumPy and CUDA are
not benchmarked. Nine alternating-order wall-time samples
for 4,096 strings with 64 unique inputs measured **61.340 → 0.944 ms** median;
the all-unique workload measured **66.934 → 63.092 ms**. Every output was exactly
equal to the baseline. The same benchmark's three 300-ms idle fixtures observed
**10/10/10 queue waits before versus 1/1/1 after**; the new single wait stays
blocked until input arrives. Every first arrival was delivered. These local
wall times varied across runs under concurrent test load and are not CPU quotas,
whole-application speedups or universal hardware claims.

The GUI tests check real callbacks, hidden/minimized native timer state,
explicit stop, single-shot completion, reparenting, rejected close and slow-read
polling. A separate 650-ms Qt sample counted 13 callbacks at 40 ms and 2 at
320 ms; after hiding, both produced zero callbacks over another 650 ms. This
measures callbacks, not CPU or memory savings.

[Resource profiles](resource-profiles.json) use injected resource samples and
a virtual clock. All four profiles complete the same 64 items at both fast and
slow item costs, then verify healthy-sample recovery. Moderate RAM pressure
reaches 4 times the base interval; severe CPU or RAM pressure reaches 8 times.
At 20 ms per item, pressured work yields after each item, with each requested
pause bounded to 50 ms. These are scheduling-policy fixtures, not emulated
physical machines or real detection measurements.

The [source inventory](source-inventory.json) covers **87 module files, 84
module classes and 53 GUI files**, with normalized source hashes and static
call sites. It includes helpers and inactive paths. It does not assert that
every source file needed a change or that every runtime path was exercised.

## Validation

- Fresh full suite: **4,991 passed, 25 skipped, 0 failures** in **1,476.27
  seconds**, with an execution trace and normal process exit. All 986 Python
  files under `src`, `tests` and `tools` stayed unchanged during that run.
- Final offscreen self-check: **28 passed, 0 failed**. All **84 modules** have
  evidence: **66 passed, 18 explicitly skipped**, plus the passing pipeline
  check and nine separate verification checks. The constrained 32-module
  performance phase completed in **92.38 ms**, with peak **2/2** active calls
  and no unfinished calls. See [sanitized evidence](selfcheck-summary.json).
- Final self-test, deadline, policy, results UI and v12 selection: **76 passed
  in 12.97 seconds**. The author's broader self-check selection passed 81 cases.
- Runtime and adjacent platform selections: **170 passed, 1 skipped**. The
  initial optional NumPy numerical check was skipped because NumPy is not
  installed in the application environment. A separate isolated NumPy 2.5.4
  target subsequently passed the entire runtime-capacity file: **29 passed,
  0 skipped** in **1.81 seconds**.
- GUI breadth selection: **60 passed**; snapshot/lifecycle selection:
  **63 passed**; final timer selection: **13 passed**. These overlap and must
  not be added together as a unique test total.
- Final static gates: **986 files compile, 0 failures**; Ruff and documentation
  drift checks pass. Detailed outcomes are in [validation evidence](validation.json)
  and the [reviewed Python source ledger](validation-sources.json).

Independent review found and fixed premature success notifications and timeout
workers escaping the selected hardware allowance. Negative regression tests
now exercise both. The initial all-module harness correctly failed USB metadata
before its canonical declaration was repaired; the final harness passed.
An initial concurrent compile encountered a Windows bytecode-cache sharing
collision. The final compile uses its own cache directory.

The first whole-suite run completed **4,987 passed, 24 skipped, 1 failed** in
792.83 seconds. The unchanged same-timestamp deception fixture hit Windows
`WinError 5` at `os.replace`, before its security assertions. It passed alone.
The fixture now retries only Windows errors 5, 32 and 33 for at most one
second; persistent or unrelated errors still raise. Its timestamp and detection
assertions remain intact. The exact cause of the temporary denial was not
established. Final-suite evidence uses a fresh workspace temporary directory
and an execution trace, with source fingerprints checked before and after.

The isolated NumPy run exposed an overly strict assertion in the new test:
the existing entropy formula's epsilon produces about `-1.44e-12` for a
constant input. After the frozen full suite completed, that one test assertion
was corrected to use the same `1e-9` tolerance as its numerical comparison.
The 29-test follow-up exercised the corrected file without skips, including
actual NUL bytes, Unicode, an unpaired surrogate and long inputs. NumPy results
matched the Git baseline exactly and the Python fallback within tolerance.
Production code did not change after the full run. The validation record
includes both source fingerprints and identifies this single test-only change.

This maintenance does not establish physical low-RAM performance, an extended
all-sensor soak, freeze-free operation, native containment effectiveness or
complete attack coverage. Platform support, release version and capability
count remain unchanged. The Word manual retains its dated chapters; the linked
operator guide supplies this update's current instructions.

## Reproduction

```text
venv/Scripts/python.exe -u -X utf8 tools/selfcheck.py
venv/Scripts/python.exe tools/benchmark_entropy_efficiency.py --baseline a5cb7a3
venv/Scripts/python.exe tools/benchmark_hardware_adaptation.py
venv/Scripts/python.exe -m pytest -q --junitxml=.tmp/hardware-full.xml
venv/Scripts/python.exe -X pycache_prefix=.tmp/hardware-compile-cache tools/compile_check.py src tests tools
venv/Scripts/python.exe -m ruff check src tests tools
venv/Scripts/python.exe tools/validate_documentation_drift.py
```

Publication uses `tools/publish_github_update.py` only after review and offline
validation. That publisher verifies canonical origin, fast-forward ancestry,
branch/default-main equality, a clean checkout and byte-identical public README
images. A local commit or unverified feature-branch push is insufficient.
