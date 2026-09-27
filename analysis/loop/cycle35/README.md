# Cycle 35 — Red Team response, report integrity, and responsiveness

Date: 2026-09-26
Release line: **v1.13.0 maintenance**
Scope: defensive simulation, exact response custody, local AI guardrails, and measured GUI/performance defects

## What changed

- The Red Team drill now stops as incomplete and score-ineligible when its exact
  target or enrolled Purple Guard/Process Monitor producers lose authority. A
  refused marker is removed by its original held Windows object even if its
  pathname was renamed or occupied by another file.
- Windows Purple Guard and Combat now coordinate an exact marker-handle handoff.
  Combat checks the signed detector receipt and pinned file identity, performs
  the quarantine, and returns a duplicate held descriptor for later AAR proof.
  Whole-target scans and marker moves are serialized without dropping the
  no-follow, content, link, or exact-identity checks. Rollback recaptures the
  original identity or invalidates the lease.
- Short-lived, signed, exact-birth process requests move ahead of slower file
  responses in Combat's bounded queue, with one waiting ordinary response
  served after at most four urgent ones; the worker still rechecks the full
  response contract. This addresses the GUI run in which 36 file moves filled
  the queue and the tagged 30-second child exited before Combat reached it.
- Authenticated containment scoring now requires a matching applied Combat
  journal commit on the exact registered worker, trigger, target, and action.
  A bus-signed event alone cannot earn response credit; any undo intent makes
  the action ineligible for current containment credit. Legitimate historical
  File Integrity Monitor (FIM) receipts remain valid across later scans within
  a bounded issued-claim history, while tampering and wrong-technique matches
  are rejected.
- Settings **Arm** saves both Combat policy and module enablement, then starts
  the worker; **Disarm** stops it. The Red Team AAR waits for pending queued and
  in-flight responses before declaring an incomplete response score.
- The local Ollama guardrail caps the complete serialized forwarded request,
  including non-prompt fields and telemetry, and scans the original model-facing
  envelope for instruction injection. Oversized `format`/`suffix` probes now
  return 413; hostile text in tool descriptions, format, suffix, and tool calls
  returns 403 in focused tests.
- Purple Guard now denies ordinary, unenrolled process receipt offers before
  expensive whole-lease validation. Packet Sniffer's bounded child teardown
  runs outside the Qt thread during Chill transition, with generation and
  child-identity guards.

No module was added; static discovery remains **84**. The product version remains
**v1.13.0**.

## Verification and meaning of the score

Two consecutive runs in one isolated Windows `MainWindow` used the actual
Settings modal **Save** button to arm Combat and the Red Team console **Launch**
button. Each completed all **38/38** comprehensive drill steps and received a
signed AAR reporting **37/37 Purple simulation-contract validations and 37/37
verified exact responses**. The runs took **90.422 s** and **98.562 s**. This is
a passing score for Angerona's inert simulation contract. Each AAR also recorded
**0/37 native analytic detections** because this GUI fixture did not enroll
FIM or another native analytic producer. Separate focused FIM verification
passed for a genuine historical receipt. The GUI simulation score does not
establish detection or containment efficacy against real attacks.

The GUI test also used a separate Python process as an independent OS witness,
instead of relying only on AAR claims. Before evidence cleanup it checked that
all **36** original marker paths were absent, that matching quarantine basenames
were present, and that three tagged process IDs with captured birth identities
were no longer alive **in each run**. After the validation lease released
Windows custody handles, a second separate process compared SHA-256 hashes of
all **36** quarantined files against the bytes captured at marker creation in
each run. The shared Combat journal recorded **72 applied file
quarantines and 6 process terminations**. The witness has a negative
control: it rejects a source marker left in place with no quarantine copy.
Process absence alone would not prove termination; the signed Combat journal
and exact response receipt supply that part of the score.

The earlier focused live gate passed **7/7**: base **13/13**, comprehensive
**37/37**, historical FIM evidence, two refused-enrollment cases, and two
failed-commit/rollback cases. Security reattack also confirmed that a
bus-signed fake Combat response without a journal commit cannot earn credit.
The Round 1 package compile passed **403/403** and its second supported
selfcheck passed **26/26** phases, with **67** module/pipeline passes and **18**
explicit optional or platform skips. A later release selfcheck first hit a
load-sensitive 12-second AI Triage timeout; its serial rerun passed **26/26**
with the same **67 passed, 0 failed, 18 skipped** self-test result. The skip
reflects a missing fresh local model attestation, not live inference coverage.
These are targeted checkpoints; final exact-commit release validation and
GitHub publication are separate gates.

## Post-commit release-gate follow-up

The first exact-commit release gate on `4c29b5e55e37a2e8ec9a0d08d4650e247d960021`
passed bytecode, dependency audit, documentation drift, and lint. Its full
pytest check failed and the Qt process aborted, so that gate **did not pass**.
An early stop-on-first-failure probe identified a fixture still passing a
`SimpleNamespace` where the strengthened Combat action now requires a signed
`Event`; the fixture was repaired to use the real Event type.

The live GUI test exposed a global `PanelRevealOverlay` that remained installed
after its window was gone, changing close behavior in later GUI tests in the
same process. Shutdown now removes its event filters, pending windows and
captured masks. The exact same-process lifecycle sequence changed from **4
failed / 21 passed** to **25 passed**. Settings Save now avoids a repeat Windows
Task Scheduler query when autostart is unchanged; an isolated unchanged-save
probe measured **111 ms**. An actual autostart change still queries OS state
and retains rollback. Deferred QThread close now retries every **100 ms** until
the native thread has stopped; close tests release blocked workers even when
an assertion fails.

A diagnostic first-1,700-test pytest selection with forced garbage collection
finished **1,693 passed / 7 skipped**, with no Qt abort. It deselected the
remaining 2,667 cases. A later full, one-process pytest run on the then-current
tree reached **100% with no Qt abort**: **4,345 passed / 20 skipped / 3 failed
in 1,641.28 s**. This was not a passing release gate. The three failures were
an empty QEMU child-pipe fixture, a ransomware content-classification fixture
whose production 2-second traversal budget expired under load, and a Windows
`WinError 5` replacing the detection-registry manifest. Focused repairs now
make the QEMU fixture mirror production pipe ownership and startup bound,
isolate the classifier's content assertion from the runtime-budget test with
coverage diagnostics, and use the existing bounded atomic-replace retry for
the registry manifest. The focused cases pass; production QEMU pipe ownership
and the ransomware runtime budget were not weakened.

The operator UI now shows a read-only Red Team containment-readiness preview
for the selected profile; Launch still makes its own current readiness check.
Combat status clears an earlier green state when its snapshot is unavailable
and gives guidance for disabled or full-queue states. The Red Team AAR names
the report, shows delivered-text versus saved-copy integrity status, and
disables **Practice Fix** on a binding or reload error. All **5** new UI tests
pass, and the selected existing UI tests pass **60/60** after a wording
correction. These targeted gates do not establish a passing full gate on the
combined tree or GitHub publication.

The next exact-commit gate on `3f48e7f` again passed bytecode, dependency
audit, documentation drift, and lint. Its pytest process aborted in Windows
Qt6Core with `0xC0000409` at collected test index 1,687 (about 38%), without
an ordinary assertion failure. Windows Error Reporting showed destruction of
a Python-owned `QThread` while it was still running. A read-only teardown probe
found one live SentinelLens `_SnapshotWorker` immediately after
`test_only_plain_loopback_ai_endpoints_are_admitted` at its original index
1,622 in two runs. A no-GC 1,700-test prefix finished **1,693 passed / 7
skipped / 2,673 deselected** and retained one such worker. Its connection to
the full-gate abort is a **supported inference, not proven causation**.

That test fixture now closes and joins its constructor worker in `finally` and
drains Qt events. The patched Sentinel module passed **20 tests / 1 skip**;
the diagnostic probe observed zero running threads at every boundary, and the
focused close suite passed **4/4**. Those results check the leak correction but
do not replace a rerun of the exact combined-tree release gate. No GitHub
publication is claimed.

## Responsiveness evidence and remaining work

The unenrolled-process fixture with 100 process offers and 68 inert markers
fell from **1,832.75 ms to 0.49 ms** median, with full-target validation calls
falling from 100 to zero. An offscreen Packet Sniffer stop fixture fell from a
**3,000.8 ms** Qt-blocking call to **1.0 ms**; its 10 ms heartbeat no longer
slipped by roughly three seconds. These are component fixtures, not whole-PC
speed claims.

An isolated real `MainWindow` Chill → Full → Chill transition took **5.36 / 6.55
/ 10.8 ms** at the three transition call sites, while a loaded GUI run measured
**52.1 s** construction and **22.9 s** Settings Arm/save under shared load.
Those larger latencies need call-site profiling on the physical host before
changing lifecycle or security-sensitive journal durability. One actual
quarantine measured **2.308 s** steady-state; **2.231 s** was spent in the two
durable journal appends, including protected anchor/witness work. The existing
`fsync` and ACL checks were retained. Long-running Chill and Full mode CPU,
memory, and freeze behavior on the user's physical host are **not yet proven**.

The coherent marker-custody optimization, slow shared-process-scan scheduling,
and replacement of Windows ACL subprocesses remain **proposed**. None was
shipped without an adversarial equivalence or authority check.

## Detailed records

- [Round 1 bug test](round1/bugtest_results.md) and [performance](round1/performance_summary.md)
- [Round 2 bug test](round2/bugtest_results.md) and [performance](round2/performance_summary.md)
- [Round 3 GUI bug test](round3/bugtest_results.md), [security reattack](round3/security_reattack.md), and [performance](round3/performance_summary.md)
- [Round 4 performance profile](round4/performance_summary.md)
