# Cycle 35, Round 1 — bug test

## Gates run

- Whole package: `PYTHONPATH=src` plus `py_compile.compile(..., doraise=True)` over every `src/angerona/**/*.py`: **403 passed, 0 failed**. No apparent mount-induced syntax error occurred.
- Direct import of every `angerona.modules.*` file: **86 passed, 0 failed**. Discovery found 84 `BaseModule` subclasses and no duplicate nonempty `CODE` values. Sixteen class-bearing files lack `register()`, but `ModuleManager` discovers classes directly; these were not import or discovery failures.
- Direct top-level `core/*.self_test()`: **24 passed, 0 failed**, including CVE ignore/advice, alert acknowledgement, incident timeline, and purple loop.
- Supported headless harness, `PYTHONPATH=src venv\\Scripts\\python.exe -u -X utf8 tools\\selfcheck.py`: first run **25 phases passed, 1 failed** because AI Triage timed out after 12 seconds; second run **26 passed, 0 failed**, with SelfTestRunner **67 passed, 0 failed, 18 explicit optional/unstarted/platform skips** (the 67 include the event pipeline). The harness's 30-step live Red Team phase passed both times. Logs: `.tmp/bug_audit_selfcheck.txt` and `.tmp/bug_audit_selfcheck2.txt`.
- Focused live AAR regression before Combat remediation: `PYTHONPATH=src venv\\Scripts\\python.exe -m pytest -q tests\\test_redteam_live_scoring_regression.py`: **0 passed, 1 failed**, at `successful_response.count == 1` versus 13 expected. Later, the focused stale-enrollment gate (`-k stale_enrollment`) returned **1 passed, 1 failed** in 3.92 seconds: ordinary post-creation refusal removed its marker, while a renamed original remained after a same-name replacement. `py_compile` and Ruff pass for the expanded test file. Full post-fix AAR gate remains pending product changes.

## Findings

### BT-01 — Red Team containment score fails despite armed response — REPORTED for product remediation

The selfcheck's live-drill phase proves only engine completion. A fresh, isolated comprehensive run used the real 38-step inert Red Team engine, live Purple Guard and Process Monitor, authenticated EventBus/FlightRecorder, and `generate_aar`. It completed all 38 steps and validated all **37/37 Purple simulation contracts**, but recorded **0 native analytic detections** and **0/37 verified responses** without Combat. That detection-only result is expected and is not evidence of real-attack detection efficacy.

A second comprehensive run added a genuinely armed Adversary Combat worker with file quarantine and tagged-process termination enabled, while network blocking, host isolation, and honeypots were disabled. The live AAR reported **37/37 Purple simulation validations, 0 native analytic detections, 1/37 verified containment**, and `outcome=partial`. Combat queued 39 response requests, executed three process requests, and returned `no_eligible_target` for 36 file-marker requests. T1059 was the only AAR step with verified containment. The other 36 steps reported no exact verified containment receipt. The isolated evidence root is `.tmp/bug_audit_response_08b2d568`.

The Windows failure is a deterministic custody conflict. `RedTeamValidationLease.register_artifact_handle` retains an open read handle for each exact marker; `_WindowsPinnedFileMove._create_file`, called by Combat quarantine, demands an exclusive no-sharing open of the same file. A direct probe proved: pinned open succeeds without the lease handle; while the marker handle is held it fails with `PermissionError [WinError 32]`; after closing that handle it succeeds. Relevant code: `src/angerona/modules/purple_guard.py` lines 999, 1027, 1729, 1776 and `src/angerona/modules/adversary_combat.py` lines 713–719, 3643. The focused test preserves the full custody, event, response, and signed-AAR path. Product remediation is coordinator-owned; any handoff must keep exact-object and alias resistance.

The Red Team UI defaults `auto_remediate=True` and checks Combat readiness before an auto-contain run. This is therefore a user-visible score failure when an otherwise ready Combat worker is present.

### BT-02 — AI Triage headless self-test had one transient timeout — OBSERVATION, no defect confirmed

The first full selfcheck, run concurrently with the 403-file compile check and other workspace activity, returned `AI Triage (Ollama): test timed out after 12s; the call is still running`; the policy correctly did not convert a timeout to an expected skip. A fresh isolated direct AI Triage self-test took **2.03 seconds** (Ollama listener lookup 0.031 seconds, Windows Authenticode check 1.765 seconds) and returned the expected unapproved-model-baseline result. The second full selfcheck classified that exact result as an optional-prerequisite skip and passed 26/26 phases. No deterministic AI defect or syntax/import failure was reproduced. Retain the initial timeout as a load-sensitive harness observation; do not weaken the timeout policy or test assertion on this evidence alone.

### BT-03 — Authentic native FIM detections lose AAR credit after later scans — REPORTED for product remediation

A third isolated comprehensive run used the real File Integrity Monitor on the exact drill sandbox at its normal maximum-mode scan cadence, with Purple Guard, Process Monitor, authenticated recorder, and signed AAR. FIM emitted **10 signed `native_analytic_detection` events** while all 38 Red Team steps completed and all 37 Purple simulation contracts validated. Nevertheless the AAR credited **0/37 native analytic detections**. The isolated evidence root is `.tmp/bug_audit_native_66e0384e`.

The verifier currently compares a historical FIM receipt's `scan_generation` with the producer's *current* `_scan_generation` at AAR time (`purple_guard.py` around line 2901). Every ordinary later scan changes that value. The one-generation claim book around lines 288–295 also drops previously claimed scans. A new focused test captures an authentic signed FIM event, checks tampering and wrong-technique negative controls, advances a normal scan, then requires both direct verification and native AAR credit. Product remediation must preserve replay and forgery rejection while retaining legitimate historical evidence. This defect is distinct from Purple's simulation-only canaries and from Combat containment.

### BT-04 — Refused marker enrollment can orphan a renamed original — REPORTED for product remediation

The parameterized Windows regression stops the actual Purple producer during marker enrollment, after the engine has exclusively created an inert marker. With the name unchanged, current work-in-progress cleanup removes the marker and the run stops after one failed step as incomplete and score-ineligible. When the original is renamed while its creating descriptor is still open and an unrelated file occupies the old name, the run still stops and preserves the replacement, but the original remains at its renamed location. `RedTeamValidationLease.discard_unenrolled_marker` currently reopens only the old pathname, so it cannot dispose that held original. The exact held-object cleanup needs to remove the original without deleting a later same-name replacement. The focused gate is **1 passed, 1 failed** pending product remediation.

## Evidence limits

The isolated AAR proves only inert marker/process validation and exact response accounting. It does not measure production native detector coverage, exploit resistance, or efficacy against real adversary behavior. The new Windows regression test asserts verified containment receipts for the 13 base expected-positive steps and keeps its diagnostic data on the repository volume under `.tmp`.
