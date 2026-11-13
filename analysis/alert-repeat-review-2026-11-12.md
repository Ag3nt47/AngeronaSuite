# Repeating-alert reliability review — 2026-11-12

Status: offline-validated isolated candidate, not installed or published. Live observation awaits the other maintainer job releasing the active workspace. Source review is not confirmation of the current host's repeating-alert family.

## What the source review established

Live Alerts reconciles stable signed-record identities rather than appending the same SQLite snapshot each refresh. Separately published observations have distinct timestamps/signatures and remain distinct evidence. Normal storage and the dashboard must not discard those originals merely because messages match. The 24-hour dashboard total includes informational telemetry as well as findings and coverage reports.

The recent repeat controls contained correctness defects: SpywareGuard could suppress an escalation or changed classification; memory grouping omitted protection and per-process coverage; Counter-Agentic could treat a failed second birth check as complete; forensic diagnostic episodes did not distinguish admitted births or reset precisely following recovery. YARA activation failures could publish one HIGH health event per retry interval.

## Candidate changes

- SpywareGuard: compare the latest severity, classification and effective eligibility for the same evidence identity; preserve new native admission opportunities. Keep advisory findings separate from authorized response evidence.
- Memory scanner: use exact native FILETIME birth keys and compare current regions, protections and coverage; preserve unresolved observations across incomplete reads; renew reporting after a complete same-object clear; bound repeat history and expose suppression/eviction accounting.
- Counter-Agentic: completed identity revalidation precedes approval or hourly grouping; preserve exact endpoint approval keys; report role transitions and distinguish process generations; bound retained state and label suppression as emission opportunities. Policy changes reset repeat histories; a verified approval ends only that exact subject’s episode, permitting immediate reporting after revocation or digest mismatch.
- Forensics: key diagnostic holds by admitted native process generation when available; clear only exact admitted holds after successful fully retired capture. Unknown and unrelated evidence gaps remain unresolved.
- YARA: keep attempting activation every ordinary retry; bound identical rejection notices to a 15-minute reminder. New rules or failure reasons report immediately; successful activation ends the episode and retains its suppressed repeat count. Coverage notices carry no response authority.
- Dashboard: name the aggregate Events (24h) and include INFO in its matching detail view; active threat tiles retain their existing classifications.

## Validation and open work

Focused inert regressions and independent static review completed in the isolated checkout. The main Windows/Python 3.12 cohort passed 394 cases with one existing availability skip (directory-symlink creation unavailable). All 50 new cases passed. After a final Counter-Agentic policy/approval recurrence correction, its two suites passed 42 cases, including two additional new cases. These scopes overlap and must not be added as independent totals. The other five changed product files, shared fixtures and earlier test files were byte-checked unchanged before that follow-up. Both accepted runs returned native exit zero with no pending retirement custody; loaded product origins and before/after source digests were checked. No live restart, scan, containment, firewall change, alert acknowledgement or baseline reset has been performed by this review.

After workspace handoff: recheck source coherence; bind the actual Core PID/image/native creation time; obtain a bounded opt-in read-only Live Debug capture and compare repeats by source, evidence, generation and disposition. Preserve authenticated originals, collector gaps and loss counters. Verify any applied source revision in a fresh process generation before claiming a live fix.

Other source-only repeat candidates remain unconfirmed: optional kernel-bridge gap warnings, driver/storage collection-health reminders, Fleet snapshot-key churn, KEV applicability advisories and critical tray cadence. Fresh canary challenge failures are separate evidence even when their summaries look similar. Quiet UI or an empty capture is not proof of complete collection.

Publication, current-head GitHub checks and release/manual updates remain pending final validation and the active job's handoff. No efficacy or all-module health claim follows from these changes.

## Validation setup history

- Initial harness attempt stopped before collection because its write boundary refused pytest’s default null-device log destination.
- The next run completed 367 passing cases, 27 failures and one skip; the isolated bootstrap omitted installed pywin32 search paths, preventing Windows custody/diagnostic-file reads. Production code was not changed to bypass those checks.
- Correcting the explicit installed dependency paths produced 394 passes/one skip, but a later orchestration tool reset lost the native completion receipt. That run was not accepted as a retirement gate and does not establish a product exit defect.
- A fresh, identical-source run retained wrapper identity, outer completion, source origins and native closure receipts: 394 passes/one skip, native exit 0, custody pending false. A source-only cleanup review found no confirmed test or product exit leak.
- The final Counter follow-up passed 42 cases, native exit 0, custody pending false.

Private raw logs, source-pin manifests and native receipts remain under known diagnostic artifact paths. Only sanitized findings belong in publication. No real spyware verdict, general catch-rate, continuous telemetry coverage or performance improvement is established by these inert tests. Matching memory region/protection metadata also does not prove that the contents of an unchanged executable allocation are benign.

## Publication handoff

Candidate branch: codex/live-alert-reliability-20261112, based on local commit 790a81714808f1c460f5943f4ecd4117647c5fa9. The active workspace has not been overwritten, no candidate commit or publication was made, and no live application was started or stopped. Recheck current owner changes and branch ancestry before integration.

The public main snapshot inspected during this review was df4e9e66e94f3f9b6c3807e518cd7c6cafb71ff4. Its CI run 43248535243 failed Python 3.10 and 3.13; three jobs were cancelled and Python 3.12 passed. Security Assurance run 43248535286 passed. Those historical checks do not certify this candidate. The other maintainer job owns its pending changes; do not stage or publish them accidentally.

After the owner handoff, follow the live-debug guide and current llms block, perform fresh bounded observation, integrate only reviewed source, finish release/manual notes, then use the guarded publisher and verify current-head hosted checks. Preserve the directory-symlink availability gap and all historical evidence.

Final isolated patch formatting check: git diff --check completed with exit 0. Ruff was unavailable in the inspected installed locations/PATH; no Ruff completion is claimed. The candidate remains uncommitted until live verification and the owner handoff permit a completed publication.
