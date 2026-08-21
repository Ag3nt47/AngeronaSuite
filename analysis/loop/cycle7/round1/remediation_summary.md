# Cycle 7 / Round 1 — Remediation Summary

Remediation date: 2026-08-20

This bounded pass addressed C7-R1-02, C7-R1-03, C7-R1-04, and C7-R1-06.
C7-R1-01 and C7-R1-05 were owned by the coordinating agent and were not
modified here.

## Coordinating-agent closure: C7-R1-01 and C7-R1-05 — FIXED

- Remote Bridge now assigns receiver-owned observe-only authority, strips every
  receiver-local PID/path alias, and forces the local module identity. Both SOAR
  engines and Evolution Engine reject observe-only evidence before any local
  process, file, or YARA-policy mutation. The re-challenge first found and then
  closed the Evolution subscriber bypass; the post-fix remote suite passes 4/4.
- Tagged-release Python wheels are installed from the committed SHA-256 lock.
  Inno Setup 6.7.1 is downloaded from its exact upstream release and checked
  against the published SHA-256 before execution. Both elevated source
  bootstraps are now explicitly CPython 3.12 x64 and use the same hash lock with
  no unhashed pip, requirements, or duplicate Vosk fallback. Release/source
  trust gates pass 32/32, and the exact Inno compiler successfully compiled the
  complete Setup script locally with placeholder release payloads.

## C7-R1-02 — FIXED

- `src/angerona/core/cve_fix_advisor.py` records `staged`, `executed`, and
  `verified` separately; both proposal and rollback paths remain inert text.
- `src/angerona/gui/threat_intel_page.py` now says **Stage proposal**, explicitly
  renders **staged — not executed**, and reserves fixed/verified copy for an
  executed operation with a passed postcondition.
- `README.md` no longer advertises confirm-then-execute or one-click rollback for
  model-authored CVE scripts.
- Gates: Python compile PASS; `cve_fix_advisor.self_test()` PASS; manual isolated
  staging contract PASS; focused copy regression PASS.

## C7-R1-03 — FIXED

- `src/angerona/gui/threat_intel_page.py` retires bulk ignore. No-fix, model
  failure, and AI outage remain active. Per-CVE exclusion is relabeled **Mark not
  applicable** and requires evidence plus an approver.
- `src/angerona/core/cve_ignore.py` fails safe for legacy/untyped records and
  requires the typed `not_applicable` classification, non-empty evidence,
  approver identity, and future expiry before a CVE can leave scoring.
- `src/angerona/modules/intel_sync.py` counts only current typed applicability
  exclusions outside posture and reports them as verified not applicable.
- Gates: all three Python files compile PASS; `cve_ignore.self_test()` PASS;
  `IntelSyncModule.self_test()` PASS; focused expiry/legacy/bulk-ignore tests PASS.

Accepted-risk and compensating-control workflow states remain a broader case/
policy feature. They intentionally do not suppress threat scoring in this patch.

## C7-R1-04 — FIXED

- `src/angerona/gui/sandbox_editor.py` no longer stops all modules or replaces
  the production EventBus publisher merely by opening the editor.
- New `src/angerona/core/sandbox_runner.py` instantiates and tests the selected
  module in an isolated Python child with `-I`, a sanitized integration-disabled
  environment, disposable `ANGERONA_DATA`, no production EventBus authority,
  and a 30-second hard deadline. A timed-out child tree is terminated without
  invoking a shell.
- Gates: both Python files compile PASS; never-returning probe terminated inside
  the deadline in 3/3 challenge runs; environment-isolation probe PASS; UI
  no-stop/no-publisher-replacement regression added (skipped only in the minimal
  gate interpreter because PySide6 is not installed there; the normal project
  suite exercises it).

The child inherits the operator's Windows token. A true AppContainer/restricted-
token and kernel-enforced network/filesystem sandbox is a future architecture
hardening item; it is no longer needed to restore sensors because production
sensors are never paused by this workflow.

## C7-R1-06 — FIXED

- `installer/Angerona.iss` reads an administrator-protected monotonic
  `HKLM64\Software\Angerona\HighestInstalledVersion` marker, bootstraps from the
  existing Inno uninstall `DisplayVersion`, parses versions fail-closed, and
  aborts when Setup is older.
- Successful installation persists the highest version during `ssPostInstall`;
  the marker deliberately survives uninstall. Recovery is explicitly separated
  from ordinary Setup.
- Gates: deterministic installer contract regression PASS; official Inno
  `PackVersionComponents`, `ComparePackedVersion`, and registry APIs verified
  against primary documentation. Local ISCC is unavailable, so actual installer
  compilation remains a release-CI gate.

## Aggregate gates

- Python compile: PASS for all seven changed Python/test files.
- Focused regression suite: **7 passed, 1 skipped** (PySide6 absent only in the
  minimal audit interpreter).
- CVE advisor self-test: PASS.
- CVE exclusion self-test: PASS.
- Intel Sync self-test: PASS.
- Sandbox timeout challenge: **3/3 PASS**.
- Inno downgrade static contract: PASS; release-CI compile pending.
