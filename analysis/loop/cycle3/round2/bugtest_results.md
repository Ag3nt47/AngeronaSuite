# Cycle 3 / Round 2 — Bug Test / QA Results

Date: 2026-07-19. Environment: Windows, project virtual environment,
`PYTHONPATH=src`, and Qt offscreen for GUI construction. This pass tested the
live shared tree while the installer, ARIA microphone, dependency, Purple Guard,
and public-release remediations were being integrated. Concurrent edits were
preserved. README, llms files, DOCX files, and ARIA HUD/microphone UI code were
not edited by this pass.

## Final decision

The combined tree is compile-, import-, discovery-, repository-test-, and
selfcheck-clean. The full application harness passed **26/26**. Three clear bugs
were fixed behind gates: the Settings Save crash, Windows timing/lock defects in
three resilience self-tests, and a stale drill test that incorrectly expected a
same-run candidate to certify itself as fixed.

Two product follow-ups remain reported: the Posture History SQLite read captured
blocking the GUI, and the AAR's legacy “Remediation rate” counting only SOAR
actions rather than separately reporting later-rerun detector fixes. One QA-only
privacy defect also remains in the Teams self-test: with PyJWT installed, its
nominally offline auth assertion contacts the Microsoft OpenID/JWKS endpoints.

## Compile, imports, discovery, and structure

- Final `tools/compile_check.py`: **206/206 source files passed**, 0 failed.
- Built-in module package files: **64/64 imported**, 0 import errors.
- `BaseModule` implementations: **63/63 constructed**.
- `ModuleManager.discover()`: **63 modules discovered**, 0 discovery errors.
- Duplicate module display names: **0**.
- Duplicate non-empty module codes: **0**.
- Every callable legacy `register()` returned a `BaseModule`, 0 failures.
- Twelve legacy module files have no `register()`; this is intentional because
  current discovery finds `BaseModule` subclasses directly. All twelve imported,
  constructed, and appeared in `ModuleManager` discovery.

## Complete self-tests and project harness

Direct class self-tests across all 63 modules returned:

- **48 truthy passes**.
- **15 expected safe-state false results**, all explained by stopped live
  sensors, an unarmed SOAR action path, or the optional kernel driver not being
  loaded.
- **0 unexpected exceptions or genuine module failures**.

Module-level self-tests across core, resilience, Shark, connectors, and GUI:
**29/29 passed** after the three resilience gates were corrected.

Final `tools/selfcheck.py`:

- **26/26 phases passed**, exit 0.
- Discovered all **63 modules** and constructed the full MainWindow offscreen.
- Raw application module drill: **50 pass, 14 expected stopped/idle skips, 0
  unexpected failures**.
- Remote Bridge mutual authentication/AES-GCM, Purple Guard exact file/process
  proofs, and in-process YARA-X EICAR detection all passed.
- Live benign Red Team drill completed **30 steps over two phases** and cleaned
  its inert marker.

Repository regression suite: **32/32 passed** with `pytest tests -q`.

Running bare `pytest` from the repository root initially attempted to recurse
into protected runtime FIM/temp sandboxes and stopped during collection with
21 `PermissionError` records. This was a test invocation/collection-scope
artifact, not a product failure; the supported source suite under `tests/` is
clean.

## Focused regressions

| Area | Result |
|---|---|
| Settings construction and Save | PASS after fix; six tabs constructed, changed model/Eco values persisted, existing Mobile values preserved, no plaintext `.env` created |
| Secure credential store | PASS; DPAPI round-trip, ciphertext does not contain the secret, no `.env`, and no Users/Authenticated Users/Everyone ACL grants |
| Remote Bridge | PASS; mutual proof, tamper rejection, session-key derivation, AES-GCM round-trip, no-key default deny, and loopback receiver default |
| Teams connector | Functional self-test PASS; production defaults are loopback, allowlist-required, bounded, and JWT fail-closed. Offline self-test egress defect remains reported |
| Purple Guard / T1059 | PASS; ordinary process telemetry stayed quiet, exact `ANGERONA_REDTEAM_<8hex>` evidence produced one HIGH proof, duplicate suppressed, AAR matcher correlated it |
| Posture two-run closure | PASS; candidate install leaves the miss VULNERABLE, then a distinct caught AAR changes it to PATCHED |
| Performance lifecycle | **11/11 PASS**: first-cycle boundary, sequential Eco wake, D-drive data, scoped Ollama unload, zero-wait storage, EventBus dedup/bounded reads, Memory Time-Machine snapshot, speculative cooldown cleanup, and Eco cancellation |
| Stop/shutdown | **3/3 PASS**: both drills cancel before later effects, ownership predicate is boundary/entrypoint aware, and only Angerona-owned Ollama models unload |
| YARA one-click dependency | PASS after the integration changed from `yara-python` (no Python 3.14 wheel; MSVC source build failed) to wheel-backed `yara-x`; EICAR and repository rules compile |
| Voice privacy | Final selfcheck constructed MainWindow without an automatic Vosk download. Earlier trace was `MainWindow -> AriaVoice thread -> _resolve_stt() -> vosk.Model(lang='en-us')`; the final resolver requires the explicitly installed verified local model path |

## Bugs fixed behind gates

### C3-R2-B01 — Settings Save always crashed after Mobile tab consolidation — FIXED

- **Symptom:** Settings constructed, but pressing Save raised
  `AttributeError: 'SettingsDialog' object has no attribute '_mob_chk'`.
- **Evidence:** the same exception exists in `runtime-data/logs/crash.log` from
  2026-07-16. A fresh isolated Settings probe reproduced it exactly.
- **Root cause:** the Mobile settings widgets were replaced by a redirect to the
  Advanced Management Console, while `_save()` still unconditionally read the
  removed widget attributes.
- **Fix:** preserve existing Mobile config when the redirect-only layout has no
  legacy widgets; still save them when an older layout provides the controls.
- **Gate:** `pages.py` compile PASS; isolated construct/save/persist/no-plaintext
  regression PASS; new repository regression PASS.

### C3-R2-B02 — Resilience self-tests had impossible/flaky Windows timing assumptions — FIXED

- **Symptom:** `resilience.manager`, `resilience.selftest`, and
  `resilience.supervisor` returned false even though the detached child later
  became healthy.
- **Root cause:** fixed sleeps assumed a detached Windows interpreter emitted its
  first heartbeat in 0.6 seconds. The dry resurrection test also asked for a
  respawn while its own spawn lock was intentionally held for the heartbeat-less
  throwaway process, so its 0.6-second deadline could not succeed.
- **Fix:** use bounded readiness/frame observation; give the throwaway an explicit
  process-liveness probe; stop that isolated process and observe an actual
  respawn. No production detection or restart threshold was weakened.
- **Gate:** all three changed files compile; the three standalone self-tests now
  pass; final 29/29 module-level self-tests and 26/26 harness pass.

### C3-R2-B03 — Drill regression expected unsafe same-run self-certification — FIXED

- **Symptom:** the legacy repository test required `resolved=1` and immediate
  PATCHED after installing a detector candidate.
- **Root cause:** that assertion described the old bug, not the new proof-carrying
  remediation contract.
- **Fix:** strengthen the test with supported T1003 evidence: the initial miss
  remains VULNERABLE after candidate install, and only a distinct caught rerun
  marks it PATCHED.
- **Gate:** focused drill policy tests **4/4 PASS**; full suite **32/32 PASS**.

## Reported follow-ups

### C3-R2-R01 — Teams “offline” self-test performs network egress — REPORTED

With PyJWT installed, `TeamsBot.self_test()` calls `_verify_auth()` with a fake
bearer token. That routine fetches Microsoft OpenID metadata/JWKS, contradicting
the self-test's no-network contract. Its assertion is also vacuous when PyJWT is
present (`result is False or _have("jwt")`). Production traffic still fails
closed; the defect is in deterministic/private testing. The active Teams owner
was notified to mock/inject auth verification for this test.

### C3-R2-R02 — Posture History can still block the GUI on SQLite — REPORTED

Today's `not_responding.log` contains a 5.7-second main-thread stall in
`AriaHud.refresh -> PostureHistory.sparkline -> series -> sqlite fetchall`.
Cycle 3 Round 1 already removed the analogous wait from the main event storage,
but Posture History needs its own zero-wait/read-cache design and Qt load test.
This was routed to the performance pass rather than patched under bug-test
authority.

### C3-R2-R03 — AAR remediation percentage does not describe verified detector fixes — REPORTED

The latest stored Red Team report has **21/52 detection catches (40%)** but
**0/56 SOAR remediations**. `aar_report.py` defines remediation only as a
correlated Active Response SOAR/SOAR Automation event. A later Purple Guard proof
can correctly mark a Posture weakness PATCHED while the visible legacy
Remediation rate remains 0%. The report should keep SOAR containment honest and
add a separate verified detector-fix measure, or correlate an explicit proof
event; it must not count same-run candidate installation as remediation.

## Crash/report review

- No 2026-07-19 unhandled Python exception was found in either crash log; today's
  crash entries are startup markers.
- Thirteen watchdog records between 09:44 and 10:23 show GUI stalls. Confirmed
  actionable stacks were main event SQLite reads (addressed in Round 1) and
  Posture History SQLite reads (reported above). Several samples landed in
  trivial painting or a modal self-test question and indicate system/GIL/modal
  pressure rather than a new exception.
- The historical Settings `_mob_chk` traceback directly corroborates C3-R2-B01.
- `diagnostics/selftest_failures.json` is clean after the final harness.
- Remediation logs show the old T1059 candidate as unsupported before this round;
  the final exact tagged-process proof regression now passes.

## Files changed by this bug-test pass

- `src/angerona/gui/pages.py`
- `src/angerona/resilience/manager.py`
- `src/angerona/resilience/selftest.py`
- `src/angerona/resilience/supervisor.py`
- `tests/test_policy_and_drill_resolution.py`
- `tests/test_cycle3_round2_bugfixes.py`

No README, llms, DOCX, installer, dependency, ARIA HUD, or microphone UI file was
edited by this pass.
