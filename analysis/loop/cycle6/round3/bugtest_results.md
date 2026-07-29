# Cycle 6 / Round 3 — Bug Test Results

Date: 2026-07-29

## Gates exercised

- Package compile: **231/231** Python files under `src/angerona` compiled.
- Full repository suite: **211 passed, 2 skipped, 0 failed** in 21.13 seconds.
- Built-in discovery: **65 modules**, with **0 discovery errors**.
- Headless application self-check: **26 passed, 0 failed** after the
  cross-platform skip-classification correction below.
- ARIA component harness: **13 passed, 0 failed**.
- Direct import scan: **67 module files imported, 0 import failures**.
- Registration convention: this repository discovers `BaseModule` subclasses
  directly; `register()` is not required. All 65 product modules were found.
- Duplicate identity check: the manager's name-keyed inventory contains 65
  unique names. No duplicate discovered module identity was accepted.

## Platform and environment skips

The full pytest suite contains two intentional platform/environment skips.
The module stress drill reported 15 non-product failures: stopped modules in
the deliberately non-starting headless harness, idle/disarmed SOAR, unavailable
Ollama, and the Windows host's macOS-only observe sensor. The remaining module
self-tests passed **51** checks. These results are classified as skips by the
outer self-check rather than concealed as module passes.

## Bug fixed

### FIXED — Windows self-check treated a macOS-only sensor as a regression

- Component: `tools/selfcheck.py`
- Symptom: the complete self-check ended **25 passed / 1 failed** even though
  the macOS Observe Sensor correctly returned “available only on macOS.”
- Root cause: the harness already classified stopped, idle, Ollama, and
  watchdog-environment outcomes as skips, but did not recognize an explicitly
  platform-only module.
- Correction: on non-macOS hosts only, classify the sensor's exact,
  self-describing platform result as an expected skip. This is narrowly scoped;
  other macOS sensor errors still fail the gate.
- Verification: rerunning `tools/selfcheck.py` completed **26 passed / 0
  failed** and still displayed the module-level platform result.

## Crash and freeze evidence

No new crash or not-responding record has been written since 2026-07-19. The
historic logs show GUI stalls in large table construction, synchronous recent
event reads, and posture-history queries. Those records predate the current
bounded Resolve Center, telemetry cursor, and refresh changes. Current focused
performance tests, full pytest, offscreen UI construction, live benign red-team
drill, and self-check all pass. The old evidence remains useful historical
context but does not prove a current regression.

The stress drill also honestly reports two remaining deployment-hardening
conditions rather than test defects: the optional native syscall bridge is not
built, and the present hermetic executable is unsigned.

## Final disposition

- Bugs fixed: **1**
- Bugs reported: **0 current regressions**
- Historical risks retained for operational soak validation: **GUI stalls under
  long-running/high-volume production load**

