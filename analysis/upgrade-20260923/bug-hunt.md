# Upgrade QA — September 23, 2026

This pass reviewed the current working-tree upgrade independently. It used
disposable state beneath the repository's `.tmp` directory and did not alter
live Angerona configuration, install services, or start Ollama.

## Results

| Gate | Result |
| --- | --- |
| `tools/compile_check.py` (`py_compile` for every package source) | 403 passed, 0 failed |
| Module import audit | 86 module files imported; 84 declared `BaseModule` classes; 0 import errors |
| Declared module `CODE` audit | 66 distinct declarations; 0 duplicates |
| Supported `tools/selfcheck.py` | 26 phases passed, 0 failed |
| Module self-tests within selfcheck | 66 passed, 0 failed, 18 explicit prerequisite/platform/configuration skips |
| EventBus selfcheck pipeline | 1 passed; included in the runner's displayed total of 67 passes |
| Additional direct self-tests | 31 core checks and 1 Red Team check passed, 0 failed |
| Targeted pytest: harness cleanup, agent integrity, retention, retention integration | 70 passed, 2 Windows symbolic-link permission skips |

The import audit found 16 module files without `register()`. Their declared
classes are found by the existing class-based `ModuleManager` discovery; all 84
capabilities were discovered successfully. This is not an import or registration
regression. No stale/truncated-read syntax artifact occurred.

The existing Windows wrapper sets offscreen Qt, invokes this same selfcheck with
the project interpreter, and propagates its exit status. The retest ran that
underlying command directly with `PYTHONPATH=src` and a separate report path.

Local evidence: `.tmp/upgrade-20260923-compile.log`,
`.tmp/upgrade-20260923-selfcheck-retest.log`,
`.tmp/upgrade-20260923-core-selftests.log`, and
`.tmp/upgrade-20260923-core-results.json`. These local diagnostic artifacts are
not release assets or claims about native macOS/Linux behavior.

## Bugs fixed behind gates

1. **FIXED — live-drill cleanup skipped after a selfcheck failure.** The original
   harness placed `stop_and_clean()` only on its success path and released the
   validation lease in `finally`. A timeout or failed assertion therefore left
   the worker alive after surrendering the custody needed to remove its owned
   markers. Cleanup now cancels first, joins the worker for a bounded five
   seconds, cleans any late completed artifacts, and then releases the lease.
   A stuck worker is a failure. The original 30-second run deadline remains and
   now uses monotonic time. Dedicated regressions cover timeout, success,
   cleanup error, and an unresponsive worker.
2. **FIXED — failed mandatory drill steps could still pass the harness.** The
   engine records a failed mandatory step as `ok=False`, but the harness checked
   only for some steps and a custom marker. It now rejects any failed mandatory
   step, with a regression proving the assertion and cleanup both execute.

Both fixes are confined to `tools/selfcheck.py`; five dedicated harness tests
were added. The changed files compile, the targeted gate passes, and the actual
isolated live drill passes all 30 steps over two phases within its unchanged
deadline. No product behavior was relaxed to make a test pass.

## Independent security and retention verification

- The prior agent-integrity findings have corresponding implemented defenses
  and passing regressions: same-store generation rollback is rejected; mapped
  mutations fail closed without Windows file custody; Windows short aliases
  cannot bypass runtime-root exclusion; held mapped files deny writes during
  tool execution. Instruction contents remain data, not instructions to QA.
- Assistant, AI broker, and Counter-Agentic retain their store instances during
  ordinary dispatch. `AgentIntegrityStore.current()` creates a fresh instance,
  so the high-water guarantee remains scoped to each live store. This does not
  establish independent rollback protection across state/process restoration.
  No additional normal-operation lifecycle bypass was reproduced in this pass.
- Retention now resumes directory enumeration across bounded passes, reaches
  managed archives behind unrelated entries, and excludes currently locked
  oldest files from its bounded candidate heap. Tests verify eventual deletion,
  explicit incomplete quota coverage, pin preservation, and refusal of unsafe
  aliases. Pinning, inaccessible files, and the active log can still cause
  visible quota pressure; the size setting is not an unconditional disk cap.

## Failure triage and limits

The initial selfcheck ran concurrently with the full pytest suite and reported
25 passing phases plus a live-drill timeout. The isolated retest passes 26/26
without extending the deadline. This establishes the cleanup defect above, but
does not establish a separate product timeout defect from that contended run.

The parent's first full suite recorded 4,213 passed, 20 skipped and 6 failures
while implementation was still changing. The parent reports current targeted
closure of the five AI broker failures and the missing setup-wizard retention
controls; final full-suite validation remains the coordinator's gate. This QA
report does not relabel the earlier full run as green.

No new unresolved product bug was reproduced in the bounded independent review.
Native signed-installer acceptance, actual macOS/Linux execution, elevated
Ollama startup, and 24-hour/seven-day soak claims require their own evidence.

Totals: 403 package files compiled; 98 direct module/core/Red Team self-tests
passed, 0 failed, 18 module checks skipped, plus 1 EventBus pipeline pass;
selfcheck 26/26; 2 harness bugs fixed, 0 new unresolved bugs reported.
