# Round 20260923 — Bug Test (deep review, pass 1)

Full report: [bugs-round1.md](../../deep-review-20260923/bugs-round1.md).

384 files compiled; 84 modules discover without import failures/duplicate declared CODEs; module self-tests 66 pass/0 fail/18 expected skips; 24 core self-tests pass; event pipeline passes; selfcheck 26/26 phases pass. Existing focused tests: 265 pass/1 skip. New adversarial-text control passes; two deterministic regressions fail for reported Lab completion queue race and Memory Time-Machine retired-ring work. No production changes by this bug hunter; patch applier and next integration QA own resolution/gates.

## Pass 2

Full report: [bugs-round2.md](../../deep-review-20260923/bugs-round2.md).

385 current source files compile; supported selfcheck 26/26, including 66 module passes, 18 expected skips and one pipeline pass. Focused integration covers 186 distinct passing tests and one skip. Both pass-1 QA regressions now pass after the patch applier's fixes. New tests prove exact authenticated response and reversible receipts with unavailable Ollama, rejection of forged AI/remote action claims, and cached, literal, asynchronous status UI behavior. Legacy fixture expectations were updated for explicit daemon preparation without inference. Native launch is forbidden in ordinary tests and the offline harness. No new production defect reported; final combined gates remain parent-owned.

## Pass 3

Full report: [bugs-round3.md](../../deep-review-20260923/bugs-round3.md).

Final compile: 388 source files pass. Supported selfcheck: 26/26, with 66 module passes, 18 explicit skips and pipeline pass; 24 direct core tests pass. Original full pytest: 3,884 pass/19 skip/3 stale fixture or documentation failures in 1,205.62 seconds. All three are corrected and gated. Final combined integration: 206 pass/1 skip; independent token boundary: 11 pass. Reconciliation accounts for all 3,991 final collected cases: latest outcomes 3,972 pass/19 skip, zero uncovered cases or unresolved failures. This is the original full run plus targeted gates, not a second all-green full run. No new production defect was established; QA changed only three tests and the evidence reports. Native acceptance limits remain documented.

## Subsequent upgrade QA

Full report: [bug-hunt.md](../../upgrade-20260923/bug-hunt.md).

403 sources compile; 86 module files import with 84 discovered capabilities and
no duplicate declared CODEs. Supported selfcheck passes 26/26, including 66
module self-tests, one EventBus pipeline check, and 18 expected module skips.
31 core checks plus the Red Team self-test pass. Targeted harness/integrity/
retention pytest: 70 passed, 2 symbolic-link permission skips. Two harness bugs
were fixed: cancellation and artifact cleanup now precede validation-lease
release even after failure, and failed mandatory drill steps can no longer pass
the live phase. The isolated 30-step drill passes within the unchanged
30-second deadline. No additional unresolved product bug was reproduced.
The coordinating parent owns the final full-suite and publication gates.
