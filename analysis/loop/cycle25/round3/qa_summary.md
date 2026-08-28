# Cycle 25 / Round 3 — Independent QA summary

Date: 2026-08-28

## Pre-final-performance serial gate

- Serial pytest: **1,808 passed / 6 expected host-platform skips / 0 failed**.
- Product compile: **346/346** Python files.
- Module structure: **82/82** module files imported, **64/64** optional legacy
  registration hooks constructed, and **80** capabilities discovered with no
  duplicate name or capability ID.
- Self-tests: **92** standalone core/module self-tests passed, **12** expected
  inactive/platform module skips, plus the EventBus pipeline passed.
- Project selfcheck: **26/26** directly and **26/26** through the supported batch
  launcher.
- Ruff and `git diff --check`: clean.

The serial result above was recorded before three final-performance regression
tests were added to collection and is retained as chronological evidence. It
was superseded by the authoritative post-documentation gate below.

## Focused final-performance gate

The new recorder/contract/Module Inspector regressions and their surrounding
performance/reliability group passed **106/106**. A scheduling-sensitive Eco
20-millisecond assertion failed once during a broader concurrent sweep and then
passed **10/10** isolated. One concurrent YARA self-test timeout passed five
immediate isolated runs, the complete module rerun, and direct/batch selfcheck.
No timeout, assertion, scanner bound, or security control was weakened.

## Authoritative post-documentation gate

- Serial pytest: **1,811 passed / 6 expected host-platform skips / 0 failed**
  in **447.31 seconds**.
- The run includes all three final-performance regression tests.
- The first post-documentation run found one Windows test-harness race. After
  two injected sharing-lock failures, the test's third attempt still called
  the real `os.replace`; a real transient scanner lock made the correctly
  bounded product helper succeed on a fourth call, contradicting only the
  test's exact-three-calls assertion. The product retry budget was unchanged.
- The schedule test now uses a deterministic injected success. **1,000**
  synthetic schedules, the focused **2/2** atomic-I/O tests, Ruff, and the final
  serial rerun passed.

Detailed commands, skips, and the one stale selfcheck expectation fixed during
QA are in [bugtest_results.md](bugtest_results.md).
