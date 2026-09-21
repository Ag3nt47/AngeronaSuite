# Round 20260921 — Performance summary

Canonical report: [module polling efficiency](../../round-20260921/performance.md).
Combined changes and final gates: [round record](../../round-20260921/README.md).

Process Monitor avoids rebuilding command text for unchanged process identities
and reuses identity normalization within each poll. Shared process/connection
cache lifetimes use monotonic time to remain correct after wall-clock changes.
Entropy self-test fixtures are cleaned up. The targeted gate passed **28 tests**.

An inert fixture of 600 stable processes, measured as five repetitions of 100
polls, reduced median loop time from **5.729 to 2.069 ms** with 16 arguments and
**19.904 to 2.199 ms** with 128 arguments: **64% and 89%** less loop bookkeeping.
These measurements exclude operating-system enumeration. They are not a claim
about whole-app CPU, live sensor throughput or multi-day memory behavior.

Reproduce with [benchmark_module_poll_efficiency.py](../../../tools/benchmark_module_poll_efficiency.py).
