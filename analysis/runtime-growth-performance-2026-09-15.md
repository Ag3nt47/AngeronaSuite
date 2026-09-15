# Runtime growth and dashboard performance review

## Findings

The maintainer reported that Angerona becomes slower the longer it runs.
This review started from `1c0d6d5785c0070311bf1d9ac392f7005fa12ea2` in an
isolated worktree, preserving the existing Analysis Lab work in the main checkout.

The existing `diagnostics/not_responding.log` includes a September 15 GUI stall
inside Python's thread-start handshake during dashboard refresh, with about 100
application threads present. Other captured stalls end inside the Qt event loop;
those samples do not identify a Python-level cause. Source inspection confirmed
that alert-count and alert-history updates each created a new thread whenever
the recorder revision advanced. The log identifies thread startup as one observed
stall location, not as the proven cause of every reported slowdown.

Three detail windows also had a reproducible lifetime problem. Events, Alert
Detail and Top Talkers can be opened directly by MainWindow, bypassing the shared
factory that requests deletion on close. Repeatedly opening and closing these
parent-owned dialogs retained their native widget trees until the parent died.
Their existing close paths made them one-use views, so preserving those hidden
trees provided no reuse benefit. Top Talkers already stopped its refresh timer
on completion; its issue here was retained windows, not continued connection scans.

SOAR had two costs that increased with queue length: every changed snapshot
destroyed and recreated all table items, and every submitted request separately
copied and scanned the same latest 500 events to find its receipt.

## Changes

- Alert count and history use the existing `AsyncSnapshot` worker lifecycle.
  Each reader keeps one sleeping thread, one bounded request and one bounded
  result. Reader closures capture storage and revision, not Qt widgets. Busy or
  failed reads do not advance the displayed revision; later refreshes retry.
  Closing stops the worker without waiting for I/O and rejects late results.
- Events, Alert Detail and Top Talkers delete their native widget trees on close,
  including when opened directly without the common dialog factory.
- SOAR keeps unchanged table items, updates changed display fields, and handles
  insertion, removal, reordering and duplicate history identifiers. Selection
  and scroll survive status updates. The full backing record is still refreshed
  when nondisplayed evidence changes. A failed paint invalidates display caches
  and retries without leaving painting or selection signals disabled.
- Receipt reconciliation reads one bounded event snapshot per batch of submitted
  requests. It retains the first valid receipt in the original oldest-first
  search order and checks HMAC, producer, request identifier, action structure
  and postcondition evidence before accepting it. There is no cross-refresh
  authentication cache. An empty submitted set performs no event read.

No sensor cadence, history retention, model trust, response authorization or
protection setting changed. Persisted approval/display state still cannot grant
session approval or authorize containment.

## Measurements

The committed `tools/benchmark_runtime_refresh.py` uses disposable workspace
state, synthetic queue records and events, and an offscreen QApplication. It
starts no sensors or inference. Run it with the development environment's Python:

```powershell
python tools/benchmark_runtime_refresh.py
```

The same harness was run before and after the product changes on this Windows
host with Python 3.12 and PySide6 6.11.1. Table timings are medians over 20 updates.

| Workload | Before | After |
|---|---:|---:|
| Reader threads started across 30 changing dashboard refreshes | 60 | 2 |
| Event snapshots read for 500 submitted requests | 500 | 1 |
| Reconcile 500 pending requests with no matching receipt | 54.012 ms | 1.755 ms |
| Change one status in a 500-row SOAR view | 48.006 ms | 17.890 ms |
| Change one status in a 50-row SOAR view | 2.609 ms | 2.006 ms |

The larger table update was about 2.7 times faster in this fixture. Stable item
identity and worker counts are deterministic regression evidence; timing depends
on host load. Repeated-close tests exercised 15 lifetimes for each of the three
dialog types and found no retained child dialogs after deferred deletion.

The recorder retention probe remains in the benchmark as a diagnostic. A proposed
expression index reduced candidate selection from 6.88 to 0.67 ms, but the median
combined insertion and pruning cycle increased from 193.79 to 215.30 ms in a
separate same-process comparison at 40,000 retained rows. That index change was
discarded; the recorder schema and maintenance behavior remain unchanged.

## Validation and limits

- Relevant dashboard, SOAR, close-lifecycle, worker, alert, layout, Chill and
  Combat regressions: **122 passed**, including **9 new regression cases**.
- Supported `tools/selfcheck.py`: **26 phases passed, 0 failed**; module/pipeline
  results **69 passed, 0 failed, 16 expected unstarted/optional skips** across
  **84 discovered modules**.
- Scoped Ruff, full package compilation, documentation validation and Git
  whitespace checks passed.

These fixes remove confirmed repeated work and retained closed-window trees.
They are not a controlled multi-hour whole-application CPU/RSS comparison.
The first start of a reader can still wait for OS/Python scheduling; subsequent
refreshes reuse it. Full scans and cold model verification remain substantial
independent costs, as documented in the September 12 review. Restart the source
application after updating to load this code. The application version remains
1.13.0; this maintenance update does not build or install a packaged release.

Publication must use the guarded publisher from the clean reviewed worktree,
verify public `main` and the publishing branch at the exact commit, and verify
all public README image bytes. The unrelated development files are excluded.

## CI follow-up

The first performance publication, `c6cf151`, failed
[CI run 35034396133](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/35034396133).
The failure had three distinct causes:

- The Top Talkers late-result test still expected a completion callback on a
  dialog that the performance change now deletes on close. Its cleanup also
  called `reject()` on a deleted child dialog. The updated test explicitly
  delivers deferred deletion, verifies both native dialogs are gone, then runs
  the queued worker and checks that no result message appears.
- The module inventory parity test assumed every `set_health` call had an
  external source. Ransomware's lifecycle override delegates through a verified
  implementation line. The common external-callsite test now invokes the base
  setter directly; a separate regression verifies the override's exact source
  path, line, SHA-256 and snapshot parity. Production provenance rules are
  unchanged.
- Python 3.10/3.11 terminated with native heap corruption while showing the
  first animated destination. Python 3.11.9 and CI's PySide6 6.11.2 reproduced
  the crash locally. Splitting the preceding tests isolated a collection-order
  interaction. A diagnostic GC trace identified an unreachable `_SecurityHarness`
  and its snapshot reader/timer being collected during the next test's window
  show. Retaining that garbage diagnostically, or collecting between tests,
  avoided the crash. The final fix explicitly stops and joins the test-owned
  reader, schedules deletion of the harness, delivers deferred deletion, and
  verifies the native widget is gone. The security and posture harnesses borrow
  MainWindow methods but do not have its shutdown path; merely closing their
  bare QWidget hid it and left callback cycles for later collection.

The health parity failure and native crash also appear in
[the preceding main CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/34800651382).
The Top Talkers expectation became stale in the performance update. No tests
were disabled, no Python versions were removed, and no GC or dependency
workaround was added to the application or test fixtures.

The previously crashing 448-case group passes with the explicit harness cleanup
(**444 passed, 4 skipped**). All affected tests plus the animation contracts pass
on Python 3.12 (**43 passed**). Scoped Ruff, full source/test/tool compilation,
documentation drift and Git whitespace checks pass.

The full Python 3.11.9 suite with the final cleanup passes: **3,643 passed,
19 skipped**, with no native crash. The full Python 3.12 suite after the two
assertion corrections also passed (**3,644 passed, 18 skipped**); the 43-case
rerun above covers the subsequent teardown edit. Optional/platform-dependent
skips differ by local interpreter and environment. GitHub must independently
complete the unchanged Python 3.10–3.13 matrix after publication.
