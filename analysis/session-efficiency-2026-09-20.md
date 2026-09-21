# Long-session resource use and speed

## Scope

The maintainer reported that running many modules slows the host and that the
slowdown grows over time. This maintenance update starts from `a6a0a6e` in a
separate reviewed worktree, preserving unfinished Analysis Lab changes in the
operator checkout. It addresses three confirmed sources of repeated work;
it does not claim to identify every cause of whole-machine load.

## Findings and changes

### DNS observation cooldowns

The network protocol decoder rebuilt its entire cooldown dictionary for each
new suspicious name once it held more than 256 names. The rebuild removed only
expired entries, so a burst of unique names could grow the dictionary without a
capacity limit and perform quadratic work on the synchronous EventBus path.
Other subscribers and the publishing sensor paid that delay too.

An ordered cooldown table now expires entries from the oldest end, caps retained
names at 4,096, and samples the monotonic clock inside its lock to preserve time
order across publishers. Each entry is inserted and removed once. All DNS names
continue through the existing lexical analysis. At capacity, the oldest
suppression entry is retired; that name can generate another observation if it
recurs. New observations are not discarded to enforce the bound. The detector's
observation severity and absence of automatic response authority are unchanged.

The old lookup used zero for an unseen name's last emission. On a host with less
than 60 seconds of monotonic uptime, that suppressed its first observation.
An explicit missing-entry check fixes this, including at clock value zero.

### Growing audit-log display count

The flow metrics cache avoided reads only when the audit log was unchanged.
Each appended entry triggered a complete line-by-line reread of its history.
The replacement keeps one file identity, byte offset, newline count, last byte,
and two 64-byte guards. Normal appends read the new bytes plus at most 256 guard
bytes, with 64 KiB read buffers; unchanged files require no content read. It
retains no complete log lines or open descriptors.

Rotation, truncation, same-size rewrites, changed guards and path changes cause
a recount. Partial final lines and CRLF append boundaries preserve binary-file
line-count semantics. A failed read does not advance the cache fingerprint, so
the next request retries even when metadata is unchanged. Missing files report
zero, and switching files cannot reuse another file's count.

This count is cosmetic, not authenticated audit evidence. The guards are not a
whole-file integrity check: arbitrary modifications to the middle of old data
combined with append, or metadata-preserving tampering, are outside this
append-only display optimization. Audit security checks do not consume it.
Initial counting and rotation still require reading the current file once.

### Reusable metrics writer

MainWindow created a new daemon thread for every canvas metrics write. A thread
start exception also left its busy flag permanently set. The feed now uses the
existing AsyncSnapshot lifecycle: one sleeping worker, one bounded result and
one coalesced follow-up. It retries failed starts and failed writes, and its
reader captures service objects rather than the Qt window. Owner destruction
and application quit stop the worker without waiting for filesystem I/O.

## Measurements

`tools/benchmark_session_efficiency.py` exercises inert DNS cooldowns and a
disposable 32 MiB audit log. It starts no sensor, network traffic, or inference.
The same harness ran before and after the changes on this Windows host with
Python 3.12.10. DNS timing is the median of three 10,000-name bursts; audit timing
is the median of twenty single-line appends after initial counting.

| Workload | Before | After |
|---|---:|---:|
| Cooldown decisions for 10,000 unique names | 7,229.045 ms | 28.113 ms |
| Retained cooldown names after that burst | 10,000 | 4,096 |
| Count after a single-line append to 32 MiB | 61.652 ms | 10.207 ms |

The regression workload also admits 50,000 unique names while checking the
4,096-entry bound on every insertion. A one-MiB fixture proves a four-byte append
consumes at most 260 logical content bytes and an unchanged count reads none. Repeated
writer requests reuse the exact same thread; 100 requests during a blocked write
produce one coalesced follow-up. Timings depend on host activity and are not a
whole-application CPU, memory or multi-hour soak comparison.

## Validation

- Targeted performance, DNS observation, subscriber, worker and Chill tests:
  **59 passed**. The final **13 new regression cases** also passed separately,
  including an additional test of a log changing during its read.
- Supported selfcheck: **26 phases passed, 0 failed**; **69 module/pipeline
  passes, 0 failures, 16 optional/unstarted skips**, with 84 discovered modules.
- Scoped Ruff, source/test/tool compilation, documentation validation and Git
  whitespace checks passed.
- Full regression run: **3,670 passed, 18 skipped, 1 failed** in 511 seconds.
  The failure reproduced in isolation: the interoperability import fixture's
  August 21 timestamps had aged past the production 30-day retention window.
  The test now supplies a fixed clock only to the evidence-store module, with
  the real performance counter retained. Import, privacy and duplicate checks
  still run, and production retention is unchanged. The complete interop,
  evidence-store and final new performance test files then passed together:
  **23 passed**, including retention enforcement. The full suite was not
  repeated after this test-only correction and the additional concurrent-read
  regression.

No protection profile, sensor cadence, model selection, or stored evidence
retention setting is changed. Version remains 1.13.0; this update does not build
or install a packaged release. A source application restart loads the fixes.
Publish only the reviewed files with the guarded GitHub publisher, verifying
the publishing branch, default `main`, and every public README image byte.
