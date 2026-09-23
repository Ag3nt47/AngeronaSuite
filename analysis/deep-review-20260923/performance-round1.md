# Idle / Chill performance and adversarial resource use — round 1

Date: 2026-09-23. Baseline: `7b7b264`. This is a new review; historical
`analysis/loop/state.json` still describes completed cycle 34. No sensors,
native defenses, inference or operator settings were started/changed by the
performance investigation. The coordinating agent owns GUI work, live
diagnostic interpretation, aggregate validation and publication.

## Confirmed causes and applied fixes

### 1. Unconfigured Detection Runtime copied every event

The always-enabled runtime starts with no active or shadow rules. Nevertheless,
its synchronous EventBus callback copied each event's nested details, generated
two JSON strings, hashed the identity, and populated two bounded identity maps.
This work ran on the publishing thread even though no evaluator could consume
the result. AI-generated event floods amplified that wasted work and retained
thousands of diagnostic identities in an otherwise unconfigured engine.

Live module ingress now observes whether either lane has configured rules under
the existing engine lock. If neither does, it increments the explicit
`unconfigured_events_skipped` snapshot counter and returns before normalization.
The original event remains unchanged in EventBus history and is delivered to
storage and every other subscriber. Direct `engine.submit()` retains its full
validation/collision diagnostics. Configured active/shadow admission, authority
revalidation, active priority, loss counters and processing cadence are unchanged.

Configuration is observed at the admission boundary. Activation already clears
previous-epoch queues; the first event after activation is admitted normally.
The skipped count describes absent configuration, never lost configured coverage.

Status: **APPLIED**. Three 20,000-event INFO/HIGH/CRITICAL fixtures retain zero
idle identity-map entries, report exact skip counts, deliver every original
event to another subscriber, and preserve the bounded priority-history overflow
signal. Activation and active-versus-shadow flood fixtures pass.

### 2. Nested oversized input expanded before rejection

Each nested container had a 256-entry limit and depth was limited, but those
local limits did not bound total work. A compact aliased Python structure or a
large structured AI transcript could expand into megabytes of normalized data
and JSON before the final 256 KiB event limit rejected it. This was synchronous
work on the same publisher path.

Normalization now shares one cumulative budget throughout recursion. It charges
a conservative lower bound on normalized JSON size, stopping oversized expansion
early. The exact serialized-byte limit still runs afterward. String truncation,
nesting/container rules, event identity construction and admitted content are
preserved. Details themselves now have a total normalization bound, including
reserved fields later replaced by canonical event metadata. Oversized ignored
fields therefore cannot demand unlimited identity-hashing work. Rejections remain
explicit in `invalid_events_rejected`; the original EventBus event is untouched.

Status: **APPLIED**. A 256-by-256 nested string fixture is rejected before 100
element visits. A separate benchmark verifies 128 accepted fixture events retain
byte-identical normalized JSON, event identifiers and identity digests across
the baseline and changed implementation. Shadow floods cannot consume active
slots; exact configured-lane drop counts remain visible.

### 3. Degraded health repeatedly resolved identical source paths

Every degraded-health report proves its source provenance. For ordinary imports,
the candidate source path, loaded module filename and import-spec origin are the
same canonical absolute string, yet all three were separately resolved strictly
on disk at every report. The shared implementation affects every module which
reports degraded health, including unbound/missing-provider idle modules.

The source candidate is still strictly resolved, stat-checked and compared with
its source manifest and exact code object. Identical filename/origin strings
reuse that resolution. Different/aliased strings still receive strict resolution
and the same identity checks. No source-provenance cache lifetime is extended.

Status: **APPLIED**. Existing trusted-callsite, forged/external-code, source-less
and all-built-in health-schema regressions pass. The benchmark exercises a real
loaded implementation's repeated incomplete-coverage reporting after warming its
source manifest; it does not mock away path validation.

## Measurements

Reproduce with the worktree `src` on `PYTHONPATH`:

`python tools/benchmark_idle_admission.py --baseline-ref 7b7b264`

The committed JSON result is `performance-benchmark-round1.json`. Timings use
three-repeat medians on Python 3.12.10. Allocation peaks use a separate
`tracemalloc` pass. Fixtures are inert; results are not a whole-PC CPU comparison
or a sustained physical-host soak.

| Fixture | Before | After |
| --- | ---: | ---: |
| 3,000 unconfigured module callbacks | 739.411 ms | 42.840 ms |
| Identity entries retained after those callbacks | 6,000 | 0 |
| Oversized 4 MiB nested transcript rejection | 216.304 ms | 0.140 ms |
| Peak traced allocation for oversized rejection | 8,212.1 KiB | 7.4 KiB |
| One repeated degraded-health report | 5.2926 ms | 1.8621 ms |
| 1,000 ordinary configured-event normalizations | 177.837 ms | 217.395 ms |

The additional admission accounting has a measured ordinary-normalization cost
in this run (about 40 microseconds/event, 22%). That explicit tradeoff bounds
adversarial expansion. The dominant unconfigured callback path is about 94%
faster, and the repeated health fixture about 65% faster. Timing varies with
host contention; no fixed production percentage is promised.

## All 84 modules: Chill cadence audit

`module-cadence-round1.json` enumerates every one of the 84 catalog classes from
the existing discovery audit. Each row includes exact source/class identity,
default enablement, Chill park/floor policy, every declared `self.sleep()` call
outside self-tests, literal/constant resolution where possible, and source-level
process/network/subprocess/file/SQLite/subscription markers. It is a static
inventory, not a claim that all 84 workers run on this Windows machine.

The policy parks **19** catalog modules; **65** are not in the parked set, with
**11** receiving cadence floors. Platform, opt-in and operator enablement gates
further reduce running counts. Dynamic expressions remain explicit rather than
being presented as measured intervals. Native callback waits and work duration
are not inferred from `self.sleep()` alone.

Remaining concrete collection overlap: the live LSASS guard enumerates rich
process metadata every 3 seconds, the recovery guard every 2 seconds, and Process
Monitor normally every 6 seconds under its 2x Chill floor. ETW/Sysmon fallbacks
and the resilience scanner can also enumerate processes. WFP has an independent
connection-table collection path. Shared connection consumers already use the
existing short-lived cache. These source-level overlaps warrant profiling, but
changing freshness or moving detection onto cached data requires separate
coverage/identity evidence and was **not applied** in this round.

The coordinator reported a historical diagnostic snapshot with Chill false,
70/73 modules running, 4,224 event revisions, 76,023 subscriber deliveries and
2,746 callback-budget violations. No live Angerona process was available for
this review. That snapshot cannot establish current idle load or prove which
subscriber caused the PC-wide slowdown; GUI diagnosis belongs to the coordinator.

## Gates and handoff

- The initial targeted admission/runtime/provenance suite passed **37 tests**.
- The additional authority, governor and Chill suite produced **58 passes,
  1 platform skip and 1 snapshot assertion requiring the new diagnostic field**.
  That assertion now permits exactly one additional unconfigured online event
  after restart while requiring every authority/rule/epoch/queue field to remain
  identical. Its complete file then passed **22 tests**. Across the distinct
  targeted cases, the result is **96 passed, 1 skipped**.
- All five changed/new Python files passed compilation and scoped Ruff;
  whitespace checks passed. The Detection Runtime self-test is included.
- No full-suite or long-session soak claim is made. Final regression and
  publication are the coordinating agent's responsibility.

Owned product files: `src/angerona/modules/detection_runtime.py` and
`src/angerona/core/module_base.py`. Support files: the new admission regression
file, one existing authority-test assertion, benchmark tool and three dated
analysis artifacts. No EventBus, sensor cadence, governor or Chill policy edits
were required for these measured fixes.

| Optimization | Component | Status | Expected/measured win |
| --- | --- | --- | --- |
| Skip payload work with no configured evaluator | Detection Runtime | APPLIED | 94% less fixture callback time; no idle identity-map growth |
| Bound recursive normalization before expansion | Detection Runtime | APPLIED | 216 ms to 0.14 ms rejection; 8 MiB to 7.4 KiB peak allocation |
| Reuse identical canonical path resolution | Shared module health | APPLIED | 65% less fixture degraded-health reporting time |
| Broader fresh process/connection collection sharing | Live sensor collectors | PROPOSED | Potential OS enumeration savings; no freshness change authorized by evidence yet |
