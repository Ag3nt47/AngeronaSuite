# Simulation, scanner, sandbox and Black Box review

9 October 2026; maintenance on v1.13.0. No capability-count change.

## Latest operator report

Read-only verification against the installation's existing authority found:

- Today's signed `redteam_history.json` was generated at 08:42:39 local time.
  The comprehensive four-cycle campaign planned 80 mandatory steps, including
  76 detection contracts. It recorded 27 steps, of which 26 executed successfully,
  before stopping after 354.97 seconds at WMI Lateral Movement with
  `RedTeamValidationError: validation producers are no longer live`.
  The manifest is incomplete and explicitly ineligible for scoring. Executed
  steps are not detection or containment receipts.
- Today's signed `shark_history.json`, generated at 08:39:41, recorded 22 steps,
  19 successful. Three BYOVD exercises failed with an existing fixed marker path.
- No finalized October 9 after-action report was available. The latest verified
  archived/final Shark AAR was September 23 (0/16 detected and no verified
  responses). Those old results do not describe today's incomplete run.

Raw reports, keys, full process command lines and private incident evidence are
not copied into this repository. A missing marker alone is not containment proof.

## Confirmed UI stalls and changes

The October 9 watchdog captured the GUI thread inside
`MainWindow._run_simulation -> acquire_redteam_validation_lease -> time.sleep`.
Both dashboard and simulation windows share that thread. Target preflight,
runtime watch enrollment, detector/recorder readiness waits and engine startup
now execute in one detached launch job. Qt displays preparation state and polls
for an explicit handoff. Duplicate launch is blocked while preparation or
cleanup owns the run. Cancellation or owner destruction before acceptance makes
the worker release its lease/watches, restore the previous temporary policy and
clean its own engines. Stop cleanup also runs off Qt, and cleanup errors remain
visible instead of being reported as success. The legacy entry point uses the
same path. Selected exercises, response authority and signed scoring stay intact.

Full-suite integration also exposed a reproducible Flow window lifetime bug:
the unowned initial AI-poll timer could start an Ollama worker after the window
had accepted close. Qt later aborted when that running thread lost its owner.
The initial timer is now owned and cancelled by the window, a closing latch
prevents late starts/results, and an active worker retains the existing deferred
close handling. Failed starts release the loading state and permit a retry.
Four inert regressions cover these cases without contacting a model service.

Shark now retires its run registration/running flag if its worker cannot start.
Each BYOVD phase receives a unique 32-hex marker suffix instead of exclusively
recreating the same pathname. The detector recognizes only the legacy name or
that exact generated form; practice/response authority still requires registered
identity and content proof. Existing files and replacement/hardlink aliases
remain protected by the original exclusive-create and cleanup checks.

Black Box's firewall refresh previously ran up to two blocking external commands
on its GUI thread. Firewall and SOAR snapshots now use bounded single-flight
background readers; failures retain the previous snapshot. Firewall enum parsing
accepts normal string values, and duplicate display names retain their exact rule
identity after sorting. SOAR reads at most the latest 1 MiB and presents 200 valid
records; malformed records cannot abort the view.
Firewall subprocess output is capped at 4 MiB before parsing; timeout, overflow
and unsuccessful exit preserve the prior display. Only owned subprocess custody
is retired. Snapshot/table limits are visible instead of implying full coverage.

Black Box log tails drain at most 16 KiB per file per poll, without altering or
skipping source evidence. Large crash snapshots show a labeled 64 KiB preview.
The log view avoids expensive wrapping of long trace lines. Process discovery
queries command lines and memory only for candidate interpreters. CPU sampling
retains the previous psutil sample only for the same PID and creation time;
recreating that sampler every poll previously displayed zero CPU.
Per-file incremental UTF-8 decoding and bounded classification context preserve
characters and critical markers across chunk boundaries; rotation resets both.

## Scanners

- Standalone telemetry scanner: rejects non-finite/non-positive intervals and
  bounds tiny intervals; stop interrupts long sleeps; a sensor exception closes
  heartbeat/ring handles. A host can run only once. GUI setup completes before
  starting the sensor, so a presentation failure cannot fall through into a
  second sensor loop. Backpressure avoids expensive command-line/executable
  enrichment for observations that would immediately be discarded.
- YARA module: directory enumeration and metadata inspection now cooperate with
  the existing responsiveness governor, not just the subsequent file scans.
  Cancellation does not advance a cursor or publish a completed scan cycle.
  Partial inventory remains explicitly incomplete. Native scanner ownership and
  signed cursor contracts remain intact.
- Scan Center: directory and file batches yield under governor pressure, with
  cancellation checked immediately afterward and the original wall deadline
  preserved. A thread-start failure now releases the busy/loading state.
- Memory Injection Scanner: reviewed existing process/region budgets, generation
  cancellation, cooperative checkpoints and explicit partial-coverage accounting;
  the focused lifecycle regressions passed. No speculative rewrite was made.

Inventory review also found a driver collector with up to 55 seconds of bounded
native work inheriting a 30-second startup/work watchdog budget. Its declared
budget now accounts for that collector, preventing premature recovery retries
while retaining a finite watchdog limit. Routine network-trust inventory opts
into existing background pacing; its route query selects default prefixes at
the provider. Evidence is collected fresh; stale observations are not reused as
trust. Duplicate cross-module boot-posture queries remain a future optimization
requiring explicit freshness/error semantics rather than an unreviewed cache.

## Sandbox

The editor retires completed Qt workers before another test, validates the opened
buffer rather than a newly selected unrelated module, and retains undo entries
when a revert fails. Source reads/writes are limited to 4 MiB with file identity
rechecks. Session undo is capped at 20 copies/16 MiB; history retains 200 entries
per module and the console 1,000 blocks.

Trusted baseline self-tests use existing child-custody helpers: a suspended
Windows child enters a Job before it receives its startup token; POSIX uses a
separate process group and resource limits. Output and cleanup waits are bounded,
and descendants are retired on completion or timeout. The supplied source root
is absolute and independent of the trusted harness bootstrap. Candidate code is
still AST-only; this is not a hostile-code execution sandbox. Working copies do
not overwrite production sources. Source open/save remains bounded synchronous
I/O, and AST parsing has an input-size bound rather than a CPU deadline.

## Validation and remaining limits

Focused regressions cover Qt heartbeat progress during blocked preparation,
cancellation before/after engine start, duplicate launch, owner deletion, failed
worker starts, cleanup error reporting, log bursts, process identity, scanner
cleanup and pacing, wrong editor selection, repeated tests and isolated child
output/descendant cleanup. The final ordinary Windows run of
`python -m pytest -q` passed **4,852 tests**, with **23 explicit skips**, in
683.08 seconds (4,875 collected; exit 0). It completed without a native abort.
Full source/test/tool compilation, fatal Ruff checks, documentation drift and
Git whitespace checks also passed.

Integration exposed three test-fixture assumptions after the Flow crash was
fixed. The GUI clickthrough now waits for the accepted asynchronous handoff and
checks its exact run ID before inspecting the report. The Defender tamper test
now proves a genuinely authenticated cursor exists before changing its parsed
record ID while retaining the original HMAC; the prior literal replacement could
leave an empty cursor unchanged. The storage classification fixture enumerates
its fresh empty directory before taking the assessment baseline: this Windows
host exposed a transient attribute change before enumeration. Production cursor
authentication and full directory-identity checks were not weakened.

Both disposable GUI campaigns passed the existing 37/37 verified-containment
contracts, including independent file/process witnesses and signed AAR checks.
The native-analytic count remained 0/37. These controlled test results do not
rescore the operator's incomplete campaign or establish real-world efficacy.

The isolated `tools/selfcheck.py` harness passed all 26 phases, with 67 module
and pipeline checks passing and 18 explicit environment/integration skips.
Its disposable 30-step drill completed and cleaned its own artifacts. It did not
start the operator's production modules or an external model service.

The master manual now includes an October 9 operator update covering preparation,
cancellation, bounded diagnostic displays, scanner pacing and sandbox limits.
Its historical chapters retain their dated evidence; current publication and CI
remain tied to the exact commit rather than a manually copied historical total.
The 47-page DOCX was rendered and checked: 22 pages were byte-identical to the
previously approved render, and all 25 changed/new page images were inspected.

Publication uses `tools/publish_github_update.py` to prove the canonical origin,
fast-forward-only default-branch update, clean checkout and six public README
image matches. The exact published commit's CI and Security assurance runs are
the current remote validation record; historical totals above are local evidence.

This review establishes specific blocking paths and failure cases; it does not
establish a maximum latency for every Windows driver, native call or heavily
loaded computer. Other October 9 watchdog samples stopped inside the native Qt
event loop, including a 60-second Black Box stall. A short host sample also
showed significant Windows service/WMI load. Those samples alone do not identify
which component caused that load. Validation producers must remain live for a
scoreable run; their liveness/authority checks are not bypassed to force a pass.
