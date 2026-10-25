# Hardware adaptation and self check

Angerona adjusts routine background work and presentation refreshes when the
host has little spare capacity. This helps keep older computers usable while
preserving explicit evidence about checks that did not run or complete. The
changes ship as maintenance to v1.13.0.

## Running on a smaller computer

### Chill mode

Keep the **CHILL** toggle on for the lowest optional activity. The saved start
preference is in **Settings → Start in Chill Mode**. The following intervals
apply while Chill is quiet; a threat can wake security modules independently.

| Work | Foreground Chill | Background Chill | Hidden/minimized Chill |
| --- | --- | --- | --- |
| Dashboard presentation tick | 15 seconds | 30 seconds | 60 seconds |
| Dashboard panels | 30 seconds | 60 seconds | 120 seconds |
| Posture display | 60 seconds | 60 seconds | 120 seconds |
| Optional flow-canvas file | 5 minutes | 5 minutes | 5 minutes |
| System Pulse sample | 30 seconds | 60 seconds | Suspended |
| Shared investigation-view refresh | At least 15 seconds | At least 30 seconds | Suspended |

If the System Pulse card itself is hidden while the dashboard stays visible,
its sampler can still serve the visible footer. Hiding or minimizing the whole
window suspends that sampling timer.

Slower views retain their previous data between updates. Manual initial reads
and buttons keep their own response path. Cosmetics, ribbon motion and the
30 Hz FPS sampler stop in quiet Chill. Other visible optional timers request an
eightfold interval, capped at five minutes added; background windows
may double that display interval further. This is scheduled work reduction,
not a measured CPU percentage.

**Local AI stays off for the entire time the Chill toggle is on.** This
includes `CHILL: ALERT`: escalation enables security sensors while keeping
Ollama startup, inference, streaming, embeddings and model-management requests
blocked. ARIA reports that Chill must be switched off manually. Self-check
records an explicit AI skip and cannot override this selection. Automatic
cooldown, threat events and drills cannot unlock AI.

Automatic core recovery also starts in Chill, including updated Python and
native Go watchdogs launched earlier in Full. Engine services always start in runtime
Chill, including restarts from older service definitions without a `--chill`
argument. Select Full manually afterward if local AI is wanted. Normal manual
desktop/headless launch still follows the saved start preference; an explicit
`--chill` overrides it for that run without saving a new preference. Attaching
the engine console with `--chill` also selects runtime Chill in an existing
engine.

Native Go supervisors must be rebuilt and redeployed to receive this policy;
an older running supervisor keeps its existing executable until replaced.

Entering Chill requests release of resident Llama/configured models, then stops
Ollama services launched and retained by this Angerona process. It retains a
service handle if exit cannot be proved. It does not kill a separately launched
or shared Ollama daemon; another application can still use that daemon. Native
runner/GPU release is dependent on the local service and is not established by
the offline fixtures. No new Angerona request can start or load a model while
the lock remains set.

Routine batches voluntarily yield with bounded pauses of up to 50 ms even on a
healthy host; disabling adaptive pressure feedback does not disable explicit
Chill policy. All selected work is retained. A native call cannot be preempted,
so this does not enforce a process CPU quota. HEAL keeps pending AI diagnoses
until Chill is manually switched off. TUNE's optional learning cadence becomes
64 seconds instead of 8 seconds.

The event recorder waits up to five seconds on an empty queue, with an arrival
waking it immediately. The first event still starts its original 100 ms batch
flush deadline. Empty dead-letter replay checks occur at most every 30 seconds;
forced replay and shutdown drain remain available. These delays affect queued
replay and presentation freshness, not signed event admission or threat wake.

### Adaptive pressure feedback

Leave **Settings → Appearance → Adaptive routine scan pacing** enabled. The
existing controller now receives RAM and host CPU observations from Adaptive
Resource Governor as well as dashboard responsiveness feedback. It reuses the
governor's sampler and also works with a headless engine when that module is
enabled. An unavailable or disabled sampler cannot supply fresh observations.

| Observation | Requested routine pacing ceiling |
| --- | --- |
| RAM use at least 85%, or available RAM at most 512 MiB | 4 times the normal interval |
| RAM use at least 92%, or available RAM at most 256 MiB | 8 times the normal interval |
| Healthy feedback after pressure | Gradual recovery toward the normal interval |

Pressure from several sources combines by the greatest requested level.
Interval additions remain capped at 30 seconds. Active routine batches keep
their cooperative elapsed-work checkpoints and bounded, interruptible pauses.
An individual native operation can still take longer than a work slice.

The footer's **Angerona pace** describes the adaptive pressure-feedback budget;
Chill adds a separate optional-work budget and display policy.
It does not measure CPU use, completed scans, or protection coverage. Slower
routine inventory can discover changes later. Streaming event delivery,
response actions and watchdogs retain their own cadence.

Close or minimize unused investigation windows. Detail dialogs, Attack
Heatmap, Top Talkers, Resolve Center, Operations Center metrics, Flow and
WorldView diagnostics, and recurring status animations suspend their
presentation timers while hidden or minimized. Visible refreshes also follow
the pressure controller. Showing a view resumes its requested timer; a timer
explicitly stopped by its owner stays stopped. Existing evidence collection
and asynchronous job completion remain independent of these display timers.

Shared snapshot readers also reduce polling while a read is slow: their timer
backs off from 40 to 80, 160 and then 250 milliseconds, and a fresh request
starts at 40 milliseconds again. This reduces steady scheduled polling from
25 to 4 times per second. A completed read can wait up to the next scheduled
poll, and a busy Qt event loop can delay that poll further.

Entropy processing no longer wakes repeatedly when its input queue is empty.
CPU-only NumPy processing counts the fixed byte domain instead of sorting
each input. The Python fallback reuses identical results within a batch while
retaining every output; it keeps no cache between batches. CUDA, NumPy and
Python remain optional execution paths; this
update does not require a newer GPU or change the supported operating systems
and Python versions.

## Checking the installation

Run `run-selfcheck.bat` from the installation directory. It writes
`selfcheck_report.txt` and returns a nonzero exit code for an unexpected
failure. The harness constructs the application and investigation views
offscreen using disposable state. It does not perform general host sensor
collection or start native Ollama, and grants no host-containment authority.

Its owned-controls drill supplies a fresh immutable empty general inventory
only within a disposable workspace `.tmp` profile, with no previously running
Process Monitor. The real issuer lease, native reads of its tagged children,
artifact custody, drill assertions and cleanup remain. The exact supplier is
restored on success or failure. The report labels this fixture explicitly;
passing it does not prove complete host inventory or collector availability.
Only the drill's own inert controls may be created and retired.

The offline harness supplies a fixed loopback HTTP URL for its provider fixture
instead of inheriting `OLLAMA_HOST`. Ollama also uses that variable for a server
bind address, which need not be a client URL ([Ollama configuration](https://docs.ollama.com/faq#how-do-i-configure-ollama-server)).
This changes only the checker process; normal application settings and URL
validation remain intact. It neither starts Ollama nor adds an expected skip.

The module runner adds shared identity, metadata and health checks to each
selected module's existing self test. Results include durations and explicit
status. Runtime-disabled modules, unsupported platforms and narrowly
recognized offline prerequisites remain skips. A skipped capability has not
demonstrated operational readiness.

The checker is also challenged with deliberately passing, failing, crashing,
malformed and slow fixtures. It checks that the expected outcomes are
recognized and reconciles report counts with structured results. These
fixtures verify the checker's behavior and accounting. They do not establish
that a real detector recognizes every attack or that native enforcement works
on the current computer.

Self-test concurrency is bounded according to available resources and current
pacing. A timeout remains a failure; Python cannot safely kill an arbitrary
running thread, so timed-out calls keep their bounded permit until they exit.
Repeated tests cannot create an unlimited number of abandoned workers.

On Windows, deadline-bound isolated sandbox children explicitly use normal
process priority even when Angerona's parent process has below-normal
priority. This corrects the scheduling starvation reproduced with a
normal-priority CPU peer. The requested output deadline (ten seconds in the
regression fixture), process-tree cleanup and memory/process/CPU limits remain
enforced. This selected child priority does not change Chill's optional-work
policy or permit local AI.

## Reproducing the engineering evidence

Use the installation's `venv/Scripts/python.exe` for these commands:

```text
venv/Scripts/python.exe tools/benchmark_hardware_adaptation.py
venv/Scripts/python.exe -m pytest -q
venv/Scripts/python.exe tools/compile_check.py src tests tools
venv/Scripts/python.exe -m ruff check src tests tools
venv/Scripts/python.exe tools/validate_documentation_drift.py
```

The hardware benchmark injects resource observations and work costs into a
virtual clock. Its healthy, low-available-RAM, severe-RAM and severe-CPU
profiles all complete the same work and verify recovery. Optional
`--output FILE` and `--inventory-output FILE` save scheduling results and a
hashed inventory of every module and GUI source file. Static call-site counts
include helpers and inactive paths; they are an inventory, not runtime
coverage or proof that every source file needed an optimization.

Measured component results and validation outcomes are recorded in the
[hardware review](../analysis/hardware-adaptation-2026-10-18/README.md) and the
[Chill follow-up](../analysis/chill-efficiency-2026-10-18/README.md).
The [October 21 timeout investigation](../analysis/timeout-rootcause-2026-10-21/README.md)
records controlled scheduling and native permission measurements together
with complete regression and offline self-check results.
Virtual profiles are distinct from actual performance measurements. Physical
low-memory machines, extended all-sensor sessions and native response efficacy
require their own validation.
