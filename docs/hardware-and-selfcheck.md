# Hardware adaptation and self check

Angerona adjusts routine background work and presentation refreshes when the
host has little spare capacity. This helps keep older computers usable while
preserving explicit evidence about checks that did not run or complete. The
changes ship as maintenance to v1.13.0.

## Running on a smaller computer

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

The footer's **Angerona pace** describes the requested routine work budget.
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
offscreen using disposable state. It does not start live sensors or native
Ollama, and does not perform real containment actions.

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
[October 18 engineering review](../analysis/hardware-adaptation-2026-10-18/README.md).
Virtual profiles are distinct from actual performance measurements. Physical
low-memory machines, extended all-sensor sessions and native response efficacy
require their own validation.
