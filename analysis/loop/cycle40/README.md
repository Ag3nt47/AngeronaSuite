# Cycle 40 — CI cleanup and incremental presentation

Date: 2026-10-02. Source version: 1.13.0.

## CI evidence and repairs

GitHub run [36896881189](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/36896881189)
failed on published commit ada57824918e52626f573ea5cca917801837bb2c.
Python 3.12 passed 4440 tests with ten skips, but fixture teardown failed with
WinError 145 in `failed-commit-runtime`. Python 3.13 passed 4439 tests with
ten skips, but the plain VMware custody fixture exceeded its 90-second bound.
All other jobs, including Python 3.10/3.11 and platform contracts, passed.

Red Team fixtures now capture their owned module threads before lease release
removes temporary producers, signal every captured module, and join them under
one ten-second deadline before closing the recorder. `BaseModule.stop()` stays
nonblocking. Teardown failure remains visible if a worker cannot finish;
cleanup errors are not ignored. A delayed final-write regression proves a
lease-removed producer finishes before its fixture can be removed.

The VMware PowerShell fixture now uses a private TEMP/TMP directory. It retains
the real Add-Type compilation, directory handles, rename challenge, reparse and
hidden-file cases, and host-service modification prohibitions. Phase markers
and bounded stderr survive a timeout without printing the encoded command.
The 90-second limit remains. The original remote timeout did not identify its
phase, so private temporary storage is a stabilization candidate, not proof of
the timeout's root cause. New remote CI results are required.

## Continued UI performance work

Module-row rendering avoids redundant flag, check-state, color, tooltip and
numeric sort-role mutations. A tooltip-only update now emits one underlying Qt
model change; the separately loaded published renderer emits two and fails the
new regression. This measures notification work, not whole-application latency.

Focused validation: 33 Red Team/VMware tests passed, followed by 18 module-table
and delayed teardown checks. Full exact-commit validation and guarded GitHub
publication are required before completion.

The first full gate on 10a3464 failed: 4425 passed, 23 skipped, four failures
in 1666 seconds. The native QEMU fixture compared the redirected C: interpreter
path with Windows' physical D: image. It now resolves the launch path before
the exact image/PID assertion. The assertion-only observer child exceeded 60
seconds; isolated observer probes now disable unrelated pytest plugin autoload
and use private TEMP/TMP, retaining the explicit observer and all assertions.
These four focused native/observer cases passed after correction.

Both live containment profiles also left queued responses beyond their original
deadlines in that full run. Both passed an isolated follow-up with unchanged
deadlines. A separate host migration was copying data; one disk sample showed
D: queue length eight and approximately 82 MB/s throughput. Contention is a
plausible contributor, not exclusive causal proof or a repaired performance
defect. No journal fsync, custody check or containment assertion was removed.
Failed evidence remains in `.tmp/cycle40_release_evidence.json` and its JSONL
journal. The corrected commit requires a fresh whole-suite gate.

## Remaining limits

Cycle 39's full local gate passed 4427 tests with 23 skips and publication
verified all five README images. That local pass did not prevent these remote
CI failures. Chill/Full stress pauses, variable native simulation scores and
the earlier unexplained Qt abort remain open. This cycle does not claim a
native coverage score or repair of all mode freezes.
