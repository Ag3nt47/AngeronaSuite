# Runtime self-healing for Black Box findings

The existing module watchdog and process supervisors already recover module
and process failures. HEAL stages proposed source changes for review. This
update fills the gap between those mechanisms: the status reporter and the
asynchronous flight recorder are application-owned background services rather
than protection modules.

`RuntimeHealer` uses direct service health probes and fixed repair methods.
Its controller confirms repeated faults, limits attempts, backs off, respects
shutdown, and observes health independently after requesting a repair. It
keeps bounded component state, cumulative service failure evidence, and recent
actions. Status reporting and Black Box expose requested, observed, exhausted,
and unavailable recovery states without granting diagnostics response authority.

The reporter now retries its intended diagnostic path after initial directory
creation failure, recreates missing directories, preserves atomic replacement,
and owns all recovery writes on its worker. Repeated starts cannot duplicate
workers. Automatic recovery cannot undo an explicit stop. The recorder starts
only a dead primary/overflow worker while retaining its live peer and queues;
it refuses to reopen a shutdown that is still draining.

Historical event-bus inactivity was a reporting classification issue, not
proof of a stalled dispatcher. Historical Ollama/model and Defender problems
cross trust/custody boundaries. This update does not reset or re-enroll that
state, clear prior findings, or claim complete event continuity after a crash.
See [automatic runtime recovery](../docs/self-healing.md) for operation and
limits.

Validation exercises confirmed failures, cooldown/exhaustion, health stability,
probe errors, shutdown races, actual daemon lifecycle, dead peer replacement,
queued signed-event delivery, directory/write recovery, redirection refusal,
quiet-mode cadence, current-process Black Box presentation, and existing
recorder, startup, shutdown, status, and watchdog behavior. Live production
workers and protected runtime evidence are not fault-injected during testing.

Verified results in an isolated checkout containing only this update:

- Focused recovery, recorder, Black Box, status, lifecycle, event-bus, and
  watchdog regressions: 175 passed, 1 platform skip. The skip is unavailable
  Windows directory-symlink creation; deterministic reparse-point and real
  hardlink refusal checks passed.
- Full offline selfcheck: 26 phases passed, zero failures. Module and event
  pipeline checks: 69 passed, zero failures, 16 expected optional/platform or
  unstarted-module skips. These skips do not certify live dependencies.
- Package syntax, changed core/test Ruff checks, Git whitespace, and offline
  documentation validation passed. Independent review found no material issue
  in lifecycle locking, failure admission, peer preservation, or fresh-status
  presentation.

Unrelated GitHub-tool and analysis-lab changes in the maintainer checkout were
excluded from the reviewed commit and clean publication checkout.
