# Read-only review follow-up: Black Box process attribution

## LD-RT-04 — Black Box can attribute another profile's process to its recorder

- **Current disposition:** mitigated by SIDE-04 in the [issue register](README.md).
  Multiple independent matching cores now produce unknown identity instead of
  selecting by RSS. The 64 affected regressions passed. Single-core discovery
  is still advisory and does not prove data-profile ownership; explicit Live AI
  Review uses the selected PID and creation time. The original reproduction and
  stronger explicit-profile binding recommendation below remain evidence.
- **Original status:** OPEN at the time of this read-only handoff.
- **Severity:** LOW — diagnostic correctness and possible reviewer confusion;
  no response authority or arbitrary process execution was demonstrated.
- **Component:** `blackbox_recorder.py:367` (`find_angerona_pid`), especially the
  highest-RSS selection at line 402; callers include the health, thread,
  memory, resource and export views.
- **Description:** The recorder reads files from its configured data profile,
  but selects its OS process observations from all matching Angerona cores in
  the current process table. After removing a matching launcher's parent, it
  chooses the remaining core with the largest resident memory. The selection
  does not bind that core to the recorder's data profile or an explicitly
  selected PID and creation time. Two concurrent development/production
  profiles can therefore mix one profile's logs with another process's OS
  diagnostics. The separate `Live AI Review` connection correctly verifies its
  explicitly selected server PID and creation time and is outside this finding.
- **Proof:** An isolated Python process imported only the recorder definitions
  with a temporary data root. Its process-table dependency was replaced with
  two inert matching core fixtures representing different profiles. The
  recorder selected the other profile solely because that fixture's RSS was
  larger. No actual host process table was queried in this reproduction; no
  application was launched, signalled or terminated.
- **Impact:** An authorized reviewer can investigate the wrong process, infer a
  false resource correlation or include a different profile's process metadata
  in an explicitly exported diagnostic bundle. This is particularly relevant
  when an isolated developer observation runs beside an existing deployment.
  It does not establish that any historical incident was misattributed.
- **Recommendation:** Pass the intended core PID and creation time explicitly
  from the app to a newly launched recorder. Validate the OS process identity
  before every observation and retain that identity consistently across health,
  thread, memory, resource and export views. When no explicit handoff is
  available, use an exact, freshness-checked profile runtime-metrics/instance
  record and verify the live process generation. On missing, stale or ambiguous
  evidence, show **UNKNOWN** rather than select the largest process. Preserve
  the read-only recorder boundary; do not introduce a command channel or weaken
  protected storage ACLs.

## Observation and shutdown constraints

The app's single-instance lease is scoped to its data profile. Black Box uses
the session-wide `Local\AngeronaBlackBox` mutex, so an existing recorder can
prevent a separate recorder for a disposable profile. Do not bypass that mutex
or stop an unverified process to make the observation work. Its manually
connected Live AI Review pane or the standalone read-only CLI can still select
an explicitly identified live endpoint when available.

Closing Angerona's ordinary window minimizes it. The header's red STOP action
intentionally targets every Angerona instance and must not be used to stop an
isolated observation beside another deployment. Use the owned application's
per-instance shutdown path or a separately reviewed observation-wrapper Qt
shutdown hook, and verify the exact launched process identity. A Windows venv
launcher PID may differ from the actual GUI/diagnostic-server child's PID.

## Current review disposition

The three earlier LOW review handoffs are fixed in the current worktree:
substring-based Black Box launch suppression, short-log-line export
amplification, and missing integrity coverage for the canonical strict
allowlist predicate. The final narrow source re-review found no remaining
blocker from those three findings. The later SIDE-04 mitigation also removes
the reproduced largest-RSS ambiguity. Exact automatic single-core/profile
binding remains a follow-up, and this report does not claim all diagnostic
issues are resolved.
