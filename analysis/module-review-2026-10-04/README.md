# October 2026 module review and responsiveness maintenance

This review covers every Python file in `src/angerona/modules`: 87 files and
84 discovered capabilities. The [group A](group-a.md), [group B](group-b.md)
and [group C](group-c.md) matrices record each file's role, correctness and
security boundaries, performance behavior, test coverage and remaining limits.
It also follows relevant core lifecycle, event, response and GUI code.

The work combines source inspection with inert reproductions. It is not a
penetration test of an elevated live endpoint, an independent certification,
or a claim that every branch and native integration has been executed.

## Operator changes

- Adaptive routine scan pacing is enabled by default. A tiny 30-Hz dashboard
  paint heartbeat and existing CPU observations progressively delay routine
  scans under pressure and restore their pace after healthy feedback.
- Footer **FPS** shows actual heartbeat deliveries and percentage of the 30-Hz
  target. **Angerona pace** shows the requested routine budget at 100%, 50%,
  25% or approximately 13%. CPU usage remains separate. Pace is not a CPU
  reservation, measured throughput, or a percentage of security coverage.
- Existing individual module ribbons, manual scrolling and optional Orbital
  display remain available. Footer content reflows at narrow widths.
- Routine scan latency can increase when paced. Event delivery, streaming
  telemetry, response actions, watchdogs and direct self-tests are excluded.
  Settings > Appearance permits opt-out.
- The simulation sandbox editor initializes on first visit and performs file
  operations through one serialized worker. Failure retains the current buffer.

See [responsiveness evidence](../sustained-responsiveness-2026-10-04.md) for
timing boundaries, cache operation counts and host-profile limitations.

## Confirmed repairs

| Area | Reproduced defect and resulting behavior |
| --- | --- |
| Memory Time-Machine | A 257-process working set defeated the old 256-PID cache on every sweep. A wider bounded index eliminates repeated forwarding while preserving the aggregate fingerprint ceiling and retry after queue failure. |
| Floating-orb UI | A queued minimize callback retained a window after restore/deletion and could corrupt later Qt painting/garbage collection. The callback is now tied to the target window's lifetime, uses weak references and rechecks validity and state. An isolated subprocess reproducer protects the native crash boundary. |
| Dynamic Resource Governor | Routine event chatter raised the entire process priority. Only active HIGH/CRITICAL incident arrivals now count; stop/exception paths restore the exact prior priority after the worker retires. |
| Cloud corroboration | Non-object or malformed replies could terminate the worker. A bounded typed verdict is required before use. |
| Combat rollback | Partial firewall mutations and uncertain process suspension could be terminalized without verified compensation. Uncertain effects retain recovery authority and block further mutation; failed firewall queries cannot prove absence. |
| Evidence Lattice | Remote observation could contribute local process response authority. Remote-observe-only evidence is excluded from local response correlation. |
| Defender telemetry | A live log replacement could move beyond the old record ID without reporting continuity loss. Live anchor validation detects replacement rather than silently accepting the next page. |
| FRZ heartbeat | Watchdog liveness overwrote repeated heartbeat-write failure with healthy status. Failed writer health now persists until successful recovery. |
| Forensics | Failed socket collection looked complete; failed memory reads bypassed the work budget. Exit status and attempted-byte accounting preserve incomplete coverage. |
| Network Monitor | Incomplete typed snapshots looked healthy. Health now follows receipt completeness and recovers only on a complete snapshot. |
| Process identity | Process Monitor preferred a stale parent cache; memory alert cooldown keyed only on PID. Current parent data takes precedence and cooldown binds process birth. |
| Provenance graph | The cycle-prevention ancestry direction was reversed. Cycles are rejected and legitimate transitive links retained. |
| SOAR delivery | Retry keys survived eviction from the bounded evidence bus. Retry state follows the retained snapshot and bus identity while keeping existing attempt limits. |
| Mobile bridge | ECO slowed the FRZ heartbeat beyond its freeze threshold. Only trusted, explicitly eligible capabilities are paced; flood token state is capped without revoking issued authority and expiry sends are aggregated. |
| Intel self-test | A fixture snapshot could overwrite an interleaved real feed refresh. Self-test now validates local immutable data without changing published IOC state. |
| Smart Deception | An in-flight name request could deploy files after stop. Generation checks prevent late work and the retiring worker owns exact-artifact cleanup. |

The new regressions use mocked OS actions, inert event streams and temporary
artifacts. Existing authorization, custody, signature and recovery tests remain
active. No policy change makes model output or a remote observation an
independent permission to mutate the host.

## Validation

- Coverage check: all 87 module filenames occur in exactly one assigned review
  matrix, 29 per group; no file is omitted.
- Offline selfcheck: 26 phases passed, zero failures. Of 84 discovered modules,
  66 passed and 18 had declared capability/inactive skips; the synthetic event
  pipeline also passed (67 passes in the combined runner).
- Compileall and Ruff's fatal rule selection passed across `src`, `tests` and
  `tools`; documentation drift and patch-whitespace checks passed.
- The updated master manual was rendered and all 45 pages visually inspected.
  The final subsection pagination change affected only pages 10 and 11; those
  were re-inspected and the other 43 PNGs were byte-identical to the reviewed
  render. Standard and Orbital public screenshots contain synthetic data only.
- Final local Python 3.12 suite: **4,649 passed, 23 skipped, zero failures** in
  719.68 seconds. The verbose, fail-fast run completed successfully after the
  floating-orb repair; no GC checks, assertions or regressions were disabled.
  Exact-commit CI and publication are verified separately through the guarded
  publisher and [GitHub Actions](https://github.com/Ag3nt47/AngeronaSuite/actions).

Targeted results and exact limits are retained in each group report; overlapping
test selections must not be added together as a unique test total. An earlier
full-suite run exposed the floating-orb native lifetime defect above;
its small reproducer and regression now pass before the final suite rerun.

## Remaining work and deployment limits

The review intentionally records findings that were not silently hidden by a
green test result. Priorities below describe follow-up engineering work, not
claims of an observed compromise.

- **Sustained retention and work:** ARP unapproved-pair deduplication and Purple
  marker-generation history can grow with churn. Shadow Shield needs an explicit
  recovery retention budget before old versions can be deleted. ETW's durable
  high-water verification rereads growing authenticated history; an optimization
  needs a reviewed authenticated checkpoint design, not bypassed verification.
- **Query memory limits:** Flight Cache bounds rows and SQLite VM work but not
  a generated result cell before allocation. Python 3.10 lacks the standard
  SQLite length-limit API available on newer supported runtimes. No production
  caller of arbitrary SQL was found; a portable engine-level design remains open.
- **Coverage and advisory behavior:** Some MITRE list metadata is not consumed
  by summary modules. Attack-feed replacement and inference-port attribution
  have documented correctness limits. Daily Briefing's optional advisory model
  path needs the same attestation/guardrail contract as the stricter triage path.
  These findings do not grant host-response authority.
- **Shutdown and throughput:** Some transport batches and native calls remain
  blocking within their existing timeouts. Cooperative pacing cannot preempt
  them. Native sensor, locale, sleep/resume and sustained elevated all-module
  testing remain required to measure actual endpoint behavior.

The module matrices contain further per-platform and per-feature limitations.
No existing recovery version or evidence journal was deleted to make this
maintenance appear faster. Private local diagnostics were used only as local
evidence and are not published.
