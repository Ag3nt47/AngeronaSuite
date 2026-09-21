# Machine-aware modules and long-session maintenance — 2026-09-21

This maintenance round reviews all **84 discovered capabilities**, improves
their shared usage/lifecycle policy, and patches module-specific defects where
the reviews found evidence. The product remains **v1.13.0**. A catalog entry is
not proof that a sensor is applicable, running or healthy on this machine.

## Runtime behavior

Dashboard, Live Defense, status output and other running-module totals use
**running / enabled for this machine**. The catalog remains available for
inspection. Unsupported platforms, saved module opt-outs and explicitly
unconfigured optional integrations are excluded from the runtime denominator.

| Condition | Runtime behavior |
| --- | --- |
| Mobile integration off in Settings | Mobile Response Bridge stays off and is excluded. |
| eBPF integration off in Settings, or unsupported platform | eBPF Sensor stays off and is excluded. |
| Active Response SOAR not armed by operator policy | The active-response worker stays off and is excluded. This is separate from the SOAR review/automation capability. |
| AngeronaSensor service positively absent | Optional Kernel Bridge stays off by default. Explicit selection requests it; installation-probe errors do not establish absence. |
| Enabled sensor fails or lacks required evidence | It remains expected and visible as a coverage gap. |
| Enabled worker paused/deferred by resource policy | It remains in the enabled total. |
| No USB device attached or WLAN link connected | Hotplug guards remain applicable so they can detect subsequent arrivals. |

The usage gate preserves saved operator choices. Optional-policy changes are
reconciled without adding a polling thread. The installation check occurs at
discovery, not on each display refresh. Counts are operational information and
do not grant response authority or improve an assurance score by themselves.

## Findings and changes

| Area | Result |
| --- | --- |
| Shared startup and wake/repair | Every staged start rechecks the registered instance, current enablement and lifecycle generation. GUI/headless Chill wakeups, maintenance, repairs and console restarts use current manager admission. Disabling a waiting module or shutting down cannot revive it from a stale startup list. |
| Disabled event consumers | Network Protocol Decoder, Provenance Graph, Speculative Triage, Flight Cache and Canary Drill reject stopped callback work. Speculative Triage retires pending work across generations. |
| AMSI Bridge | Native scan/context lifetime is serialized; stopping does not close a context still in use. Successful restart clears fallback. Native scan errors/closed contexts no longer report a clean verdict. |
| API Patch Detector | Alert suppression has bounded retention and expiry; a subsequent incident can alert again. |
| Process Monitor | Already-seen process identities skip command formatting; normalization is reused within each poll. The complete parent-name map is preserved. Process-generation and event behavior remain regression-gated. |
| Shared process/connection telemetry | Cache lifetimes use monotonic time, avoiding stale reuse or unnecessary collection after wall-clock corrections. Existing TTLs and completeness/error receipts are preserved. |
| Entropy self-test | Temporary fixture directories are scoped and removed after the test. |
| Public documentation | What's new follows the description and screenshot section. Existing screenshot assets and their paths are retained. |

The [exhaustive module audit](module-audit.md) and its
[machine-readable companion](module-audit.json) record every module's
prerequisites, baseline self-test and review disposition. Reviewed modules with
no reproduced module-specific defect do not receive cosmetic patches. The
shared usage and lifecycle changes apply across the managed catalog.

The [finding closure record](findings-after.json) maps both adversary findings
and all six bug-hunter finding groups to their fixes and regressions. Callback
findings overlap between the two reviews; they are not separate defect counts.

The [post-change usage inventory](module-usage-after.json) records all 84
capabilities under isolated default Windows settings: **73 enabled, 11 off**,
with no sensor workers started. Saved settings determine the actual runtime
total; this is an eligibility example, not a running-sensor measurement.

## Performance evidence

The inert benchmark uses 600 stable process records, five repetitions of 100
polls, and reports median loop time. It excludes operating-system process
enumeration and does not measure whole-app CPU use or a multi-day session.

| Fixture command length | Before | After | Loop-time reduction |
| --- | ---: | ---: | ---: |
| 16 arguments | 5.729 ms | 2.069 ms | 64% |
| 128 arguments | 19.904 ms | 2.199 ms | 89% |

The performance agent's **28 targeted tests passed**. See
[measurement details and limits](performance.md) and the reproducible
[benchmark](../../tools/benchmark_module_poll_efficiency.py). This round builds
on the separately published [session-efficiency fixes](../session-efficiency-2026-09-20.md).

## Validation record

The pre-change baseline compiled **377 files**, discovered **84 modules** with
no import/construction errors or duplicate declared CODEs, and passed **68
module self-tests**, **24 core self-tests** and the separate EventBus pipeline
check. **16 module tests were expected skips**, not passing live sensor tests.
The supported isolated selfcheck passed **26/26 phases**. Details and exact
baseline artifacts are in the [bug-hunt report](bug-hunt.md).

Post-change aggregate gates:

- Full pytest suite: **3,717 passed, 18 skipped, 0 failed** in 557.31 seconds.
- Supported isolated selfcheck: **26 phases passed, 0 failed**. Its module
  runner reports **66 module passes, one pipeline pass and 18 expected skips**;
  the additional opt-in skips reflect parked integrations, not passing sensors.
- All **378 package Python files** compile. Repository Ruff over `src`,
  `tests` and `tools`, documentation-drift validation and diff whitespace checks
  pass.
- Final usage/status regression group: **29 passed, one expected skip**.
  Startup/Chill/self-test/drill UI regressions: **92 passed**. Patch and
  performance focused results are detailed in their reports.
- All 84 capabilities discover without errors. README retains the same five
  tracked screenshot assets; What's new follows their caption.

Machine-readable results: [validation-after.json](validation-after.json).
The [full pytest summary](pytest-after.txt) and [final selfcheck output](selfcheck-after.txt)
retain the aggregate evidence. These are offline gates, not a multi-day live
soak or certification of Windows, Linux or macOS sensor coverage.

Publication uses `python tools/publish_github_update.py` after the reviewed
commit is clean. It requires canonical HTTPS origin, matching branch/default
main commits, a fast-forward update and byte-identical reachable public README
assets. The original checkout's unfinished Analysis Lab files are excluded
from this published maintenance update and preserved locally.

## Requested review roles

| Role | Evidence / responsibility |
| --- | --- |
| Adversary bot | [Read-only findings and reproductions](adversary.md); stopped consumers and staged-startup policy races. |
| Visionary bot | [Eight ranked proposals with primary sources](visionary.md); shared usage policy informs this round, with broader snapshot, attribution, AI admission, driver-cache and notification designs retained as proposals. |
| Bug hunter | [Bug findings](bug-hunt.md), [84-module audit](module-audit.md), compile/self-test baseline and inert reproductions. |
| Patch applier | [Seven-module fixes and regression gates](patches.md): callback lifecycle, AMSI and API-hook corrections. The performance bot owns entropy fixture cleanup. |
| Performance bot | [Polling analysis and measurements](performance.md), targeted regression tests and benchmark. |
| Promotional GitHub bot | README placement, factual maintenance notes, this report and research/performance cross-links. The coordinating maintainer performs the guarded publication. |

Restart Angerona to load these source changes. This offline review does not
establish live sensor coverage on every supported operating system, or claim
that all 84 catalog capabilities should run on one machine.
