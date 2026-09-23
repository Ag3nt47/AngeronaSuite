# Three-round deep review — 2026-09-23

This v1.13.0 maintenance update combines three adversarial/QA rounds, targeted
patches, two performance passes, native startup work and a primary-source
research comparison. All **84 catalog capabilities** are inventoried. Shared
health/lifecycle improvements apply across the suite; reproduced defects receive
module-specific fixes. This does not claim 84 separate module patches or that
all catalog entries should run on one machine.

The six requested roles contributed adversarial discovery, visionary research,
bug hunting, patch application, performance engineering and public documentation.
The coordinator owns final integration, native acceptance and guarded publication.

## Results that matter during use

- Unconfigured Detection Runtime callbacks avoid normalization and identity-map
  retention. Oversized nested input has a cumulative work budget before JSON
  expansion. Source-health reporting reuses identical path resolution without
  extending source-trust cache lifetimes.
- Security event bursts keep one GUI wake pending through the complete reader
  operation, then coalesce further demand into one follow-up. Retained serious
  events are still classified; shutdown refuses late callback/result delivery.
- Local Ollama service preparation runs asynchronously on launch, AI Triage
  restart and explicit self-test. Its percentages describe completed service
  checks; model approval and inference readiness remain separate.
- Stopping Memory Time-Machine leaves resource cleanup with its retiring worker
  and rejects late collection results. Lab completion survives a progress-queue
  race. Keyword-only LSASS/recovery command matches remain visible observations
  without inducing deep active-threat work.
- Mac/Linux source installers use staged runtimes, exact dependency locks,
  safely escaped paths and prerequisite/rendering checks before replacing a
  launcher. The Intel Mac path explicitly builds its missing binary dependency.
- Analysis Lab controls and optional VMware setup are implemented, but native
  analyzer acceptance failed on this host. Run remains gated, with the failure
  explained rather than weakening configuration custody.

The September 21 [machine-usage policy](../round-20260921/README.md) was reviewed
again. Unsupported, disabled and unconfigured optional modules are excluded from
running/enabled counts. Failed expected sensors, paused configured workers and
hotplug guards retain their existing coverage semantics.

## Findings and disposition

| Finding | Fix / current disposition | Evidence |
| --- | --- | --- |
| D23-R1-01 — VMX configuration could change before consumption (Medium) | Exact bytes, identity and single-link checks; no-write/delete handle retained through supervision/receipt acceptance. Source custody fixed; native VMware compatibility remains unresolved. | [Discovery](adversary-round1.md), [patches](patches-round1.md), [native result](native-acceptance.md) |
| R1-QA-01 — Lab completion lost during concurrent progress drain | Best-effort eviction tolerates an empty queue and delivers the final result without leaving controls busy. | [Bug report](bugs-round1.md), [patches](patches-round1.md) |
| R1-QA-02 — Retired Memory Time-Machine sweep admitted late work/used a closed ring | Worker-owned ring retirement, post-collection cancellation checks, safe closed-ring status and restart handling. | [Bug report](bugs-round1.md), [patches](patches-round1.md) |
| D23-R2-01 — Semantic-only text asserted an active attack (Low) | Exact producer branches and a narrow historical classifier keep uncorroborated text observational. Exact dangerous commands remain active even when incomplete identity denies response. | [Discovery](adversary-round2.md), [patches](patches-round2.md) |
| D23-R2-02 — Ollama attestation and HTTP could select different loopback addresses (Medium) | Attestation and HTTP bind the same pinned literal address; applicable wildcard ambiguity fails closed. | [13-case regression evidence](adversary-round2.md) |
| D23-R3-01 — Service helper accepted ambiguous unquoted executable paths (Medium) | Reject whitespace ambiguity; recheck exact registration before mutations and hold the verified image through startup. | [Review and closure](adversary-round3.md) |

The adversary found **three Medium and one Low** issues across the three rounds.
Their source fixes were reviewed; the VMX fix exposes a remaining compatibility
blocker rather than a passing Lab. The two distinct QA defects were fixed and
retested. Reports retain discovery-time statuses; this table records the combined
disposition. Final review of optional setup, prerequisite checks, cancellation
and readiness retirement found no additional confirmed security issue.

Additional integration fixes came from native/installer review: Windows Ollama
connection refusal and `stat`/`fstat` timestamp semantics, cancellation before
spawn, safe staged installer publication, interpreter/architecture selection,
native dependency diagnostics, source dependency-graph closure and escaped
launcher/service paths. See [startup](ollama-startup.md) and
[installer evidence](native-installers.md).

## Performance measurements and tradeoffs

These are inert component fixtures on Python 3.12.10, not whole-PC CPU savings,
multi-day memory measurements or changes to sensor collection frequency.

| Workload | Before | After |
| --- | ---: | ---: |
| 3,000 unconfigured Detection Runtime callbacks | 739.411 ms | 42.840 ms |
| Identity entries retained after those callbacks | 6,000 | 0 |
| Oversized 4 MiB nested transcript rejection | 216.304 ms | 0.140 ms |
| Peak traced allocation for that rejection | 8,212.1 KiB | 7.4 KiB |
| Repeated degraded-health report | 5.2926 ms | 1.8621 ms |
| 1,000 ordinary configured-event normalizations | 177.837 ms | 217.395 ms |
| Qt wake callbacks during a blocked-reader 1,001-event fixture | 1,001 | 1 |

Idle callback time fell approximately **94%** and repeated health reporting
approximately **65%** in these fixtures. The cumulative input budget increased
ordinary normalization cost by approximately **40 microseconds/event (22%)** in
the recorded run; this is the explicit tradeoff for bounded hostile expansion.
Accepted fixture identities remained byte-identical.

The GUI preservation test classified all **1,001 retained serious events in two
reads**, reused the same worker and reached the current revision despite general
history overflow. INFO-only traffic started no security reader. No new timer or
worker was added. Existing event-loss signals and deterministic response remain
independent of the presentation gate.

Evidence: [performance round 1](performance-round1.md),
[measurement JSON](performance-benchmark-round1.json),
[reproducible benchmark](../../tools/benchmark_idle_admission.py),
[performance round 2](performance-round2.md).

The [all-module cadence inventory](module-cadence-round1.json) records 84 classes:
19 in the Chill parked set and 11 cadence floors among the remaining 65, before
platform/opt-in/operator gates. It is a source inventory, not a live worker count.
Broader overlapping OS process/connection collection was identified for future
profiling; collection freshness was not relaxed to obtain these results.

## AI readiness and response evidence

The actual vendor-signed Windows Ollama executable passed a cold start in
**16.44 seconds**, progressing through 10/25/45/60/80/100 percent. No model was
downloaded or loaded; the resident model inventory remained empty. Warm and
explicit Chill service checks also passed. **Service readiness is not approved
model identity or successful inference.** Native macOS/Linux startup was not
available on this Windows host; those ownership paths have fixture coverage.
POSIX automatic startup requires a recognized root-owned image and protected
parent chain; user-owned or symlinked Homebrew/application paths may fail closed.

For elevated Windows Protect startup, a narrow helper uses only the same user's
linked medium token and validates the suspended child's token/image before
resuming it. No administrator parser fallback exists. Its first combined gate
passed 116 tests; the native token reader passed a read-only check. Actual
elevated-to-medium process creation remains a native acceptance gap.

Startup coalesces requests, verifies listener/image ownership, pins the endpoint,
sanitizes launch environment and keeps status refresh memory-only. Explicit
shutdown/deadline checks prevent late launch or successful readiness publication.
AI Triage skips optional narrative requests when telemetry neutralization fails
and emits narrative-only output without response authority.

The real Combat worker was tested with inference unavailable. It consumed an
authenticated typed request for an inert exact-path/exact-hash file, quarantined
it, verified and journaled the result, emitted a matching authenticated receipt,
and restored the exact bytes through production Undo. Four forged AI/remote/prose
variants caused no action or receipt. This validates the existing separation of
deterministic response and optional inference; it does not establish live threat
coverage or the current machine's model/response readiness.

Evidence: [native acceptance](native-acceptance.md),
[Ollama startup](ollama-startup.md), [autonomous-response QA](bugs-round2.md),
[response regressions](../../tests/test_deep_review_autonomous_response.py).

## Analysis Lab: implemented controls, failed native acceptance

The pinned Bandit/Gitleaks catalog, fixed offline appliance, input bounds,
supervision, cancellation, redacted reports/history and GUI exist. Their offline
tests do not prove a working VMware guest. No external report gains native
response authority.

With explicit approval, the reviewed helper configured VMware Authorization
Service to **Manual/Running**. Workstation **25.0.1 build 25219725** then refused
the generated VMX while its deny-write/delete seal was held, recording
`ERROR_SHARING_VIOLATION`. `config.readOnly` and bounded direct-VMX trials also
failed. Existing VMs were neither changed nor started. No analyzer receipt or
successful readiness record was accepted.

The seal stays intact, and each explicit readiness check retires prior success
before beginning. Failed/cancelled checks cannot preserve stale green readiness.
Remaining work is a reviewed VMware-compatible custody handoff or another
reviewed backend, followed by actual passing Bandit and Gitleaks guest fixtures.

Optional Full Setup explains why VMware is used, its extra resources and Skip.
It opens Broadcom's official account/compliance download process. The user selects
an installer whose vendor, product, file identity and parent custody are checked
and held through interactive UAC/installer exit. Service configuration is a
separate confirmed action limited to the verified Authorization Service. Neither
installation nor service startup enables Run. A real selected VMware 25 installer
passed native vendor/product/custody/digest verification. Its installer was not
launched; the interactive installation handoff remains fixture-covered.

Evidence: [native result](native-acceptance.md),
[final adversarial review](adversary-round3.md),
[current Lab design/status](../../docs/design/red-team-github-tool-library.md).

## Native source installers

The Mac launcher covers **macOS 14+**, Intel and Apple Silicon, including Rosetta
handoff and matching Python 3.12. Intel's cryptography 50 dependency uses a pinned
source build with Xcode Command Line Tools, Rust and OpenSSL, locked/offline Cargo
compilation, two build workers and a local build receipt. This is not a notarized
universal binary or a claim to support every macOS version.

Linux source installation targets **x86_64/glibc**, with Ubuntu 24.04 the reviewed
CI target. Fixed package guidance covers Python/venv and Qt native libraries.
A bounded child instantiates a real offscreen QApplication and renders a widget;
Linux also loads the XCB plugin. Probe failures prevent launcher publication.
A visible X11/Wayland session remains a separate runtime requirement.

Separate source-runtime locks close their reviewed dependency graphs: 23 packages
for Linux and Apple Silicon, 22 plus the explicit cryptography build for Intel.
Installers stage/validate a new runtime, safely quote paths and retain the old
validated generation on failure. Optional voice is separate. Native CI lanes
are configured for Ubuntu, Apple Silicon and Intel. The initial published
revision passed native Ubuntu installation/rendering. Mac execution exposed a
shell path-quoting bug; its correction and subsequent CI results are tracked in
the [publication follow-up](publication-followup.md).

**Remaining packaging issue:** older full POSIX release-build locks still have
PyObjC/macholib/typing-extensions graph omissions. They are not consumed by the
new source installer. Source-install validation is not full packaged-release
acceptance. Evidence: [installer review](native-installers.md),
[user setup guide](../../docs/NATIVE_INSTALL.md).

## Research decisions

The [visionary comparison](visionary-comparison.md) examines primary material
from Wazuh, osquery, Velociraptor and Falco with pinned repository references.
It proposes adaptations, not product parity or independent efficacy claims.

| Proposal | Disposition |
| --- | --- |
| Fail closed on AI telemetry-neutralizer failure | Applied in AI Triage. |
| Prove autonomous response without inference | Applied through real-worker inert quarantine/receipt/Undo regressions. |
| Bound Combat overload notification amplification | Proposed. The implemented GUI wake coalescing is a different boundary. |
| Expose response queue age and verified completion latency | Proposed. |
| Wake idle analytical workers on work/configuration changes | Proposed; current polling cadence was not broadly rewritten. |
| Share a bounded local-inference admission permit | Proposed. |
| Declare minimum telemetry dependencies for active analytics | Proposed; absent recent events do not authorize sensor shutdown. |

## Validation record

The [round 3 module inventory](module-inventory-round3.md) accounts for all
**84 modules: 66 passes, 18 expected prerequisite/platform skips, 0 failures**.
The separate EventBus pipeline adds one pass to the harness display. The
[core batch](core-selftests-round3.json) records **24 passes, 0 failures**;
the [round 3 compile snapshot](compile-round3.json) records **388 files, 0 errors**.
Skipped or stopped sensors are not represented as live coverage.

Round-specific gates are preserved in [QA round 1](bugs-round1.md),
[QA round 2](bugs-round2.md), [QA round 3](bugs-round3.md), patch, performance and
installer reports. Their test
selections overlap; summing them would invent a unique full-suite count. The
supported selfcheck passed **26/26 phases** in all three QA passes.
Native starts, inert unit tests, GUI fixture rendering and live-host evidence
remain separate categories.

The aggregate pytest run recorded **3,884 passed, 19 skipped and 3 failed in
1,205.62 seconds**. Its three failures were stale test assumptions: a disposable
workspace-contained PATH fixture, a nested deployment-stage fixture, and the
README's previous installation heading. This is the raw captured run, not an
all-green full-suite claim.

The corrected publication group passed **58 tests**. The corrected deployment
and frozen Lab/Ollama/setup/native-installer selection passed **96 tests with
1 expected skip**. The README now retains the meaningful signed-package,
SHA-256, publisher and no-Python/terminal installation statements under its new
heading; the corrected release/setup group passed **22 tests**. Late startup changes and deduplicated
coverage accounting are recorded in [QA round 3](bugs-round3.md); these focused
results must not be relabeled as one rerun of the entire suite.

The pre-publication Windows reconciliation accounts for **3,991 collected cases:
3,972 latest passes, 19 expected skips, no uncovered cases or unresolved
failures**. This combines the aggregate run with targeted reruns, including the
final integration gate (**206 passes, 1 skip**) and **11** independent Windows
token-boundary passes. Overlapping cases are counted once in the
[reconciliation record](pytest-reconciled-round3.json).

The coordinator owns final integration and guarded publication.
Additional post-publication native findings and targeted checks are recorded in
the [publication follow-up](publication-followup.md); they are outside that
Windows reconciliation snapshot.
No pending native Lab or macOS/Linux acceptance is converted into a pass by the
offline gates. Historical cycle34 closure remains unchanged.
