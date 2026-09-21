# Visionary review: useful modules, truthful coverage, bounded work

Research date: 2026-09-21 UTC. Round 1; design only. This document does not
implement or validate the proposals. Product changes and publication belong to
the coordinating maintainer agent. All proposals are defensive only.

## Baseline checked

Reviewed `README.md`, `llms.txt`, `analysis/loop/state.json`, module discovery,
the v12 capability contract, lifecycle/control paths, platform declarations,
capability assurance, module counts, resource governance, sensor caches, soak
evidence, local inference, and the concrete integration gates below. The saved
loop state describes completed cycle 34; this report does not reopen that cycle.

Angerona already has a local assistant, ATT&CK heatmap, incident correlation,
SOAR, driver provenance, bounded resource governors, process/connection snapshot
caches, reusable UI workers, and an external long-session soak runner. Those are
not new proposals. In particular, `attack_tracker.py` already pins a curated
ATT&CK 19.2 catalog including Stealth and Defense Impairment; no tactic migration
is proposed here. The README/LLM inventory describes 84 Windows-target
capabilities, not a promise that every capability runs on every machine.

The immediate recommendation is one shared module-usage projection, used by
startup, settings, watchdog eligibility and all runtime count displays. It must
separate operator intent, platform applicability, integration opt-in and runtime
health. A failed detector must never become an inapplicable detector merely to
make the dashboard look healthier.

## Exact eligibility contract recommended for this round

Use the following independent fields; names are illustrative, not an API change:

| Field | Meaning |
| --- | --- |
| `requested_enabled` | Persisted module switch or its declared default. |
| `applicability` | `applicable`, `not_applicable`, or `unknown`, with a stable reason. |
| `integration_requested` | Exact existing opt-in gate, where that module has one. |
| `effective_enabled` | Requested enabled, no proven unsupported platform, and integration requested. |
| `runtime_state` | Starting, running, paused/deferred, stopping, failed, stopped, etc. |
| `coverage_state` | Fresh, partial, degraded, unavailable, unknown, or explicitly not requested. |

An unknown applicability result is not grounds to stop an otherwise enabled
detector. A provider permission failure, missing Sysmon, disconnected ETW,
disabled audit policy, unreadable registry key, no recent events, transient
hardware absence, missing configured integration dependency, or failed helper
must remain visible as degraded/unknown coverage. None proves inapplicability.

Do not persist an automatic eligibility decision into `config.module_states`.
Preserve the operator's switch so a supported platform/configuration can restore
the expected lifecycle. Match built-ins by exact reviewed class identity or
capability identity, not a display-name substring that an extension can imitate.
Keep external modules on their verified declarations; unknown declarations
must not grant privileged services or new response authority.

### Gate map verified in the current code

| Exact built-in | Existing gate | Safe exclusion | Remains a visible failure |
| --- | --- | --- | --- |
| `mobile_bridge.MobileResponseBridge` / Mobile Response Bridge | `Config.mobile_enabled`, default false | Explicit mobile opt-out; avoid creating its currently idle worker. | Opted-in executable trust, PIN/storage, or transport failure. |
| `ebpf_sensor.EbpfSensorNode` / Linux eBPF Sensor | Literal `SUPPORTED_PLATFORMS = ("linux",)`; `Config.ebpf_enabled`, default false | Unsupported OS or explicit eBPF opt-out. | Opted-in Linux without root/BCC/kernel capability, attach failure, or lost events. |
| `soar_engine.ActiveResponseSOAR` / Active Response SOAR | `ANGERONA_SOAR_KILL_AND_ROLLBACK == "1"` exactly | Disarmed optional response tier; its loop currently wakes every two seconds before returning early. | Armed but failing evidence, response-scope, journal or runtime requirements. |
| `siem_forwarder.SIEMForwarderModule` / SIEM Forwarder | Module default off; `Config.siem_host` is mirrored to `ANGERONA_SIEM_HOST` | Existing explicit module opt-out. Empty destination is optional-unconfigured only when forwarding has not been requested. | Requested forwarding with missing destination, TLS/CA, durable outbox, or delivery failure. |
| `remote_bridge.RemoteBridge` / Remote Bridge | Module default off; `Config.remote_bridge_mode` is mirrored to `ANGERONA_BRIDGE_MODE` | Existing explicit module opt-out. No mode is optional-unconfigured only when bridging has not been requested. | Requested bridge with missing/invalid mode, strong key, crypto package, bind or peer failure. |
| Cloud CTI Escalation | Module default off | Existing explicit module opt-out. | User-enabled module without credentials/provider dependency. Do not read keys merely to calculate a module count. |

`Config.publish_integration_environment()` is the current config-to-environment bridge;
use whichever authoritative value the module actually consumes after validation.
Do not silently accept broader truthy environment values than a gate accepts.

Fleet Health Monitor is deliberately **not** gated on `fleet_service_enabled`:
its bound local `FleetFabricStore` and signed local evidence have value without
remote transport. An unbound store currently reports health 35 and is a binding
failure. Also, `aria_enabled == false` does not prove AI Triage or Scheduled AI
Security Briefing is unrequested; neither uses that as its independent module
master switch. Hardware-Rooted Integrity has DPAPI work even without a TPM.
USB/WLAN/peripheral guards must remain ready for removable hardware and changes.

### Counts, scores and display

- The machine runtime denominator is the count of effective-enabled modules.
  Operator-disabled modules and known inapplicable/opted-out modules are excluded
  as requested. Configured modules deferred by Chill/Eco, paused, starting,
  failed or temporarily unavailable remain in that expected denominator.
- The numerator means actually running workers in that set. Do not label it
  "protected" or "healthy": a live worker may have degraded evidence. Prefer
  `X/Y enabled modules running` plus separate degraded and excluded details.
- Keep the release catalog, discovered runtime inventory, configured count and
  running count separate. Discovery already omits some unsupported built-ins
  before import; `len(manager.modules)` is not a cross-platform release catalog.
- A zero operational denominator displays zero configured modules, with coverage
  unavailable/not assessed. It is never 100% protection. A user disabling a
  relevant detector must remain an explicit coverage gap in assurance/ATT&CK,
  even though the operational module denominator shrinks.
- Status export, dashboard cards, Modules page, live-defense panel and startup
  summary should read the same bounded, memory-only projection. Avoid computing
  authenticated capability inventory or probing the OS from a GUI paint/timer.

### Lifecycle, changes and minimum acceptance cases

Reconcile after a successfully validated settings save; parked Mobile/eBPF
workers cannot notice a changed setting if their old polling loop no longer
exists. Use the manager control lock and existing worker-generation protections.
A failed startup remains expected and failed. Do not mark a worker stopped while
its prior generation still executes, and never start an overlapping generation.
Reconciliation must honor shutdown, explicit operator-off state and pending
deferred startup. Do not start parked response modules from untrusted event text.

At minimum, exercise unsupported Windows eBPF, disabled Mobile, disarmed SOAR,
explicitly enabled integration with broken prerequisites, configured failed and
deferred sensors, user disable/re-enable, settings opt-in after startup, zero
configured modules, and conflicting names from extensions. Assert no unexpected
worker creation, no repeated setting writes, consistent counts, unchanged
protection/assurance semantics, and preserved privacy/response authority.

## Ranked proposals

Rank is estimated impact divided by effort, not a benchmark result. Impact is
1–5; effort uses S=1, M=3, L=8 planning units. Equal ratios favor direct relief
for this user's PC. S means a focused cross-cutting change; M needs lifecycle or
evidence integration; L would need a larger collection boundary. No proposal
requires a new kernel component.

| Rank | Proposal | Impact | Effort | Ratio |
| --- | --- | ---: | --- | ---: |
| 1 | One machine-usage contract for every module | 5 | S | 5.00 |
| 2 | Complete process snapshots with targeted reuse | 5 | M | 1.67 |
| 3 | Attribute long-session growth to module-owned state | 5 | M | 1.67 |
| 4 | Source-freshness limits on analytical resource leases | 5 | M | 1.67 |
| 5 | Shared admission for local AI work | 4 | M | 1.33 |
| 6 | Explain analytic coverage from actual source readiness | 4 | M | 1.33 |
| 7 | Incremental driver checks with policy-generation invalidation | 3 | M | 1.00 |
| 8 | Notification-driven device refresh with retained sentinel | 3 | M | 1.00 |

### 1. One machine-usage contract for every module

**Pitch:** Remove genuinely unused workers and make every runtime count explain
which modules the machine is expected to run.

**Why now:** ATT&CK's October 2025 defensive restructuring ties analytics to
specific platforms and log sources, which is a better basis for capability
claims than installed-module totals. [MITRE ATT&CK: Updates — October 2025](https://attack.mitre.org/resources/updates/updates-october-2025/).

**Fit:** Core `module_manager.py`, `module_contract.py`, `platforms.py` and a
small shared usage projection; GUI/count consumers and `status_report.py`.
**Harden / Visualize.** Apply the gate map above, with no module-specific probe
or per-module worker. The proposal is the shared runtime contract, not another
sensor or a change to the existing native-versus-adapter inventory.

**Effort:** S. Preserve legacy enabled defaults and settings authority. Parent
agent selected this direction for this round; inclusion here is a design record,
not a claim that the implementation has shipped.

**Acceptance:** A discovered but inapplicable/opted-out built-in creates no
worker. A failed enabled sensor stays visible. Every count agrees on one
snapshot. Pausing configured sensors does not improve a protection score.

**Safety:** Defensive only; no offensive tooling, permission elevation,
configuration of remote systems, or automatic response expansion.

### 2. Complete process snapshots with targeted reuse

**Pitch:** Extend the existing shared process cache with explicit completeness
and immutability, then migrate only compatible duplicate enumerations.

**Why now:** The current psutil performance guidance documents shared underlying
calls and `oneshot()` for grouped process reads. This is an implementation
opportunity, not evidence of a measured Angerona speedup.
[psutil: Performance](https://psutil.io/performance/).

**Fit:** `telemetry/sensors.py` already caches process/connection tables; its
`ConnectionSnapshot` has coverage metadata but `list_processes()` returns a
mutable list without a comparable receipt. Add bounded immutable process rows,
monotonic cache age, completion time, enumerated/skipped counts and typed errors.
Evaluate reuse in `lsass_guard.py` and `shadowcopy_guard.py`; preserve each
consumer's required fields and maximum age. **Detect / Harden.**

**Effort:** M. PID plus creation time is mandatory; an identity-incomplete row
must not authorize action. A snapshot that lacks required command fields is
partial, not evidence of absence. Do not replace fresh memory/API reads with
cached process metadata or weaken an ETW collection boundary.

**Acceptance:** Concurrent eligible consumers perform one enumeration per
allowed window; a caller cannot mutate another caller's rows. Access-denied,
PID reuse, wall-clock reversal and empty-success fixtures stay distinguishable.

**Safety:** Defensive only; never read credentials or treat cached observations
as authority to terminate a process. Revalidate identity before existing actions.

### 3. Attribute long-session growth to module-owned state

**Pitch:** Make the existing soak evidence explain which bounded queues,
workers and caches grew after warm-up, including repeated lifecycle transitions.

**Why now:** Python's allocation tracer can compare snapshots by traceback,
while process measurements cover resources outside Python allocations. These
are established tools directly suited to the user's worsening-over-time report.
[Python: tracemalloc — Trace memory allocations](https://docs.python.org/3.13/library/tracemalloc.html).

**Fit:** Extend existing `core/operational_slo.py`, `tools/run_soak.py`,
`BaseModule.operational_snapshot()` and module resource contracts. Existing
soaks already record peak RSS/thread/handle growth, queue pressure and loss;
the new part is bounded owner attribution, post-warm-up trend and a repeatable
enable/disable/restart cohort. **Harden / Visualize.**

**Effort:** M. Export declared low-cardinality counters, not arbitrary object
graphs. Use tracemalloc only in explicit diagnostics to avoid permanent tracing
cost. Python allocation snapshots do not account for all native/GPU memory.

**Acceptance:** Fixed synthetic event cohorts and repeated view/lifecycle cycles
reach a stable retained-state plateau; every resource cap exposes eviction or
loss. Do not equate one short test with an actual 24-hour physical-host soak.

**Safety:** Defensive only; fixtures contain no exploit payloads or real secrets.
Do not auto-restart healthy protection modules to hide a leak or clear evidence.

### 4. Source-freshness limits on analytical resource leases

**Pitch:** Extend opt-in throttling with a visible freshness deadline for each
dependent analytic, while preserving event collection and response cadence.

**Why now:** Microsoft's July 2026 ETW documentation explicitly exposes lost
events/buffers and explains how slow consumers lose events. This supports
measuring reduced work together with coverage quality.
[Microsoft: About Event Tracing](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing).

**Fit:** `modules/resource_governor.py` already limits throttling to explicit
opt-in modules; `core/perf_governor.py` is presentation-only. Extend the former's
leases and `ResourceBudget` with an analysis deadline and input-freshness
requirement. Consume `telemetry_coverage.py`/operational health counters without
introducing another collection loop. **Detect / Harden / Visualize.**

**Effort:** M. Compatibility modules with undeclared budgets retain conservative
behavior. Saturation must expose missed/deferred work and source age. Lease
expiry, worker replacement and governor failure must restore baseline settings.

**Acceptance:** Under resource pressure, approved analytics perform fewer
redundant recomputations while sensor delivery and response fixtures preserve
their timings. A stale input cannot yield a fresh/healthy assurance result.

**Safety:** Defensive only; no throttling of audit collection, containment,
watchdog, heartbeat or security-event ingestion, and no silent event sampling.

### 5. Shared admission for local AI work

**Pitch:** Give optional prewarming, briefings and triage one bounded inference
admission queue so simultaneous consumers cannot multiply model memory demand.

**Why now:** Ollama documents memory growth with parallel contexts and overload
queues; OWASP's 2025 guidance calls for separating untrusted content and model
authority. [Ollama: FAQ](https://docs.ollama.com/faq),
[OWASP: LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).

**Fit:** Extend `core/ollama_lifecycle.py`; connect `ai_triage.py`,
`daily_briefing.py` and `speculative_triage.py`. Existing timeouts, circuit
breakers, bounded prewarm queue and Chill unload lease remain. The new part is
shared admission across consumers, bounded queued context bytes, explicit
coalesced/deferred outcomes, and priority for requested user work over
speculation. **Harden / Visualize.**

**Effort:** M. Do not silently change a shared Ollama server's global settings.
Use app-owned requests and model identity; allow only evidence-equivalent
deduplication. Cancellation releases a lease after the request really stops.

**Acceptance:** Bursts from all three modules obey the app admission bound;
optional prewarming yields to demand; a deferred narrative does not suppress its
original detection. Untrusted log text cannot request tools or change priority.

**Safety:** Defensive only, local-first and narrative-only. No automatic model
downloads, cloud fallback, arbitrary commands, or model-granted response powers.

### 6. Explain analytic coverage from actual source readiness

**Pitch:** Add an explanation for each curated analytic: its expected evidence,
current source age/loss and why it is active, degraded or out of scope.

**Why now:** ATT&CK v18 introduced Detection Strategies/Analytics and v19 updates
their underlying data components. Angerona already has the v19.2 tactic labels;
the missing proposed layer is readiness tied to analytic inputs.
[MITRE: Updates — October 2025](https://attack.mitre.org/resources/updates/updates-october-2025/),
[MITRE: Updates — April 2026](https://attack.mitre.org/resources/updates/updates-april-2026/).

**Fit:** Extend the curated mapping in `core/attack_coverage.py`, contract input
declarations, `capability_assurance.py` and `gui/attack_heatmap.py`. Join approved
local mappings with the usage projection and telemetry coverage; keep event heat
separate from readiness. **Detect / Visualize.**

**Effort:** M. Pin a reviewed ATT&CK dataset and mapping revision; no runtime web
fetch or inference that technique tagging proves tested detection. Start with a
small reviewed analytic subset, not a claim to cover the whole framework.

**Acceptance:** Disabling a required sensor produces an explicit gap even if
runtime module counts look fully running. Unsupported platforms differ from
failed providers. Restored input needs fresh evidence before readiness improves.

**Safety:** Defensive only; use inert event fixtures, not exploit or credential
theft tooling. No inflated efficacy, attribution or certification claims.

### 7. Incremental driver checks with policy-generation invalidation

**Pitch:** Reduce repeated driver hashing/signature work while invalidating
results whenever driver identity or the reviewed block policy changes.

**Why now:** Microsoft distinguishes vulnerable-driver write prevention from
load blocking and notes that policy activation does not stop already running
drivers. A recent policy file alone is not proof the host enforces it.
[Microsoft: Recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules).

**Fit:** `driver_provenance_guard.py` already joins hashes, signing, catalog,
blocklist and HVCI/boot evidence, and deduplicates resulting findings. The new
part is bounded expensive-collection reuse plus invalidation on boot, policy
revision and relevant authenticated Code Integrity events; connect the existing
`app_control_monitor.py`/`kernel_posture_ledger.py`. **Detect / Harden.**

**Effort:** M. Cache keys need descriptor-bound file identity and trustworthy
change evidence, not just path, size and mtime. If identity/change authority is
unavailable, recollect within the existing maximum age and mark partial input.
Keep a bounded periodic full reconciliation for missed notifications.

**Acceptance:** Unchanged driver inventory avoids repeated expensive reads;
replacement, changed policy and missed-event fixtures invalidate old results.
Installed block policy and actual enforcement remain separate observations.

**Safety:** Defensive only; no vulnerable-driver loading, kernel patching,
callback tampering or automatic driver blocking that could destabilize the PC.

### 8. Notification-driven device refresh with retained sentinel

**Pitch:** Let shared device-change notifications trigger deeper hardware work
without disabling the guards that must detect the next arrival.

**Why now:** This is a mature Windows mechanism, not a new security trend.
Microsoft documents registering before initial enumeration and handling
duplicate arrival observations, directly addressing safe hotplug lifecycle.
[Microsoft: CM_Register_Notification](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_register_notification).

**Fit:** A small app-owned Windows device observer feeds existing
`usb_monitor.py`, `peripheral_dma_guard.py` and appropriate WLAN/interface
refresh paths. Retain one lightweight sentinel and coalesce only refresh hints;
do not discard security events. **Detect / Harden.**

**Effort:** M. Windows 8+ API gating, callback lifetime and shutdown discipline
are required. Use network/WLAN-specific notifications where PnP does not express
link state. Slow reconciliation handles dropped hints and resume from sleep.

**Acceptance:** Register then enumerate; duplicate arrival causes one deep
refresh. Removal/reinsert, sleep/resume and notification failure preserve
observable coverage and do not duplicate workers.

**Safety:** Defensive only. Absence of a USB stick or wireless link never means
the protection module is permanently inapplicable. No device probing, driver
installation or unsolicited hardware/policy modification.

## Maintainer handoff

For this round, prioritize proposal 1 plus focused fixes supported by the bug
and performance agents. The remaining proposals are reviewable follow-ups,
not requirements to make every source file change. Shared lifecycle/count
improvements can benefit all modules without inventing per-module patches.

The assigned output is this file only. The final documentation owner can link
this ranked proposal record from `analysis/loop/innovation_ideas.md` and append
the following under `## Round 1 — Innovation` in `analysis/loop/LOOP_LOG.md`:

> 2026-09-21: Visionary review produced eight ranked defensive-only proposals,
> with primary sources and exact built-in applicability gates. Recommended a
> shared machine-usage contract that parks explicitly unrequested integrations,
> preserves configured failures as coverage gaps, and keeps operational counts
> separate from protection scores. Follow-ups cover process-snapshot receipts,
> attributed long-session growth, freshness-limited analytical resource leases,
> shared local-AI admission, analytic coverage explanations, incremental driver
> checks and device notifications. Research/design only; implementation status
> must be established by the coordinating agent's validation record. Details:
> `analysis/round-20260921/visionary.md`.
