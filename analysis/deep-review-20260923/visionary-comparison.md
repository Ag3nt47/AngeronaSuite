# Visionary comparison: verified response and inexpensive idle operation

Research date: 2026-09-23. One bounded primary-source review. Research/design
only: this report does not implement fixes, run hostile programs, change policy,
or claim peer-product parity. Concurrent changes elsewhere in this worktree are
owned by the coordinating agent and are not assessed as released functionality.

## Recommendation for this round

Keep autonomous containment independent of inference. Angerona already does
this: `AdversaryCombat` acts under configured standing authority, checks exact
response contracts, journals intent and verifies action postconditions. Its
worker does not call Ollama. The useful improvement is to preserve and test that
separation under missing models, adversarial narrative text and queue pressure.

Prioritize the optional-AI sanitizer failure path, bounded overload reporting,
and an end-to-end no-model response regression. Improve idle work by waking
analytical workers on work/configuration changes instead of repeatedly polling
an empty queue. Keep ingestion, protection and journal recovery semantics intact.

## Current GitHub reference points

These public repository HEAD values were read from GitHub's REST API on the
research date. They identify moving development trees, not installed versions,
stable releases or deployment endorsements. Only the listed source areas and
official documentation were examined; this was not a whole-project audit.

| Project | Observed HEAD and commit date | Examined primary material |
| --- | --- | --- |
| Wazuh | [`2c5e3a92a5ca`](https://github.com/wazuh/wazuh/commit/2c5e3a92a5ca53af26e50191b594cad93d482df9), 2026-09-21 | [Active Response implementation](https://github.com/wazuh/wazuh/blob/2c5e3a92a5ca53af26e50191b594cad93d482df9/src/active-response/src/active_responses.c), official response protocol. |
| osquery | [`1889d51f0d16`](https://github.com/osquery/osquery/commit/1889d51f0d1680672016a801e9d65799eb5fc5dc), 2026-09-22 | [CLI flags and watchdog/event controls](https://github.com/osquery/osquery/blob/1889d51f0d1680672016a801e9d65799eb5fc5dc/docs/wiki/installation/cli-flags.md). |
| Velociraptor | [`79fbf7e59a17`](https://github.com/Velocidex/velociraptor/commit/79fbf7e59a178547039865b5967d7b8c6c53b03d), 2026-09-21 | [Client/server configuration reference](https://github.com/Velocidex/velociraptor/blob/79fbf7e59a178547039865b5967d7b8c6c53b03d/docs/references/server.config.yaml), official collection limits. |
| Falco | [`b987d795d889`](https://github.com/falcosecurity/falco/commit/b987d795d8898ad0f55a435172ba3473411467a6), 2026-09-23 | [Runtime configuration](https://github.com/falcosecurity/falco/blob/b987d795d8898ad0f55a435172ba3473411467a6/falco.yaml), official source selection and event-loss guidance. |

The cited controls include mature designs. Their current implementations and
guidance were checked; their inclusion does not mean each technique originated
within the last year.

## Comparison with the inspected Angerona code

| Peer pattern | Angerona already has | Practical gap or adaptation |
| --- | --- | --- |
| Wazuh Active Response uses structured messages; its stateful protocol coordinates duplicate keys and timed reversal. [Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html). | `adversary_combat.py` has bounded admission, deduplication, exact target contracts, journal recovery, verified receipts and Undo; `response_capability.py` binds typed privileged actions. | Test the complete existing response path with inference absent. Keep admission, execution and verified success separate; never substitute a model verdict for response authority. |
| osquery constrains worker resources and warns that denylisting event-drain queries can worsen buffered-event/storage pressure. [Pinned CLI documentation](https://github.com/osquery/osquery/blob/1889d51f0d1680672016a801e9d65799eb5fc5dc/docs/wiki/installation/cli-flags.md). | Module lifecycle/watchdog controls, presentation and analytical governors, bounded telemetry caches, and operating-system-specific applicability already exist. | Avoid a blanket "slow or stop busy modules" policy. Idle analytical work can wait; ingestion/drain paths and response must retain service. |
| Velociraptor exposes collection CPU/IOPS/operation/data limits, while documenting that those limits do not control invoked external tools. [Limiting resource usage](https://docs.velociraptor.app/docs/artifacts/resources/). | Angerona has bounded queues, per-rule evaluation budgets, forensics limits and isolated worker lifecycles. | Bound combined optional work, especially inference across consumers. Do not describe application timeouts as operating-system CPU/memory enforcement for external tools. |
| Falco can choose syscall inputs required by active rules while preserving inputs needed by its internal state engine; it exposes event loss. [Advanced Performance Tuning](https://falco.org/docs/concepts/event-sources/kernel/tuning/), [Dropping events](https://falco.org/docs/troubleshooting/dropping/). | Detection Runtime separates active and shadow lanes, and the current worktree adds no-evaluator admission skipping. EventBus already exports bounded callback timing/budget metrics. | A future dependency plan must keep minimum lineage/state inputs; first remove empty worker polling and unnecessary normalization. Do not disable a sensor because its recent output is quiet. |

These are different products with different collection/privilege boundaries.
Falco's syscall selection is a design analogy, not a directly portable Windows
ETW configuration. Angerona's user-mode observations and local-first operating
model do not imply fleet, kernel or tamper-resistance parity with these projects.

### Local observations that constrain the proposals

- `adversary_combat.py:_submit()` checks policy, severity, local provenance,
  deliberate response authority, a response contract and event integrity before
  bounded admission. `_handle()` rechecks policy/contract and performs the
  existing action-specific target/authority checks. The queue is 2,048 entries.
  Overflow rolls back dedup admission and emits a failure event. That loss is
  already visible; this report does not call it silent loss.
- `response_snapshot()` is already memory-only and separates disabled,
  starting, recovery-required, journal-full and queue-full states. It reports
  depth, capacity, drops and fixed decision counters. It does not expose oldest
  admitted age or processing latency in the inspected version.
- `EventBus.publish()` invokes subscribers inline, outside the ring lock. It
  measures callback budgets but cannot preempt a blocked callback. Metrics are
  already consumed by health/status surfaces; proposing metrics from scratch
  would duplicate functionality.
- `ai_triage.py:_ask()` neutralizes telemetry, but its broad exception handler
  falls back to the original prompt if neutralization fails. This is a
  source-level fail-open path for an optional narrative request, not proof of a
  successful prompt-injection exploit. Its emitted verdict is INFO and carries
  no response contract. Explicit narrative-only metadata would make that
  authority boundary clearer.
- Local AI already has attestation, circuit breakers, bounded output and Chill
  unload leases. `ai_security_broker.py` separately supports typed, authorized
  tool execution. Therefore "no AI anywhere can invoke any tool" would be false;
  the specific verified claim is that Combat's deterministic response path does
  not depend on inference and narrative text is not its authority.
- `speculative_triage.py` waits on an empty queue at 0.1-second intervals.
  `detection_runtime.py:run()` also sleeps 0.1 seconds between process/snapshot
  passes even when it has no active work. No-evaluator admission skipping is
  already present in concurrent work; a future wait must still wake on rule
  activation, work arrival, stop and generation replacement.
- The September 21 machine-usage contract, source caches, 84-module audit,
  existing long-session soak runner and current ATT&CK catalog are baseline
  features. They are not new results of this research pass.

## Ranked buildable proposals

Estimated impact uses 1–5; planning effort uses S=1, M=3, L=8. Ratios are
prioritization estimates, not performance measurements. No new BaseModule is
needed for any item. Defensive-only scope applies throughout.

| Rank | Proposal | Impact / effort | Fit |
| --- | --- | --- | --- |
| 1 | Fail closed when AI telemetry neutralization fails | 5 / S = 5.00 | AI Triage; Harden. |
| 2 | Bound overload notification amplification | 5 / S = 5.00 | Combat admission and EventBus handoff; Harden / Respond. |
| 3 | Prove autonomous response with inference unavailable | 4 / S = 4.00 | Existing response integration fixtures; Respond. |
| 4 | Expose response queue age and verified completion timing | 3 / S = 3.00 | Combat snapshot and response panel; Visualize. |
| 5 | Wake idle analytical workers on work | 5 / M = 1.67 | Detection Runtime and speculative triage; Harden. |
| 6 | Share a bounded local-inference admission permit | 4 / M = 1.33 | Ollama lifecycle and optional AI consumers; Harden. |
| 7 | Declare the minimum telemetry needed by active analytics | 4 / M = 1.33 | Contracts, rules and coverage; Detect / Visualize. |

### 1. Fail closed when AI telemetry neutralization fails

**Pitch:** Skip optional inference if its telemetry boundary fails, and mark AI
narrative output explicitly as non-authoritative.

**Why now / source:** Current OWASP agent guidance requires backend authority
checks and treatment of external content as untrusted; prompt text alone cannot
enforce permissions. [OWASP: AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html).

**Fit:** `modules/ai_triage.py:_ask()` and verdict publication; use the existing
`engines/ai_guardrail.py`. **Harden.** Replace the raw-prompt exception fallback
with a bounded health diagnosis and no HTTP call. Publish stable fields such as
`response_authorized=False` and an established narrative/advisory disposition;
do not invent a new disposition unsupported by downstream classifiers.

**Effort / limitation:** S. Preserve the existing model attestation and request
cancellation ordering. Missing AI assistance must not stop deterministic
collection, detection or response. The filter does not guarantee that the model
will never follow malicious instructions.

**Acceptance:** A sanitizer exception produces zero inference calls; a hostile
fixture appears only as bounded data; an AI verdict cannot mint a response
contract or raise its own response authority. Use existing offline fixtures.

**Safety:** Defensive only. No offensive payload, auto-execution of generated
commands, model-issued privilege changes or new network egress.

### 2. Bound overload notification amplification

**Pitch:** Preserve exact rejected response requests while coalescing generic
queue-pressure notifications so overload does not create more overload.

**Why now / source:** Falco documents that slow processing can increase kernel
event loss and recommends observing loss while reducing unnecessary work.
[Falco: Dropping events](https://falco.org/docs/troubleshooting/dropping/).

**Fit:** `adversary_combat.py:_submit()` currently publishes a saturation event
for each rejection, synchronously through EventBus. **Harden / Respond.** Keep
the drop counter and failed-admission dedup rollback. Aggregate generic detector
overflow into a bounded first/periodic/recovery health report with exact deltas.
Retain the signed per-request failure path for `queue_request_id` because SOAR
needs a terminal result for that exact request.

**Effort / limitation:** S for generic-notification coalescing only. Moving
request receipts off publisher callbacks is a separate M change requiring a
bounded receipt path and explicit handling when that path is full. Never claim
"accepted" until the request has actually entered an owned queue.

**Acceptance:** A large rejection burst yields exact drop counts, bounded
generic alerts and prompt callback return; every explicit SOAR request still
receives its exact failure result. Existing signed-failure tests remain valid.

**Safety:** Defensive only. Do not suppress original evidence, silently discard
action receipts, evict accepted work to admit newer work, or weaken integrity.

### 3. Prove autonomous response with inference unavailable

**Pitch:** Add an integration regression that verifies existing automatic
containment without a model or an AI-generated decision.

**Why now / source:** Wazuh's documented Active Response protocol is structured
and rule-triggered. The transferable principle is deterministic response
orchestration, independent of narrative assistance.
[Wazuh: Custom active response scripts](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html).

**Fit:** Existing Combat fixtures, `response_capability.py`, action journal and
verified drill result harness. **Respond.** Force model request entry points to
raise if called, deliver authenticated inert evidence to the normal response
worker, and require exact-target postcondition and signed committed result.
Include stale target identity, missing contract and incomplete postcondition
negative cases; a queued request alone must not satisfy the test.

**Effort / limitation:** S using deterministic fake action adapters. This
establishes control-flow independence, not physical-host containment efficacy.
Reuse real journal/contract logic while replacing only OS mutation. Live
validation remains bound to the existing installed authority and safe drill.

**Acceptance:** Model absence and hostile narrative strings neither block a
valid response nor authorize an invalid one. Report accepted/applied/verified
separately and verify that the original event survives a skipped AI narrative.

**Safety:** Defensive only; no malicious execution or unapproved process
termination. Existing standing authority remains the sole policy source.

### 4. Expose response queue age and verified completion timing

**Pitch:** Let the user distinguish a responsive armed worker from an armed
worker whose accepted work is waiting too long.

**Why now / source:** Current Velociraptor configuration separately controls
concurrency and waiting, illustrating why queue length alone does not explain
resource pressure. [Velociraptor: Pinned configuration reference](https://github.com/Velocidex/velociraptor/blob/79fbf7e59a178547039865b5967d7b8c6c53b03d/docs/references/server.config.yaml).

**Fit:** `AdversaryCombat.response_snapshot()` and `gui/response_status.py`.
**Visualize.** Track monotonic admission timestamps in bounded queue-owned state,
oldest queued age and a fixed-size processing-latency histogram. Show verified
completions separately from submissions. Snapshot reads must remain memory-only
and must not acquire the journal lock.

**Effort / limitation:** S. Treat counters as diagnostics, never authorization.
Do not read `queue.Queue` internals without its documented synchronization or
introduce an unbounded map keyed by event IDs. This proposal does not add a new
response expiration policy; that would require a separate contract migration.

**Acceptance:** Clock adjustment, queue rejection, cancellation and worker
restart cannot produce negative/incorrect ages or retained-state growth.
Blocked postconditions never increment the verified-completion counter.

**Safety:** Defensive only. No automated isolation escalation from queue age,
no action retry based solely on dashboard state, and no disclosure of targets.

### 5. Wake idle analytical workers on work

**Pitch:** Remove repeated empty processing passes while keeping immediate
reaction to accepted work and configuration changes.

**Why now / source:** osquery's current documentation warns against stopping
event-drain work as a generic performance response. The safe distinction is
between an empty consumer and a consumer with pending security evidence.
[osquery: Pinned event/watchdog controls](https://github.com/osquery/osquery/blob/1889d51f0d1680672016a801e9d65799eb5fc5dc/docs/wiki/installation/cli-flags.md).

**Fit:** `DetectionRuntimeEngine`/`DetectionRuntimeModule` and the worker in
`speculative_triage.py`; no new sensor. **Harden.** Introduce a generation-bound
work signal or condition with bounded health heartbeat. Signal on queue
admission, rule install/remove/activation and shutdown; check queue/configuration
predicate under the same synchronization to prevent lost wakeups. Skip creating
new expensive snapshots when neither state nor the health deadline changed.

**Effort / limitation:** M. The current worktree already has `submit_configured`
to avoid normalization when no evaluator exists; retain that change. A stopped
generation must never consume a later generation's work. Keep active/shadow
fairness and budget/loss accounting; no increased sensor polling interval.

**Acceptance:** With no rules/events, empty process passes stay near the health
heartbeat rate rather than ten per second. Rule activation and the first event
wake promptly. Repeated stop/start produces one consumer, no hang and no loss.

**Safety:** Defensive only; preserve native sensor ingestion, response, source
continuity and watchdog liveness. Quiet telemetry is not permission to disable
coverage.

### 6. Share a bounded local-inference admission permit

**Pitch:** Bound the combined cost of triage, briefing and prewarming requests
instead of relying only on independent per-module limits.

**Why now / source:** Ollama explains that concurrent contexts increase memory
requirements and queued requests can accumulate; Velociraptor separately limits
concurrent client collections. [Ollama: FAQ](https://docs.ollama.com/faq),
[Velociraptor: Pinned configuration reference](https://github.com/Velocidex/velociraptor/blob/79fbf7e59a178547039865b5967d7b8c6c53b03d/docs/references/server.config.yaml).

**Fit:** `core/ollama_lifecycle.py`, `ai_triage.py`, `daily_briefing.py` and
`speculative_triage.py`. **Harden.** Start with one app-owned optional-background
permit, bounded waiting/context bytes and generation cancellation. Speculation
may decline admission; deterministic evidence remains on the existing bus.
User-requested work can have a separately bounded lane, never unlimited bypass.

**Effort / limitation:** M. A semaphore is sufficient for an initial admission
boundary; a new elaborate scheduler is unnecessary. Do not change a shared
Ollama server's global configuration. Release permits after work actually ends,
including timed-out/cancelled requests. Keep existing model attestation and
Chill immediate-unload leases. This refines the prior visionary recommendation,
not a claim that shared admission is already implemented.

**Acceptance:** Simultaneous calls from all consumers obey the app limit;
prewarming cannot starve requested work; faults release capacity; accepted
background work and bytes remain bounded during an unavailable daemon.

**Safety:** Defensive only, local-first, and no model downloads or cloud fallback.
Inference pressure must not delay the deterministic response worker.

### 7. Declare the minimum telemetry needed by active analytics

**Pitch:** Make source-cost reductions explainable through a reviewed dependency
plan that always retains the minimum state needed for reliable detection.

**Why now / source:** Falco selects required rule inputs while preserving extra
events needed for its state engine. [Falco: Advanced Performance Tuning](https://falco.org/docs/concepts/event-sources/kernel/tuning/).

**Fit:** Capability inputs/dependencies in `module_contract.py`, governed
Detection Runtime rule metadata and `telemetry_coverage.py`. **Detect /
Visualize.** Begin with a display-only plan: each enabled analytic lists its
required provider/channel and freshness requirement; shared collection is
attributed once. Preserve required process birth/exit and lineage feeds even if
no explicit user rule mentions them. Unknown compatibility declarations stay
conservatively enabled.

**Effort / limitation:** M for the reviewed plan; changing native subscriptions
is a separate, larger phase. Do not copy Falco's Linux syscall sets into Windows
ETW or claim ETW-TI access without its real platform/signing prerequisites.

**Acceptance:** Disabling a module never removes a still-shared source; paused
or failed required sources remain explicit coverage gaps. Displayed expected
inputs correspond to pinned rule/configuration generations.

**Safety:** Defensive only. No driver installation, kernel callback changes,
event-loss concealment or automatic policy weakening. Defer collection changes
until the read-only dependency plan is validated.

## Scope and evidence limits

No product code, release files, launchers or VMware files were edited by this
agent. Mac/Linux launchers and the unfinished Analysis Lab are separate owned
workstreams. Universal startup must not imply universal Windows protection
parity; a VMware job completing must not imply a verified host response.

This report supplies design estimates and concrete acceptance conditions. It
does not establish whole-app speedups, lower long-session memory use, detection
efficacy or complete resistance to adversarial AI. The coordinating agent must
record implemented items, actual offline checks and publication separately.
