# Round 3 — Visionary Summary

Date: 2026-07-14. Scope: one bounded, local-first architectural validation
capability. The runtime-generated `rules/_active_combined.yar` file was not
touched.

## Research basis

Primary and authoritative sources ground the design. The Angerona-specific
architecture and conclusions are inferences from those sources, not claims the
sources make about this project.

- [MITRE ATT&CK Host Status (DC0018)](https://attack.mitre.org/datacomponents/DC0018/)
  identifies telemetry about the health and operational state of host security
  sensors, including failures, tampering, misconfiguration, and deliberate
  evasion. This supports validating whether a sensor path actually produces its
  expected evidence rather than assuming a running thread is healthy.
- [NIST SP 800-137](https://csrc.nist.gov/pubs/sp/800/137/final) describes
  continuous monitoring as providing visibility into assets, threats, and the
  effectiveness of deployed security controls. A deadline-bound benign probe is
  a small, automatable control-effectiveness measurement.
- [NIST SP 800-137A](https://csrc.nist.gov/pubs/sp/800/137/a/final) describes
  repeatable assessment criteria and procedures for evaluating monitoring
  programs. This supports declarative, deterministic expectation contracts over
  ad hoc success messages.
- [OpenTelemetry semantic conventions for events](https://opentelemetry.io/docs/specs/semconv/general/events/)
  specify named point-in-time occurrences, timestamps, severities, and structured
  attributes. TECT similarly uses stable, low-cardinality echo names while probe
  identifiers remain opaque data.
- [NIST IR 8356](https://csrc.nist.gov/pubs/ir/8356/final) describes electronic
  representations of entities and their state transitions, monitoring,
  simulation, testing, and trust considerations. It grounds the future isolated
  counterfactual-replay candidate, but that larger design did not clear this
  round's isolation and effort gates.

## Existing-capability exclusion

Inspection covered Round 2's ELAT implementation and visionary scorecard,
`modules/canary_drill.py`, `core/eventbus.py`, the recorder, provenance graph,
incident correlation, SOAR, and the Red Team simulation.

Angerona already had entity-scoped weak-signal fusion, time-bucket incidents,
process provenance, a hard-coded process canary, coarse sensor-silence checks,
event HMACs, and deterministic benign Red Team markers. It did not have a
general bounded evaluator for the invariant “probe X must produce named echoes
A/B before deadline D.”

Code inspection also found that the existing DRILL accepted any EventBus message
containing its tag. Its own `DRILL canary fired: <tag>` announcement therefore
satisfied the pending probe without an ETW event. Separately, after any historic
successful catch, firing the next probe reset a current miss streak; two real
consecutive misses could fail to reach the configured escalation threshold.
TECT was selected because it creates a reusable validation primitive and fixes a
demonstrated false-health path rather than adding another detector.

## Candidate scorecard

Scale: novelty, defensive value, and fit are 1 (low) to 5 (high). Effort,
false-positive risk, privacy burden, and required privilege are 1 (low) to 5
(high); lower burden is better.

| Candidate | Novelty | Value | Fit | Effort | FP risk | Privacy | Privilege | Decision |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| **Telemetry Expectation Contracts (TECT)** | 4 | 5 | 5 | 2 | 2 | 1 | 1 | **IMPLEMENTED** |
| Isolated counterfactual detector replay with mechanically disabled action sinks | 5 | 5 | 4 | 5 | 3 | 1 | 1 | PROPOSED |
| Offline failure-mode mutation harness for dropped, delayed, duplicated, and reordered telemetry | 4 | 4 | 4 | 4 | 2 | 1 | 1 | PROPOSED |
| Keyed causal-ledger checkpoints exposing event deletion and reordering | 3 | 4 | 5 | 3 | 1 | 1 | 1 | PROPOSED |
| Privacy-preserving local novelty sketches over process/network behavior | 5 | 4 | 3 | 4 | 4 | 1 | 1 | PROPOSED |

Only TECT cleared the bounded-MVP bar. Counterfactual replay still lacks a
mechanically provable action-sink isolation boundary. Failure mutation needs
clone-safe detector interfaces and a representative oracle. Ledger chaining
needs migration, checkpoint, and crash-recovery design. Novelty sketches need a
benign corpus and threshold calibration before they can be trusted.

## Selected concept — Telemetry Expectation Contracts

`core/telemetry_contracts.py` is a pure, thread-safe state machine. A caller arms
an opaque probe ID with a contract name, up to 16 required named echoes, and a
monotonic deadline. Exact echoes advance only the matching probe. Unknown probes,
unrelated or duplicate echoes, late echoes, and capacity overflow cannot create a
success. Completion returns an explainable satisfied/missed outcome; TECT itself
does not alert or act.

```text
DRILL arms benign_process_creation_echo(tag, deadline=6s)
                    |
                    v
             benign cmd /c REM tag
                    |
                    v
ETW Core Listener + EID 4688 + exact tag
                    |
                    v
       TECT observes sensor.process_create
             /                     \
    before deadline              missing/late
         |                           |
  satisfied outcome              missed outcome
         |                           |
reset DRILL miss streak       existing DRILL alert path
```

DRILL now maps only `ETW Core Listener`/test-equivalent events with structured
EID 4688 to `sensor.process_create`; its own announcement and any unrelated
module quoting the tag are rejected. A successful contract resets the miss
streak. Probe creation no longer resets it, so consecutive real misses can reach
the existing HIGH/CRITICAL path. Stop/start also reuses one EventBus subscription.

## Privacy and threat model

- TECT is memory-only, local, deterministic, and capped. DRILL allows eight
  pending probes; the generic engine defaults to 256. There is no persistence,
  socket, cloud/model call, privileged polling, or new host action.
- Probe identifiers are treated as opaque bounded strings. Even a
  PowerShell-looking identifier is compared as data and never interpreted.
- TECT contains no callbacks or response sink. It cannot terminate, suspend,
  isolate, write a rule, or change the host.
- The strict module-name/EID mapping prevents accidental self-acknowledgment,
  but module names remain logical in-process identities, not cryptographic sensor
  identities. A compromised in-process module could still forge a matching
  event, consistent with the EventBus trust limitation.
- A missing echo can reflect audit-policy/configuration failure rather than an
  adversary. DRILL's existing two-miss escalation and diagnostic wording remain
  important false-positive controls.

## Implementation diff

- Added `src/angerona/core/telemetry_contracts.py`:
  - immutable contract/outcome records;
  - bounded pending state with duplicate/capacity fail-closed behavior;
  - exact named echoes, monotonic deadline enforcement, late/missing outcomes,
    cancellation, and deterministic offline `self_test()`;
  - malicious-looking opaque-ID, wrong-probe, wrong-echo, duplicate, late,
    partial-expiry, capacity, and cancellation controls.
- Updated `src/angerona/modules/canary_drill.py`:
  - migrated pending canaries to TECT;
  - accepts tags only from trusted ETWG-compatible EID 4688 events;
  - rejects the module's own tagged announcement;
  - resets consecutive misses on a real satisfied contract only;
  - preserves miss streaks across later probe fires and prevents duplicate bus
    subscriptions after stop/start;
  - expanded deterministic self-test to cover TECT and strict source filtering.

No response policy, severity threshold, host configuration, network behavior,
YARA rule, or detector cadence changed.

## Verification evidence

- `py_compile` for both changed files: **PASS**.
- Project `compileall -q src tools`: **PASS**.
- TECT deterministic self-test: **PASS** — bounded contracts, opaque IDs, exact
  echoes, deadlines, and false-positive controls.
- DRILL deterministic self-test: **PASS** — its self-announcement is rejected and
  a trusted ETWG/EID 4688 echo is accepted.
- Module discovery: **61 modules**, **0 discovery errors**; DRILL discovered.
- Full offscreen `tools/selfcheck.py`: **26 passed, 0 failed, exit 0**.
- Module runner inside selfcheck: **47 passed, 15 expected stopped/idle/Ollama
  skips, 0 genuine failures**; both ELAT and DRILL explicitly passed.

## Next experiments and honest limitations

1. TECT is intentionally integrated with one contract only. Add another contract
   only after defining a trusted structured producer/echo mapping and measuring
   normal latency; never infer success from free-text messages.
2. Record aggregate satisfied/missed latency histograms locally before changing
   the six-second deadline. This MVP intentionally adds no persistence.
3. If sensors later move into isolated processes, bind echo identity to an
   authenticated process/channel rather than a module-name string.
4. A probe spawn failure is reported separately by DRILL; the armed expectation
   may subsequently time out. A future lifecycle refinement can call the existing
   cancellation API only after proving all spawn-failure paths are distinguishable
   from “spawn succeeded but sensor was blind.”
5. Keep counterfactual replay proposed until every participating detector exposes
   a pure cloneable analysis interface and action sinks can be mechanically
   replaced and audited as no-ops.

## Final disposition

| Candidate | Novelty / value / effort | Status |
|---|---|---|
| Telemetry Expectation Contracts | 4 / 5 / 2 | **IMPLEMENTED** |
| Isolated counterfactual detector replay | 5 / 5 / 5 | PROPOSED |
| Offline telemetry failure mutation | 4 / 4 / 4 | PROPOSED |
| Keyed causal-ledger checkpoints | 3 / 4 / 3 | PROPOSED |
| Local novelty sketches | 5 / 4 / 4 | PROPOSED |
