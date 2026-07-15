# Cycle 2 / Round 1 — Innovation Research

Date: 2026-07-14. Scope: defensive, local-first architectural research for
Angerona. This phase changed no source code, runtime configuration, rules, or
host state. The three candidates below are proposals for Round 2/3 visionary
review, not shipped capabilities.

## What was excluded as already present or previously proposed

The current tree already has a shared HMAC-signed EventBus, a bounded SQLite
flight recorder, thread-based `BaseModule` workers, sequential Eco wake-up,
resource/performance governors, local behavioral tuning, opt-in Remote Bridge,
deterministic red-team correlation, Evidence Lattice Fusion, Telemetry
Expectation Contracts, and ARIA's confirm-then-execute gate.

The prior loop already proposed a counterfactual detection twin, causal-ledger
checkpoints, telemetry mutation, and local novelty sketches. Those ideas were
not repackaged as new Cycle 2 candidates. OpenTelemetry's stable log model does
provide `TraceId`/`SpanId`, and W3C Trace Context standardizes propagation of a
shared trace identity, but a replay twin remains a previously proposed future
project rather than a new shortlist entry.

Source basis: [OpenTelemetry Logs Data Model](https://opentelemetry.io/docs/specs/otel/logs/data-model/)
and [W3C Trace Context](https://www.w3.org/TR/trace-context/). Any application
of those standards to Angerona is an architectural inference, not a claim made
by the standards.

## Scorecard

Value, feasibility, and safety use 1 (low) to 5 (high). Performance cost uses
1 (low overhead) to 5 (high overhead), so lower is better.

| Rank | Proposed capability | Value | Feasibility | Safety | Performance cost | Disposition |
|---:|---|---:|---:|---:|---:|---|
| 1 | Response Safety Kernel | 5 | 4 | 5 | 1 | **Recommend bounded shadow-mode MVP** |
| 2 | Angerona Sensor Cells | 5 | 3 | 5 | 3 | Recommend one-parser isolation prototype |
| 3 | Collective Baseline Exchange | 4 | 2 | 3 | 3 | Research only; no MVP until threat model is complete |

## 1. Response Safety Kernel — one policy boundary for every host change

### The leap

Create one small, deterministic authorization service through which *every*
state-changing action must pass: ARIA writes, SOAR containment, Resolve Center
fixes, process trust changes, firewall changes, drill cleanup, patch application,
and remote/mobile directives. Today these paths have multiple good but separate
safety checks. The kernel would make the safety contract uniform and auditable.

Each request becomes a structured tuple:

- principal: operator, ARIA, SOAR, mobile bridge, or module instance;
- action: suspend, terminate, trust, block, rollback, patch, clean, or dispatch;
- resource: immutable process-start identity, exact path/hash, rule, or host;
- context: evidence quorum, severity, expiry, confirmation identity, simulation
  flag, reversibility, and expected rollback.

The kernel returns deny/allow plus determining policy IDs, an immutable action
digest, an idempotency key, and the conditions that must remain true at execute
time. A confirmation token would authorize that exact digest, not merely a tool
name and mutable arguments. Policy errors, stale process identity, missing
evidence, changed target hash, or expired context would fail closed.

### Why the research supports it

Cedar models authorization as principal/action/resource/context and provides
default-deny with forbid-overrides-permit semantics and diagnostics. Its
security documentation describes a Lean formal model, Rust implementation,
differential testing, schema validation, bounded-input guidance, and centralized
authorization logic. These properties make Cedar a useful design reference for
Angerona even if the first MVP is a dependency-free Python decision facade.

Sources: [Cedar authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html),
[Cedar security and validation model](https://docs.cedarpolicy.com/other/security.html),
and [Cedar policy validation](https://docs.cedarpolicy.com/policies/validation.html).

Angerona-specific inference: Cedar uses skip-on-error for an individual policy;
the Angerona adapter should inspect diagnostics and deny a host mutation if *any*
policy error affects the request. That stricter behavior is not a Cedar default.

### Bounded visionary experiment

Build only a pure `core/action_policy.py` shadow evaluator. Mirror proposed SOAR
and ARIA actions into it, compare its decision with the current decision, and
write an audit event. Do not place it in the execution path and do not add a new
dependency. A later gate can be considered only after deterministic tests cover
stale PID reuse, argument mutation, token replay, missing context, rule errors,
and protected-process denial.

### Non-negotiable safety boundaries

- No new automatic action and no weakening of current confirmation.
- Immutable target identity: PID plus process start time and executable hash/path.
- Confirmation binds principal, action, resource, context digest, policy version,
  and expiry.
- Every allow has a dry-run preview, expected effect, rollback route, and receipt.
- Policy editing is itself a gated action; invalid policy cannot become active.

## 2. Angerona Sensor Cells — isolate modules from one another and the GUI

### The leap

Move selected high-risk or failure-prone work from shared in-process threads into
least-privileged child “cells.” A cell receives a narrow capability manifest,
an authenticated local-only channel, memory/CPU limits, and a restart budget.
It can submit immutable observations but cannot directly invoke response code or
publish as another sensor.

This changes Angerona's trust model. Today a buggy or compromised in-process
module can stall shared resources and logical module names are not cryptographic
identities. A cell would have an OS process identity and per-cell key, so EventBus
provenance can distinguish independent sensor boundaries. Crashing or leaking
one optional scanner would no longer freeze the GUI or corrupt every module's
state.

### Why the research supports it

Microsoft documents AppContainer as a Windows security boundary that restricts
process, file, registry, network, device, credential, and user-data access unless
explicitly granted. Windows Job Objects can manage processes as a unit, enforce
working-set/priority/CPU limits, send limit notifications, and account for
resources. Restricted tokens can remove privileges and apply restricting SIDs.
Named pipes support ACL-controlled local IPC; Microsoft explicitly advises
denying network identities or using local RPC when a pipe is local-only.

Sources: [Microsoft AppContainer launch and capability model](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer),
[Microsoft Windows application isolation](https://learn.microsoft.com/en-us/windows/security/book/application-security-application-isolation),
[Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken),
and [Microsoft Named Pipes guidance](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipes).

### Bounded visionary experiment

Isolate exactly one read-only parser that handles untrusted input, not a real-time
sensor or response module. Feed it a fixed corpus through a bounded local channel,
apply a Job Object memory/CPU ceiling, deny network access, and compare result,
latency, crash containment, and cleanup with the in-process implementation. The
prototype must fall back to “sensor unavailable,” never silently to unsandboxed
execution.

### Non-negotiable safety boundaries

- No network capability by default and no inheritance of the main process token.
- Per-cell allowlisted input/output schema, message-size cap, rate cap, nonce,
  and authenticated identity.
- Cells emit evidence only; they cannot contain, patch, trust, or write policy.
- Critical real-time coverage stays on the proven current path until measured
  latency and failover behavior are acceptable.
- Cell death is visible and cannot be reported as healthy sensor silence.

## 3. Collective Baseline Exchange — learn across nodes without sharing telemetry

### The leap

Allow an explicitly enrolled Angerona fleet to answer questions such as “how
common is this parent/child transition or destination class?” without uploading
raw process names, paths, command lines, IPs, alerts, model weights, or per-host
records. Each node would contribute clipped, bounded sketches or histograms;
secure aggregation would reveal only a minimum-size group aggregate, and
differential privacy would limit what the published aggregate reveals about any
one host.

The output must remain advisory: it may adjust an analyst-facing rarity score,
but it must never auto-trust a process, suppress a sensor, lower severity, or
authorize containment. This complements the local Behavioral Tuner and opt-in
Remote Bridge; it does not replace them.

### Why the research supports it

Google Research's secure-aggregation paper presents a failure-robust protocol
that lets a server collect only an aggregate of user-held updates and analyzes
honest-but-curious and malicious-server settings. NIST SP 800-226 describes
differential privacy as a mathematical framework for quantifying privacy loss
and warns that practical systems have privacy hazards beyond simply selecting
an algorithm.

Sources: [Google Research — Practical Secure Aggregation for Privacy-Preserving Machine Learning](https://research.google/pubs/practical-secure-aggregation-for-privacy-preserving-machine-learning/)
and [NIST SP 800-226 — Guidelines for Evaluating Differential Privacy Guarantees](https://csrc.nist.gov/pubs/sp/800/226/final).

Secure aggregation and differential privacy solve different problems. Secure
aggregation hides individual contributions from the aggregator; differential
privacy limits inference from released aggregates. Neither alone prevents a
malicious participant from poisoning the aggregate. That threat requires its
own enrollment, clipping, robust-aggregation, quorum, replay, and audit design.

### Research gate before any prototype

First write a data inventory and adversary model: which statistic is useful,
which input could identify a host, minimum cohort size, clipping bound, privacy
budget, retention, node authentication, dropout behavior, poisoning tolerance,
operator consent, and deletion/withdrawal semantics. If a useful statistic
cannot be defined without stable host-identifying data, do not build it.

### Non-negotiable safety boundaries

- Off by default; explicit enrollment and a visible per-round disclosure preview.
- No raw events, paths, usernames, command lines, IPs, hashes, or persistent host
  identifier leave the machine.
- Minimum cohort and contribution limits; no query on a single or tiny cohort.
- Privacy budget is finite, visible, testable, and cannot silently reset.
- Aggregate output can raise curiosity only; it cannot create an allowlist or
  weaken detection/response.

## Recommendation for the visionary phases

Round 2 should consider only the **Response Safety Kernel shadow evaluator** as
the bounded MVP because it has the highest value, lowest runtime cost, and a
clear no-action test boundary. Sensor Cells should remain a one-parser lab
prototype until compatibility and latency are measured. Collective Baseline
Exchange should remain research-only during this three-loop cycle.

