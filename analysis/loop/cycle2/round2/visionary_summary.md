# Cycle 2 / Round 2 - Visionary Summary

Date: 2026-07-14. Scope: evaluate the three Round 1 innovation candidates
against the current post-remediation architecture and implement at most one
bounded, defensive MVP. No rules, runtime configuration, external dependency,
network behavior, visible GUI, host process, or persistent runtime data changed.

## Scorecard and disposition

Value, feasibility, and safety use 1 (low) to 5 (high). Performance cost uses
1 (low) to 5 (high), so lower is better.

| Candidate | Value | Feasibility now | Safety now | Performance cost | Round 2 disposition |
|---|---:|---:|---:|---:|---|
| Response Safety Kernel | 5 | 5 | 5 | 1 | **One shadow-only MVP implemented** |
| Angerona Sensor Cells | 5 | 2 | 4 | 3 | Proposed only; no process-isolation prototype in the live suite |
| Collective Baseline Exchange | 4 | 1 | 3 | 3 | Research only; threat model, consent, privacy budget, and poisoning controls remain prerequisites |

The Response Safety Kernel was the only candidate with a useful experiment
that could be added without creating a new privilege, process, network path, or
automatic response. Round 2 also strengthened ARIA's immutable confirmation
binding, making a shadow comparison at its existing preview boundary a natural,
low-risk observation point. Sensor Cells would require Windows token/job/IPC
design and compatibility measurement. Collective exchange would introduce an
external trust and privacy boundary. Neither was safe to build during this
bounded loop.

## Implemented MVP - pure Response Safety Kernel shadow evaluator

New `src/angerona/core/action_policy.py` provides a dependency-free, stateless
evaluator for a structured principal/action/resource/context proposal. It:

- accepts only bounded, JSON-compatible data and produces deterministic
  canonical JSON plus a SHA-256 request digest;
- emits an explicitly non-authoritative `ALLOW` or `DENY`, a policy version,
  and stable diagnostic codes without returning raw arguments;
- denies inside its own shadow result when required context is missing,
  authorization is incomplete, an action digest changes, a process identity is
  stale, a target is a protected Windows process, or a policy raises/errors;
- gives each optional experimental policy an isolated request copy and converts
  malformed policy sets/results/exceptions to shadow denials;
- contains no I/O, host lookup, network, dependency, rule load, persistent
  state, or action callback.

`Assistant._record_shadow_preview()` mirrors only an already-staged ARIA WRITE
preview. The existing path's `STAGE` disposition is compared with the shadow's
expected denial while operator confirmation is still pending. The audit stores
only policy version, digest, boolean alignment, and diagnostic codes in ARIA's
already-bounded conversation deque. It does not return a value to the caller.

No live SOAR wiring was added. Process-shaped SOAR proposals are covered by the
standalone evaluator tests, but adding any read, log, or failure mode to the
active containment path was not justified by Round 2 evidence. A future phase
may mirror a pre-existing recommendation event after proving event-rate bounds;
the shadow must still remain outside containment decisions.

## Exact safety boundary

- The kernel's `ALLOW`/`DENY` is shadow data, not authorization. Production
  code does not consult it before confirming or executing an action.
- The only production hook runs after ARIA has staged a WRITE. It never runs in
  `confirm()`, SOAR containment, Resolve Center, drill cleanup, or host shutdown.
- The hook returns nothing, catches every evaluator failure, and records a
  fail-closed shadow diagnostic while leaving the existing preview intact.
- Audit metadata contains no principal/resource values, arguments, paths,
  indicators, preview text, confirmation token, or callback. It contains only a
  digest and fixed codes, and cannot grow beyond the configured ARIA memory.
- There is no wait, retry, lock, worker, disk write, network call, automatic
  response, or new host action. A 10,000-evaluation in-memory probe measured
  353.088 ms total, approximately 35.309 microseconds per preview.
- No rules or policy file is activated. Experimental policy errors fail closed
  only in the non-authoritative result.

## Deterministic verification

New `tests/test_cycle2_round2_visionary.py` passed **7/7** cases:

1. digest stability across mapping order;
2. argument mutation changes the digest and fails expected-digest binding;
3. PID/start-time identity reuse is denied as stale;
4. missing context returns a deterministic denial rather than an exception;
5. an experimental policy exception is contained and denied;
6. a protected-process target is denied;
7. ARIA stages without executing, records one bounded digest-only shadow audit,
   and treats `STAGE` plus shadow `DENY` as aligned.

Additional gates passed:

- warning-as-error compile of the three affected/new Python files: **3/3**;
- action-policy module self-test: **PASS**;
- existing Round 2 remediation runner: **5/5**;
- ARIA standalone suite: **12/12**;
- project compile helper after the addition: **195/195**, 0 failures;
- targeted diff-integrity check: PASS (line-ending notices only).

## Implemented versus proposed

Implemented now: one pure shadow evaluator, one ARIA preview-only in-memory audit
hook, seven deterministic tests, and this audit record.

Not implemented: a real authorization boundary; SOAR/Resolve Center/drill/
firewall/patch/remote action gating; executable hashing; live process lookup;
policy editing or loading; durable audit receipts; Sensor Cells; collective
learning; any new GUI; or any automatic response. Those remain proposals and
must not be described as shipped protection.

## Rollback

Rollback is local and state-free: remove the single
`self._record_shadow_preview(...)` call and its helper from `core/assistant.py`,
then remove `core/action_policy.py` and its focused test. There is no schema,
configuration, rule, runtime database, firewall rule, process, or persisted
audit record to migrate or clean.

## Round 3 audit targets

1. Search every production consumer and prove no action branches on
   `ShadowDecision.allowed`, `decision`, `aligned`, or any shadow diagnostic.
2. Re-run mutation, stale-PID, malformed-input, protected-process, and policy-
   error cases plus ARIA's full confirmation suite.
3. Fuzz bounded canonicalization with unusual numeric/container/key inputs and
   confirm deterministic digests and no exception escape.
4. Confirm the audit deque remains bounded under long WRITE-preview sessions
   and that no raw argument, preview, path, indicator, or token reaches its
   metadata.
5. Measure preview overhead again with representative nested ARIA arguments.
   Do not promote the shadow into an authorization gate during this loop.
6. Keep SOAR unwired unless a separate audit proves a post-proposal observation
   point cannot affect containment latency, event recursion, or availability.

Round 2 visionary status: **one bounded MVP implemented; gates pass; no current
action authority or host behavior changed.**
