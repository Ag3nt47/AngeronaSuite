# Program-firewall transaction custody

R6-03 remains **partially open**. Windows termination already retains a native
process handle; program-firewall mutation still uses PID/birth/path snapshots
around a pathname-based rule. This source review identifies missing transaction
custody. It does not demonstrate a host exploit or establish that an observed
alert resulted from this gap. No implementation, runtime experiment or host
firewall change is part of this review.

## Current transaction boundary

[Process admission](../../src/angerona/modules/adversary_combat.py#L4340)
checks psutil process identity, expected creation time and protected-target
policy before calling
[`_block_program`](../../src/angerona/modules/adversary_combat.py#L5263).
The latter holds the journal transaction, persists intent, adds an outbound
`program=<exe>` rule, then obtains another psutil PID/birth/path observation.
An observed mismatch invokes the existing uncertain-mutation rollback.

Journal locking and durable I/O can separate the upstream process check from
firewall dispatch. The post-dispatch comparison recognizes a changed PID birth
or pathname, but cannot distinguish different executable file objects occupying
the **same pathname**. This action also does not install an exact-object
terminal validator, leaving another observation-to-commit interval.

[`_run_firewall`](../../src/angerona/modules/adversary_combat.py#L4458)
uses bounded netsh calls and checks managed-rule presence after an add. That is
useful command/postcondition evidence; it does not bind a rule to a retained
process or executable file object. The existing
[PID-change rollback regression](../../tests/test_adversary_combat_boundaries.py#L286)
proves its modeled rollback behavior, not custody across the transaction.

## Existing primitives and reuse constraints

| Primitive | Useful foundation | Constraint |
| --- | --- | --- |
| [WindowsProcessLease](../../src/angerona/core/windows_process_lease.py#L128) | Non-inheritable process handle, raw birth identity, liveness checks and a fixed monotonic lifetime. | Its rights include `PROCESS_TERMINATE`; its terminal proof requires an exited process. A firewall-only lease needs query/synchronize rights and an alive-object proof. |
| [Windows quarantine move guard](../../src/angerona/modules/adversary_combat.py#L586) | Retained directory/file objects and handle-based identity checks. | Its leaf requests DELETE with exclusive sharing. Dropping that contract onto a running image or firewall reader is unsuitable. |
| [Pinned trusted executable](../../src/angerona/core/executable_trust.py#L319) | Its sealed leaf open denies write/delete sharing while allowing readers. | The public API requires independent publisher/hash pins and protected ancestry. Response targets need not be trusted; those requirements must remain intact. Leaf custody alone also leaves ancestor replacement unresolved. |
| [Authentication component custody](../../src/angerona/core/windows_auth_extensions.py#L2682) | Bounded retained plain ancestors, read-sharing participation and object/name revalidation. | Reuse the low-level design without coupling Combat to the entire collector or claiming resistance to a privileged adversary. |

## Smallest defensible implementation scope

Add a bounded program-firewall transaction lease combining a query/synchronize-
only process handle, sealed current executable file object and retained plain
local ancestors. Reject unsupported paths, reparse-backed ancestry, uncertain
identity, unsupported aliases and incompatible sharing. Do not relax executable
trust verification to admit malicious targets.

Acquire custody before intent; revalidate after intent and immediately before
firewall dispatch. Retain the same objects through rule observation and terminal
persistence, or through verified rollback. Compose its proof with the existing
[`_terminal_commit_validator`](../../src/angerona/modules/adversary_combat.py#L3736),
which runs inside the retained
[journal writer](../../src/angerona/modules/adversary_combat.py#L3568).

Mark possible effect before dispatch. Later identity, deadline or proof failure
must use the existing uncertain-mutation rollback and recovery circuit. Do not
fall back to a PID-only action. Preserve a fixed lease deadline; synchronous
native calls remain cooperatively bounded rather than forcibly preemptible.

## Adversarial acceptance evidence

- Refuse PID reuse before acquisition, during intent persistence and during a
  simulated firewall call; never substitute a later PID lookup.
- Attempt same-path leaf replacement, ancestor rename and reparse changes while
  custody is held. Native tests must show denial or explicit refusal.
- Expire the lease during intent, dispatch and terminal persistence. Preserve
  uncertainty if an effect may already have occurred.
- Exit the target while retaining its original process handle; require the
  correct liveness result rather than treating handle presence as a live process.
- Model rule creation followed by a false return or exception, and rollback
  with unavailable or unproven absence. Keep recovery visible when needed.
- Fail terminal validation or journal persistence after rule creation. Prove
  rollback or preserve the durable unresolved intent.
- Exercise partial acquisition and close failures, exact handle ownership,
  query/synchronize-only rights, non-inheritance and no PID fallback.
- Separate inert adapter tests from an owned-child/scratch-file native custody
  gate. The latter needs no actual firewall mutation and must prove child and
  handle retirement.

## Remaining guarantees

This scope would prove transaction custody of a process object and the current
executable pathname/file object. It would **not** establish that those file bytes
equal the process's originally mapped image. After custody closes, a persistent
pathname rule still lacks a process/file identity lease for its entire lifetime.

Native WFP process-bound connection admission is a separate implementation and
validation task. The current
[egress guard](../../src/angerona/modules/process_egress_guard.py#L1) is an audit
observer, and its [broker](../../src/angerona/core/process_egress_lease.py#L1) is a
policy primitive. The
[privileged response service](../../src/angerona/core/response_service_host.py#L1)
also remains diagnostic only. A transaction-custody patch would not close those
deployment or enforcement boundaries, nor the remaining suspension/undo portions
of R6-03.
