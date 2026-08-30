# Cycle 27, Round 1 — Second Independent High-A Re-audit

Scope was limited to the second remediations for `C27-R1-A01`,
`C27-R1-A10`, and `C27-R1-A16`. All hostile checks were local and inert: a
fake process object, an in-memory EventBus/broker, and a fake Windows Security
channel were used. No live process was terminated, no host event log or policy
was changed, no network target was contacted, and no product code was edited.

The focused affected suites pass (`60 passed`), and compile plus Ruff are clean.
The original EventBus producer-forgery issue is closed. Two state-transition
bypasses remain: an operator disposition can terminalize an in-flight process
intent before its mutation finishes, and one Security-cursor approval can be
replayed to erase a later generation gap. Therefore A01 and A16 remain open.

| Original finding | Independent verdict | Residual severity | What held | Residual bypass |
|---|---|---:|---|---|
| `C27-R1-A01` | **REOPENED / PARTIAL** | HIGH | Post-kill exceptions and orphan-append failure trip the circuit, survive restart, and journal tampering prevents reconciliation. | The disposition API accepts a bare in-flight intent. A concurrent disposition written before the later orphan is treated as terminal on restart, so the completed-but-uncertain mutation re-arms. |
| `C27-R1-A10` | **CLOSED** | — | Generic EventBus claims, fake producer/consumer objects, cross-producer receipts, registry rebinding, old lifecycle generations, and receipt replay were rejected. Genuine APID/FIM/native-AMSI paths can close their own contracts; NDRD remains explicitly unassured. | No bypass within the stated shared-EventBus/confused-sibling boundary. Arbitrary code already executing in this Python process remains outside this assurance claim and must not be described as isolated producer security. |
| `C27-R1-A16` | **REOPENED / PARTIAL** | HIGH | Missing, malformed, MAC-altered, other-host, live clear/refill, retention, and anchor mismatch states remain below 100 across restart. | A previously used human approval is reusable for a newly detected generation, clearing and persisting the gap at health 100. Older valid cursor/channel snapshots also have no independent anti-rollback anchor. |

## `C27-R1-A01` — An in-flight intent can be disposed before the mutation resolves

### Control credit

- `src/angerona/modules/adversary_combat.py:1854-1879` now crosses an explicit
  uncertainty boundary before `kill()`. A kill-side exception or an
  unprovable postcondition appends a non-terminal orphan and opens the circuit.
- If the orphan append itself fails, the fsynced intent is sufficient for a new
  instance to recover `RECOVERY REQUIRED`; the inert replay produced current
  and restarted health `0` with mutation blocked.
- Altering the signed orphan record caused `_reconcile_state()` to return false
  with health `0` and `combat journal integrity failure`.

### Residual reproduced

`_pending_recovery_records()` at
`src/angerona/modules/adversary_combat.py:2150-2169` calls every non-terminal
intent a recovery record. `resolve_nonreversible_recovery()` at lines
`2227-2253` verifies that the action is non-reversible, but does not require the
latest record to be an `orphan` with `mutation_started=true`, membership in
`_recovery_required`, or an already-open circuit. It can consequently append an
`operator_disposition` while `_act_on_process()` is between its durable intent
and postcondition.

An inert fake process blocked inside `kill()`. While it was blocked, a fresh,
exact, HMAC-valid human decision disposed the bare intent as
`confirmed_not_applied`. The fake kill was then released, marked its effect
complete, and raised from `is_running()`. The exact result was:

```text
disposition_ok=true
effect=true
journal=[intent, operator_disposition, orphan]
current_mutation_blocked=true
restart_reconciled=true
restart_mutation_blocked=false
restart_pending=[]
```

The restart bypass occurs because `_recover_orphaned_journal()` at lines
`2008-2028` accumulates terminal action IDs without phase ordering: the earlier
operator disposition permanently suppresses the later orphan. A second inert
check also showed that the public `now=` argument can make an old otherwise
valid human decision appear fresh, so freshness currently depends on caller
clock discipline.

### Impact and recommendation

An operator/UI thread racing the response worker can attest that a mutation did
not happen before it actually finishes, and a later crash/restart silently
forgets the uncertainty. Hold one state-transition lock from intent through
commit/orphan; permit disposition only for the exact latest authenticated
`orphan` whose `mutation_started` and recovery state are valid and whose HMAC is
the one bound into the disposition. Journal replay must reject a disposition
that precedes its bound orphan or any later orphan for that action. Use an
internal trusted clock in production and add the reproduced concurrent ordering
as a regression test.

## `C27-R1-A10` — Object-bound detector receipts resist the tested forgeries

### Closure evidence

The broker at `src/angerona/core/assurance_receipts.py:166-412` binds each
receipt to the exact registry object, capability, detector code/name,
lifecycle generation, source epoch, one-time challenge, target/evidence digest,
observation, and time window. The consumer is also object-bound, and successful
verification consumes the challenge.

Independent inert checks produced all of the following results:

```text
generic EventBus field forgery rejected=true
producer-object spoof rejected=true
consumer-object spoof rejected=true
cross-producer issue rejected=true
registry rebind rejected=true
old lifecycle generation rejected=true
second receipt consumption rejected=true
native AMSI genuine observation accepted=true
shared-bus NDRD remained unassured=true
```

The dedicated tests additionally prove APID requires a complete live-prologue
comparison and FIM hashes the exact watched marker contents. The default
observation-only AMSI and shared-bus-only NDRD correctly fail rather than
manufacturing assurance. This closes the original self-echo and generic
shared-EventBus publisher bypass.

The closure is intentionally scoped: Python object identity is not a sandbox.
Code already executing arbitrarily inside the manager process can introspect or
modify Python objects and must be treated as process compromise, as the EventBus
module already documents. Any future claim of protection from malicious loaded
extensions requires process-isolated producers/broker authority, not stronger
wording around this in-process receipt.

## `C27-R1-A16` — Cursor approval replay can erase a later Security-log gap

### Control credit

- `src/angerona/modules/etw_listener.py:187-267` rejects missing, malformed,
  MAC-invalid, unsafe, and host-mismatched cursor objects and carries a persisted
  gap forward.
- Lines `502-627` detect clear/refill, numeric reset, retention advancement,
  record replacement, missing records, backlog, and failed durable progress.
- A current cursor cannot be enrolled without a fresh, exact human
  `policy.approve` decision and a recent caught-up bounds sample.

### Residual 1: one approval clears more than one generation

`enroll_security_cursor()` at
`src/angerona/modules/etw_listener.py:339-430` verifies the decision signature,
generic `Security` resource, and age, but it does not consume the authorization
request or bind it to the current generation, bookmark, anchor, gap digest, or
cursor sequence. The same decision can therefore authorize a different state
transition later in its five-minute window.

The inert replay first enrolled generation 1 at bookmark 3. A clear/refill to
generation 2 was detected and persisted at health 45. Reusing the exact same
decision immediately returned `ok=true`, cleared the gap, set health 100, and a
new process loaded that state at health 100:

```text
before_replay_health=45
before_replay_gap="record numbers reset below bookmark 3 to high watermark 2"
generation=2
same_approval_replay_ok=true
after_replay_health=100
restart_health=100
restart_gap=""
```

### Residual 2: valid snapshot rollback has no freshness authority

The cursor contains an authenticated `sequence`, but lines `187-267` have no
independent monotonic high-water against which to compare it. An old, valid
same-host cursor and corresponding old channel snapshot were restored after the
listener had advanced from sequence 1/bookmark 5 to sequence 2/bookmark 10. A
new process accepted the rollback with health 100, no gap, and no replayed
events. HMAC proves snapshot integrity, not freshness.

### Impact and recommendation

A captured or accidentally retained approval can convert a newly detected log
clear into a durable green baseline without a new human decision. Make
enrollment a one-time, durably consumed transaction bound to the exact current
host, generation, sequence, bookmark, anchor, bounds, gap digest, and reason;
resample the channel under the cursor lock immediately before commit. Anchor
cursor sequence/gap history in an independent append-only high-water (and, when
available, TPM-backed state or Windows Event Log service identity evidence), or
explicitly disclose that whole-host snapshot rollback cannot be proven by the
software HMAC alone. Add approval-replay, stale-snapshot, and concurrent
read/enroll tests.

## Gate evidence

- Focused affected suites: `60 passed in 7.34s`.
- Dedicated High-A suite: included in the 60 passing tests.
- `py_compile`: pass for all nine affected product files and the dedicated test.
- Ruff: pass for the same scope.
- Independent hostile outcomes: A01 concurrency bypass reproduced; A10 seven
  negative boundaries plus genuine native AMSI/NDRD truthfulness held; A16
  approval replay and authenticated snapshot rollback reproduced.
- Final verdicts: **1 CLOSED**, **2 REOPENED / PARTIAL**.
