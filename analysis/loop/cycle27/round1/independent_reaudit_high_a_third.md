# Cycle 27, Round 1 — Third Independent High-A Re-audit

Scope was limited to the latest remediations for `C27-R1-A01` and
`C27-R1-A16`, plus a regression check that `C27-R1-A10` remained closed. All
hostile checks were local and inert. They used temporary journals, fake process
objects, an in-memory EventBus/receipt broker, and a fake Windows Security
channel. No live process was terminated, no host event log or policy was
changed, no network target was contacted, and no product or test code was
edited.

The 64 focused affected tests pass, and compile plus Ruff are clean. The latest
changes close A01's in-flight intent race and A16's ordinary approval replay and
cursor-only rollback paths. Two stricter state-authority checks still fail:
Adversary Combat replay accepts an HMAC-authentic but semantically invalid
operator terminal, and deleting both ETW authority-state files recreates the
exact already-used enrollment resource so the old approval works again.

| Original finding | Independent verdict | Residual severity | What held | Residual bypass |
|---|---|---:|---|---|
| `C27-R1-A01` | **REOPENED / PARTIAL** | MEDIUM | The kill transaction and disposition now share one lock; blocked/failed/uncertain kills remain health 0; stale/wrong-resource receipts fail; wrong orphan HMAC, sequence, or mutation generation cannot close recovery; and any later orphan reopens it. | Ordered replay validates only the bound orphan HMAC/sequence/generation. An HMAC-authentic terminal with the exact binding but a wrong action, status, or disposition is treated as terminal and restarts health 100. The signed authorization resource also does not bind the selected disposition/reason, and freshness can be revived by host wall-clock rollback. |
| `C27-R1-A10` | **CLOSED** | — | Generic EventBus claims, producer-object impersonation, and receipt replay remain rejected; genuine object-bound APID/FIM observations work; NDRD remains explicitly unassured. | No new bypass inside the documented trusted in-process boundary. Arbitrary code already controlling the manager process remains outside the assurance claim. |
| `C27-R1-A16` | **REOPENED / PARTIAL** | HIGH | Current-generation replay, wrong reason/state, cursor-only rollback, malformed state, interrupted cursor/high-water transactions, and concurrent in-process read/enroll are fail-incomplete. | Removing both cursor and high-water files recreates the exact pre-enrollment state/resource and accepts the already-used approval at health 100. Restoring both older valid state files with the corresponding older channel snapshot is also accepted. An exact-bounds sample can additionally race a pre-bookmark replacement while retaining the sampled final bookmark; restart stays green and emits none of the replacement records. |

## `C27-R1-A01` — Core kill ordering holds, but terminal semantics are not fully authenticated

### Controls independently verified

- `src/angerona/modules/adversary_combat.py:1773-1807` holds the same re-entrant
  transition lock from the durable termination intent through `kill()`, wait,
  postcondition, and commit/orphan. The former blocked-kill disposition race now
  waits, then rejects the bare-intent approval. Restart remains health 0 with the
  exact mutation-started orphan pending.
- A kill exception, a successful fake effect followed by an unprovable
  postcondition, and orphan-phase write loss all stay fail-closed. The durable
  intent reconstructs `RECOVERY REQUIRED` on restart.
- `src/angerona/modules/adversary_combat.py:2009-2082` rejects terminals whose
  bound orphan HMAC, bound sequence, or mutation generation differs from the
  latest pending orphan. Each hostile replay remained `blocked=true`,
  `health=0`, and `pending=true`.
- A valid disposition followed by a later mutation-started orphan reopens the
  action. The inert replay restarted `blocked=true`, `health=0`, with the later
  `orphan` as the pending phase.
- Two simultaneous callers cannot consume the same current state: the shared
  lock serializes them, the first durable terminal removes the pending orphan,
  and the second call fails. A normal second use of the same receipt likewise
  failed.

### Residual 1: an authenticated but semantically invalid terminal closes recovery

The replay validator at `src/angerona/modules/adversary_combat.py:2063-2081`
checks that `bound_record_hmac`, `bound_record_sequence`, and
`mutation_generation` match the latest valid orphan. It does not require the
terminal's `action` and `combat_id` to match that orphan, `status` to equal
`operator_disposed`, `disposition` to be one of the two allowed values, or the
stored authorization receipt fields to constitute a verifiable decision.

Using `_append_journal()` only as an inert trusted-writer simulator produced
valid chained record HMACs. Each journal was `[intent, orphan,
operator_disposition]`. The exact outcomes after restart were:

```text
wrong bound HMAC       -> blocked=true,  health=0,   pending=true
wrong bound sequence   -> blocked=true,  health=0,   pending=true
wrong generation       -> blocked=true,  health=0,   pending=true
wrong action           -> blocked=false, health=100, pending=false
wrong status           -> blocked=false, health=100, pending=false
invalid disposition    -> blocked=false, health=100, pending=false
```

This is not an arbitrary-file-tamper bypass: an external writer without the
journal key still fails the chain. Its exploitability is limited to a defective,
confused, compromised, or cross-version trusted journal writer. The impact is
still unsafe re-arming from a phase that is not a valid operator disposition,
so the exact state-machine invariant is not closed.

### Residual 2: authorization does not attest the selected outcome or trusted time

`src/angerona/modules/adversary_combat.py:2027-2034` constructs the approval
resource from action ID, mutation generation, and orphan HMAC. The resource does
not include the selected `confirmed_applied`/`confirmed_not_applied` outcome or
a digest of the operator reason. Consequently the same fresh decision is bearer
authority for either result and for caller-selected audit text. One inert receipt
was accepted for `confirmed_not_applied`; the resource contained no outcome.
The second use failed only because the orphan was already terminal.

Freshness at `src/angerona/modules/adversary_combat.py:2310-2353` uses only wall
clock time. A decision stamped `1000.0` was accepted when the simulated host
wall clock was moved to `1001.0`, despite the actual 2026 wall time. Removing the
caller-selected `now=` argument prevents an ordinary API override, but does not
provide a trusted-clock or monotonic freshness authority against an elevated
host clock change.

### Recommendation

Validate the complete terminal schema during ordered replay: exact action ID,
combat ID, action type, status, allowed disposition, normalized reason digest,
principal, and a retained full authorization receipt/HMAC must all match the
latest orphan and its expected authorization resource. Include the chosen
disposition and reason digest in the resource the human approves. Retain the
existing transition lock and later-orphan precedence. For freshness, combine a
per-process monotonic deadline with a durable one-time challenge/sequence; state
the remaining whole-host clock/rollback limitation explicitly when no hardware
or external time witness is configured.

## `C27-R1-A10` — Object-bound Chaos receipts remain closed

No A10 product path changed in a way that weakened the object-bound broker.
Current checks at `src/angerona/core/assurance_receipts.py:166-412` and
`src/angerona/modules/chaos_harness.py:105-172` still bind a challenge to the
exact enrolled registry object, consumer, capability, lifecycle generation,
source epoch, nonce, target/evidence digest, observation, and one-time
consumption.

The focused suite reconfirmed:

```text
generic bus field forgery rejected=true
impostor producer object rejected=true
genuine enrolled producer accepted=true
second receipt consumption rejected=true
APID complete live-prologue path accepted=true
FIM exact watched-content path accepted=true
shared-bus-only NDRD assurance remains false=true
```

Closure remains deliberately scoped. Python object identity is not a sandbox;
malicious code already executing arbitrarily in the manager process is process
compromise, not an assurance receipt forgery this mechanism claims to withstand.

## `C27-R1-A16` — Used approval is replayable after local authority-state loss

### Controls independently verified

- `src/angerona/modules/etw_listener.py:248-282` binds a normal enrollment to
  host, generation, cursor sequence, bookmark/anchor, sampled bounds, gap
  digest, and reason digest.
- `src/angerona/modules/etw_listener.py:683-804` serializes reads and enrollment
  under `state_lock`, verifies a fresh human `policy.approve` decision, rejects
  the latest consumed request ID/digest, resamples the channel, and commits both
  cursor and high-water state.
- A generation-1 decision was rejected after a generation-2 reset before and
  after restart. A newly signed generation-2 approval was required.
- Restoring only an old authenticated cursor while retaining the newer
  high-water was detected as rollback and stayed health 45.
- Missing/malformed/MAC-altered/other-host state and cursor/high-water crash
  mismatch remained incomplete. Concurrent in-process read/enroll cannot
  interleave because both acquire the same lock.

### Residual 1: deleting both state files revives a consumed approval

The consumed request is recorded only in the cursor and adjacent high-water.
When both are absent, `_load_cursor_state()` at
`src/angerona/modules/etw_listener.py:454-489` returns to the deterministic
"cursor missing" state. With the same unchanged channel, generation, bookmark,
anchor, bounds, gap string, reason, and cursor sequence are recreated exactly.
There is no boot/session nonce in `_enrollment_state_digest()`.

An inert replay performed a valid first enrollment, deleted only
`etw-security-cursor.json` and `etw-security-cursor-highwater.jsonl`, restarted
the listener against the unchanged fake Security channel, and submitted the
already-used decision:

```text
first enrollment ok=true
both authority-state files absent before restart=true
recreated resource equals original resource=true
already-used approval accepted=true
health after replay=100
gap after replay=""
```

The protected files and host-bound HMACs raise the privilege required for this
attack, but the intended deployment is elevated and the scenario does not need
the EventBus signing key, authorization key, or channel contents to be changed.
It directly defeats the claimed one-time approval property after local state
loss.

### Residual 2: the co-located high-water does not detect paired rollback

The new high-water detects an old cursor only while the newer high-water remains
present. Restoring both older valid files and the corresponding older channel
snapshot was accepted without restoring or changing either signing authority:

```text
accepted cursor sequence=1
accepted bookmark=5
events emitted after rollback=0
health=100
gap=""
```

This is a software-only local anti-rollback limit, not an HMAC failure. The
remediation notes a whole-host rollback boundary, but the reproduced rollback
needed only the two state files plus telemetry snapshot; the stable protected
keys continued authenticating the old state. Health and documentation must not
describe this co-located file as an independent freshness authority against an
elevated snapshot adversary.

### Residual 3: the final bounds check is not atomic with the external channel

`_enrollment_bounds_match()` at
`src/angerona/modules/etw_listener.py:660-681` closes its channel handle before
`enroll_security_cursor()` clears the gap and persists. The Python `state_lock`
cannot lock the Windows Event Log service. In the inert race, the exact sample
passed, then two records below the bookmark were replaced while the final record
and bounds were retained. Enrollment returned health 100. A new listener saw
the same final bookmark anchor and bounds, emitted zero replacement records, and
also remained health 100 with no gap.

This precise fake models a privileged telemetry snapshot replacement, not a
normal append. Ordinary appends are safely picked up on the next read, and a
clear/refill with a changed final anchor is detected. Exploitability therefore
requires elevated control of the telemetry state, but it defeats the claimed
exact state binding under the stated high-end adversary model.

### Recommendation

Include a cryptographically random per-listener enrollment challenge in every
approval resource and invalidate outstanding approvals on restart; this alone
prevents an old decision from becoming valid when both files disappear. Durably
consume request IDs in an authority that is not reset with the cursor, and use
a TPM monotonic counter or externally witnessed transparency entry for a real
anti-rollback claim. Without such an authority, keep assurance below 100 and
state the limit explicitly. Bind enrollment to a stronger channel-generation
identity and rolling retained-record digest, and revalidate the exact channel
state after the cursor/high-water transaction before reporting green.

## Gate evidence

- Dedicated High-A suite: `19 passed in 5.72s`.
- Dedicated plus affected Adversary Combat/ETW suites: `64 passed in 14.90s`.
- `py_compile`: pass for the nine affected product files and dedicated test.
- Ruff: pass for the same scope.
- Independent hostile matrix: wrong HMAC/sequence/generation and later orphan
  held; wrong action/status/disposition terminal replay failed safe-state
  validation; A16 authority-file-loss replay, paired rollback, and
  bounds/bookmark swap reproduced.
- Final verdicts: **1 CLOSED**, **2 REOPENED / PARTIAL**.
