# Cycle 27, Round 1 — Remaining A02/A03/A07/A13/A14 Remediation

Scope is limited to the five independently re-audited residuals in
`independent_reaudit_remaining_a02_a03_a07_a13_a14.{md,json}`. All regression
work is defensive and inert: temporary files, synthetic event records, fake
event-log APIs, in-memory event buses, and offline evidence objects only. No
live host response, quarantine, Security log, driver, network target, or policy
change was exercised. These are remediation results; independent hostile
re-attack remains the closure gate.

## C27-R1-A02 — bounded, constant-time authenticated journal state

Status: **FIXED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/adversary_combat.py:101-103` reserves explicit
  worst-case terminal capacity before a mutation or undo can start.
- `src/angerona/modules/adversary_combat.py:1213-1235` makes readiness fail
  closed when that capacity is unavailable.
- `src/angerona/modules/adversary_combat.py:2684-2990` maintains an
  authenticated retained-tail cache and O(1) commit/undo indexes. The cache is
  reusable only when the current file fingerprint, exact terminal bytes, and
  recovery anchor still agree; normal appends no longer reparse and copy the
  complete journal.
- `src/angerona/modules/adversary_combat.py:3923-3970` and
  `:4462-4690` reconcile and select undo candidates from complete retained
  state instead of the former 500/5,000-record windows. Undo holds the writer
  lease, receipt lock, and pinned journal session through the host effect and
  terminal receipt.

Regressions prove correct undo selection after 5,001 completed actions,
pre-effect refusal at terminal-capacity exhaustion, and no full-journal read
on a steady-state append.

## C27-R1-A03 — exact-object quarantine custody

Status: **FIXED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/adversary_combat.py:368-820` rejects source or
  destination objects with a link count other than one and retains pinned
  identity/topology custody across same-volume and cross-volume moves.
- `src/angerona/modules/adversary_combat.py:3247-3305` records independently
  verified source and destination link counts in the signed evidence receipt.
- The moved destination handle (and, on POSIX, destination directory
  descriptor/name) remains held through terminal journal commit. A post-move
  alias or identity uncertainty now enters an explicit orphan/undo terminal
  sequence at `:3078-3160`; it cannot be reported as a successful quarantine.

Regressions reject pre-existing hardlinks, prove custody is held through
terminal commit, and prove a forced post-move alias signal rolls back without
emitting success.

## C27-R1-A07 — retained Defender continuity and durable delivery

Status: **FIXED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/av_telemetry_bridge.py:196-270` opens an authenticated,
  purpose-separated Defender checkpoint and HMAC-protected durable outbox.
- `src/angerona/modules/av_telemetry_bridge.py:326-689` replays retained native
  records on first enrollment, resumes from authenticated record
  number/digest anchors, stages before EventBus publication, advances the
  checkpoint only after delivery, and acknowledges the outbox last.
- Clear/refill, rollback, anchor mismatch, tamper, decode/read failure, and
  unavailable continuity state create durable gap evidence and cap health.
- `src/angerona/modules/av_telemetry_bridge.py:691-807` gives the PowerShell
  fallback stable evidence identities, durable replay/deduplication, bounded
  persistence, and explicit gap reporting instead of seeding away retained
  detections.

Regressions cover retained first-run replay, restart deduplication, pending-row
replay after a publish interruption, tampered cursor refusal, and PowerShell
fallback restart continuity.

## C27-R1-A13 — observer-honest deception claims

Status: **FIXED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/deception.py:1-10`, `:72-151`, and `:222-249` now claim
  only file mutation/deletion visibility. Canary content and SOAR wording say
  explicitly that reads require a separately configured OS audit source.
- Module evidence advertises `read_visibility=False`; health cannot imply read
  telemetry that this observer does not receive.

The regression rejects the former “any access is logged” claim and requires
the explicit read-visibility boundary in both user-visible and evidence text.

## C27-R1-A14 — live-object-bound driver provenance contract

Status: **FIXED — PENDING INDEPENDENT RE-ATTACK**.

- `src/angerona/modules/driver_provenance_guard.py:31-135` upgrades evidence to
  schema v2 and requires binding state, binding source, and a cryptographic
  binding receipt for any `loaded-image-bound` claim.
- `src/angerona/modules/driver_provenance_guard.py:244-280` makes missing
  live-image binding an explicit unknown and prevents unbound samples from
  reaching `provenance-verified`.
- `src/angerona/modules/driver_provenance_guard.py:500-535` labels the current
  Windows service-path sample `configured-path-sample-unbound`, with unknown
  load state and no kernel-load receipt. It remains useful negative evidence
  without being represented as proof about the loaded kernel object.

Regressions reject malformed or contradictory binding claims and prove an
unbound configured path cannot assert running/stopped kernel state or verified
provenance.

## Gates

| Gate | Result |
|---|---|
| Dedicated five-finding regressions | `PASS` — `13 passed in 11.43s` |
| Full focused affected suites | `PASS` — `144 passed, 1 skipped in 45.21s` |
| `py_compile` for four product modules and dedicated regression file | `PASS` |
| Ruff for four product modules and affected regressions | `PASS` |
| Deception, driver provenance, and AV telemetry `self_test()` | `PASS` — `3/3` |
| `git diff --check` for affected tracked files | `PASS` (line-ending notices only) |
| Independent hostile re-attack | **PENDING — required before closure** |

## Honest residual boundary

Journal exhaustion intentionally fails closed and requires operator archival or
recovery. Windows supplies delete-denying live-object custody; POSIX verifies
pinned identity and topology but cannot promise a kernel-enforced deny-unlink
guarantee against a privileged non-cooperating process. Defender continuity
proves what the retained source and local authenticated state expose; complete
rollback of that state with its signing identity still requires TPM monotonic
state or an independently administered witness. Driver provenance stays
explicitly unbound until an independent kernel load observer supplies a
cryptographic live-image receipt.
