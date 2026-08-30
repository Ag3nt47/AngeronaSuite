# Cycle 27 Round 1 — Independent C27-R1-B10 Typed-Authorization Re-attack

Date: 2026-08-28
Scope: `C27-R1-B10` only, after the typed mobile authorization remediation in
`src/angerona/modules/mobile_bridge.py`
Method: manual source review plus inert fault injection and mocked command
effects. No real process, file, network, firewall, service, registry, driver, or
host-security mutation was attempted. Product source and existing tests were
not edited.

## Verdict

**REOPENED / PARTIAL — MEDIUM residual severity.**

The authorization bypass described by the original finding is substantially
closed. Every state-changing command now reaches one of two shared typed gates;
the independent matrix rejected missing, stale, future-dated, and replayed
transport identities for all seven command forms (`ECO ON`, `ECO OFF`,
`LOCKDOWN`, `KILL`, `SUSPEND`, `ROLLBACK`, and `MUTE`). Sender, nonce/token,
expiry, action scope, PIN, lockout, one-use, and signed-bus preconditions held.
No unauthenticated remote mutation path was found.

Three completion-state weaknesses remain after valid authorization:

1. ECO rollback is not transactional and can produce a validly signed
   `rejected` receipt plus “no cadence change” text while module and governor
   cadence have changed.
2. A Combat directive remains live after the bridge's fixed three-second wait.
   A delayed `LOCKDOWN`, `KILL`, or `SUSPEND` can complete after the bridge has
   already signed and sent a `rejected` / “no host action” result.
3. Receipt authority is checked before mutation, not at receipt commit. If bus
   signing authority disappears in that interval, a reversible action can be
   applied and an unsigned event returned to the operator as a “signed receipt.”

The first two are **MEDIUM** safety/truthfulness defects because they can leave
the endpoint in a materially different state than the authenticated operator is
told. The authority-loss race is **LOW** on its own because it requires an
in-process integrity fault after a valid nonce+PIN authorization. Together they
keep `C27-R1-B10` reopened at **MEDIUM**.

## Hostile probe matrix

| Probe | Result | Exact observation |
|---|---|---|
| Missing/stale/future/replayed envelope for each of seven mutators | **CAUGHT (28/28)** | No mocked ECO, lockdown, process, rollback, or mute effect was reached. The common gates require a 64-hex identity, a wall-clock time inside the 120-second/30-second window, and one-use replay admission. |
| Admin nonce sender, expiry, and reuse | **CAUGHT** | Wrong sender did not consume or use the nonce; an expired nonce did not mutate; the first valid use cleared the challenge; a later fresh-envelope reuse did not execute. |
| Admin/alert action confusion | **SCOPED** | An admin challenge is deliberately scoped to the three administrative choices (`ECO_ON`, `ECO_OFF`, `LOCKDOWN`) and cannot cross into alert-token commands. Alert tokens accept only their stored action set. The admin nonce is not single-action-consent-bound, but changing action still requires the same sender, fresh envelope, nonce, and PIN; no independent privilege escalation was reproduced. |
| PIN search and lockout | **CAUGHT** | Five distinct wrong-PIN attempts entered a 900-second monotonic mutation lockout, and a correct PIN during lockout did not execute. The four-digit PIN remains a small secret, but Signal sender authority, a fresh nonce/token, bounded guesses, and lockout materially change the original exposure. |
| Alert-token entropy | **HELD** | 256 independently generated tokens were unique lowercase 64-hex values (`secrets.token_hex(32)`, 256 bits). |
| Alert-token sender/action/expiry/single-use | **CAUGHT** | Wrong action and sender left the token inert; expiry rejected mutation; one valid MUTE removed the token; a second fresh command with the same token produced no second receipt/effect. KILL/SUSPEND/ROLLBACK use the same authorization gate and `_gated()` pops before execution. |
| ECO setter mutates then raises; rollback setter also raises | **BYPASSED TRANSACTION** | The signed receipt recorded `outcome=rejected` and SMS said “no cadence change,” while the target remained at throttle `6.0`. A governor that began at `4.0` was incorrectly changed to `1.0`. |
| Bus authority disappears after authorization and during ECO apply | **UNSIGNED CLAIM** | ECO reached throttle/governor `6.0`; the emitted `applied` receipt had no HMAC and the bus was unarmed, yet SMS called its random receipt ID a “signed receipt.” |
| Combat worker completes just after the three-second bridge deadline | **ORPHAN ACTION** | The bridge signed `outcome=rejected` and sent “no host action,” but the already-published exact isolation directive had no cancellation identity/tombstone. A later verified `isolate_host` action row for that exact trigger was accepted by `_receipt_ids()`. |

## Residual 1 — ECO rollback and postcondition claims are not atomic

### Source evidence

- `src/angerona/modules/mobile_bridge.py:1539-1557` applies each module's
  `set_throttle()` sequentially. It records the governor's real prior level only
  after all module calls have succeeded.
- `src/angerona/modules/mobile_bridge.py:1558-1565` swallows every rollback
  exception. If an apply call changes state and then raises, or the compensating
  setter fails, the bridge neither verifies nor identifies residual drift. If a
  module fails before line 1556, `prior_governor` is still the hard-coded `1.0`,
  so the exception path can alter a governor that was never part of the failed
  apply.
- `src/angerona/modules/mobile_bridge.py:1566-1572` nevertheless signs
  `outcome="rejected"` and sends “no cadence change.” The success path at
  `:1574-1592` also records the requested level, but performs no postcondition
  readback.

### Impact and existing mitigation

A faulty, stopping, or concurrently changing module can leave monitoring
cadence partially throttled or unexpectedly accelerated while the authoritative
operator receipt says nothing changed. This does not bypass nonce, sender, PIN,
or bus authorization: an authenticated ECO request and an apply/rollback fault
are both required. The bus HMAC protects the false receipt from later editing;
it does not make the recorded outcome true.

### Required remediation

Snapshot every exact module and the governor before the first mutation. Apply
under a manager-owned state transition lock, read back every postcondition, and
commit only if the entire target set matches. On failure, compensate and verify
every prior value. If any compensation or readback fails, emit a signed
`partial` / `rollback_failed` terminal state naming the exact modules and
observed levels, hold health red, and never say “no cadence change.” Preserve
operator-selected throttle floors and concurrent governor ownership explicitly.

## Residual 2 — Combat timeout creates a contradictory late terminal state

### Source evidence

- `src/angerona/modules/mobile_bridge.py:1777-1789` publishes an authenticated
  response event before waiting for completion. Adversary Combat admits such
  events to its worker queue in `src/angerona/modules/adversary_combat.py:1178-1224`.
- `src/angerona/modules/mobile_bridge.py:1792-1801` stops polling after three
  seconds and returns `False`, but publishes no cancellation CAS, tombstone, or
  request-state transition. The queued consumer can still execute.
- `src/angerona/modules/mobile_bridge.py:1821-1833` then signs a rejected
  LOCKDOWN receipt and says “no host action.” The same contradiction is rendered
  for process actions at `:1864-1893`.
- Combat performs mutations asynchronously and records its terminal action only
  after execution (`src/angerona/modules/adversary_combat.py:1168-1176,1500-1607`).
  A slow queue or a host action taking longer than the bridge deadline can
  therefore complete after the mobile rejection.

### Impact and existing mitigation

The operator can be told the host was not isolated or a process was not acted
on, then observe that exact change later. They may retry, take conflicting
manual action, or reason from a false safety state. The directive is still
nonce+PIN authorized, target-scoped, policy-checked, HMAC-protected, and
postcondition-verified by Combat, so this is not an attacker gaining new action
authority. It is a security-control state-machine and receipt-truth failure.

### Required remediation

Give every mobile mutation a durable unpredictable request ID and a state
machine such as `AUTHORIZED -> ADMITTED -> APPLIED|REJECTED|CANCELLED`. Obtain
an authenticated admission receipt before describing the result. A local wait
deadline must return `PENDING`, never `REJECTED`; reconcile the durable Combat
receipt later and notify the operator exactly once. If cancellation is offered,
make it a compare-and-set consumed by Combat before the mutation boundary, and
distinguish `cancel_requested` from `cancelled`. Never infer “no host action”
from lack of a receipt within a wall-clock timeout.

## Residual 3 — Receipt signing authority is a precheck, not a commit condition

### Source evidence

- `src/angerona/modules/mobile_bridge.py:1306-1309,1342-1345` checks only that
  the current bus reports `integrity_enabled` before returning authorization.
  The actual mutation occurs afterward.
- `src/angerona/modules/mobile_bridge.py:1347-1373` generates a 128-bit receipt
  ID, delegates publication through `BaseModule.emit()`, and returns the ID. It
  does not retain the exact published event, prove a non-empty HMAC, re-verify
  it, or confirm it exists in the signed ring.
- `src/angerona/core/module_base.py:718-720` silently does nothing if the module
  has no bus. `src/angerona/core/eventbus.py:250-263,301-305` signs only while an
  authority is present. Authority loss between the precheck and publication can
  therefore produce no signed terminal receipt.
- All user-facing success/rejection paths label the returned random ID a
  “signed receipt,” including ECO (`:1566-1592`), LOCKDOWN (`:1803-1833`),
  process/rollback (`:1836-1893`), and MUTE (`:1919-1940`).

### Impact and existing mitigation

An in-process bus-integrity failure can leave an applied reversible change with
an unsigned or missing audit record while the operator is explicitly told the
receipt is signed. Under normal startup with a stable armed EventBus, the events
are HMAC-signed and the precondition works. No remote-only technique for
removing the authority was found, so this residual is LOW independently.

### Required remediation

Make receipt publication return the exact signed event and verify a non-empty
HMAC, the current authority epoch, command/request ID, nonce hash, sender scope,
pre-state digest, post-state digest, and terminal outcome before reporting it.
For reversible ECO/MUTE changes, restore and verify prior state if receipt commit
fails; report `partial/receipt_unavailable` if compensation fails. For
irreversible Combat/rollback operations, treat the durable consumer completion
receipt as canonical, keep the mobile request `PENDING` until reconciliation,
and never synthesize “signed” from a random identifier alone.

## Validation

- `python -m pytest -q tests/test_cycle27_b10_independent_reattack.py` — **33 passed**
- `python -m pytest -q tests/test_cycle29_mobile_typed_authorization.py tests/test_soar_mobile_response_boundaries.py tests/test_adversary_combat_boundaries.py` — **23 passed**
- Wider mobile/Combat compatibility set (independent reattack, cycle 29 typed
  authorization, round-1 high-B, PIN integration, cycle-19 hardening, SOAR
  boundaries, and Combat boundaries) — **75 passed**
- `python -m py_compile` for Mobile Bridge, Adversary Combat, EventBus,
  BaseModule, and the dedicated reattack — **passed**
- Ruff on Mobile Bridge and the dedicated reattack — **passed**
- `MobileResponseBridge().self_test()` in its safe default configuration —
  **passed**, reporting `disabled (opt-in)`
- JSON parse and targeted `git diff --check` — **passed**

The dedicated adversarial test is
`tests/test_cycle27_b10_independent_reattack.py`. Its residual tests assert the
observed vulnerable states rather than encoding the desired remediation, so a
future fix should deliberately invert or replace those assertions.
