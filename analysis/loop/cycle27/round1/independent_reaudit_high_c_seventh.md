# Cycle 27 Round 1 — Seventh Independent High-C Re-attack

Date: 2026-08-28
Scope: seventh remediation of `C27-R1-C03` and `C27-R1-C13` only
Method: manual source review plus inert temporary-directory probes for content
classification, adversarial enumeration order, traversal time, split durable
commits, first enrollment, exact CAS replay, and restart behavior. No product
source, service, driver, registry object, network endpoint, user document, or
host security control was changed.

## Verdict summary

| Finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| `C27-R1-C03` | **REOPENED / PARTIAL** | **MEDIUM** | Suffix/magic/unchanged pseudo-review is removed, order-independent reservoir selection works, prior receipt attacks remain fail-visible, and partial content remains non-green. The complete-stream reservoir performs unbounded metadata work without consulting the advertised traversal deadline, so an attacker-populated directory can stall the entire detector before it updates coverage. A crash between state replacement and witness replacement also leaves the durable tracker permanently recovery-required. |
| `C27-R1-C13` | **REOPENED / PARTIAL** | **MEDIUM** | Production injection, the default domain, normal transient-outage replay, lost-response recovery, fork rejection, and the Windows writer lease held. Two exact crash states do not: first enrollment can persist a complete local authority before the transition outbox exists, and an ordinary event can commit SQLite before its local head/witness advances. Both leave enough authenticated information for exact recovery but restart refuses before reconciliation, permanently disabling capture until manual repair. |

Neither result permits forged evidence or a false immutability claim. Both are
availability/liveness weaknesses in security-critical detectors, and all
observed terminal states ultimately fail closed or become non-green.

## Exact hostile probe matrix

### `C27-R1-C03` — ransomware heuristics

| Probe | Result | Exact observation |
|---|---|---|
| High-entropy `.zip` with `PK 03 04`, new and then unchanged | **CAUGHT** | The exact object remained an entropy candidate on both cycles and emitted two HIGH entropy events after the dedup interval. Magic metadata did not exclude it. |
| Same eligible set in forward vs reverse attacker-controlled enumeration order | **HELD** | With a fixed key, epoch, identity set, and limit, both orders selected the exact same 13 names. Selection no longer privileges the filesystem prefix. |
| Complete-stream reservoir after the 250 ms traversal deadline | **BUDGET BYPASS / STALL** | An inert stream advanced the monotonic clock by 100 ms per entry. The budget expired after three entries, but `_fair_directory_entries()` consumed all 100 before `_bounded_tree()` checked time again; reported elapsed time was at least 10 seconds. |
| Crash after authenticated state replace but before witness replace | **PERMANENT SAFE OUTAGE** | The next load authenticated both files individually but refused `rollback violates enrolled high-water`; there is no pending transaction or exact pair repair path. Entropy remains available only after the run path degrades durable tracking to health 60. |
| Prior rollback/deletion, representative-range, byte-budget, ancestry, and transition cases | **HELD / HONESTLY INCOMPLETE** | The wider high-C regression set passed; local-only freshness remains capped at 90 and range/traversal/content omissions stay non-green. |

### `C27-R1-C13` — Smart Deception custody

| Probe | Result | Exact observation |
|---|---|---|
| Normal `ModuleManager`, application, and headless injection surfaces | **HELD** | `ModuleManager._construct_module()` binds only a bundled module; both application constructors pass the optional provider. External drop-ins do not receive it implicitly. |
| Default Personal Sentinel domain | **HELD** | The shared constant is exactly `smart-deception-custody` and is in `DEFAULT_ALLOWED_DOMAINS`. |
| Transient external outage, local-ahead restart, and lost response | **RECOVERED** | The existing exact pending CAS tests advanced only the authenticated predecessor/new tuple and removed the outbox after a verified authority read. |
| Remote fork/gap and concurrent writer | **CAUGHT** | A conflicting remote head remains recovery-required. The Windows lock denied both a second writer and replacement/unlink of the live lease object in inert probes. |
| First enrollment fails before the outbox write | **PERMANENT SAFE OUTAGE** | SQLite, local head, and local witness existed; the remote domain and outbox did not. Restart classified the absent remote namespace as `migration-required` and had no exact first-enrollment recovery path. |
| SQLite COMMIT succeeds, then local head write fails | **PERMANENT SAFE OUTAGE** | The authenticated event row and exact pending transition survived, and remote remained the exact predecessor at revision 1. Restart nevertheless stopped at `custody ledger rolled back or is incomplete` before consulting the outbox. |
| Post-final mutation/local administrator boundary | **HONESTLY DISCLOSED** | Evidence remains typed `captured_unverified`; local bytes are not described as WORM, and independent freshness caps health at 95. |

## `C27-R1-C03` — fair selection is not bounded by the traversal contract

**Verdict: REOPENED / PARTIAL (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/ransomware_heuristics.py:1735-1736` computes a two-second
  deadline, but `:1691-1719` exhausts the complete held-directory iterator with
  no deadline or stop-token check.
- The next clock check occurs only after reservoir construction, at
  `:1812-1817`. Coverage and elapsed time are not published until `:1946-1958`.
  A directory with attacker-amplified metadata therefore monopolizes the module
  before the promised truncation can become visible. The central watchdog can
  report a missed cycle, but it cannot safely terminate the stuck worker or
  complete another ransomware scan while that enumeration remains blocked.
- `:851-895` replaces authenticated state and only afterward replaces the
  witness. No pending pair-transition record exists. An interruption at
  `:885-888` produces two authentic adjacent generations that `:745-751`
  permanently rejects rather than reconciles.

### Impact and controls that held

The full-stream reservoir fixes the old deterministic prefix bias and remains
`O(limit)` in memory, but it removes the wall-clock bound. A dense or unusually
slow directory can delay all other roots, entropy scoring, rename correlation,
health publication, and the next scan for an attacker-controlled duration.
This is detector denial, not code execution. The watchdog makes the liveness
loss externally visible after its deadline, which limits but does not remove
the impact.

The magic/suffix bypass is closed. Exact held-object revalidation, full reads
through 8 MiB, partial-content health caps, authenticated transition alerts,
rollback refusal, and order-independent selection all held.

### Required remediation

1. Do not exhaust an unbounded directory stream inside one tick. Carry a
   durable handle-relative continuation/journal cursor or a bounded per-tick
   reservoir segment, check both deadline and stop token during enumeration,
   and persist enough authenticated progress to prevent restart/prefix
   starvation. Report unvisited metadata immediately and remain non-green.
2. Journal the exact `(old state, new state, old witness, new witness)` pair
   before either replacement. On restart, repair only a one-step authenticated
   transition whose old/new heads and sequences match; refuse gaps, forks,
   deletion, or ambiguous state.
3. Retain the present content scoring, exact object/ancestry custody, alert
   caps, and local-authority health ceiling.

## `C27-R1-C13` — the outbox does not span all local durable commit boundaries

**Verdict: REOPENED / PARTIAL (MEDIUM residual).**

### Exact source evidence

- On first enrollment, `src/angerona/modules/smart_deception.py:1644-1761`
  creates/opens SQLite, writes the local head, and writes the witness before
  `_establish_external_custody()` at `:1762-1764`. The transition outbox is not
  created until `:1173-1182`. A failure in that gap leaves a locally enrolled
  sequence-zero authority, no outbox, and an absent remote namespace. Restart
  calls `assess_high_water(... revision=sequence+1)` at `:1157-1163` and refuses
  `migration-required` rather than completing the provable first enrollment.
- For subsequent events, the outbox correctly precedes SQLite, but
  `:1863-1887` commits SQLite first, then replaces the local head, then the
  witness, then reconciles the authority. `_load_custody_state()` verifies
  ledger/head/witness equality at `:1747-1761` before it invokes outbox
  reconciliation. A crash after COMMIT but before either metadata replacement
  therefore cannot reach the exact recovery proof already on disk.
- The same ordering leaves an analogous head-new/witness-old interruption.
  Every state is fail-closed, but none is automatically repairable.

### Impact and controls that held

A transient disk/AV interruption or process/power loss at either boundary can
permanently disable new Smart Deception custody. During the event window, the
tampered source is not retired without a successful commit path, and restart
does not claim healthy custody, so this is a safe denial rather than evidence
forgery. It is still material because a security-critical capture channel can
remain unavailable even when the external authority is healthy and the exact
authenticated predecessor/transition survived.

Bundled-only provider injection, domain policy, authenticated single-link
outbox parsing, exact CAS echo, transient outage replay, lost-response recovery,
fork/gap refusal, Windows writer exclusion, ACL proof, terminal reserve, and
`captured_unverified` semantics all held.

### Required remediation

1. Create the authenticated first-enrollment intent before any local artifact
   makes the installation look enrolled, or add a typed genesis intent whose
   exact sequence-zero digest can safely finish the remote CAS after restart.
2. On every restart, validate the outbox before demanding local
   ledger/head/witness equality. Permit only the finite adjacent states the
   intent proves: no local commit, SQLite committed with old metadata,
   head-new/witness-old, fully local-new/remote-old, and remote-new response
   lost. Repair local metadata or retry CAS only when all authenticated
   sequence, HMAC, digest, installation, domain, and predecessor fields match.
3. Keep the writer lease across repair and irreversible capture boundaries;
   preserve fail-closed handling for gaps, forks, ambiguous COMMIT outcomes,
   missing intent, and changed installation identity.

## Validation record

```text
Independent attack-shaped regressions:
6 passed in 2.35s

Independent plus all wider high-C focused/compatibility regressions:
96 passed, 1 skipped in 56.65s

Ruff (8 reviewed source files + independent test): PASS
py_compile (same files): PASS
RANS self_test: PASS
SDEC self_test: PASS
```

The single skip is the pre-existing privilege-dependent directory-link fixture.
The original narrow C03/C13 findings remain resolved; the seventh remediation
is reopened only for the independently reproduced boundedness and crash-recovery
residuals above.
