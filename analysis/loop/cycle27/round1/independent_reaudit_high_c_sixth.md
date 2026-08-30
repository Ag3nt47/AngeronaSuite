# Cycle 27 Round 1 — Sixth Independent High-C Re-attack

Date: 2026-08-28
Scope: sixth remediation of `C27-R1-C03` and `C27-R1-C13` only
Method: manual source review plus inert temporary-directory state, content,
budget, authority-outage, and hard-link probes. No product source, test file,
service, driver, registry object, network endpoint, user document, or host
security control was changed.

## Verdict summary

| Finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| `C27-R1-C03` | **REOPENED / PARTIAL** | **MEDIUM** | The fifth-round authenticated-state rollback/deletion, suffix-only disguise, and 50% strided-content bypasses are fixed. Two residuals remain: four attacker-controlled ZIP magic bytes plus one automatic unchanged observation promote a new entropy-8 object into the exclusion set with no alert at the module's maximum local-authority health; and the claimed durable fair rotation truncates to one enumeration prefix before sorting/rotation, so entries outside that prefix are never selected on any epoch. |
| `C27-R1-C13` | **REOPENED / PARTIAL** | **MEDIUM** | Local custody is now honestly `captured_unverified`; post-final alias mutation remains possible but is permanently non-green, and ordinary local rollback/deletion is refused. The independent high-water control is not reachable through normal module discovery, its domain is absent from the packaged authority's default enrollment, and one transient authority failure after the local commit leaves custody permanently `local-ahead` with no automatic authenticated replay. |

The original findings' narrow scopes remain resolved: ransomware traversal is
bounded, recursive, no-reparse, and fail-visible; honeytoken reads are bounded,
restaging is exclusive, deduplication is bounded, and custody failures never
return to health 100.

## Exact hostile probe matrix

### `C27-R1-C03` — ransomware heuristics

| Probe | Result | Exact observation |
|---|---|---|
| Valid authenticated content-state rollback with the unchanged witness | **CAUGHT** | `_load_change_state()` refused `rollback violates enrolled high-water`. |
| Delete key plus state while enrollment key/witness survive | **CAUGHT** | Load refused `bundle was deleted after enrollment`. |
| Delete/replace every local authority object coherently | **DISCLOSED BOUNDARY** | Software-only re-enrollment remains possible, but complete coverage is capped at health 90 with `local-authenticity-only`; this is not a false-green closure claim. |
| Entropy-8 bytes named `.zip` without ZIP magic | **CAUGHT** | The suffix alone no longer excludes the object; the focused author regression passes. |
| 50% alternating clear/random 64 KiB windows | **CAUGHT** | Fixed-window high-entropy fraction is about 0.5 and the candidate is scored above threshold. |
| New entropy-8 object beginning with `PK 03 04`, named `.zip` | **MISSED / MAXIMUM LOCAL HEALTH AFTER ONE TICK** | Cycle 1: zero candidates, zero alerts, `unproved_exclusions=1`, health 75. Cycle 2: zero candidates, zero alerts, transition `unchanged=1`, `unproved_exclusions=0`, `complete=true`, health 90. Four magic bytes are treated as format validity and an automatic second observation is described as review. |
| Fair rotation over ten stable mocked entries with a five-entry view | **FAILED** | Epochs 0 through 11 only permuted `f00` through `f04`; `f05` through `f09` never entered the rotation set. The real first-root limit is approximately 29,095 entries. Coverage is truthfully truncated/non-green, but persistent tail starvation remains possible. |
| Large-file representative-range or 64 MiB byte-budget miss | **HONESTLY INCOMPLETE** | Existing focused regressions retain health below 100; stable objects that enter the bounded rotation set move across epochs. |

### `C27-R1-C13` — Smart Deception custody

| Probe | Result | Exact observation |
|---|---|---|
| Post-completion hard link followed by same-size evidence mutation | **NOT PREVENTED, FAIL-VISIBLE** | Archive returned `captured_unverified`, source retired, link count became 2, refresh returned false, and health was 65 with durable topology uncertainty. The inert source run had `namespace_protected=false`; source review confirms packaged required-ACL failure refuses capture. |
| Complete local authority deletion/rollback with an independent head | **CAUGHT** | Sixth author regressions return `local-behind`/recovery-required. |
| Complete local authority substitution without an independent head | **DISCLOSED BOUNDARY** | Health is capped at 70 and reports `prior_history_may_have_been_erased=1`; no software-only HMAC can distinguish coherent administrator replacement. |
| Production discovery of Smart Deception | **CONTROL UNREACHABLE** | `ModuleManager.discover()` constructs every class as `cls()`; `SmartDeception()` defaults `high_water=None`, has no authority binder, and `register()` also supplies none. The normal suite therefore cannot reach independent freshness. |
| Default Personal Sentinel authority configuration | **DOMAIN REJECTED BY DEFAULT** | Smart Deception requests `smart-deception-custody`, while `DEFAULT_ALLOWED_DOMAINS` contains only audit, network, and platform domains. A custom authority can opt in, but no product wiring supplies it. |
| One transient external-authority failure after a local event commit | **PERSISTENT SAFE OUTAGE** | Initial enrollment was independently verified at external revision 1. The local event committed, external advance returned `provisional-offline`, and restart after authority recovery refused the exact state as `local-ahead`. No path retries the authenticated one-step CAS, so custody remains unavailable pending manual recovery. |
| Ledger capacity, topology, digest mutation, and crash/race regressions | **HELD** | The wider 80-test gate passed; terminal reserve, two-phase eviction, exact digest inventory, and same-sequence refusal remain fail-closed/non-green. |

## `C27-R1-C03` — automatic pseudo-review and pre-rotation truncation leave deterministic gaps

**Verdict: REOPENED / PARTIAL (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/ransomware_heuristics.py:246-285` treats a small prefix
  signature as sufficient packed-format proof. For ZIP and Office containers,
  four bytes (`PK\x03\x04`) suffice; no bounded structural parser, central-directory
  proof, or operator-approved receipt is required.
- `src/angerona/modules/ransomware_heuristics.py:1841-1871` labels a new object as
  an unproved exclusion but commits its content receipt. At
  `:1943-1950`, a new or automatically unchanged declared container is omitted
  from entropy evaluation. One subsequent scan therefore turns observation
  stability into exclusion authority without any actual review.
- `src/angerona/modules/ransomware_heuristics.py:2002-2018` clears the unproved
  condition on that second scan and returns the module's maximum software-only
  score, health 90. The only remaining note concerns local state freshness, not
  the unvalidated container exclusion.
- `src/angerona/modules/ransomware_heuristics.py:1666-1681` stops enumerating as
  soon as `len(entries) >= limit`; sorting and epoch rotation occur only afterward
  at `:1681-1694`. The caller's bound at `:1743-1758` therefore rotates one
  fixed prefix and can never select an object omitted before the sort.

### Impact and controls that held

An attacker can make a newly created high-entropy object look like a ZIP with
four controlled bytes, wait one scan interval, and receive no entropy alert or
remaining exclusion uncertainty. Changes to an already authenticated object,
renames of an authenticated identity, and deletion of prior objects still
produce `changed`/`missing` alerts, so this is not a universal ransomware bypass.

An attacker can also sustain more directory entries than the view limit and
place a target outside the filesystem's returned prefix. That denial is
truthfully visible at health 65 rather than green, but the remediation's
specific promise that durable epochs eventually cover a stable tail is false.
Full reads through 8 MiB, unpredictable bounded ranges above 8 MiB, fixed-window
entropy, exact object/ancestry holds, receipt rollback checks, and incomplete
coverage caps all held.

### Required remediation

1. Do not equate a magic prefix and one unchanged automated observation with a
   reviewed container. Use a bounded structural validator where feasible and
   retain new high-entropy containers as candidates or persistent uncertainty
   until an authenticated operator/policy approval exists. Bind any approval to
   exact identity, path, full content digest, parser result, and policy version.
2. Rotate selection before truncation. Use a durable resumable directory cursor,
   USN/journal position, handle-relative continuation key, or a bounded
   pseudo-random/reservoir selection over the complete enumerated namespace.
   Persist per-directory progress so restart cannot reset tail coverage, and
   report oldest-unseen age in addition to truncation counts.
3. Preserve the current 90 cap for purely local freshness and the lower scores
   for range, time, byte, and traversal incompleteness.

## `C27-R1-C13` — independent freshness exists only as an unwired, brittle injection point

**Verdict: REOPENED / PARTIAL (MEDIUM residual).**

### Exact source evidence

- `src/angerona/core/module_manager.py:84-113` discovers built-ins by invoking
  `cls()` and binds only the manager/recorder contracts. Smart Deception exposes
  no high-water binder.
- `src/angerona/modules/smart_deception.py:283-329` defaults
  `high_water=None`; `:2419-2420` does the same through `register()`. Repository
  search found no production construction or binding that passes an
  `IndependentHighWater` to this module.
- `src/angerona/modules/smart_deception.py:104` uses the domain
  `smart-deception-custody`, while
  `src/angerona/core/personal_sentinel_authority.py:62` omits that domain from
  `DEFAULT_ALLOWED_DOMAINS`. Custom enrollment is possible, but it is not the
  shipped/default path.
- `src/angerona/modules/smart_deception.py:1325-1385` commits SQLite, local head,
  and local witness before advancing the external authority. If that advance
  fails, `:825-836` later classifies the locally committed sequence as
  `local-ahead` and refuses it. There is no durable pending-transition replay or
  exact one-step reconciliation path.
- `src/angerona/modules/smart_deception.py:1440-1459,1919-1996` applies/verifies
  required ACLs before source retirement and returns typed
  `captured_unverified`. `:2292-2347` keeps topology/local-authority limits below
  green. Those honest controls materially reduce the residual severity.

### Impact and controls that held

The advertised administrator-resistant freshness cannot be enabled by the
normal suite, so every real Smart Deception instance remains at the explicitly
disclosed local-authority boundary. If an integrator manually injects an
authority, one ordinary availability failure during any event append can make
all later custody loads recovery-required even after the authority is healthy.
This is fail-closed—not evidence forgery—but it is a practical denial of the
capture channel and makes the optional protection unreliable.

The packaged Administrators/SYSTEM DACL proof, exact object holds, permanent
topology uncertainty, typed outcome, external rollback comparison, capacity
reserve, and durable loss reconstruction held in source review and focused
tests. A same-host administrator can still mutate local evidence after the
last userspace observation; the module now says so and never reports that
evidence as immutable. True administrator-resistant preservation still needs a
separately administered authority plus minifilter or remote append-only/WORM
custody.

### Required remediation

1. Add a reviewed application-owned high-water provider and explicit
   `bind_high_water()`/constructor factory path in `ModuleManager`; enroll
   `smart-deception-custody` in the authority policy and expose configured,
   unavailable, rejected, and local-only states in UI/health.
2. Implement a durable two-phase external-transition outbox. On restart, query
   the authenticated remote head and retry only an exact one-step local-ahead
   transition whose previous revision/digest/head match that authority. Refuse
   gaps, forks, ambiguous resets, or changed installation identity. Cover
   fail-before-CAS, committed-but-response-lost, crash-after-CAS, and concurrent
   writer cases.
3. Retain `captured_unverified`, the current ACL verification, conservative
   local/remote health caps, terminal capacity reserve, and durable
   topology/loss events. Do not promote health above 95 until evidence bytes
   themselves cross an independently administered append-only/WORM boundary.

## Validation record

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py \
  tests/test_cycle27_high_c_fifth_remediation.py \
  tests/test_cycle27_high_c_sixth_remediation.py \
  tests/test_deception_data_boundary.py \
  tests/test_semantic_response_contracts.py \
  tests/test_round7_performance_boundaries.py
80 passed, 1 skipped in 30.06s

python -m py_compile src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py \
  src/angerona/core/independent_high_water.py \
  tests/test_cycle27_high_c_sixth_remediation.py
PASS

python -m ruff check <the three reviewed source files and four focused test files>
PASS

RANS self_test: PASS
SDEC self_test: PASS
```

The single skip is the pre-existing privilege-dependent directory-link fixture.
The original C03 and C13 scopes are verified resolved; both remain partial only
for the independently reproduced sixth-round residuals above.
