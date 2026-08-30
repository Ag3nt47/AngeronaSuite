# Cycle 27 Round 1 — Fifth Independent High-C Re-attack

Date: 2026-08-28
Scope: fifth remediation of `C27-R1-C03` and `C27-R1-C13` only
Method: manual source review plus inert, temporary-directory content-placement,
timestamp-restoration, byte-budget, authenticated-state rollback/deletion,
hard-link, evidence-mutation, crash-stage, capacity, witness-substitution, and
concurrent-writer probes. No service, driver, registry object, user document,
network endpoint, security control, product source, or test file was changed.
The transient audit harnesses were removed after execution.

## Verdict summary

| Finding | Verdict | Residual severity | Independent result |
|---|---|---:|---|
| `C27-R1-C03` | **REOPENED / PARTIAL** | **MEDIUM** | The exact fourth-round fixed-prefix and restored-mtime attacks are caught, and larger-file/budget misses are truthfully non-green. However, the new authenticated content-state can be rolled back or fully re-enrolled at health 100 and is never compared with current observations. A high-entropy file renamed to a blanket-excluded extension and a 50% strided-encryption file also produced zero alerts with complete coverage and health 100. |
| `C27-R1-C13` | **REOPENED / PARTIAL** | **MEDIUM** | All ordinary fourth-round false-green cases now fail closed or remain durably non-green, and crash/capacity/concurrency controls held. Evidence can still be changed through a hard link created at the final publication boundary, although permanent topology uncertainty now prevents green health. Complete deletion or coherent replacement/rollback of every local authority component is accepted as a fresh/older authority; total deletion returned health 90. This is an honestly documented software-only local-authority boundary, but not evidence preservation against an administrator-equivalent actor. |

The original findings' narrow scopes are materially resolved: recursive nested
ransomware traversal works, and bounded honeytoken reads/exclusive restaging
prevent the original memory-exhaustion and repeated-alert defects. The reopened
status is for independently reproduced residuals in the stronger closure claims.

## Exact attack matrix

### `C27-R1-C03` — Ransomware heuristics

| Probe | Result | Alert / health / completeness |
|---|---|---|
| Fourth attack: 4 MiB file with the first 64 KiB unchanged, the remaining bytes uniform-high-entropy, and mtime restored two hours old | **CAUGHT** | entropy `7.977157`; 1 alert; 0 errors; `complete=true`; health 100 |
| Fourth attack: wholly high-entropy 64 KiB file with mtime restored two hours old | **CAUGHT** | entropy `8.0`; 1 alert; 0 errors; `complete=true`; health 100 |
| 64 MiB file encrypted everywhere except the nine exact ranges selected by the running process | **MISSED, HONESTLY INCOMPLETE** | whole entropy `7.991095`; selected-range entropy `0.0`; 0 alerts; `content_incomplete=1`; `complete=false`; health 80 |
| Same 64 MiB file after module restart | **CAUGHT** | range set changed; sampled entropy `8.0`; 1 alert; `complete=false`; health 80 |
| Eight 8 MiB benign files consume the real 64 MiB content budget before a last-created 4 MiB encrypted file | **MISSED, FAIL-VISIBLE** | target was not a candidate; `content_budget_exhausted=1`; `skipped=1`; `truncated=1`; 0 alerts; health 65 |
| Isolated authenticated content-state deletion while its key survives | **CAUGHT** | `_load_change_state()` refused `durable content-state authority is incomplete` |
| Authenticated content-state rollback under the unchanged key | **MISSED / FALSE GREEN** | sequence 2 was restored to valid sequence 1; load succeeded; current traversal remained `complete=true`; health 100 |
| Deletion of both content-state and its local signing key | **MISSED / FALSE GREEN** | silently enrolled sequence 0; no fault; `complete=true`; health 100 |
| 4 MiB entropy-8 content named `encrypted.zip` | **MISSED / FALSE GREEN** | no candidate; `skipped=0`; `complete=true`; health 100 |
| 4 MiB file alternating 64 KiB clear and 64 KiB uniform-random ranges | **MISSED / FALSE GREEN** | whole/sample entropy `4.981552`; 0 alerts; 0 errors; `complete=true`; health 100 |

The large-file offset secret did what it claims within its boundary: offsets
changed across restart and the second process sampled encrypted content. The
first miss is still possible if an actor can observe the live process's chosen
ranges, but the module correctly labels representative-range coverage as
incomplete and never promotes it to health 100. Likewise, resource exhaustion
is exploitable as a detection-denial technique, but it is visible at health 65.

### `C27-R1-C13` — Smart Deception custody

| Probe | Result | Exact custody outcome |
|---|---|---|
| Pre-existing source hard link, then restart | **CAUGHT / DURABLE** | source alias survived; restart reconstructed `aliases=1`, `topology=1`, `degraded=true`; health 65 |
| Hard link created immediately after the final real evidence audit, then mutation through that link | **NOT PREVENTED, NEVER GREEN** | archive returned success; the alias and later digest change were detected; durable `alias=1`, `topology=1`; refresh false; restart health 65 |
| Pending evidence crash cleanup, then restart | **CAUGHT / DURABLE** | `loss=1` survived restart; health 65 |
| Authenticated age eviction, then restart | **CAUGHT / DURABLE** | restart reconstructed `evictions=1`, `loss=2`; health 65 |
| Delete evidence plus key/SQLite/head while enrollment key/witness survive | **CAUGHT** | refresh false; authority remained unenrolled; saturated; health 65 |
| Restore an old SQLite/head pair while the current witness survives | **CAUGHT** | refresh false; saturated; health 65 |
| Same-size evidence tail mutation with exact mtime restoration | **CAUGHT** | digest reconciliation failed before and after restart; saturated; health 65 with a live logical slot |
| Delete only the high-water witness | **CAUGHT** | incomplete enrollment witness refused; refresh false; health 65 |
| Eviction crash after durable intent but before deletion | **RECOVERED** | restart completed the eviction; chain remained valid; health stayed non-green from durable topology uncertainty |
| Eviction crash after deletion but before terminal `evict` event | **FAIL-VISIBLE** | restart appended durable continuity loss; `loss=1`; refresh false; health 65 |
| Terminal-reserve exhaustion (8-event inert bound, 2 reserved) | **SAFE REFUSAL** | remaining capacity was exposed before capture; health 30; tampered source was not retired and remained in place |
| Two ordinary concurrent archives | **SERIALIZED** | both completed into a valid sequence-4 ledger; restart inventory matched; health 65 from two durable topology events |
| Forced same-sequence commit race | **SAFE CAS FAILURE** | one archive completed; the other returned false and retained its source; restart accepted one exact evidence record at sequence 2 |
| Delete evidence, key, SQLite, head, enrollment key, and witness | **MISSED WITH DISCLOSED LOCAL BOUNDARY** | fresh sequence 0 enrolled; refresh true; no loss counter; health 90 with `freshness=local-authenticity-only` |
| Restore an older SQLite/head/witness set together | **MISSED WITH DISCLOSED LOCAL BOUNDARY** | older sequence 2 and its one surviving evidence object were accepted; health 65 because the older topology event remained |
| Replace the enrollment key and coherently re-sign the witness at the current head | **MISSED WITH DISCLOSED LOCAL BOUNDARY** | refresh true; witness reported verified; health 65 because topology uncertainty remained |

## `C27-R1-C03` — Loaded receipts are not detection authority; two deterministic green evasions remain

**Verdict: REOPENED / PARTIAL (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/ransomware_heuristics.py:450-528` authenticates and
  loads records into `_change_receipts`.
- Repository search finds `_change_receipts` only at initialization and the two
  assignments at lines 525 and 573. No scan, comparison, candidate admission,
  alert, or health path reads a prior receipt. The state is therefore an
  authenticated historical snapshot, not active change detection.
- `src/angerona/modules/ransomware_heuristics.py:565-574` increments a sequence
  and overwrites that snapshot after a complete cycle, but no independent
  high-water or enrollment witness exists. A correctly HMAC-authenticated older
  JSON file is accepted, and loss of both the JSON and key is treated as first
  enrollment at lines 450-457.
- `src/angerona/modules/ransomware_heuristics.py:223-231,1381-1430,1490-1497`
  excludes archive/media/PDF/Office extensions before sampling without
  incrementing `skipped`, `truncated`, or `errors`. Thus an encrypted file with
  an attacker-selected excluded suffix contributes to health-100 coverage but
  receives no content proof.
- `src/angerona/modules/ransomware_heuristics.py:928-962` computes one aggregate
  histogram for a complete file. It uses per-range maxima only for incomplete
  large-file sampling. Consequently, substantial alternating encryption can be
  diluted below 7.9 by clear ranges even though individual encrypted ranges are
  entropy 8.
- `src/angerona/modules/ransomware_heuristics.py:1515-1545` grants health 100
  when traversal counters are complete. Neither an excluded file nor a
  below-threshold mixed-content file creates uncertainty, and rolled-back
  receipts do not affect health.

### Impact and existing mitigations

An actor does not need to defeat the held-object or ancestry controls. It can
use a known excluded extension or encrypt alternating ranges slowly enough to
stay below the rename-rate threshold. Both probes retained health 100. An actor
able to write protected local state can also erase or roll back the advertised
durable change history without a health penalty.

The new full-file stream closes the exact 4 MiB tail and restored-mtime attacks.
All current-file reads remain identity-bound and held through publication.
Large-file sampling and resource truncation are explicitly below 100, and a
new per-process range secret prevented the same unsampled layout from surviving
restart. Other sensors and the same-directory rename correlator provide useful
defense in depth.

### Required remediation

1. Consume the authenticated prior receipt before replacing it. Bind a typed
   observation transition (`unchanged`, `changed`, `new`, `missing`,
   `incomplete`) to exact identity/path and expose transition evidence in alerts
   and health. If this state is only diagnostic, stop describing it as durable
   change tracking.
2. Add an independently enrolled install/key witness and protected monotonic
   high-water. Refuse an older valid sequence and refuse key+state loss after
   enrollment. Clearly cap software-only local freshness when no TPM or remote
   witness is configured.
3. Do not blanket-exempt files solely by mutable suffix. At minimum inspect
   magic/type and changes into an excluded suffix, bind exclusions to a prior
   reviewed identity/content receipt, count unproved exclusions, and keep their
   coverage below 100.
4. Preserve fixed-window or chunk-level entropy evidence even for fully read
   files. Alert/correlate on high-entropy range fraction, range deltas, and
   extension/rename changes rather than only whole-file aggregate entropy. Add
   regressions for alternating/strided encryption and low-and-slow renames to
   every excluded suffix class.
5. Keep the current honest large-file and budget health caps. Add a durable,
   fair cursor so repeated directory order cannot starve the same target on
   every tick.

## `C27-R1-C13` — Ordinary rollback is fixed, but local authority and link-topology boundaries still permit evidence loss

**Verdict: REOPENED / PARTIAL (MEDIUM residual).**

### Exact source evidence

- `src/angerona/modules/smart_deception.py:965-1144` correctly validates the
  complete HMAC chain and compares SQLite/head against the separately stored
  witness. It also reconstructs durable loss, alias, topology, refusal,
  eviction, and pending state across restart.
- At lines 984-990, absence of all five local authority objects is the sole
  definition of `fresh_authority`. There is no installer-owned or external
  enrollment fact that survives deletion of both local bundles.
- `src/angerona/modules/smart_deception.py:717-824` stores the enrollment key and
  witness as ordinary local files under the same runtime parent. An actor able
  to replace both can choose a new key and produce a valid witness for the
  current or an older locally captured head.
- `src/angerona/modules/smart_deception.py:1653-1682` performs a strong full
  digest and pre/post link-count audit, but link creation is not indivisible
  with the final `fstat`. The fifth code acknowledges this at lines 1738-1747
  and appends permanent `topology` uncertainty before success.
- `src/angerona/modules/smart_deception.py:1758-1768` repeats the audit after
  source retirement. A real hard link created immediately after that audit's
  final observation still survived and later changed the evidence. The new
  durable topology/alias events ensure this no longer appears green.
- `src/angerona/modules/smart_deception.py:2050-2096` caps an initialized local
  witness at 90 and any durable topology/loss state at 65. Total local authority
  deletion therefore no longer returns 100, but it still returns 90 with no
  explicit continuity-loss fact.

### Impact and existing mitigations

The ordinary attacker-visible false-green defects from the fourth re-attack
are fixed. Isolated deletion, ordinary paired rollback, pending/eviction loss,
capacity exhaustion, digest mutation, and writer races all failed closed or
remained durably non-green. The original bounded-read and alert-dedup controls
also continue to pass.

The residual requires either access to the evidence namespace during the tiny
publication boundary or write authority over every local witness component.
Those are materially stronger prerequisites than the original C13 attack, and
the module now discloses both limits. Nevertheless, the consequence is real:
retained evidence can be changed, or its entire history can be erased and
re-enrolled at health 90. An HMAC cannot provide freshness against the actor who
can replace its key; this is an architectural boundary, not a cryptographic
implementation bug.

### Required remediation

1. Separate the capture writer from the attacker class. Apply and verify an
   explicit Windows ACL/mandatory-integrity policy to the quarantine namespace,
   open it through a service-owned handle, and deny ordinary user processes the
   ability to create links or write evidence. Where the threat includes local
   administrators, use a reviewed minifilter, remote append-only replication,
   WORM storage, or another independently administered boundary.
2. Make enrollment installer-owned and operator-resettable, not
   create-on-total-absence inside the module. A missing established enrollment
   must be `RECOVERY_REQUIRED`; a legitimate reset needs a durable, explicit
   disposition receipt.
3. Bind the high-water to TPM NV/attestation or a remote monotonic transparency
   service before presenting high rollback assurance. When only local files
   exist, retain the current `local-authenticity-only` label but use a more
   conservative score and state explicitly that prior custody may have been
   erased.
4. Return a typed `captured_unverified` outcome while link topology is
   uncertain, replicate the sealed digest/evidence before retiring the source
   when policy requires preservation, and do not let a boolean success imply
   immutable evidence.
5. Preserve the current two-phase eviction, capacity reservation, durable loss
   reconstruction, and same-sequence writer refusal regressions.

## Validation record

```text
python -m pytest -q tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py \
  tests/test_cycle27_high_c_fifth_remediation.py
43 passed, 1 skipped in 14.99s

python -m py_compile src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py
PASS

python -m ruff check src/angerona/modules/ransomware_heuristics.py \
  src/angerona/modules/smart_deception.py \
  tests/test_cycle27_round1_high_c.py \
  tests/test_cycle27_high_c_third_remediation.py \
  tests/test_cycle27_high_c_fifth_remediation.py
PASS

RANS self_test: PASS
SDEC self_test: PASS
```

The pytest skip is the pre-existing directory-link privilege fixture. Every
hostile probe above used only automatically cleaned temporary files. Green
author tests substantiate the controls that held, but do not negate the
independently reproduced false-green and local-authority results.
