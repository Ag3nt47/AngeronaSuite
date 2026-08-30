# Cycle 27 Round 1 — Seventh High-C Remediation

Date: 2026-08-28
Scope: `C27-R1-C03` and `C27-R1-C13` only
Status: **implemented and author-validated; independent re-attack required**

This pass addresses only the two residuals in
`independent_reaudit_high_c_sixth.md`. All attack-shaped validation used inert
pytest temporary directories. It does not claim perfect ransomware detection,
administrator-proof local evidence, or an automatically provisioned external
authority.

## C27-R1-C03 — packed-file pseudo-review and fixed-prefix starvation

Status: **FIXED in author validation; pending independent re-attack.**

`src/angerona/modules/ransomware_heuristics.py` now:

- never treats a suffix, magic prefix, or repeated automated observation as
  exclusion authority. Declared container metadata remains descriptive, and
  new and unchanged high-entropy ZIP/Office/media-like files continue through
  the same identity-held entropy scoring as other files;
- enumerates the complete held directory stream before traversal-budget
  selection and retains only a keyed `O(limit)` reservoir. The authenticated,
  restart-persistent scan epoch changes the ranking on complete and incomplete
  cycles, so an attacker-controlled filesystem enumeration prefix no longer
  receives permanent selection priority; and
- reports total eligible entries, selected entries, and a conservative
  restart-persistent oldest-unseen epoch age. Truncation, content budget,
  partial large-file proof, traversal error, and local-only freshness continue
  to prevent a full-health claim.

Exact implementation anchors are `_fair_directory_entries()` at line 1663,
coverage accounting at lines 1788-1801, candidate admission at lines 1960-1984,
and health evidence at lines 1994-2028.

Operational boundary: without an authenticated human/policy approval workflow,
legitimate high-entropy archives can produce alerts. This remediation chooses
false-positive visibility over a four-byte bypass. Full metadata enumeration is
memory-bounded but can consume the directory's enumeration time; content reads
and downstream traversal remain explicitly bounded and non-green when
incomplete.

## C27-R1-C13 — production authority wiring and recoverable exact CAS

Status: **FIXED in author validation; pending independent re-attack.**

The production composition and custody protocol now provide:

- an explicit `SmartDeception.bind_high_water()` contract (line 353), a guarded
  `ModuleManager` constructor/factory binding path (line 190), and application
  plus headless construction parameters. Only bundled modules can receive the
  privileged provider; external drop-ins cannot acquire it implicitly;
- the exact `smart-deception-custody` domain as a shared protocol constant and
  a member of Personal Sentinel's default allowed-domain policy;
- an authenticated, single-link, byte-bounded external-transition outbox
  written before each local ledger commit (line 870), protected by a
  state-root-scoped non-blocking OS writer lease;
- restart reconciliation (line 1123) that accepts only one of three exact
  states: remote still equals the authenticated predecessor and the local
  commit did not occur; local is exactly one revision ahead and the authority
  accepts the saved CAS; or the remote already contains the exact new revision,
  state digest, and predecessor after a lost response. Gaps, forks, changed
  installation identity, malformed/tampered outbox state, missing transition
  proof, and ambiguous CAS results remain recovery-required; and
- explicit configured, unverified, unavailable, rejected/forked, local-only,
  pending-transition, and independently fresh evidence in the module health
  note/snapshot. The existing `captured_unverified` result, ACL proof, terminal
  reserve, loss/topology evidence, health-95 ceiling, and non-WORM disclosure
  remain unchanged.

Operational boundary: the normal application can now receive a reviewed
provider, but no network authority is silently enrolled. A deployment must
explicitly provision and pass a separately administered Personal Sentinel (or
equivalent protocol implementation); absent that provider, health continues to
say `local-authenticity-only`. A same-host administrator can still deny service,
delete local pending state, or mutate local evidence. Those actions fail closed
or remain `captured_unverified`; preservation against that actor still requires
remote append-only/WORM custody or a kernel/hardware boundary.

## Adversarial regressions and gates

New file: `tests/test_cycle27_high_c_seventh_remediation.py` (10 tests).
The suite covers magic-plus-unchanged scoring, full-stream reservoir coverage,
eligible/selected/unseen evidence, default domain enrollment, production
manager binding, transient local-ahead replay, committed-but-response-lost
reconciliation, pre-local-commit cleanup, remote-fork refusal, and OS
second-writer exclusion.

```text
Focused/wider high-C pytest:
90 passed, 1 skipped in 24.63s

ModuleManager/authority/capability compatibility pytest:
44 passed in 17.57s

py_compile (7 source files + 2 focused test files): PASS
Ruff (same files): PASS
owned-file git diff --check: PASS (line-ending notices only)
RANS self_test: PASS
SDEC self_test: PASS
Personal Sentinel authority self_test: PASS
```

The skip is the pre-existing privilege-dependent directory-link fixture. These
are author-side gates, not independent closure; a seventh hostile re-attack must
decide whether the two findings can be marked closed.
