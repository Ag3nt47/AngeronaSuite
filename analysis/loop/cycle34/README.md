# Cycle 34 — post-release security and performance convergence

Date: 2026-08-30

Release line: **v1.13.0 post-release maintenance**
Scope: authorized defensive-only hardening
Disposition: **three code rounds complete; final release gate and publication
pending**

## Net result

Cycle 34 hardened the three v1.13.0 Local SOC programs and the local flow
canvas without adding a module or changing the product version.

- The flow canvas now uses a loopback-only, Host-checked, exact-allowlist
  server. It performs descriptor and final-path checks, accepts only a bounded
  fresh metrics schema, renders values as text, and uses an operating-system-
  selected port.
- DetectionForge promotion now binds one exact live Detection Runtime, one
  governed full active set, an atomic recovery journal, nondecreasing authority
  time, a PID-bound cross-process root-owner lease tied to immutable registry,
  state, quality, policy, clock, path, and runtime authority, a durable
  governance anchor, and journaled quarantine convergence. Trust keys and
  signed artifacts are read as stable, bounded operation-wide snapshots.
- Fleet health custody authenticates every retained row and uses guarded
  incremental exact-row projections. Persistent admission state survives
  restart, exact retries do not consume new burst, and a failed transaction
  does not consume volatile quota. Retention is capped at 5,000 evidence rows,
  8 KiB each, with a roughly 40.96 MB encoded cache ceiling.
- Local Operations Center construction is single-flight, nonblocking,
  cancellable, and bound before dependent modules can start. Detection Runtime
  and Fleet Health Monitor use the exact composed authorities.
- AegisPath selection uses immutable path/node indexes, avoiding a full graph
  scan for every click.

No Cycle 34 research proposal shipped. Round 1 ranked 11 primary-source
defensive proposals, but High-severity convergence took priority. Round 3
produced eight additional local design proposals; all remain backlog.

## Round records

- [Round 1](round1.md): initial five-finding repair, flow-canvas boundary,
  composition binding, and AegisPath indexes.
- [Round 2](round2.md): DetectionForge atomic/lifecycle convergence, canvas and
  startup lifecycle re-attack, authenticated Fleet retention, and removal of
  the Fleet 3N+1 verification path.
- [Round 3](round3.md): temporal/migration/owner/quarantine closure, durable
  Fleet admission, trust-store time-of-check/time-of-use closure, and the final
  publication-bound lease/fork re-attacks.
- [Innovation record](innovation_ideas.md): proposal-only research disposition.

## Current verification

The completed targeted Cycle 34 gate passed **91 tests with two expected
Windows host-capability skips** (symlink creation and POSIX `fork`). Adjacent
compatibility and integration
selection passed **128 tests**. Package compile passed **368/368**. Standalone
self-tests passed **93 with 0 failures**, plus **16 expected platform,
disabled, or optional-prerequisite skips**. Supported selfcheck passed
**26/26**.

These are overlapping targeted gates. The full serial pytest run, authoritative
five-check release gate, validated commit, evidence-manifest digest, guarded
publication, and public README-asset proof remain pending and must not be
inferred from the earlier Cycles 31–33 release evidence.

The canonical Word manual was rebuilt from its pristine pre-Cycle-34 snapshot,
reconciled to this maintenance tree, and passed structural plus page-by-page
visual QA as a 41-page document.

## Residual boundaries

- A privileged rollback of the complete detection root and its local key can
  also roll back every software checkpoint. An independent service or hardware
  witness is required to prove that event.
- Published-v2 and floorless-v3 detection state migrates only when its complete
  authenticated history is unambiguous. Truncated, contradictory, or partially
  restored history fails closed and requires operator recovery.
- Only a genuinely legacy registry with no governance record can receive its
  first governance anchor automatically. An already governed prepublication or
  work-in-progress registry whose anchor is missing fails closed; compatibility
  does not silently mint a replacement.
- Fleet Fabric remains a local lab. It has no remote transport, dispatch,
  high-availability service, distributed quota authority, or production mTLS
  coordinator.
- Fleet retains at most 5,000 health rows. After a pruned-history restart,
  admission state begins conservatively and refills from elapsed trusted time;
  startup still performs a full retained-state verification.
