# Cycles 31-33 — enterprise-pattern defensive programs

Date: 2026-08-30

Release target: **v1.13.0**
Scope: authorized defensive-only theoretical hardening

## Net result

Three new local-first programs are integrated as native Local SOC tabs:

- **Fleet Center / Fleet Fabric Lab** provides sealed enrollment grants,
  durable device bindings, bounded authenticated health evidence, and governed
  desired-versus-effective rollout planning with canary halt and proposal-only
  rollback. It implements no remote coordinator transport, dispatch channel,
  high availability, or production fleet service.
- **DetectionForge** provides immutable replay cohorts, candidate-versus-active
  detection diffs, an alert-inert shadow lane, chained quality receipts, and
  exact one-use promotion or rollback receipts. It is local governed detection
  evaluation, not a production multi-tenant detection-content service.
- **AegisPath** provides an evidence-bound exposure graph, bounded confirmed and
  speculative attack paths, choke-point and blast-radius analysis, inert
  breakpoint counterfactuals, and explainable KEV/EPSS/criticality priority.
  It does not claim exploitability, breach probability, reachability proof, or
  remediation proof.

The Windows-target inventory is now **84 capabilities: 9 native contracts and
75 explicit compatibility adapters**. All built-in implementation labels are
1.13.0. Product version, implementation label, contract maturity, and efficacy
remain separate claims.

## Adversarial disposition

Initial audits recorded **31 findings**: Cycle 31 had 9 (3 High, 5 Medium,
1 Low), Cycle 32 had 13 (6 High, 7 Medium), and Cycle 33 had 9 (2 High,
6 Medium, 1 Low). The first remediation mapped and fixed all 31.

Independent re-attacks then found **15 additional bypasses** rather than
counting author-green results as closure:

| Cycle | Re-attack IDs | Severity | Final status |
| --- | --- | --- | --- |
| 31 | `C31-NEW-01..03` | 2 Medium, 1 Low | 3/3 fixed |
| 32 | `C32-RA-01..05` | 3 Medium, 2 Low | 5/5 fixed |
| 33 | `C33-RA-01..07` | 2 High, 3 Medium, 2 Low | 7/7 fixed |

Cycle 32's final bounded re-attack found no new issue, reproduced all five
repaired attacks as blocked, and retained all 13 original closures. Cycle 31
and Cycle 33 second-repair regressions plus the root serial and integration
gates found no reopened issue.

## Performance and responsiveness

- Fleet custody projection changed from per-device query/reverification work to
  one ordered tenant scan, reused already verified head evidence, and removed a
  redundant dashboard custody recomputation.
- AegisPath summary counts are accumulated in O(paths) work, initial large
  analysis runs off the GUI thread, and duplicate Local SOC/widget refresh was
  removed.
- DetectionForge retains bounded ledgers, replay cohorts, evaluator budgets,
  and reserved active/shadow lanes. No optimization weakened receipt,
  loss-accounting, promotion, or alert-inert shadow semantics.

## Verification evidence

- Cycle 31 focused: **23/23**; broad fleet/policy/hunt: **148/148**.
- Cycle 32 focused: **47/47**; compatibility: **60/60**.
- Cycle 33 focused: **40/40**.
- Integrated six-cycle-file root selection: **110/110**.
- Performance/integration selection: **113/113**; GUI/integration: **86/86**.
- Package compile: **368/368**.
- Capability contract tests: **6/6**.
- Discovery: **84 capabilities**, zero errors; **9 native / 75 adapters**.
- Module harness: **69 passed / 16 expected platform, disabled, or optional-
  prerequisite skips / 0 failed**.
- Supported selfcheck: **26/26**; Ruff clean; workflow policy **3/3**.
- Historical pre-documentation gate: **2788 passed / 13 intentional platform
  skips / 1 expected documentation-drift failure**. The sole failure was the
  stale README marker (`81` versus discovery `84`), which the v1.13.0
  documentation corrected.
- Authoritative terminal five-check release gate on exact commit
  `edefd8b07b94da4d682a35ace23057e7b22c3790`: **2790 passed / 13 intentional
  platform skips / 0 failed in 325.19 seconds**. Evidence-manifest SHA-256:
  `23fd1c70b5b227f45175570eee14774a1693d93f1fe4e8cb914b8ce9a5d2b813`.
  Validation is complete; guarded publication remains pending.

## Explicit trust and scale boundaries

- Fleet Fabric uses local SQLite, HMAC, and software checkpoints. They cannot
  prove whole-store rollback if local authority and tenant key are both
  compromised. Ed25519 custody is not hardware attestation. Remote transport,
  dispatch, distributed quotas, HA, and production mTLS coordination are not
  implemented. Full custody review is O(retained state), tombstone chains grow
  over tenant lifetime, and Local SOC/store opening is synchronous.
- DetectionForge cannot prove all-file rollback without an independent or
  hardware anchor. One validated in-process Sigma evaluator call cannot be
  forcibly preempted without process isolation. Its recursion boundary assumes
  synchronous EventBus dispatch, and its bounded quality store can reverify up
  to a 16 MiB ledger.
- AegisPath manifests and absence evidence rely on local governed provider and
  policy authority, not external PKI. Python can quarantine a blocked provider
  but cannot terminate it. Work-byte estimates are not operating-system RSS.
  Large what-if rendering is deliberately deferred to bounded backend analysis;
  simulation is inert and proves neither reachability nor remediation.

The programs implement enterprise-inspired local patterns. They do not establish
commercial EDR/XDR parity, distributed fleet readiness, independent efficacy,
or resistance to a compromised Administrator, SYSTEM, kernel, hypervisor,
firmware, publisher, or external identity authority.

## Public demonstration

The reproducible synthetic capture is
[`docs/screenshots/angerona-v1.13-enterprise-programs.png`](../../docs/screenshots/angerona-v1.13-enterprise-programs.png).
It contains synthetic data only and demonstrates the three Local SOC program
surfaces; it is not production telemetry or a scale benchmark.
