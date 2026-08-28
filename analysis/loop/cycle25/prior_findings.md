# Cycle 25 — Finding reconciliation and inherited residuals

Date: 2026-08-28
Product version: 1.12.0

## Reading this record

Round 1 recorded twelve risk/reliability lineages without retrospective CVSS
scoring. Round 2 deliberately re-audited durability and lifecycle paths, and
Round 3 used closure checks, so those records overlap and must not be summed as
unique vulnerabilities. This table is the current disposition.

| Lineage | Current disposition | Evidence of change | Residual boundary |
| --- | --- | --- | --- |
| C25-R1-01, universal capability truth | **Fixed** | Validated v12 contracts and operational snapshots cover all 80 discovered capabilities; inventory is reproducible. | Five contracts are native; 75 are explicit compatibility adapters with gaps. Product and implementation semver are independent. |
| C25-R1-02/03, Guided Auto Adapt and recovery | **Fixed within scope** | Closed choices, immutable consent data, completeness gate, no-write simulation, separate exact-plan confirmation, explicit non-replaceable baseline, journal/reconciliation/rollback. | Baseline restores complete Windows Firewall policy only. Hardware/services/ports/network are observational. |
| C25-R1-04, proposal versus authority | **Fixed** | Context automation, evolution, mitigation tuning, and unapproved behavioral changes cannot mutate unattended; bypass receipts are typed/single-use. | Human-approved, exact typed response paths still depend on OS privilege and evidence quality. |
| C25-R1-05, exact remediation | **Fixed** | PID/creation-time/executable revalidation; driver/firewall return-code, postcondition and rollback checks; ambiguous ACL action removed. | User-mode postconditions cannot remain authoritative after privileged compromise. |
| C25-R1-06, behavioral approval drift | **Fixed** | Learning epochs, review log, exact SHA-256 approval, CAS drift proposals, approved-only export. | Database custody is local; it is not independently witnessed against privileged rollback. |
| C25-R1-07, callable self-integrity | **Fixed** | Full marshalled code, defaults, keyword defaults, closures, and bounded canonical extras are covered. | In-process/local custody cannot defeat a privileged attacker controlling code and keys together. |
| C25-R1-08, persistence completeness | **Fixed** | Typed COMPLETE/PARTIAL/UNKNOWN, bounded WMI/registry/tasks, strict error and exact Winlogon handling. | Unelevated/unavailable sources remain unknown rather than being promoted to clean. |
| C25-R1-09, IPC custody/truth | **Fixed within scope** | Protected-store key, exact legacy migration/residue removal, bounded loopback authentication and fail-closed storage. | Diagnostic admission preview only; no production payload consumer, remote channel, or TPM claim. |
| C25-R1-10 -> C25-R2-01..04, durable delivery | **Fixed with residuals** | Durable SIEM/Remote outboxes, drain-stage-drain, revision cursors, full mutable-state HMAC, independent queue key. | At-least-once duplicates, row deletion/whole-DB rollback without an independent witness, restart-epoch transport coordination. |
| C25-R2-05/06, transactions and generations | **Fixed** | Atomic settings/intel replacement, protected-credential/autostart compensation, generation/cancel/status rechecks. | A composite failure can still require manual review and is surfaced as such. |
| C25-R1-11, standards truth | **Fixed within declared subset** | ATT&CK 19.2/15 tactics, Navigator 5.3.2/layer 4.5, typed constrained OCSF 1.8, atomic constrained Sigma receipts. | Curated catalog and constrained mappers/evaluator are not complete upstream implementations. |
| C25-R1-12, clickable bounded evidence | **Fixed** | Typed sortable tables, governed path/detail views, stable alert identity, bounded analysis queue, recoverable SOAR archive, owned CVE workers. | SOAR archive digest is not independent anti-rollback evidence; global distinct-CVE worker cap remains proposed. |

## Inherited Cycle 24 boundaries

Cycle 25 does not remove the need for externally provisioned Windows publisher
trust, protected release roots/policy, clean-machine installation acceptance,
independent Personal Sentinel/recovery custody, hardware or external monotonic
state, or separately privileged enforcement adapters. It also does not make
the user-mode suite tamper-proof against Administrator, SYSTEM, kernel, or
firmware compromise.

Round evidence:

- [Round 1 adversarial findings](round1/redteam_findings.md)
- [Round 2 reliability re-audit](round2/redteam_findings.md)
- [Round 3 final closure](round3/redteam_findings.md)
- [Cycle summary](summary.md)
