# Cycle 24 — Finding reconciliation and inherited residuals

Date: 2026-08-27
Product version: 1.11.0
Mode: actor-neutral, defensive secure-code review using static analysis and
benign local fixtures

## Reading this record

Round 1 opened ten defects and one informational runtime/deployment boundary.
Round 2 intentionally re-audited several Round 1 themes and opened seven issue
records, so the round totals overlap and must not be presented as eighteen
unique vulnerabilities. Round 2's post-remediation statuses are the current
code disposition. Deployment and architecture dependencies remain open where a
repository cannot create independent custody, operating-system publisher
policy, hardware state, or a separate failure domain.

## Cycle 24 reconciliation

| Finding lineage | Current disposition | What changed | Residual boundary |
| --- | --- | --- | --- |
| R1-01 -> R2-01, first-install authenticity | **Fixed in repository contract; deployment required** | Public first install is a signed full-trust x64 MSIX validated by Windows before activation. Classic Setup is non-public and prior-approved-install migration-only. | Exact publisher identity, chain/policy provisioning, and clean-VM acceptance are external. There is no Store deployment claim. |
| R1-02 -> R2-02, signer independence/root enrollment | **Fixed in code; protected custody required** | Signer jobs are separated; response artifacts carry no public keys; finalization requires separately supplied enrolled roots and an exact protected root-policy digest. | Protected environments, HSM/KMS-equivalent custody, reviewer policy, and root recovery are deployment responsibilities. |
| R1-03, capability replay after restart | **Fixed in code** | Durable epoch, issuance/consumption high-water state, exclusive lease, and deletion anchor reject ordinary restart/replay/deletion. | Privileged whole-host snapshot rollback needs TPM-backed or independent monotonic state. The primitive must remain narrowly wired. |
| R1-04, symmetric Sentinel verifier authority | **Fixed in code** | Production roles use Ed25519: the authority holds private response/state signing material and the monitored host holds a public verifier. Client request identity remains separate. | Private-key custody, certificate enrollment, and service-host administration are external. |
| R1-05, Sentinel rollback/fork | **Fixed primitive; deployment residual** | OS singleton lease, signed generation, compare-and-swap state, durable response floors, and irreversible close semantics prevent ordinary concurrent forks and stale-instance writes. | Full appliance snapshot rollback needs the optional external generation floor, TPM, WORM log, or second witness. |
| R1-06, TLS handshake admission denial | **Fixed in code** | Pre-authentication handshakes have separate bounded capacity/deadlines; authenticated workers are bounded; production mTLS is mandatory; shutdown drains admitted workers before releasing authority. | Network reachability, certificate operations, service monitoring, and denial-of-service capacity planning remain deployment work. |
| R1-07 -> R2-05, trusted-time replay/composition | **Fixed in code** | Current challenge binding, durable sequence/time floors, and deterministic transport/appraisal namespaces reject replay without consuming one domain's floor twice. | Floor custody must remain outside a restorable monitored-host snapshot when snapshot rollback is in scope. |
| R1-08, mixed/future recovery evidence | **Fixed in code** | Excessive future timestamps are rejected; copy/domain/signer/posture/restore requirements are satisfied only inside one exact revision/archive/manifest cohort. Reads and directories are bounded and identity-stable. | Evidence truth, immutability, offline/offsite claims, signer independence, and restore execution come from external backup authorities; Angerona does not restore or recreate deleted evidence. |
| R1-09, silent driver truncation | **Fixed for reported issue** | Total/truncation evidence makes over-limit inventory incomplete; Windows enumeration is filtered and bounded; visible images retain hash/signature/catalog/blocklist posture. | A user-mode on-disk pathname does not perfectly prove the identity of bytes already loaded in the kernel. The guard is observe-only. |
| R1-10 -> R2-04, producer provenance | **Fixed for temporal, identity, and SSH consumers** | Sensor broker credentials, fixed producer/schema maps, and sequence/loss state gate trusted analytic inputs. SSH consumer validation occurs before broker continuity mutation. | Broker credentials and privileged producer custody are deployment boundaries. EventBus HMAC alone remains storage integrity, not producer identity. |
| R1-11, foundations not all runtime enforcement | **Informational boundary remains** | Recovery, release, provenance, Sentinel, measured-boot, RAG, and egress foundations now have stronger code contracts and focused regressions. | Process egress needs a privileged adapter; measured boot needs a real quote provider/verifier; several modules remain observe-only or injected. No enforcement claim is made. |
| R2-03, portable release rollback | **Fixed in code; whole-host rollback external** | Installed native verifier validates threshold authorization and protected numeric version/sequence floors before target mutation; root replacement/downgrade fail closed. | Windows ACLs do not defeat privileged whole-host rollback. TPM-backed or independently witnessed state is required for that model. |
| R2-06, post-close Sentinel transactions | **Fixed in code** | Close is irreversible; processing/state I/O require a held lease; admission stops and workers drain before lease release. | Correct service supervision and host isolation are still operational responsibilities. |
| R2-07, Linux removable completeness | **Fixed in code** | Absence is complete only when all enumerated entries are stable no-follow valid zeros. Mixed, empty, invalid, disappearing, unreadable, or over-budget evidence remains incomplete. | Local sysfs truth cannot survive kernel compromise and is observe-only. |

## Round 3 reliability findings

Round 3 opened four finding IDs: one High, one Medium, and two Low. All four
were fixed and retested. The High finding removed the classic migration Setup
from the public/clean-install path; the Medium finding hardened installed
authority and target custody; the Low findings completed multi-controller
Thunderbolt reduction and corrected public documentation. In parallel, Round
3 applied six bounded reliability and presentation changes:

1. Cap peripheral enumeration at `limit + 1`.
2. Bound recovery directory traversal and stable no-follow reads.
3. Drain Personal Sentinel admission/worker state deterministically.
4. Run SSH producer/type/schema checks before continuity mutation.
5. Freeze all relevant timers and fixtures for byte-reproducible public
   screenshots.
6. Encode Qt translucent theme colours in the toolkit's alpha-byte order.

These changes preserve cadence, cryptographic checks, evidence fields,
response boundaries, and fail-closed behavior.

## Inherited findings outside Cycle 24

| Prior ID | Status | Current boundary |
| --- | --- | --- |
| A-07 | **Resolved** | Shadow Shield uses SHA-256; no current weak-hash finding remains. |
| C23-R2-01 | **External dependency remains** | Local audit/network state has authenticated continuity, but independent freshness still requires a separately administered monotonic authority or policy-bound hardware floor. Personal Sentinel supplies a reference implementation; its independent deployment is not created automatically. |
| A-04 | **Open architectural boundary** | Admitted extensions still execute in-process with the suite token. A separate least-privilege extension host remains future work. |
| A-06 | **Open architectural boundary** | New release paths use narrower policy, but legacy trusted PowerShell collectors retain a broad execution-policy surface. Fixed trusted executable paths reduce injection but do not equal a brokered constrained-language collector service. |
| R6-03 | **Open defense-in-depth boundary** | Path-wide program firewall mutation still lacks the preferred retained OS process handle plus bounded executable-file identity lease across the complete mutation. The v1.11 process-egress broker/guard is policy/audit, not that enforcement adapter. |

## Deployment and architecture residuals that must stay visible

- Public Windows release requires provisioned MSIX publisher identity,
  certificate chain/trust policy, protected release roots, and clean-VM
  installation validation.
- A local signed or ACL-protected high-water cannot resist privileged whole-host
  rollback. Use a TPM or separately administered witness when that threat is in
  scope.
- Sentinel, broker, recovery, and trusted-time authority state must be held
  outside the monitored host's restorable snapshot to claim independence.
- Personal Sentinel is not a router appliance, router management channel,
  routing role, firewall mutation API, credential store, or firmware attestor.
- Event-log controls detect observed clears and continuity loss; they cannot
  reconstruct events erased before collection.
- Measured-boot, identity/session, process-egress, recovery, and RAG conclusions
  remain only as authoritative as their injected producers/verifiers.
- User-mode observation cannot guarantee truth after Administrator, SYSTEM,
  kernel, firmware, or trusted-authority compromise.

## Source records

- [Round 1 findings](round1/redteam_findings.md)
- [Round 1 remediation](round1/remediation_summary.md)
- [Round 2 findings and reassessment](round2/redteam_findings.md)
- [Round 2 remediation](round2/remediation_summary.md)
- [Round 3 findings and reassessment](round3/redteam_findings.md)
- [Round 3 release remediation](round3/release_remediation_summary.md)
- [Round 3 performance and reliability](round3/performance_summary.md)

This reconciliation is a defensive engineering record, not independent
certification or an attribution statement.
