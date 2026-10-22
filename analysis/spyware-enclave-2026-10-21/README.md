# SpywareGuard, UGCAP and Enclave Mesh review — 2026-10-21

Final validation: **5,775 tests passed, 28 skipped; one Windows file-replacement failure passed three repeats and the 33-test repair follow-up**.
The full attempt exited 1; every follow-up exited 0. GitHub publication uses the guarded publisher and must verify public `main`. Earlier failures
below were repaired; they are not the final verdict. This source review does
not certify live spyware removal or an uncompromisable platform.

## Delivered scope

[SpywareGuard](../../docs/spyware-guard.md) adds a dashboard, settings, dated
news, research URLs, inert sandbox and response/evidence receipts. Scope:

1. Persistence: bounded Windows registry/service/WMI/COM/startup and POSIX
   launch/systemd audits; `.lnk` targets are not resolved.
2. Runtime: optional executable private-region metadata and local API/file-read
   adapters; no universal interception or kernel scan.
3. NDR: reviewed indicators, DNS patterns and adapter-provided egress counters.
   A port alone proves neither encryption nor exfiltration.
4. Ad-tech: renderer/child and cleartext identifier observations; no universal
   zero-click blocker, TLS decryption or identifier stripping.
5. Intelligence: bounded, public-address-pinned HTTPS ingestion and literal
   extraction. Candidates require digest-scoped review; staged YARA/Sigma/NDR
   artifacts remain inactive. Prose grants no response authority.
6. Response: first local rule requests exact-target containment or local-host
   isolation, independently gated by Adversary Combat. No automatic persistence
   deletion; encrypted copies retain the journaled plaintext quarantine.

The opt-in Hail Mary watcher checks identity, liveness and authorized destinations
for minimal notifications. Containment, outages or compromise can block delivery.

[UGCAP and Enclave Mesh](../../docs/ugcap-enclave-mesh.md) add an explicit
secondary-volume encrypted baseline, hardware-plus-passphrase verification and
approved recovery. Strict startup holds ordinary imports until a fresh receipt
matches exact source bytes. X25519 sessions rotate every ten seconds, with
Ed25519-certified identities and HKDF/AES-GCM keys; the isolated integrity worker
uses encrypted authenticated pipes. Integrity failure holds managed workers;
UGCAP/Adversary Combat remain available. Recovery requires a new process and
verification; unsupported recovery defers offline.

Full Setup maps all 12 new fields, validates prerequisites and includes network
opt-ins in review. Users can extend the source through
[Writing modules](../../docs/writing-modules.md); intentional edits require
review and explicit new enrollment.

## Concrete review fixes

- Rejected simulated/remote provenance before both behavioral and direct-sensor
  conversion; advisory records cannot be republished with local response power.
- Bound loading to a complete current source receipt; revocation, incomplete
  verification and recovery cannot silently reopen workers.
- Preserved partial memory coverage, matched displayed approval to report digest,
  and bounded executable reads on retained custody after pathname replacement.
- Retried encrypted archive failures and unblocked saturated news refresh queues.
- Retained recovery custody, prevented overwrite, refused missing-parent writes
  and removed pathname staging chmod. Pending enrollment requires explicit
  authenticated resumption.
- Fixed beacon reader cancellation on revocation; stale authorization suppresses
  delivery and retires the child.
- Adaptation overlaps bounded probes, preserves partial evidence and moves recovery
  hashing off the GUI. Self-Test/Red Team improved completion and evidence reporting.

## Validation evidence and limits

| Checkpoint | Observed result |
| --- | --- |
| Final full regression | 5,775 passed, 28 skipped, one Windows replacement failure; 1,003.02 s; pytest exit 1 |
| Repair follow-up, unchanged source | Exact case passed three repeats; all 33 repair tests passed; exits 0 |
| Initial full regression, before repairs | 3 failed, 5,686 passed, 28 skipped; 1,090.09 s |
| Full Setup follow-up | 32 passed; Ruff and diff checks passed |
| New integrity/mesh core and guard checkpoint | 136 passed, 2 platform skips |
| Fresh GUI startup boundary | 2 passed; no ordinary module imports before challenge |
| Beacon child lifecycle follow-up | Three real-child repetitions, five checks each, passed |
| Final inventory export | 86 capabilities: 11 native contracts, 75 compatibility adapters |
| Offline selfcheck checkpoint | 28 phases passed, 0 failed; 86 modules: 68 pass, 18 expected skip; pipeline pass; 9 verifier passes |
| Selfcheck measured work | 1,713.8328 ms, with 2 worker checks; excludes I/O |
| Actual read-only protected-scope scan | 1,193 files; 19,249,746 bytes; 0 read errors; no enrollment, vault or hardware writes |

Initial failures were a stale receipt fixture, missing setup fields and a beacon
revocation child hang; all received specific repairs. The final rerun supplies
the verdict. Default host selfcheck flagged an existing Ollama wildcard bind;
the service was unchanged. An isolated port-65534 run passed after a nonblocking
history-retry harness fix.

Read-only research checks found one [Citizen Lab feed](https://citizenlab.ca/feed/)
item (October 8) and one [Project Zero index](https://projectzero.google/)
item (October 6; homepage 46,083 bytes). CISA HTTP 403 was reported as unavailable.
Source availability is not a threat detection.

The [Adaptation benchmark](../../docs/adaptation-button-review.md) measured a
4.321× median scheduling ratio with five synthetic 20 ms probes; cold startup
was slower. The local mesh fixture measured a 0.773 ms median. Neither measures
whole-PC performance or spyware detection efficacy. The
[button review](../../docs/selftest-redteam-button-review.md) retains its
historical pre-UGCAP checkpoint and qualified PID-query measurements.

Production containment, live spyware, physical TPM provisioning and external
notifications were not exercised. Python wiping is best effort; runtime,
packages and bootstrap remain trusted. TPM continuity is not remote attestation
or vTPM clone resistance. The kernel can access mounted media; audit rollback
needs an independent witness. Pauses are cooperative; no YubiKey backend or
universal kernel/firmware defense is supplied. Exact limits are in the guides.

Machine-readable evidence: [validation.json](validation.json). Product and test
source remained fixed during the final suite. The standalone selfcheck retry
call was corrected and validated separately. Final source-input manifest
SHA-256: `0332f433a6b806543c00336c3c00a6f5f7628150a585a5f59ceaf0991ac8d73b` (1,056 files).

The final full attempt encountered a Windows `File.Replace` I/O failure before
the startup-repair crash injection could run. The original environment was
restored. Three exact-case repetitions and the entire repair test file then
passed without changing product or test code. This is consistent with
transient replacement contention; the locking process and cause remain
unproven. The original full-run failure is retained above.

The final syntax gate compiled all 429 source files using an isolated bytecode
cache. A concurrent attempt against the normal cache encountered eight Windows
replacement denials while imports were active; it did not identify syntax errors.
Ruff passed for all 62 changed Python files. Workflow policy and documentation
drift checks passed.
