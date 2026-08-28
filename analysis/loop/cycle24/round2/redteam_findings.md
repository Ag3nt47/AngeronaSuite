# Cycle 24 Round 2 — Red-Team Engineering Assurance

Date: 2026-08-26
Mode: authorized, actor-neutral defensive secure-code review; benign local
fixtures and static workflow inspection only; no product-code edits, live
probing, destructive actions, or operational attack material

## Outcome

Seven open issues or residual trust-boundary gaps were confirmed: **one High,
three Medium, and three Low**. Round 1 materially improved release staging,
capability continuity, Sentinel cryptographic roles and availability, recovery
cohort checking, driver completeness, and analytic provenance. The principal
remaining release risk is that first-install trust is still evaluated by code
inside the candidate Setup rather than by an OS-enforced package identity.

| Severity | Open findings |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 3 |
| Low | 3 |
| Info | 0 |

## R2-01 — First-install publisher trust is still candidate-controlled

- **Severity:** HIGH
- **Component:** `installer/Angerona.iss:14-37,79-106,159-171`;
  `Verify-Angerona-Release.ps1:69-178`;
  `.github/workflows/release.yml:354-395`
- **Status:** OPEN; residual of R1-01

### Description

The release workflow now pins the PFX leaf certificate by SHA-256, signs the
final Setup through Inno Setup, and verifies its Authenticode chain. The Setup
also checks its own signature and embedded certificate digest before
installation. Those are meaningful controls for an authentic build.

They are not an external first-install authorization boundary. The check and
the expected digest at `installer/Angerona.iss:79-106` are both executed from
the candidate executable. A different candidate controls whether that code and
pin exist. Windows UAC displays publisher information but does not itself make
an unsigned or differently signed classic executable impossible to authorize.
The adjacent PowerShell verifier can enforce an exact publisher and GitHub
attestation, but the verifier is not independently authenticated on first use
and running it is not a prerequisite enforced by the operating system.

### Observed fail-closed property

The authentic Setup rejects invalid/mismatched signatures, invalid versions,
publisher rotation, and downgrade against an existing HKLM floor. The staged
verifier protects exact copied bytes and fails closed when GitHub CLI,
attestation, checksum, or the expected publisher identity is unavailable.
These properties become authoritative only after a trusted verifier or package
identity has already been established.

### Defensive recommendation

Make the supported first-install path an OS-enforced signed package, preferably
a signed **MSIX/App Installer** package whose publisher identity is verified by
Windows before package activation. Enterprise deployments can equivalently
require a WDAC/AppLocker/Smart App Control policy pinned to the approved
publisher. Keep the internal Setup self-check as defense in depth, but do not
present it as the trust bootstrap. If classic Setup remains supported, publish
a separately signed verifier through an independently authenticated channel
and require an external launcher/policy to refuse any candidate that is
unsigned or signed by another publisher before its first instruction runs.

## R2-02 — Threshold finalization accepts public roots supplied by signer artifacts

- **Severity:** MEDIUM
- **Component:** `.github/workflows/release.yml:241-353,354-395`;
  `tools/build_release_authorization.py:343-435`;
  `Install-Angerona-Release.ps1:198-270,331-359`
- **Status:** OPEN; R1-02 partially remediated

### Description

The two release secrets now live in separate named jobs and protected
environments, and each job receives only one secret. This closes the original
co-resident-secret defect. The finalizer, however, is told only the expected
labels `release-a` and `release-b`. Each response artifact carries its own
`public_key`; finalization verifies the signature with that supplied key and
writes those same supplied keys into `release-trust.json`. No expected signer
public-key digest is pinned in a configuration or service outside the
repository-controlled finalizer domain.

Consequently, the generated trust document proves that two distinct keys
signed the statement, but it does not independently prove that they are the
enrolled release-authority keys. The Windows finalizer also holds the publisher
PFX and the installers authenticate publisher/catalog/attestation evidence,
not an externally pinned threshold root, before target mutation. Protected
GitHub environment reviewers remain useful but are an external deployment
configuration, not a cryptographic property visible in this repository.

### Observed fail-closed property

Finalization rejects missing/duplicate signer labels, duplicate public keys,
statement-digest mismatches, and invalid Ed25519 signatures. Artifact v4 job
separation and per-job secrets materially reduce accidental key exposure. The
remaining gap is root enrollment, not signature verification.

### Defensive recommendation

Pin each enrolled signer public key or its digest in an independently
administered finalizer/HSM/KMS policy that repository code and signer-response
artifacts cannot rewrite. Signer artifacts should carry only the signer label,
statement digest, and signature. Require old-root threshold authorization for
key rotation. Ideally make publisher signing conditional on a verified
threshold receipt in that external finalizer domain, and preserve the receipt
for installer verification and public transparency.

## R2-03 — Portable upgrades do not enforce an authenticated rollback floor

- **Severity:** MEDIUM
- **Component:** `Install-Angerona-Release.ps1:145-270,273-359,361-411`;
  `installer/Angerona.iss:152-203`
- **Status:** OPEN

### Description

The protected portable updater verifies the exact staged archive, GitHub build
attestation, installed trust-root digest, publisher certificate, Authenticode
signatures, payload manifest, and signed Windows catalog before changing the
target. It nevertheless never parses the signed release authorization's
`version`/`sequence` and never compares it with a protected highest-installed
value. It can therefore accept an older, otherwise authentic release from the
same enrolled publisher and root. The Inno Setup path has an HKLM version floor,
so the two supported upgrade paths currently enforce different rollback
policies.

### Observed fail-closed property

The updater fails closed on missing installed trust, trust or publisher
rotation, invalid signatures/catalogs, incomplete manifests, reparse points,
and failed outer attestation. Protected staging closes the previously reported
ordinary pathname handoff/TOCTOU gap. The finding is limited to monotonic
release freshness.

### Defensive recommendation

Before any target mutation, validate the authorization schema and threshold
signatures against the installed pinned roots, compare its numeric release
sequence/version with a protected highest-installed floor, and reject lower
values. Commit the new floor transactionally with installation state and use
the same policy for Setup and ZIP upgrades. Anchor the floor in TPM-backed or
independently witnessed state where whole-host rollback is in scope; reserve
intentional rollback for a separately audited recovery path.

## R2-04 — SSH live ingestion lacks authenticated producer provenance

- **Severity:** LOW
- **Component:** `src/angerona/modules/ssh_surface_guard.py:277-308,796-813`;
  `src/angerona/core/ssh_surface.py:3261-3388`;
  `src/angerona/core/eventbus.py:60-68`
- **Status:** OPEN

### Description

The SSH guard's live EventBus adapter selects input by caller-provided
`event.module`, `channel`, or `provider` strings. It does not require a
`SensorProvenanceBroker` envelope or a fixed broker-assigned producer/schema
identity. Every admitted line advances `_known_source_tokens`. That state is
then used to suppress the specific notification for a successful key
authentication that is no longer considered a newly observed source.

A focused benign in-memory fixture confirmed that an unprovenanced bus event
advanced the trusted known-source set and changed the classification of a
later independently analyzed key-authentication observation. This is the SSH
analogue of R1-10; the temporal and identity consumers were remediated, but the
SSH live adapter was not.

### Observed fail-closed property

Live ingestion is disabled until the module explicitly enables it; input is
bounded to one 8 KiB record; retained identities are keyed tokens rather than
raw accounts or addresses; and the EventBus HMAC protects stored event bytes.
Those controls protect availability/privacy/integrity-at-rest, but the HMAC
does not identify the producer.

### Defensive recommendation

Accept live SSH records only through a fixed producer-to-schema map backed by
`SensorProvenanceBroker` credentials and sequence/loss metadata. Keep
unprovenanced EventBus text in a separate low-confidence diagnostic lane and
never let it advance the trusted known-source baseline. Persist trusted source
state only from the fixed Windows OpenSSH provider adapter or stable local log
descriptors with explicit completeness.

## R2-05 — Trusted-time receipt flooring is consumed twice across client and appraisal

- **Severity:** LOW
- **Component:** `src/angerona/core/personal_sentinel_authority.py:1116-1205,1234-1255`;
  `src/angerona/core/trusted_time.py:190-233`
- **Status:** OPEN; integration residual of R1-07

### Description

A production `PersonalSentinelAuthorityClient` must advance its durable
`response_floor` before returning a time receipt. `assess_trusted_time()` then
requires `witness_floor.compare_and_advance()` for that same sequence and time.
The floor interface has no namespace/domain parameter and correctly rejects an
equal sequence. Reusing the production floor therefore causes a valid fresh
receipt to be classified as an untrusted regressed witness.

A focused benign end-to-end fixture reproduced that composition: the
production client accepted and durably recorded the receipt, after which the
appraisal rejected the same receipt as non-advancing. Unit tests currently
exercise the client and appraisal with separate fresh floor objects and do not
cover their production composition.

### Observed fail-closed property

Both layers fail closed: no stale receipt becomes trusted, nonce challenges
remain exact, and replay/regression is rejected. The defect is an assurance
availability/integration failure rather than a freshness bypass.

### Defensive recommendation

Advance each receipt exactly once. Return a typed verified-receipt result from
the production client that cryptographically/structurally records successful
durable advancement, and let appraisal consume that result without a second
CAS; alternatively give explicitly separate named floor domains and document
their independent custody. Add a production transport-to-appraisal regression
using the actual durable floor implementation.

## R2-06 — A closed Sentinel authority remains able to process state transactions

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/personal_sentinel_authority.py:599-602,713-769,778-789,872-940`;
  `tools/personal_sentinel_server.py` shutdown lifecycle
- **Status:** OPEN

### Description

`PersonalSentinelAuthority.close()` releases the OS singleton lease and sets
`_lease` to `None`, but `process()` and `_save_state()` do not check a closed
state or verify that the lease remains held. A benign local lifecycle fixture
confirmed that an old instance could process and persist a receipt after it
was closed while a replacement instance held the singleton lease. In a
threaded server this matters for shutdown/restart and pending-handler races,
because two authority objects can then access the same state outside the
intended lifetime exclusivity contract.

### Observed fail-closed property

Constructing a second authority while the first remains open is rejected by
the OS lease, and state writes are serialized within each object and signed.
The gap begins only after the original object explicitly releases its lease.

### Defensive recommendation

Add an irreversible closed flag under `_lock`; require a live held lease at the
start of `process()`, `_load_state()`, and `_save_state()`; and fail closed after
release. During server shutdown, stop admission and join all request/handshake
workers before closing the authority. Add close-then-process and
close/reopen-with-pending-request regression tests.

## R2-07 — Linux removable-device inventory can report complete absence with unreadable entries

- **Severity:** LOW
- **Component:** `src/angerona/core/peripheral_posture.py:452-474,477-547`
- **Status:** OPEN

### Description

The Linux collector reads every `/sys/block/*/removable` flag, filters values
to `0` or `1`, and reports `absent` whenever at least one readable flag is `0`
and no readable flag is `1`. If another enumerated block entry is unreadable,
oversized, invalid, or changes during the read, that unknown entry is discarded
and the overall snapshot still counts `linux-removable` as a complete source.
The result can therefore claim complete absence without complete enumeration.

### Observed fail-closed property

An unreadable or over-budget `/sys/block` directory produces `unknown`; a
readable `1` produces `present`; and the global directory bound prevents
unbounded enumeration. Only mixed valid/unknown per-entry results are
misclassified.

### Defensive recommendation

Report `absent` only when every enumerated block entry yields a valid `0` from
a stable read. Any missing/invalid/changed flag must make removable posture
`unknown` and source completeness false, while still reporting a separate
positive `present` observation when a valid `1` exists. Add mixed `0`/unknown,
empty-directory, disappearing-entry, and overflow fixtures.

## Round 1 and older-finding reassessment

| Prior item | Round 2 status | Evidence boundary |
|---|---|---|
| R1-01 | **Still open** | Exact staged-byte, Authenticode, catalog, and attestation checks are strong; first-install enforcement remains candidate-controlled (R2-01). |
| R1-02 | **Partially fixed** | Secrets are separated by job/environment; externally pinned signer roots are still absent (R2-02). |
| R1-03 | **Fixed in code** | Durable epoch, issue/consume state, OS lease, and deletion anchor reject ordinary restart/replay/deletion. TPM/independent whole-host rollback resistance remains deployment-only. |
| R1-04 | **Fixed** | Production roles use client Ed25519 public verification and appliance-only response/state private signing. |
| R1-05 | **Fixed primitive; deployment residual** | OS singleton and signed generation exist. The production CLI does not supply the optional external generation floor, so full-appliance snapshot rollback resistance remains an external dependency. |
| R1-06 | **Fixed** | Bounded three-second TLS handshakes, separate pre-auth capacity, bounded request workers, and mandatory mTLS are present. |
| R1-07 | **Partially fixed** | Challenge binding and durable floors reject replay; production composition has the double-floor defect in R2-05. |
| R1-08 | **Fixed** | Future timestamps are rejected and recovery quorum is computed within an exact revision/archive/manifest cohort. |
| R1-09 | **Fixed for reported issue** | Collector exposes total/truncation and marks overflow incomplete. Loaded-kernel-image versus on-disk-file identity remains an honest observe-only residual. |
| R1-10 | **Fixed for named consumers** | Temporal and identity consumers use broker provenance/confidence caps; SSH has the analogous separate gap R2-04. |
| R1-11 | **Still open / deployment boundary** | Provenance, RAG, process-egress, measured-boot, peripheral, and Sentinel foundations remain partly injected, observe-only, or unwired and are not promoted to enforcement claims. |
| C23-R2-01 | **Still open / external dependency** | No independently administered production monotonic high-water service is wired. |
| A-04 | **Still open architectural boundary** | Admitted extensions still execute in-process with the suite token. |
| A-06 | **Still open architectural boundary** | Fixed trusted PowerShell paths reduce injection, but broad execution-policy bypass remains in legacy helpers/collectors. New Cycle 24 release helpers use `RemoteSigned`. |
| R6-03 | **Still open architectural boundary** | Response still lacks a retained OS process/executable-file lease spanning complete response mutation. |

Counting the eleven Round 1 items strictly, **six are fully resolved, three are
partially resolved/fixed with a deployment residual, and two remain open**.
All four requested older architectural/deployment items remain open. No defect
was reproduced in release catalog/manifest set reconstruction, recovery cohort
binding, driver overflow accounting, capability restart replay, Sentinel
Ed25519 role separation, bounded TLS/mTLS, dashboard public-event redaction, or
the Defense Memory one-excerpt cloud cap.

## Focused proof summary

- Benign in-memory SSH provenance fixture: **confirmed R2-04**.
- Benign production-client/trusted-time composition fixture: **confirmed R2-05**.
- Benign Sentinel close/reopen lifecycle fixture: **confirmed R2-06**.
- Static exact-path/schema review: **confirmed R2-01, R2-02, R2-03, and R2-07**.
- No live network connection, host configuration mutation, installer launch,
  signing-secret access, or product-code edit was performed.

## Post-remediation disposition

The findings above preserve the independent pre-fix Round 2 audit record. A
subsequent remediation pass closed R2-01 through R2-07 in repository code and
added focused regressions. R2-01 remains dependent on provisioned Windows
publisher trust and clean-VM deployment validation; R2-02 remains dependent on
protected external root/policy custody; and R2-03 cannot resist privileged
whole-host rollback without TPM-backed or independent monotonic state. These
are deployment or architectural boundaries, not capabilities claimed by the
repository. See `remediation_summary.md` for the exact controls and tests.
