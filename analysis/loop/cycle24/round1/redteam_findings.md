# Cycle 24 Round 1 — Red-Team Findings

Date: 2026-08-26
Mode: authorized, actor-neutral defensive secure-code review; benign local
fixtures only; no product-code edits, live network probing, or destructive host
actions

## Outcome

Eleven new issues or deployment gaps were confirmed: **one High, seven Medium,
two Low, and one Info**. The highest-risk defect is that neither supported
Windows installation path makes external artifact authenticity a prerequisite
to privileged installation. The new release signatures and GitHub attestations
are useful evidence, but today they are optional/post-start checks rather than
an installation authorization gate.

| Severity | New findings |
|---|---:|
| Critical | 0 |
| High | 1 |
| Medium | 7 |
| Low | 2 |
| Info | 1 |

## R1-01 — Supported installers do not enforce externally anchored artifact authenticity

- **Severity:** HIGH
- **Component:** `Install-Angerona-Release.ps1:69-90,99-113,115-195`;
  `installer/Angerona.iss:34-46,57-59,118-149`;
  `Verify-Angerona-Release.ps1:9-40`;
  `.github/workflows/release.yml:414-429`;
  `src/angerona/modules/release_transparency_guard.py:133-159`
- **Status:** OPEN

### Description

The portable ZIP installer reads `release-files.sha256` from the same extracted
directory as the payload and verifies only that the files match that
bundle-carried manifest. On first installation it also accepts the
bundle-carried `release-trust.json`; the hash comparison at lines 99-113 only
prevents an ordinary later ZIP upgrade from silently rotating a root already
installed. A replacement ZIP can therefore contain replacement executables,
SBOM, provenance, authorization, trust store, and a freshly generated checksum
manifest that passes lines 69-90.

The Inno Setup path copies the same payload and launches `Angerona.exe` after a
version-floor comparison. `InitializeSetup()` does not authenticate the setup
or its embedded payload. The workflow does publish Sigstore-backed GitHub build
attestations, and the separate verification script can invoke `gh attestation
verify`, but neither supported installer invokes a verified receipt before
writing or starting privileged code. The release-transparency module verifies
after Angerona has already started and defaults to the adjacent bundle trust
store, so it cannot be the bootstrapping gate.

The optional verification script also opens a mutable pathname several times:
it inspects it at line 10, hashes it at line 28, and asks `gh` to reopen it at
line 36. A process able to write the download directory can swap ordinary files
between these operations; the script retains neither a stable handle nor a
protected staged identity tying the bytes it reports to the bytes later run.

### Impact

A state-level supply-chain, release-account, cache, mirror, download-directory,
or local race adversary can make a self-consistent replacement bundle install
and execute with the user's elevated installer authority. The outer GitHub
attestation substantially helps a user who independently runs the verifier in a
non-raced directory, and the ZIP installer has good reparse checks, protected
staging, post-copy hashing, and ACLs. Those controls prevent partial copying and
many local path attacks, but they do not establish who authorized the first
payload.

### Recommendation

Make authenticity a fail-closed precondition before any target write or payload
launch. Stage the selected setup/archive in an administrator-protected,
non-reparse location; verify one externally anchored publisher identity over
the exact staged artifact; and install only those exact bytes. Suitable anchors
include an Authenticode publisher/certificate policy or a bundled verifier with
an out-of-band embedded Ed25519 root. A GitHub attestation is acceptable only
when the trusted verifier and expected repository/workflow identity are pinned
and available. Bind the complete setup/archive or every installed executable
and evidence manifest. Apply rollback/version policy after cryptographic
authenticity, never use a root carried only inside the candidate bundle to
bootstrap first-install trust, and use stable handles/file identities through
verification and execution.

## R1-02 — The advertised two-signer release threshold has one CI failure domain

- **Severity:** MEDIUM
- **Component:** `.github/workflows/release.yml:136-168`;
  `tools/build_release_authorization.py:166-188`;
  `src/angerona/modules/release_transparency_guard.py:133-140`
- **Status:** OPEN

### Description

Both private signer seeds are exposed to the same GitHub Actions job and the
same invocation of a repository-controlled Python script. The build script
correctly rejects duplicate public keys, but it then derives both public keys,
creates both signatures, and writes the candidate trust store in that one
process. The workflow error calls these keys "independent," even though a
compromised runner, release workflow, or signing script obtains both at once.
The default runtime verifier then loads the trust store written beside the
executable rather than an out-of-band pinned root.

### Impact

The 2-of-N mathematics prevents one leaked key from satisfying the threshold,
but it does not protect against the more relevant compromised release job or
malicious workflow threat: that one failure domain sees both keys and can also
replace the public root consumed on first use. This is a supply-chain design
weakness, not an Ed25519 break.

### Recommendation

Place each signing key in a separate protected environment, HSM/KMS identity,
or independently approved signing job. Each job should receive only an exact
pre-hashed release statement and one signing capability; a later unprivileged
job may aggregate signatures. Pin the initial public root outside the candidate
bundle, and require a threshold signature from the old root for key rotation.
Change documentation and health text to avoid calling co-resident secrets
independent until the failure domains are actually separate.

## R1-03 — A consumed privileged capability is valid again after authority restart

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/response_capability.py:251-273,378-391`;
  `src/angerona/core/privileged_service.py:275-297`
- **Status:** FIXED

### Description

`ResponseCapabilityAuthority` resets its issued and consumed sequence counters
to zero in every constructor. Its `authority_id` is deterministic from the
long-lived HMAC secret, and replay rejection compares only with the in-memory
`_consumed_sequence`. A still-live token consumed by one authority instance is
therefore accepted by a new instance using the same secret and clock domain.

A benign deterministic fixture reproduced the issue:

```text
{'replay_after_restart_accepted': 1, 'new_consumed': 1}
```

The privileged-service lock correctly burns a capability before calling its
executor and keeps it burned on executor failure, but it cannot preserve that
property across process restart because the authority has no durable epoch or
high-water store.

### Impact

If this primitive is wired to network isolation, event-log export, driver
quarantine, audit append, or another closed opcode, a captured capability can
repeat its privileged operation after service restart while its TTL remains
valid. The primitive is not wired to a production listener/executor in the
current tree, so this is a pre-deployment design defect rather than a currently
reachable remote action path.

### Recommendation

Persist an authenticated, rollback-resistant consumed high-water mark in
privileged custody and bind every token to an unpredictable service/boot epoch.
Reject tokens from earlier epochs after restart. For state-actor resistance,
advance the epoch/high-water through an OS-protected transactional store plus a
TPM NV counter or separately administered witness; a replaceable same-host HMAC
file alone does not resist snapshot rollback. Add consume/restart/replay and
clock-domain restart regressions before wiring an executor.

## R1-04 — The production Sentinel CLI cannot give the monitored host verifier-only receipt authority

- **Severity:** MEDIUM
- **Component:** `tools/personal_sentinel_server.py:127-143,256-294`;
  `src/angerona/core/personal_sentinel_authority.py:180-197,200-272,949-980`
- **Status:** FIXED

### Description

Production mode now requires separate HMAC keys for client requests and
authority responses/state, which is an improvement over one shared key.
However, HMAC verification is symmetric: a monitored host that verifies an
authority receipt must possess the same response key that signs it and can
therefore manufacture authority responses and signed state locally. Core
Ed25519 signer/public-verifier classes exist, but the bundled server CLI exposes
only HMAC key-file options and constructs an HMAC response signer/verifier.

### Impact

A compromised monitored host can forge evidence that appears to have been
signed by the separate Personal Sentinel, weakening the claimed independent
custody of time, high-water, and clone/fork receipts. TLS, certificate pinning,
separate request and response keys, and optional mTLS protect transport and
client authentication; they do not turn a symmetric response verifier into a
verification-only credential. The client is not automatically injected into
runtime guards yet, which limits present exploitability.

### Recommendation

Make production provisioning asymmetric: the appliance holds an Ed25519
response/state private key; the monitored host holds only its pinned public
verifier. Give the client a distinct request private key and the appliance only
that client's public verifier, preferably with mTLS identity as an additional
layer. Expose these separate key roles in the server/client configuration and
reserve HMAC response mode for conspicuously labelled loopback tests or
migration, never independent-assurance claims.

## R1-05 — Sentinel state signatures do not prevent snapshot rollback or cross-process forks

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/personal_sentinel_authority.py:554-555,575-668,745-801`
- **Status:** FIXED

### Description

The authority validates a bounded signature over its state, but it has no
monotonic value outside that same state file. Restoring an older correctly
signed snapshot passes `_load_state()` after restart; `_initialized` is only an
in-memory missing-file guard. The state is saved by replacing one file.

Serialization is protected only by `threading.RLock`, so two server processes
can both load the same head, accept different successors, and return two signed
responses before last-writer-wins replacement discards one branch. Per-process
CAS, nonce replay history, strict schemas, fsync, and protected production path
checks are meaningful controls, but none provides an interprocess transaction
or an external rollback floor.

### Impact

An operator error, appliance-local adversary, restored VM/disk snapshot, or
duplicate service instance can erase accepted high-water transitions or create
equivocating signed histories. That undermines the central reason to move audit,
network, clone, and recovery freshness off the monitored host.

### Recommendation

Enforce one authority instance with an OS-level exclusive lease, and perform
load/compare/update under an interprocess file lock or transactional database
CAS that checks generation and file identity. Anchor the generation in a TPM NV
monotonic counter, WORM/append-only remote log, or second independently
administered witness so restoring an old signed file is detectable. Persist a
client-observed high-water as an additional alarm, and add two-process fork and
old-snapshot restart tests.

## R1-06 — TLS handshakes can block the Sentinel server's accept loop before worker limits apply

- **Severity:** MEDIUM
- **Component:** `tools/personal_sentinel_server.py:102-124,164-166,298-309`
- **Status:** FIXED

### Description

The server correctly bounds its request queue and worker count and sets a
ten-second timeout in the HTTP handler. In production, however, it replaces the
listening socket with `SSLContext.wrap_socket(..., server_side=True)` using the
default `do_handshake_on_connect=True`. Python's `SSLSocket.accept()` wraps and
handshakes the accepted socket before `ThreadingHTTPServer` dispatches it to
`process_request()`. The handler timeout and worker semaphore therefore do not
cover a client that opens TCP and stalls during the TLS handshake.

### Impact

One unauthenticated peer able to reach the private bind can hold the main accept
loop and deny time/CAS service to every legitimate client. Independent
high-water consumers are expected to fail closed when the authority is
unavailable, so this becomes a low-cost availability attack against protective
operations. Private-address-only bind and optional mTLS narrow reachability,
but mTLS is not required by default and the stall occurs before application
authentication.

### Recommendation

Accept raw sockets, set a short pre-authentication timeout, and perform the TLS
handshake inside a bounded worker or nonblocking event loop. Bound concurrent
handshakes separately from authenticated request workers, limit connections per
source, and prefer mandatory mTLS in production enrollment. Add a regression
where one client sends no TLS ClientHello while a second enrolled client still
receives service within its deadline.

## R1-07 — Trusted-time appraisal accepts a captured receipt without challenge or durable sequence continuity

- **Severity:** LOW
- **Component:** `src/angerona/core/trusted_time.py:99-190`;
  `src/angerona/core/personal_sentinel_authority.py:980,987-1054`
- **Status:** FIXED

### Description

`assess_trusted_time()` verifies receipt signature and static installation/client
identities, but it accepts no expected request challenge and no prior/persisted
authority sequence floor. Receipt freshness is judged solely against the
current host wall clock. A captured signed receipt can therefore be accepted
after restart if the host clock is rolled back into that receipt's window.

The live authority client does bind a fresh nonce to each response and enforces
an in-memory response sequence. Those controls prevent ordinary live network
replay within one client lifetime. They do not follow a detached receipt into
the appraisal API, and `_last_sequence` resets to zero with each client object.

### Impact

A caller may label time `externally-witnessed` based on old evidence after host
clock rollback/restart. No current production guard consumes this API for
response authorization, so the defect is Low and pre-deployment rather than a
current action bypass.

### Recommendation

Appraise only a receipt obtained for the current unpredictable challenge, and
persist an authenticated client-side sequence/time floor with external or
hardware rollback detection. Compare witness time with monotonic elapsed time
across a known boot epoch; treat mutable wall time as evidence, not the sole
freshness oracle. Keep detached/unbound receipts explicitly historical.

## R1-08 — Recovery assurance can report healthy for mixed revisions and future-dated evidence

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/recovery_assurance.py:93-126,228-309`;
  `src/angerona/modules/immutable_recovery_guard.py:105-147`
- **Status:** OPEN

### Description

Freshness tests subtract each signed timestamp from `now` but do not reject
future timestamps; negative ages therefore pass every maximum-age test. The
assessment then counts copies, failure domains, signers, immutability, offline,
offsite, separate identity, and expected source revision independently across
the entire set. It requires only any one current copy to name the expected
revision. It does not form a cohort by source revision plus archive/manifest
digest before satisfying the quorum.

A benign fixture with three different revisions, all timestamps in the future,
only one expected-revision copy, one immutable/separate-identity old copy, and
one offline/offsite old copy returned:

```text
{'healthy': True, 'findings': (), 'verified_copies': 3, 'current_revision': True}
```

All statements were structurally valid `VerifiedRecoveryCopy` objects; no
signature check was bypassed.

### Impact

The dashboard can present recovery readiness even though no single current
backup generation has the required 3-2-1/offline/immutable posture. During
ransomware or destructive state-actor recovery, the expected revision may exist
only in an online writable copy while the properties making the overall set
look healthy belong to unrelated older archives. External Ed25519 trust and the
observe-only/no-restore boundary remain intact.

### Recommendation

Reject timestamps beyond a small explicit future-skew allowance. Partition
evidence into exact cohorts keyed by source revision, archive digest, manifest
digest, and size/backup-set identity, then satisfy copy/domain/signer/restore
quorums inside one expected-revision cohort. Express immutable, offline,
offsite, encrypted, and separate-identity requirements as per-copy or
policy-defined quorum predicates rather than independent `any()` checks. Bind
restore-test evidence to the exact archive/manifest digest it exercised.

## R1-09 — The driver collector silently truncates at 256 and reports complete coverage

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/driver_provenance_guard.py:261-320,351-441`
- **Status:** FIXED

### Description

The Windows query sorts running `Win32_SystemDriver` services by attacker-
influenceable service name and applies `Select-Object -First 256` before
serialization. Python accepts any returned list of at most 256 rows and returns
`DriverCollection(..., complete=True)` with no total count or overflow marker.
On a host with more than 256 running driver services, omitted drivers are
therefore invisible rather than an explicit coverage gap. A driver service can
be named to sort after the retained set.

The query also hashes and Authenticode-checks the current pathname, not the
already loaded kernel image identity. Its before/after length and write-time
check catches some races but does not retain a file handle or bind the bytes to
the kernel module that was loaded. Nonmatches against the small bundled name
list correctly remain `unknown`, which prevents false blocklist-cleared status
for visible rows.

### Impact

On sufficiently driver-heavy systems an adversary can place a malicious or
BYOVD service outside the retained prefix and receive no per-driver assessment
or incomplete-coverage event. The host used during development had 194 visible
drivers, so this is conditional rather than universal, but the failure mode is
silent exactly where coverage exceeds the bound.

### Recommendation

Query the total before truncation and mark the collection incomplete whenever
it exceeds the bound; preferably paginate all running drivers under an overall
time/byte budget. Use a trusted kernel loaded-module inventory and bind service,
module base/load epoch, canonical path, file ID, and a stable open-file digest
so on-disk evidence cannot be confused with loaded bytes. Add a >256 regression
with a high-sorting malicious fixture, and consume a signed Microsoft/local
hash policy feed while preserving `unknown` for incomplete policy coverage.

## R1-10 — Temporal and identity analytics promote EventBus integrity into producer provenance

- **Severity:** LOW
- **Component:** `src/angerona/core/eventbus.py:8-23,241-265`;
  `src/angerona/modules/temporal_tradecraft_correlator.py:169-224`;
  `src/angerona/core/temporal_tradecraft.py:96-121,327-347,690-729`;
  `src/angerona/modules/identity_session_guard.py:157-204`
- **Status:** FIXED

### Description

The EventBus explicitly documents that its HMAC protects stored event bytes,
not in-process producer identity; when unarmed, `verify()` also returns true.
Nevertheless, the new temporal and identity consumers call only
`EventBus.verify()` and label accepted evidence `authenticated-bus`. Temporal
classification trusts caller-selected finding codes/classifications and can
construct High/Critical SSH-path-log-clear campaigns. Identity accepts any bus
event carrying an `identity_session_evidence` mapping. Neither consumer binds
the event to a broker-assigned sensor identity, fixed producer/schema allowlist,
or `SensorProvenanceBroker` sequence/loss record.

### Impact

An admitted or compromised in-process module can manufacture campaign chains
or identity anomalies that look authenticated, poison bounded analytic state,
and create alert fatigue. Both consumers remain observe-only and set
`response_authorized=False`, so this does not itself grant a privileged action.
The required in-process foothold overlaps the already documented A-04 residual,
which keeps severity Low; the new weakness is the evidence-grade promotion.

### Recommendation

Admit analytic evidence only through immutable broker-assigned producer IDs and
per-sensor keys/sequences/loss counters. Define a fixed producer-to-event-schema
allowlist and use EventBus HMAC only as downstream storage integrity. Downgrade
unprovenanced data to local/untrusted, never call it authenticated producer
evidence, and require independent source domains before escalating a campaign.

## R1-11 — Several Cycle 24 foundations are not runtime enforcement yet

- **Severity:** INFO
- **Component:** `src/angerona/core/sensor_provenance.py:1-12`;
  `src/angerona/core/privileged_service.py:1-7`;
  `src/angerona/modules/process_egress_guard.py:1-5,39-68,96-127`;
  `src/angerona/modules/rag_provenance_guard.py:1,24-39,73-81,185-198`;
  `src/angerona/core/personal_sentinel_authority.py:946-1055`
- **Status:** OPEN

### Description

Repository-wide reference searches found no production construction/wiring of
`SensorProvenanceBroker`, `ResponseCapabilityAuthority` plus
`PrivilegedService`, or `PersonalSentinelAuthorityClient` outside their own
contracts/self-tests. The process-egress module defaults to
`broker-audit-not-connected`, explicitly performs no enforcement, and has no
privileged connection-admission adapter. The RAG provenance guard explicitly
validates only future/inert sources and does not register or mutate the actual
retrieval index. Default platform posture is OS-reported and does not claim a
TPM quote. These are honest, fail-visible boundaries in code, not exploitable
bugs in the primitives.

### Impact

Documentation or release promotion that counts these foundations as deployed
state-actor enforcement would create a dangerous assurance gap. In particular,
the system does not yet use broker provenance to cure R1-10, does not make
privileged actions capability-only, does not force application traffic through
process-bound egress leases, and does not obtain independent Sentinel freshness
for audit/network/release/platform state.

### Recommendation

Keep these capabilities labelled prototype/observe-only until app/module-manager
dependency injection, protected key custody, transport, lifecycle, health, and
end-to-end fail-closed tests are present. Wire one narrow feature at a time;
surface `unconfigured`/`external-enforcer-required` prominently; and never
silently fall back to legacy direct privileged actions or unrestricted sockets.
RAG sources should enter retrieval only through the validated inert bundle
contract, with provenance/taint retained through every answer.

## During-review remediation verified (not open)

The initial review found that the Windows peripheral probe invoked bare
`powershell.exe`, permitting current-directory/PATH redirection under Angerona's
token. This was corrected before this report was finalized:
`src/angerona/core/peripheral_posture.py:287-298,338-347` now resolves only
`trusted_powershell_path().resolve(strict=True)` and fails to unknown with no
PATH fallback. `tests/test_peripheral_dma_guard.py:25-48` asserts the exact
trusted argv[0]. This item is intentionally excluded from the open JSON list and
severity totals. The broader prior A-06 `ExecutionPolicy Bypass` residual still
exists elsewhere.

## Controls reviewed without a new defect

- RAG provenance uses strict bounded JSON, root confinement, reparse rejection,
  stable open/read checks, digest binding, optional publisher verification, and
  inert data-only taint. It is not yet an index-ingestion control, as documented.
- Measured boot never manufactures a TPM quote. Hardware attestation remains
  false unless a supplied verifier validates the nonce, enrolled key, PCRs, and
  policy; OS posture is labelled user-mode/OS-only.
- Process-egress leases bind process start, executable digest, user, DNS/IP,
  port, protocol, byte/connection budgets, path token, gateway posture, and
  clock continuity, and fail closed on missing observers. The missing privileged
  adapter is recorded as R1-11, not mischaracterized as a broker bypass.
- The privilege-service contract has no listener, shell, dynamic import, or
  general argv surface. Its concrete replay defect is R1-03.
- Peripheral DMA/IOMMU values that the bounded Windows collector cannot prove
  remain `unknown`; no active-IOMMU or hardware-enforcement claim was found.

## Prior-status accounting

| Prior set | Resolved/mitigated and verified from the retained record/current checks | Still open or deferred |
|---|---:|---:|
| Cycle 23 findings | 15 | 1 (`C23-R2-01`, external monotonic custody/deployment) |
| Explicit older findings | 5 (`A-01`, `A-02`, `A-03`, `A-05`, `A-07`) | 3 (`A-04`, `A-06`, `R6-03`) |
| **Total prior** | **20** | **4** |

The new Personal Sentinel server is meaningful progress toward C23-R2-01, but
R1-04 through R1-07 and absent runtime injection mean the independent-custody
dependency is not yet closed. No regression was found in the retained A-01,
A-02, A-03, A-05, or A-07 mitigations. A-04, A-06, and R6-03 remain unchanged
architectural/defense-in-depth residuals and are not duplicated as new findings.
