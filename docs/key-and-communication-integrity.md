# Key and communication integrity

This maintenance review covers credential concurrency, scanner-ring key custody,
key migration, memory identity and truthful encryption status. Angerona remains
in development at v1.14.0; broader v1.15 integration is incomplete. Consult the
[current scoped evidence](../analysis/live-debug-2026-10-22/README.md) and the
[historical key/memory review](../analysis/live-debug-2026-10-22/key-and-memory-review.md)
for their separate validation states.

## Model manifest and approved-baseline parser integrity

Manifest, inventory and approved-baseline readers now translate the relevant
integer-limit ValueError, deeply nested JSON RecursionError and numeric
OverflowError paths into their existing typed integrity refusal. Three
exception tuples change; the hash, HMAC, explicit approval, baseline byte
preservation and inference-blocking contracts do not. Malformed evidence does
not authorize a new baseline or replacement key.

The original source passed 60 and failed 23 of 83 controlled cases; the corrected
source passed all 83 with zero errors/skips. The deep-input fixture uses a bounded
probe against the real JSON decoder, rather than an assumed recursion depth.
An earlier 74-pass/nine-fail candidate run is retained as rejected fixture
evidence. Fresh integration passed 1258 of 1263 cases with five unchanged native
availability skips; default selfcheck passed 29 phases with 18 module skips.
These checks resolve the scoped SEC-20 normalization gap, not a demonstrated
HMAC bypass, universal parser-exhaustion defense or administrator/kernel boundary.

A real private AI Model Integrity Guard worker completed its first check during
30.062 seconds of observation. The absent approved baseline remained
approval-required, with health 25 and a verified signed MEDIUM availability
event. No baseline was enrolled, default key handling and normal cadence stayed
in place, and two health/interval availability gaps remained explicit. The
outcome is OBSERVED_WITH_GAPS, not healthy attestation or a host-model verdict.
Review notes and valid event signatures confer no approval or response authority.
See the [current scoped evidence](../analysis/live-debug-2026-10-22/README.md).

## Credential creation and updates

Protected credentials share a serialized transaction for their actual backing
store. A same-process reentrant lock and an exclusive OS file lease cover the
read, modification, protected write and readback. Thread admission has a
one-second budget. Contention is an explicit refusal; callers must retry rather
than save a stale map or fall back to plaintext. An admitted OS backend operation
can still take longer than that admission budget.

Atomic first creation generates a candidate only while holding this transaction.
Existing empty or malformed values are errors for the consumer to validate;
they do not authorize replacement. Seven consumers use this creation path:
SOC master, Device Security Lab authority, UGCAP witness host identity,
Independent Recovery drill, local Fleet bundle, IPC authentication and
SpywareGuard archive keys. Legacy imports preserve an existing protected value.

On Windows, locking follows the canonical protected credential file and retains
the deployed data-root custody check. On macOS and Linux, lock selection uses
the OS account's home and service/account identity, independently of HOME, XDG
or a caller-selected data directory. Unsafe directory ancestry fails visibly.
POSIX fork handling prevents a child from retaining its parent's transaction
state or unlocking the parent's lease.

These are cooperative writer and custody protections. They do not exclude
malicious code in the same user process, defeat an administrator or compromised
kernel, prove independent freshness after a whole-host rollback, or guarantee
forensic erasure of Python key copies.

## Scanner IPC ring key custody

The scanner ring keeps its existing 32-byte authority in ipc_ring.key as hexadecimal
text. It is not newly encrypted by DPAPI or moved into a credential backend.
Initialization now uses the public protected-store transaction only for its
cooperative lock namespace; it does not read or write protected credentials.
On Windows this shares the data root's credential-file lease. On macOS/Linux it
uses the OS-account namespace and its existing safe-home prerequisites. Missing
or unsafe custody, an unavailable account home or a contended lease is an explicit
refusal. The one-second local admission budget does not bound all filesystem,
hardening or backend latency.

A loader admits at most 4096 bytes, opens and retains the file descriptor, and
requests the admitted size plus one byte. Named-path and held-file identity,
size and timestamps must stay stable through the read and final custody readback.
On Windows the cross-API comparison uses the available comparable birth-time
field; each API's own raw change time is still checked exactly. Links, reparse
points, malformed encodings, unexpected key length and changed objects refuse
admission. Existing valid 32-byte keys and supported hexadecimal whitespace
remain compatible; frame HMAC, AAD, sequence, schema and ring layout do not change.

Cooperating initialization uses two finite rounds, with bounded collision and
custody reclassification. It never replaces a malformed existing key merely to
recover availability. A failed or partial creation stays visible for explicit
recovery; cleanup does not unlink a name that might belong to a successor.
Stop the affected peers, preserve the failed artifact and diagnostic evidence,
and review custody under the existing recovery/authorization workflow before
retrying. Coordinate restarts when upgrading peers: older or uncooperating
callers do not participate in the new transaction. This is not exclusion of a
malicious same-user writer or a cross-process convergence guarantee.

The constructor also owns its acquired file and mapping through header setup;
on a tail failure it attempts to close both before propagating the original
error. Tests inspect actual closed flags before fixture fallback cleanup.
Cleanup-close failure injection, native POSIX home/lease behavior and elevated
Windows ACL enforcement were not demonstrated by this Windows checkpoint.
The two-mode property check's Linux namespace is a private model using the real
Windows lease, not a native Linux run.

At the preceding IPC checkpoint, scoped validation accepted 1175 passes and five
exact native availability skips across 43 suites/1180 cases. Separate staged negative controls and the
30.172-second raw process-telemetry observation are documented in the
[current evidence reference](../analysis/live-debug-2026-10-22/README.md).
Selfcheck's 29 phases passed with 18 module skips and IPC naturally unloaded;
selfcheck does not establish execution of the ring self-test. These results do
not prove field efficacy, a clean host, kernel resistance or complete telemetry.

## Remote Bridge migration

An explicitly configured strong hexadecimal ANGERONA_BRIDGE_KEY remains a
supported, separate configuration path. It must decode to at least 32 bytes.
Disabled or invalid Bridge mode does not read credentials or acquire a key lease.
For a configured mode without that explicit key, Bridge uses protected storage. A locked, damaged or unavailable
store does not authorize a plaintext fallback.

A legacy bridge.key file must pass strict identity, single-link, size and
before/after read checks. Migration participates in the protected transaction,
refuses a conflicting existing key, verifies protected readback, and removes the
unchanged legacy file before enabling Bridge. A cleanup failure holds Bridge;
fixed diagnostic codes omit key values and raw exception text. This migration
is not a new default remote listener or deployment of external trust.

A later 40-case diagnostic captured a separate Windows false-hold mode: 29
repetitions passed and 11 failed because CPython 3.12.10 reports named-path ctime
as creation time and descriptor ctime as change time. Device/inode/size/mtime
and birth agreed in the failed repetitions; the clocks called ctime did not.
The source repair compares Windows birth across those API views and separately
retains the complete descriptor before/after identity, including raw change time.
All named-path, custody, single-link, size, protected-store, readback and cleanup
refusals remain. This timestamp repair leaves secure-store code unchanged; the
broader key maintenance does change protected-store transactions. Original test
bytes remain an exact prefix, and 16 additional inert cases passed within the
accepted 32-suite cohort. Fresh SpywareGuard/scanner solos and a 600.531-second
15-module observation completed with their coverage gaps retained. Guarded GitHub
publication is a separate mandatory gate; test/observation receipts alone do not
prove publication. This later capture does not establish the original R4 exception cause,
and metadata checks do not provide a malicious-writer-proof unlink lease.

## Linux locked items and absent items

A failed secret-tool lookup is not sufficient evidence that a credential is
absent: an existing Secret Service item may be locked. Only the exact eligible
empty-not-found result proceeds to a separate, nonsecret metadata check. A
fixed gdbus SearchItems request must prove that both unlocked and locked result
arrays are empty. Missing gdbus, nonempty arrays, malformed output, abnormal
exit, unsupported custom/portal backends and uncertain results refuse new-key
creation. Successful existing-key lookups retain the selected backend.

First provisioning through this path requires GLib's gdbus tool and the default
native Secret Service backend. Metadata output is bounded to 2 KiB per stream
and five seconds; it does not retrieve secret values or pass them as arguments.
Inert tests on Windows do not establish native Linux Secret Service, macOS
Keychain or POSIX fork behavior on a physical supported platform.

## SGX and SQLCipher status

An SGX/Gramine environment variable or pseudo-file is a runtime hint. The UI
reports it in amber as unverified; neither the legacy active property nor
summary text establishes hardware attestation, an enclave measurement or a
protected flight-cache deployment.

The optional compatibility helper requires a nonempty SQLCipher version and a
successful schema query before reporting connection checks complete. Plain
SQLite silently ignores unknown PRAGMAs; that behavior cannot report encryption
success. Helper-key creation and singleton construction are separately locked.
The helper has no production flight-cache caller, does not migrate or prove an
encrypted database, and does not establish enclave key custody or memory erasure.

## Communication and response boundaries

The EventBus distinguishes archived HMAC integrity from the manager-issued live
module identity and generation. A valid historical signature is not current
response permission. Redacted Live Debug records and AI annotations are advisory
copies; authenticated originals and loss/coverage evidence remain authoritative.

The rotating Enclave Mesh uses fresh X25519 exchanges, Ed25519 signatures,
AES-GCM, epoch binding and replay state in its implemented paths. Its presence
as a library does not prove that every module message passes through it.
Python-level key disposal does not prove perfect memory erasure. See the
[UGCAP and Enclave Mesh boundary](ugcap-enclave-mesh.md).

The separately authenticated privileged response service remains diagnostic;
process-bound WFP enforcement is not deployed by this maintenance update.
A complete process/file identity lease across program-firewall mutation remains
open. A local authenticated journal cannot replace an independently administered
rollback witness or backup.

## Review discipline

Use independent source reviewers for generators, custody, transport consumers
and authority decisions. Validate a confirmed repair with adversarial failure
controls and fresh observations of the changed revision. Never print a live key,
read the credential store to populate a report, rotate a key to hide a test
failure, clear an alert to make a dashboard green, or replace a baseline without
its existing authorization. See [AI-aware defense](ai-aware-defense.md) and the
[live review workflow](live-debug-harness.md).
