# Cycle 23 Round 2 — Red-Team Findings

Date: 2026-08-26  
Scope: the Cycle 23 Round 1 remediations and performance changes for event-log
continuity, SSH posture/runtime evidence, zero-trust network paths, Personal
Sentinel Gateway, live activity, Defense Memory/ARIA, and their observe-only
integration. This was an actor-neutral defensive audit. No web research was
performed, no product/test/configuration/asset file was changed, and no live
event log, route, network, firewall, SSH service, or host control was mutated.

## Outcome

Six new weaknesses were confirmed: two Medium and four Low. There is no new
Critical or High finding, remote entry point, code-execution path, credential
exposure, or response-authority bypass. The highest-value item is the
independently reproduced paired-state rollback reported by Round 1 QA: HMAC
authenticates origin and integrity but cannot prove that a mutually consistent
cursor/epoch pair is the newest pair ever accepted.

| Severity | New findings |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 2 |
| Low | 4 |
| Info | 0 |

Controlled in-memory or temporary-state probes reproduced all six conditions.
A focused regression gate covering quiescent checkpoint verification, lazy SSH
client command-line collection, forged-label stripping, competing/dual-stack
route rejection, and post-attestation route revalidation passed **5/5**.

## R2-01 — Matching authenticated state pairs can be rolled back after a newer revision

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/event_log_integrity.py:324-379,507-540,575-684`;
  `src/angerona/core/network_trust.py:892-920,1076-1180`;
  `src/angerona/core/personal_sentinel_gateway.py:478-496,862-1036`
- **Status:** OPEN

### Description

`AuthenticatedEventLogCheckpoint` and `NetworkTrustBaselineStore` each keep a
cursor/baseline and a separately keyed enrollment document. Both members carry
the same enrollment ID and revision, both signatures are checked, and an
in-process save compares the exact bytes admitted by the preceding load. These
controls reject a missing member, a forged member, a mixed-revision pair, and a
stale writer.

They do not retain the latest accepted revision outside the same two replayable
files and process memory. A controlled probe saved one valid pair, advanced it
to a newer revision, restored both older members byte-for-byte, and constructed
a new store instance. The event store returned `authenticated` with the older
revision/checkpoint, and the network store returned `trusted` with the older
revision/baseline. No HMAC forgery was needed. This independently reproduces
QA-R1-01.

The Personal Sentinel client contains a privacy-preserving witness submission
primitive, but neither state store uses it. Its current receipt hash is an
unkeyed canonical hash of client-known values; the live TLS/pin/nonce/freshness
checks authenticate the exchange, but the repository does not define or query
a server-enforced per-installation high-water head. Therefore it is not yet an
independent anti-rollback authority.

### Impact and limits

An offline actor who can stop Angerona and replace **both** protected documents
can make an older network baseline look current and can move the audit cursor
back to an older authenticated state. Newer retained event rows will ordinarily
be replayed, and anchor/generation checks may still expose an intervening clear;
this finding does not by itself prove silent erasure of all audit evidence.
Likewise, it does not grant response authority or break the HMAC keys.

The precondition is strong local custody over both state paths, so Medium is
appropriate for the intended elevated single-host deployment. Administrator or
SYSTEM can also stop sensors, deny witness connectivity, tamper below user mode,
or destroy availability; no local high-water design should claim to make those
principals harmless.

### Independent high-water design assessment

| Design | Defensive value | Important limit |
|---|---|---|
| A third local HMAC/DPAPI/ACL/registry file | Detects accidental corruption or a one-file edit | It is replayable under the same host custody and does not solve paired rollback. Local Event Log/USN evidence has the same administrative-custody problem. |
| Off-host append-only witness | Best fit when it has a genuinely separate administrative/physical trust domain and enforces monotonic compare-and-swap | Availability becomes an explicit policy choice. A router administered by the same compromised principal is not independent custody. |
| TPM NV monotonic/high-water state | Can make ordinary filesystem rollback detectable without network availability | TPM clearing, authorization policy, cloning/migration, firmware/boot assumptions, wear, and denial of service remain. Incrementing it on every poll is not practical. |
| Hybrid local hash chain plus periodic external/TPM head | Reduces witness writes while bounding the rollback window | Offline/provisional behavior, crash ordering, and recovery must be explicit and fail visible. |

### Recommendation

Use separate audit and network witness domains. Bind at least
`(schema, installation/enrollment ID, domain, revision, state digest,
previous-head/receipt)` to a server-enforced monotonic namespace authenticated
with a device identity (preferably mTLS), and return either a server signature
or a head that is authenticated again through a live query. On load, compare
the local pair to that independent head and reject a behind or conflicting
pair. The server must reject duplicate/forked revisions rather than merely echo
the supplied sequence.

For an offline-capable deployment, hash-chain local transitions and checkpoint
the chain head periodically to the witness or a policy-bound TPM NV value.
Treat unwitnessed state as bounded and provisional; never silently promote it
to current. Define two-phase/crash recovery, backup restore, device clone,
re-enrollment, TPM clear, witness loss, and legacy migration behavior before
enforcement. An older valid local pair should enter recovery/provisional state,
not be declared fresh. Document that this detects rollback under stated trust
assumptions; it does not prevent Administrator/SYSTEM denial, kernel/firmware
tampering, or destruction of the external authority.

## R2-02 — Per-user SSH sources are resolved against the config directory and replacement custody is incomplete

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/ssh_surface.py:946-1006,1028-1046,1204-1315,1318-1382,1504-1585`;
  `src/angerona/modules/ssh_surface_guard.py:296-330,530-591`
- **Status:** OPEN

### Description

OpenSSH gives relative `AuthorizedKeysFile` and
`AuthorizedPrincipalsFile` values per-user home semantics. The new configured-
source collector instead sends every relative value to `_static_ssh_path()`
with the directory containing the applicable `sshd_config` as `base`. For
example, `.ssh/custom_keys` under a Windows root config is observed as
`C:\ProgramData\ssh\.ssh\custom_keys`, while sshd resolves it for Alice under
`C:\Users\Alice\.ssh\custom_keys`. The incorrect ProgramData path is recorded
as `missing`; the actual custom file is absent from both configured-source
digests and key candidates. Default enumeration only covers conventional
`.ssh\authorized_keys` paths, so it does not close the custom-name gap.

Values containing `%`, `$`, or `~` are conservatively labeled `unresolved`,
which is fail visible. The silent error is the common plain relative form. A
controlled path-resolution probe reproduced the ProgramData/custom-user
divergence.

Windows custody also verifies only the target file's owner and DACL. It does
not verify the parent chain or account for a non-trusted principal's
`FILE_DELETE_CHILD`/rename/replacement rights on a parent. A file can therefore
be labeled `verified` even when its directory custody permits replacement.
Stable no-follow reads prevent an in-flight path swap, but do not make that
custody label accurate after the read.

### Impact and limits

A principal able to write the real configured per-user source, or replace a
nominally protected file through a writable parent, can add/change SSH
authorization material without the intended source/key drift. The static
configuration does not have to change. This requires local write/replacement
rights and does not create those rights. Runtime process/socket drift and
OpenSSH authentication logs remain independent chances to detect subsequent
use, so this is Medium rather than High.

### Existing controls that held

The Include graph is root-confined, byte/file/depth bounded, stable-read, and
aggregate hashed. Absolute configured files, default key locations, CA files,
and command-backed source declarations are represented; dynamic paths are
reported unresolved; source evidence stores keyed tokens/digests rather than
raw paths or key text; and the authenticated baseline detects correctly
resolved changes. The weakness is effective per-user path semantics and full
replacement custody, not arbitrary path traversal.

### Recommendation

Resolve only the directives that OpenSSH defines as per-user sources with the
correct bounded token grammar (`%%`, `%h`, `%u`, `%U`) and plain-relative-home
semantics for each admitted local account. Keep server-global directives such
as trusted CA paths under their own documented semantics. Enforce user/file
bounds, Match/effective-configuration context, root confinement, stable
non-reparse admission, and an explicit incomplete state when account expansion
cannot be proven. Distinguish `unresolved`, `not applicable`, and genuinely
`missing`; do not emit a false `missing` source for another path.

For Windows custody, validate the target plus every relevant parent back to a
trusted root, including owner, inheritance, write/delete/rename and
`FILE_DELETE_CHILD` replacement rights. Make expected ownership policy
user-aware for per-user files and administrative for shared files. Include the
normalized full-chain custody result in the authenticated baseline.

## R2-03 — The 64-interface collector cap can hide a standby route while completeness remains asserted

- **Severity:** LOW
- **Component:** `src/angerona/modules/network_trust_monitor.py:351-387,520-603,685-836`
- **Status:** OPEN

### Description

`observe_system_network()` iterates `sorted(addresses)[:64]` before filtering
down/loopback/virtual links and never records that additional interfaces were
omitted. It still advertises `interfaces`, `routes-ipv4`, and `routes-ipv6` as
complete when their individual collectors succeeded. `_selected_route_context`
can therefore reason over a truncated link set and require exactly one route
per family without knowing that another interface was dropped.

A controlled snapshot probe returned an accepted selected-route context when
only the retained Wi-Fi route was present. Adding one higher-metric standby
Ethernet route made the same function correctly return `None`. The live
collector can create the first view when the standby interface sorts beyond
the 64-name cap. This is distinct from the per-link 16-route cap: retaining 16
routes still leaves multiple candidates and fails closed; the interface cap
can omit the entire competing link.

### Impact and limits

A highly privileged local actor able to create/rename enough active adapters
and a standby physical egress route can suppress that competitor from the
attestation context, allowing a positive gateway label that the complete view
would reject. It requires an unusually large adapter set and route-management
authority. Endpoint resources remain untrusted, all responses remain
observe-only, and a lower-metric omitted competitor usually causes the retained
route's selected bit to fail rather than pass. The practical issue is a hidden
higher-metric/failover path, so Low is appropriate.

### Recommendation

Detect interface overflow before slicing or filtering. Carry explicit
`interfaces-overflow`, rejected-row, and per-family route/link completeness
state into `NetworkSnapshot` and each affected link. Never issue
`gateway-attested` when any active interface or default-route candidate was
omitted, even if the retained route is selected. Prefer bounded semantic
selection that retains all default-route-bearing links first, but still fail
closed and report overflow rather than treating a sampled inventory as
complete. Apply the same rule to the post-exchange observer.

## R2-04 — A transient Windows OpenSSH source-open failure is never retried

- **Severity:** LOW
- **Component:** `src/angerona/modules/ssh_surface_guard.py:202,336-406,452-487`
- **Status:** OPEN

### Description

`_collect_windows_event_lines()` adds each OpenSSH channel to
`_windows_event_attempted` **before** calling its source factory. If opening the
channel raises once, the channel is marked unavailable but remains attempted;
later polls skip the factory and find no source. An in-memory factory that
always raised was called once per channel across two polls, proving that the
module cannot recover without reconstruction/restart. In contrast, query
failures after a source exists are retried on subsequent polls.

### Impact and limits

A transient startup access/WEVT/channel condition—or an actor able to create
one during module startup—can turn brief failure into persistent OpenSSH
authentication-log blindness. The sensor emits an unavailable coverage issue
on every poll and health does not claim complete coverage; static config/key,
process, socket, and optional text-log evidence remain active. This is
fail-visible degradation, not a silent bypass, so Low is appropriate.

### Recommendation

Replace the attempted set with a bounded source lifecycle state machine. Retry
open failures with capped exponential backoff and jitter, expose last failure
and next retry as non-sensitive health, and emit a recovery transition after a
successful reopen. After repeated query failures, close the stale source and
re-enter the same bounded reopen path. Initialize from the existing bounded
tail and preserve explicit history-bounded state; do not hot-loop or imply that
unobserved history was recovered.

## R2-05 — SSH forwarding option normalization misses real tunnels and creates false High alerts

- **Severity:** LOW
- **Component:** `src/angerona/core/ssh_surface.py:1692-1716,1930-2028`;
  `src/angerona/modules/ssh_surface_guard.py:659-682`
- **Status:** OPEN

### Description

`_normalized_forwarding_flags()` recognizes direct `-L`, `-R`, `-D`, `-w`,
and `-W` arguments, but it examines each argument independently. The common
split form `ssh -o RemoteForward=... host` produces no forwarding flag because
`-o` contains no marker and the following option value does not start with
`-`. Forwarding declared through a `-F` client configuration is also not
represented or marked as unknown.

For `L`, `R`, and `D`, the function additionally treats the uppercase marker
appearing anywhere in any hyphen-prefixed argument as a combined short option.
The controlled probe produced `('dynamic-forward', 'local-forward')` for the
unrelated `-oLogLevel=DEBUG`, while the split `RemoteForward` form produced an
empty tuple. These results feed a dedicated High forwarding event, so the bug
causes both missed classification and noisy false positives.

### Impact and limits

A tunnel launched with a missed option form loses the specific High-confidence
forwarding signal, and benign SSH options can generate one falsely. A newly
started SSH client and its tokenized connections still change the authenticated
runtime baseline and produce a generic High drift event; OpenSSH log patterns
may also identify forwarding. This is detection fidelity/triage degradation,
not complete process invisibility, so Low is appropriate.

### Recommendation

Parse a strict, bounded subset of the SSH client option grammar with explicit
argument consumption. Recognize the direct short forms and the supported
`-oName=Value`, `-o Name=Value`, and single-argument `-o "Name Value"` forms
for `LocalForward`, `RemoteForward`, `DynamicForward`, and `Tunnel`. Do not use
substring matching. Treat `-F` as `client-config-uninspected` unless a separate
root-confined, stable, bounded and privacy-reviewed parser is implemented.
Retain only normalized labels and completeness state—never raw endpoints,
commands, or configuration contents.

## R2-06 — Audit XML classification accepts foreign providers and attacker-shaped field keys

- **Severity:** LOW
- **Component:** `src/angerona/core/windows_event_log.py:32-55,90-117`;
  `src/angerona/core/event_log_integrity.py:143-164,206-266`;
  `src/angerona/modules/audit_log_guard.py:148-166,296-331`
- **Status:** OPEN

### Description

The fixed live source constrains the channel and Event IDs, but its XPath does
not constrain provider. `parse_audit_integrity_xml()` extracts the XML provider
without validating it, never compares the XML `<Channel>` element to the fixed
caller channel, and classifies solely by `(caller_channel, event_id)`. A
synthetic `ForeignProvider` event whose XML channel said `Application` was
accepted as a Critical System event-log clear when the caller supplied
`System` and event ID 104.

Unexpected EventData **values** are redacted, but attacker/provider-controlled
field names remain dictionary keys. More importantly, values under generic
allowlisted names such as `Status`, `State`, or `Channel` are preserved before
the provider schema is authenticated. The same probe retained a path-like
`Status` value in `admitted_fields`; the module publishes provider and the
whole field mapping to the EventBus.

### Impact and limits

A local principal able to register/write a colliding provider event into a
protected channel can create false high/critical audit-integrity alerts and
place bounded attacker-shaped metadata into local event details. This requires
substantial Windows event-provider/channel write privilege. The foreign
provider remains visible, raw XML is omitted, unknown values are redacted, XML
and field counts are bounded, continuity anchors still advance, and the guard
is observe-only. It is therefore Low, not an event-log erasure or response
authorization bypass.

### Recommendation

Define and test authoritative `(channel, provider, event ID)` admission sets,
including any legitimate version/provider variants. Require the XML channel to
match the fixed source channel and reject mismatched providers before typed
field extraction. Map only per-event allowlisted inputs to fixed Angerona-owned
output keys; never use XML names as EventBus dictionary keys, and apply privacy
redaction to every retained value. Advance past rejected, parseable record IDs
through the existing bounded checkpoint flow while emitting a bounded
provider/schema-rejected coverage signal so a hostile row cannot create an
infinite replay loop.

## Regression and control accounting

The exact Round 1 behaviors reported as fixed remain fixed in this review:

- Event-log first enrollment replays retained evidence, missing/tampered
  members fail closed, staged records survive neither late nor post-commit
  generation races, stable handles reject reparse/path swaps, and the
  quiescent performance path still re-reads both authenticated files before
  accepting no change.
- SSH Include traversal remains root-confined and bounded, aggregate digests
  and configured-source evidence remain private/authenticated, the fixed
  OpenSSH XML parser validates provider/channel/Event ID, non-service server and
  client processes/sockets remain observed, and the lazy command-line change
  still queries only admitted SSH clients.
- Network incomplete telemetry cannot enroll/promote/advance the baseline;
  lower-metric, retained standby, ambiguous, and IPv6 competitors prevent a
  positive label; interface index/epoch/family/gateway/metric are revalidated
  after attestation; forged collector labels are stripped; and the immutable
  fast path still scans every retained link/route.
- Gateway transport remains explicit-enrollment, private/loopback HTTPS only,
  TLS/hostname/pin/peer/nonce/freshness/schema/size checked, no-proxy and
  no-redirect. It does not make endpoint resources trusted or authorize a host
  response.
- Live activity remains bounded and never reads `Event.details` or model
  chain-of-thought. Defense Memory remains digest-pinned, strict-schema,
  root-confined, stable-read and process-cached. Only the dedicated Defense
  Memory reference is eligible for ARIA cloud fallback; live environment,
  operator/model-pack context stays local.
- No new `exec`/`eval`, unsafe deserialization, `shell=True`, interpolated OS
  command, disabled TLS verification, unbounded queue/cache, or response-
  authority path was found in the Cycle 23 surfaces. Fixed inventory commands
  use argv arrays, bounded in-flight output, timeout and termination handling.

The five focused regression tests passed. The six findings above are edge
conditions beyond those fixed behaviors; they do not erase the credit for the
Round 1 controls that held.

## Prior-status accounting

- **Round 1 red-team findings:** 9 exact reported behaviors verified resolved,
  0 reopened. R2-02 is a new effective-path/replacement-custody boundary beyond
  the earlier tested R1-03 repair, not a claim that Include aggregation was
  reverted.
- **Round 1 QA residual:** QA-R1-01 remains open and is now tracked as R2-01.
- **Older architectural residuals:** A-04 (drop-in module trust), A-06 (broad
  PowerShell policy), and cosmetic A-07 remain open by prior disposition and
  were not relabeled as Cycle 23 findings.

