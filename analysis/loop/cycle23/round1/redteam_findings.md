# Cycle 23 Round 1 — Red-Team Findings

Date: 2026-08-26  
Scope: the current dirty worktree, with emphasis on the Windows event-log
adapter and continuity guard, SSH Surface / Key / Tunnel Guard, zero-trust
network monitor, Personal Sentinel Gateway, live defense activity card, ARIA
Defense Memory and cloud-reference boundary, and their EventBus/ModuleManager
integration. This was an actor-neutral, defensive source audit. No product,
test, configuration, or asset file was changed and no host security control or
real event log was exercised.

## Outcome

Nine new findings were confirmed. None grants response authority, remote code
execution, or credential access. The most consequential weaknesses are
detection-continuity and coverage gaps: a capable local actor who can stop or
race the observer can cause some state changes to become a new trusted-looking
observation rather than drift evidence.

| Severity | New findings |
|---|---:|
| Critical | 0 |
| High | 0 |
| Medium | 5 |
| Low | 3 |
| Info | 1 |

Focused regression evidence remained green: `104 passed, 1 skipped` across
`test_event_log_integrity_guard.py`, `test_ssh_surface_guard.py`,
`test_network_trust.py`, `test_personal_sentinel_gateway.py`,
`test_live_defense_activity.py`, and `test_defense_memory.py`. The findings
below come from manually reviewed data flow and controlled fake-source probes
outside those happy-path cases.

## R1-01 — A missing checkpoint silently baselines past retained log-clear evidence

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/audit_log_guard.py:150-191,281-301`;
  `src/angerona/core/event_log_integrity.py:186-204,257-360`
- **Status:** OPEN

### Description

`assess_continuity()` treats `checkpoint is None` as a first authenticated
baseline and resumes at the channel's newest record. `_poll_channel()` then
anchors that record and returns without reading any retained records. There is
no authenticated installation/provisioning marker that distinguishes a genuine
first run from deletion of the checkpoint after Angerona has already operated.

The checkpoint store also checks `exists()`, `is_file()`, `stat()` and
`read_text()` as separate path operations and does not reject a link/reparse-
backed file or parent before loading/replacing it. Forged contents still fail
HMAC, but deletion, redirection to an old valid checkpoint, and path-swap denial
are not covered by the stronger file-admission pattern used by the SSH and
gateway stores.

A controlled in-memory source containing an already-retained Security event
1102 produced zero events, zero clear alerts, and health 100 on the first poll.
The same behavior occurs if the checkpoint is absent after an offline clear.
Thus the very explicit clear event the guard is designed to prioritize can be
skipped while it is still available locally.

### Impact

An actor with enough local access to stop the module and remove its checkpoint,
or one who clears logs before the first Angerona run, can make retained clear
evidence fall behind the new baseline. This does not let a remote network actor
tamper with the HMAC and it requires a strong local precondition, so it is not
rated High. It does undermine the independent evidence expected after log
clearing or agent suppression.

### Existing mitigations

Established checkpoints are purpose-keyed and HMAC authenticated. An invalid
checkpoint is treated as untrusted and replays retained evidence, established
record gaps are reported, raw XML is omitted from events, and the module is
observe-only. The weakness is specifically the unauthenticated distinction
between "never installed" and "checkpoint disappeared."

### Recommendation

Persist a separately authenticated installation/continuity epoch in protected
custody independent of the replaceable cursor file. After that epoch exists, a
missing channel checkpoint must be an untrusted condition, not a first
baseline. Read/write the cursor through a regular-file, reparse-rejecting,
stable-handle path-admission check and reject rollback of its monotonic epoch.
On genuine first enrollment, perform a bounded oldest-to-newest replay (or at
minimum a bounded lookback for the fixed clear/tamper event IDs) before
committing a provisional baseline. Emit an explicit coverage-start event and
promote the baseline only after the replay and terminal anchors are stable.

## R1-02 — The continuity guard can bridge old rows to a post-clear terminal anchor

- **Severity:** LOW
- **Component:** `src/angerona/modules/audit_log_guard.py:206-265,281-301`
- **Status:** OPEN

### Description

For a live checkpoint, the guard rechecks the prior anchor immediately before
and after `read_after()`. It then parses and emits those rows, samples only the
candidate terminal record, and commits that terminal anchor. It does not recheck
the original admission anchor after the terminal sample. Therefore a channel
generation can change after the post-query check but before terminal anchoring.

A deterministic fake source changed generations at exactly that boundary and
refilled the terminal record ID. The poll emitted/accepted the old-generation
rows, saved the new-generation terminal anchor, reported no gap, and the next
poll treated the replacement generation as live. This is a continuity race,
not a parser failure.

### Impact

A local actor able to coordinate clear/refill activity with polling can bridge
two event-log generations without a continuity alert. Real exploitation must
win the late post-query/parse window and recreate the prior terminal record ID
inside the replacement generation. That is often infeasible for a mature
channel, and the audit did not demonstrate the race against physical WEVT, so
the confirmed logical TOCTOU is rated Low.

### Existing mitigations

The guard already performs admission-anchor checks on both sides of the event
query, detects missing terminal records, uses bounded batches and strict XML,
and authenticates the persisted checkpoint. Those controls close the common
clear-before-query and clear-during-query cases; the uncovered interval is
after the second admission check.

### Recommendation

Stage parsed records without publishing them. Sample the candidate terminal
anchor, then revalidate both the original admission anchor and the terminal
anchor immediately before commit. If either vanished or changed, discard the
staged batch, report a generation gap, and replay from the oldest retained
record. Bind checkpoint persistence to the expected prior `(record_id, anchor)`
so an update is an explicit compare-and-swap, and publish staged records only
after that generation-consistent transition succeeds.

## R1-03 — Effective SSH configuration and key custody are not baselined across configured sources

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/ssh_surface.py:375-456,861-925,1047-1123`;
  `src/angerona/modules/ssh_surface_guard.py:279-306,377-407`
- **Status:** OPEN

### Description

The parser intentionally does not expand `Include`; its snapshot digest covers
only the root `sshd_config` bytes. An included fragment can therefore change
without changing the authenticated configuration digest. The posture evaluator
correctly emits ambiguity for affected directives, but a later malicious change
inside an already-ambiguous include produces no new drift transition.

The key inventory likewise enumerates only conventional per-user and shared
administrator paths. Parsed `AuthorizedKeysFile` values do not drive the
inventory, and external/key-authority sources such as `AuthorizedKeysCommand`,
`TrustedUserCAKeys`, and authorized-principals files are not represented in the
baseline. Finally, the inventory has a Windows ACL-verifier hook, but the module
never supplies one, so every existing Windows authorized-key file remains
`windows_acl_unknown`; custody is advised rather than verified. `sshd_config`
custody is not assessed either.

### Impact

An actor who can alter an included SSH policy fragment, custom key source, CA or
principals source can establish or weaken SSH access without a precise
authenticated drift event. This requires local write access to SSH-managed
configuration, but those files are a high-value persistence boundary and this
module is explicitly intended to detect key and tunnel posture drift.

### Existing mitigations

The root file and conventional keys use bounded, link/reparse-aware,
change-during-read checks. Baseline bytes are strictly schema-validated and HMAC
authenticated with purpose-separated keys. Private key material and comments
are not retained, public keys are fingerprinted, and include ambiguity and
unknown Windows ACLs are surfaced rather than falsely declared safe.

### Recommendation

Add a bounded include resolver with maximum depth/file/byte limits, canonical
allowed roots, reparse rejection, stable file-handle reads, and an aggregate
digest over every admitted file and its identity. Resolve configured local
`AuthorizedKeysFile`, CA and principals paths under equally strict path rules;
emit explicit unsupported-source findings for command-backed key authorities.
Implement native Windows ACL verification for configuration, host-key and
authorized-key files, and include its normalized custody result in the
authenticated baseline.

## R1-04 — Default Windows OpenSSH authentication and non-service tunnel activity are blind

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/ssh_surface.py:1338-1443,2057-2070`;
  `src/angerona/modules/ssh_surface_guard.py:246-334`
- **Status:** OPEN

### Description

On Windows the log collector tails only optional text files beneath
`ProgramData\ssh\logs`. The standard OpenSSH Operational event channel is not
opened by this module or the new fixed-channel event adapter. `_on_bus_event()`
can parse an OpenSSH-looking event published by another component, but there is
no built-in producer for that channel, so a default Windows OpenSSH deployment
has no authentication/tunnel log feed. Microsoft documents that the default
`AUTH` facility sends Windows OpenSSH logs to ETW/Event Viewer and that file
logging requires an explicit `LOCAL0` configuration: [OpenSSH Server
configuration for Windows](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration).

The Windows runtime collector also enumerates only `psutil.win_service_iter()`.
Unlike its POSIX branch, it does not enumerate the process table. A portable,
scheduled-task, or otherwise non-service `sshd.exe` is therefore absent, and
its listeners are excluded because listener admission is keyed only by PIDs
learned from services. Outbound `ssh.exe` forwarding/reverse-tunnel processes
and their sockets are also outside the runtime snapshot.

### Impact

Successful key/password authentication, forwarding signals, and a non-service
SSH foothold can be invisible on the primary Windows deployment. Static
configuration and conventional key drift still provide useful signals, but
runtime and authentication coverage can be absent precisely when an actor uses
portable tooling or default event-channel logging.

### Existing mitigations

Configured text logs are bounded and reject links/reparse points; normalized
log evidence retains keyed account/source tokens rather than raw identities.
Registered Windows OpenSSH services and their listeners are baselined, and all
output remains observe-only. The generic EventBus ingestion hook allows a
future trusted adapter without changing parser semantics.

### Recommendation

Add a fixed-provider Windows Event Log adapter for the OpenSSH Operational/Admin
channels with explicit event IDs, bounded XML/message parsing, provider/channel
verification and the same privacy tokens. Enumerate local `sshd.exe` and
`ssh.exe` processes with PID birth time, canonical executable identity and
signature/path classification, then bind relevant listening/established sockets
to that identity. Normalize only forwarding flags and keyed endpoints; do not
retain full command lines. Expose explicit per-source completeness so missing
ETW, service, process or socket evidence cannot look fully healthy.

## R1-05 — Network drift state and collection quality reset across process restarts

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/network_trust_monitor.py:60-73,125-171,287-359,375-390,530-552`;
  `src/angerona/core/network_trust.py:583-599`
- **Status:** OPEN

### Description

Each module instance creates a random privacy key and an empty in-memory
`NetworkTrustEvaluator` baseline. Neither survives restart. A controlled pair
of module instances observed one DNS set before restart and a different DNS set
after restart; the second observation produced no DNS drift and reported health
100 because it was a new baseline under a new token key.

Collector failures also collapse to empty strings/collections. `NetworkSnapshot`
has no field-level completeness metadata, and `_tick()` reports health 100 for
any type-valid result, including an empty or partially populated first sample.
The nominal 256-KiB command-output limit is applied only after
`subprocess.check_output()` has captured the complete child output, so it is not
an actual memory bound.
On Windows, global DNS values are assigned to every interface and a DHCP server
is attached only when exactly one exists system-wide, so multi-interface path
identity can be incomplete or mis-associated without a degraded sensor state.

### Impact

DNS, DHCP, route, gateway-identity or profile changes made while Angerona is
stopped/restarted are accepted as the next starting state. A local actor who
suppresses a bounded inventory command during enrollment can also create a
stable empty baseline. The paths remain labeled untrusted, so this does not
grant network or response authority, but it removes the historical drift signal
needed to recognize a changed LAN/WLAN environment.

### Existing mitigations

Within one uninterrupted process, present-to-missing and changed values do emit
drift findings. Raw interface, SSID, gateway, DHCP and DNS identifiers are
converted to purpose-specific tokens, observations and arrays are bounded, and
the module never changes firewall/routes or authorizes response.

### Recommendation

Derive a dedicated network-privacy/baseline key from protected Angerona key
custody and persist a strict, bounded, HMAC-authenticated baseline with
provisional/trusted states. Treat missing-after-install and failed
authentication as degraded/untrusted, never as a clean first sample. Add
per-interface, per-family completeness/error fields and withhold health 100 and
baseline promotion when required evidence is absent. Enforce output limits
while reading child pipes rather than after capture. Prefer structured
interface-bound Windows API/PowerShell output for DNS, DHCP, routes and neighbor
identity instead of applying global sets to every link.

## R1-06 — Gateway attestation labels an interface despite competing or unobserved egress routes

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/network_trust_monitor.py:207-224,410-478`;
  `src/angerona/core/network_trust.py:402-425`
- **Status:** OPEN

### Description

The monitor requires only that the enrolled endpoint IP appear somewhere in the
target interface's set of default-route gateways. It does not require that route
to be the selected/lowest-metric route for its family, nor does it bind the
attestation result to one route/family. A successful HTTPS attestation then
changes the entire interface label to `gateway-attested`.

A synthetic snapshot with an enrolled gateway at metric 50 and a competing
gateway at metric 5 still received the attested label. The evaluator separately
raised a multiple-route finding, but the label remained. On Windows the route
collector runs only `route print -4`; a concurrent IPv6 default path is not
observed at all and therefore cannot qualify or prevent the interface-wide
label.

### Impact

Traffic can bypass the Personal Sentinel Gateway while the interface displays
the positive attestation label. This is false assurance rather than an
authorization bypass: endpoint resources remain untrusted and
`response_authorized` is false. It is nevertheless material because the label
is the core evidence that traffic is traversing the intended intermediate
firewall.

### Existing mitigations

Enrollment is explicit; endpoints must be private/loopback HTTPS IPs; TLS chain,
hostname and leaf pin checks, nonce/freshness, policy digest, peer-IP matching,
strict schemas, response bounds, no-proxy/no-redirect behavior and optional mTLS
all held in review. The interface name and enrolled endpoint must match a
locally observed route gateway, failures stay untrusted, and competing observed
routes do generate a separate High finding.

### Recommendation

Represent attestation per egress route and address family, not per interface.
Before and immediately after the exchange, resolve the selected default egress
route for each applicable family and bind interface index, family, gateway,
metric and interface epoch into the attestation result. Keep the overall
interface untrusted unless every applicable default path is proven to traverse
the enrolled gateway; use a distinct partial label otherwise. Collect both IPv4
and IPv6 routes on Windows through bounded structured output and fail closed
when either family's route inventory is incomplete.

## R1-07 — Live defense messages can expose MAC/SSID/user text and path fragments

- **Severity:** LOW
- **Component:** `src/angerona/gui/live_defense_activity.py:27-81,89-124`;
  `src/angerona/modules/arp_watchdog.py:171-179,278-287`
- **Status:** OPEN

### Description

The card correctly never reads `Event.details`, but it displays the public
`Event.message` after generic redaction. The sanitizer has no MAC-address or
SSID pattern and removes only environment-known user/host names. Its Windows
path expression stops at whitespace, so an unquoted path such as
`C:\Program Files\Secret Project\report.txt` leaves the suffix after
`C:\Program` visible. Existing ARP Watchdog public messages contain raw IP and
MAC identities; IPs are redacted by the shared helper but MACs remain.

Controlled strings confirmed that a MAC and arbitrary SSID/account labels
survive, and that the spaced Windows path is only partially redacted.

### Impact

Local network identifiers and filesystem/project-name fragments can appear on
the dashboard or in screenshots. The surface is local, bounded, non-exporting,
and does not reveal Event details or model reasoning, so this is Low rather than
a cloud-egress or credential finding.

### Existing mitigations

Rows, inputs and output lengths are strictly bounded. Control characters,
credentials, bearer/JWT/provider tokens, IP addresses, current local identity,
common no-space paths and private-reasoning phrases are removed. The card owns
no subscription or timer and cannot authorize a response.

### Recommendation

Define an EventBus `public_message` contract and make producers place raw local
identifiers only in governed details while emitting identity-free summaries.
Add MAC and common adapter/SSID identity redaction, and handle quoted/spaced
Windows paths without leaving suffixes. Add regression cases using real public
messages from ARP, network, process and file modules rather than sanitizer-only
fixtures.

## R1-08 — The network monitor's advertised non-Windows support is skipped by preflight

- **Severity:** INFO
- **Component:** `src/angerona/modules/network_trust_monitor.py:362-373`;
  `src/angerona/core/platforms.py:140-172`;
  `src/angerona/core/module_manager.py:142-159`
- **Status:** OPEN

### Description

Non-Windows module discovery performs an AST-only preflight and recognizes only
a literal module-level `SUPPORTED_PLATFORMS`. The network monitor declares only
a class attribute (`supported_platforms = frozenset(...)`). It is consequently
treated as legacy Windows-only and skipped before import on Linux and macOS,
despite its class and collector claiming those platforms. The SSH guard uses
the required module-level form and is discoverable.

### Impact

There is no effect on Angerona's primary Windows deployment. On advertised
Linux/macOS operation the new zero-trust network monitor silently does not load,
removing the intended LAN/WLAN observation without a module runtime health
signal. This is an interoperability/coverage defect, not an exploitable host
boundary, hence Info.

### Existing mitigations

The conservative preflight prevents incompatible Windows imports from crashing
non-Windows startup. Discovery errors and the dashboard's loaded-module state
can help an operator notice the absence.

### Recommendation

Add a literal module-level
`SUPPORTED_PLATFORMS = ("windows", "macos", "linux")` and reference it from the
class. Add discovery tests that run the AST preflight for both Linux and macOS
and assert that this module is admitted without weakening the legacy-Windows
default for undeclared modules.

## R1-09 — Defense Memory reads an unbounded, reparse-following asset before enforcing its cap

- **Severity:** LOW
- **Component:** `src/angerona/core/defense_memory.py:234-263,374-386`
- **Status:** OPEN

### Description

`load_defense_memory()` calls `Path.read_bytes()` before checking
`MAX_FILE_BYTES`. That operation follows links/reparse points and allocates for
the complete target, so the documented 64-KiB cap is enforced only after the
unbounded read. The bundled loader points at a fixed release asset, but it does
not verify a regular, non-reparse file or compare stable file identity around a
bounded descriptor read.

### Impact

An actor who can replace or redirect the bundled asset can cause memory
pressure, a GUI stall, an extreme-case OOM, or loss of Defense Memory/RAG
grounding before the pinned digest rejects the data. The ARIA integration
catches ordinary load exceptions and continues, so this is not described as an
assured full application/startup crash. The attacker already needs write access
to a release/source asset boundary; severity is therefore Low.

### Existing mitigations

The canonical SHA-256 pin, strict duplicate-key parser, structural and text
bounds, exact schemas, inert governance fields and cloud-reference filter
prevent modified content from becoming trusted prompt context. The weakness is
resource/path admission before those controls execute, not content integrity.

### Recommendation

Reject any link/reparse component and require a regular file under the expected
resource root. Open once with no-follow semantics where available, compare the
opened identity to the admitted path, read at most `MAX_FILE_BYTES + 1`, and
recheck stable identity/metadata before parsing. Keep the canonical digest and
all existing schema/governance validation after the bounded read.

## Controls that held

- The Windows event adapter uses fixed channels/event filters, bounded XML and
  batch sizes, closes event/query handles, and does not accept arbitrary routes.
- Personal Sentinel Gateway configuration and transport enforce strict
  duplicate-free schemas, private/loopback HTTPS endpoints, TLS verification,
  hostname and peer-IP binding, leaf-certificate pinning, request freshness,
  response/header/body bounds, no proxies, no redirects and no router
  credential storage. Witness and primary authentication purposes are separated.
- Defense Memory is static data-only, strict-schema/bounded, canonical-digest
  pinned, and rejects duplicate keys and unsafe content. ARIA's cloud boundary
  admits only the selected `angerona://defense-memory` excerpt after redaction;
  arbitrary runbooks, raw telemetry, local files and conversation history remain
  local.
- New event details consistently carry `response_authorized=False`; gateway
  resources do not become trusted after attestation. EventBus history and the
  live card are bounded, and ModuleManager start/stop subscription ownership is
  coherent in the reviewed paths.
- SSH/gateway/defense-memory file readers generally reject symlink/reparse paths,
  compare stable identities around bounded reads, and authenticate persisted
  security state with purpose-separated keys. No new unsafe deserialization,
  command injection, SSRF/redirect, unauthenticated listener, or dynamic-code
  path was confirmed in the Cycle 23 additions.

## Previously known residuals checked (not new Cycle 23 findings)

| Prior item | Current result |
|---|---|
| A-04 external/drop-in execution boundary | The original automatic arbitrary drop-in behavior is strongly mitigated by explicit opt-in, publisher/digest verification and execution of the verified byte snapshot. The architectural residual remains open: an admitted extension still executes in-process with the suite token, and EventBus HMAC authenticates stored bytes rather than producer identity. |
| A-06 broad `ExecutionPolicy Bypass` | Still open. Source call sites remain in `modules/kernel_posture_ledger.py` and `modules/remediation_actions.py`, and multiple root helper BAT launchers retain fixed-script `-ExecutionPolicy Bypass` calls. They were not re-filed because this is the known centralization/policy residual. |
| A-07 cosmetic SHA-1 path identifier | Resolved. `shadow_shield.py` now uses SHA-256 consistently. |
| R6-03 process-handle/program-file lease | Still open as documented defense-in-depth: process response revalidates PID birth/executable state but does not retain an OS process handle and bounded executable-file lease through the complete mutation. |

Prior items explicitly rechecked: **1 resolved, 3 still open/architectural**.
New Cycle 23 findings: **9 open (0 Critical, 0 High, 5 Medium, 3 Low,
1 Info)**.
