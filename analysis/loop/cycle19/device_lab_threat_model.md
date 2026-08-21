# Device Security Lab threat model

Date: 2026-08-21  
Scope: design review for an owner-authorized, defensive Device Security Lab in
Angerona's Red Team UI. This document does not authorize offensive testing and
does not change product code.

## Security position

The safe product is an **authenticated posture-assessment mesh**, not a remote
attack platform. Each enrolled companion runs a small Angerona collector that
inspects only its own operating-system state and returns a signed, bounded,
privacy-minimized report. The controller must not discover arbitrary targets,
scan subnets, crack wireless security, inject traffic, guess credentials,
exploit services, persist on another host, or convert a cable/radio sighting
into permission to test that device.

The words “Red Team” describe the defensive workflow and the presentation of
weaknesses. They must not broaden probe authority. A USB, HDMI, Ethernet,
Wi-Fi, or Bluetooth connection is evidence that an interface exists; it is not
proof of ownership, enrollment, or consent by the device at the other end.

Remote companion testing must remain disabled until all mandatory gates in
this document exist. Local read-only inspection can ship earlier behind the
same owner-attestation and audit controls.

## Existing Angerona foundations and boundaries

The current repository already has useful components, but none is a complete
remote Device Lab transport:

- `gui/red_team_console.py:66,106-109` is the natural UI integration point. The
  existing drill engine is explicitly a benign simulation against this
  instance; remote assessment must be a separate tab and service, not a new
  target value passed into the marker engine.
- `core/endpoint_identity.py:282,401-468,556-650` provides per-endpoint Ed25519
  identity, proof-of-possession enrollment artifacts, signed connection
  envelopes, sequence handling, and verification. Its own module contract says
  that it does not provide a server, transport, or mutual TLS.
- `core/fleet_control_plane.py:210-236,539-636` provides bounded device records,
  tenant predicates, integrity-protected state, key-conflict rejection, and
  explicit quarantine/revoke/retire transitions. New devices currently enter
  active state, so a production Device Lab needs a pending/approved enrollment
  state instead of treating registration as approval.
- `core/fleet_service.py:832-876,1285-1286` is a bounded authenticated **loopback**
  HTTP service. Settings explicitly state that remote fleet access remains
  disabled until mutual TLS is deployed (`gui/pages.py:4264-4272`). Do not
  expose or rebind this service to implement the Device Lab.
- `core/fleet_jobs.py:65-241` supplies useful bounded job lifecycle and signed
  result-receipt concepts. Device Lab jobs must be typed catalog entries, never
  arbitrary commands or scripts.
- `core/authorization.py:204-218,267-430` has scoped RBAC, explicit deny,
  separation of duties, signed decisions, and fail-closed audit handling.
- `core/admin_audit.py:149-263` supplies an append-only, per-tenant HMAC chain.
  Every enrollment, probe, result, revoke, export, and remediation decision
  should enter that ledger.
- `core/eventbus.py:75-91` defines `remote-observe-only`. Imported device
  findings must preserve that authority so remote PIDs, paths, addresses, and
  device identifiers can never drive actions on the controller.
- `modules/remote_bridge.py:153-160,411-450` mutually authenticates and encrypts
  remote event forwarding, strips local-action identifiers, and republishes as
  observe-only. It is an observation bridge, not an enrollment/control/job
  transport, and its shared-key topology should not become the Device Lab mesh.
- `core/evidence_store.py:179-260` deliberately defaults to local-only evidence.
  Do not weaken this boundary. Store remote Device Lab evidence in a separate,
  explicitly remote, tenant/device-scoped store, then expose only normalized
  findings to the local evidence UI.
- `core/evidence_ingestion.py:26-47` is a useful bounded, non-blocking ingestion
  pattern. Device reports need equivalent queues, byte limits, batching, and
  drop/failure telemetry.
- `modules/usb_monitor.py:26-49,52-116` observes newly attached removable
  volumes. It is not a general USB bus interrogator and must not read or execute
  content as part of Device Lab discovery.
- `core/response_broker.py:116` and
  `core/safe_response_session.py:141` are the correct pattern for previewed,
  authorized, receipt-bearing remediation. Remote findings must not bypass
  those boundaries.

At the time of this review the shared working tree also contained an in-progress
Device Security Lab tab that referenced `core.device_security_lab`. An early
companion-flow draft asked the operator to paste a 32-byte device key. The
implementation owner accepted the correction during this review: the companion
private key remains on the companion, the controller stores only the public
key/fingerprint and revocation state, and local enrollment has a separate
authorization path. The remaining protocol and test gates below still apply
before networked companion assessment can be released.

## Proposed architecture

```text
Operator / Red Team UI
        |
        | scoped RBAC decision + owner attestation + signed preview
        v
Local Device Lab controller
        |
        | pinned mTLS, per-device certificate, bounded typed messages
        v
Enrolled companion agent (least privilege, local probes only)
        |
        | platform OS APIs; no shell, scripts, raw radio, or packet injection
        v
Local interface and posture metadata

Companion result -> Ed25519 signature -> mTLS -> schema validation ->
quarantine/staging -> controller receipt -> remote evidence store ->
rule-based findings -> optional reviewed remediation proposal
```

The initial topology should be hub-and-spoke. “Mesh” means that many enrolled
devices can independently connect to the controller; it must not mean that one
companion can instruct or impersonate another. Peer-to-peer routing, relay, and
transitive trust are out of scope for the first release.

### Enrollment

1. The operator creates a five-minute, one-use enrollment invitation for one
   tenant, one expected device, and an explicit set of probe capabilities.
2. The companion generates its Ed25519 private key locally and never exports it.
3. The companion signs the invitation using
   `EndpointIdentity.enrollment_request`; the controller validates expiry,
   nonce replay, device ID derivation, and proof of possession.
4. Both screens display the same short authentication string (or QR + SAS).
   The operator confirms it on both devices. Merely importing a file is not
   approval.
5. An enrollment authority issues a short-lived client certificate bound to
   tenant ID, device ID, public-key fingerprint, allowed probe set, and expiry.
6. The controller records the device as `pending`, then performs an audited
   compare-and-swap to `active` only after human approval and certificate proof.
7. Rotation requires old-key and new-key signatures. Revoke/quarantine is
   immediate and cannot be overridden by a stale job or cached session.

Enrollment links must not contain credentials. A copied invitation alone must
not be enough to enroll. No trust-on-first-use after the displayed confirmation
step, no shared fleet-wide secret, and no self-enrollment directly into active
state.

### Transport and protocol

- Create a separate Device Lab service using TLS 1.3 mutual authentication and
  certificate pinning. Keep the existing fleet HTTP service bound to loopback.
- Bind only to explicitly selected private interfaces. Default to no listener.
  Show the exact interface/address before enablement and fail closed if the
  interface changes to public/untrusted.
- Never honor inherited proxy variables for local/private companion transport.
- Frame messages with strict length, depth, key-count, numeric, string, and
  collection limits. Reject duplicate JSON keys, non-finite numbers, unknown
  fields, unsupported compression, ambiguous framing, and version downgrade.
- Require tenant ID, device ID, connection sequence, session nonce, request ID,
  message kind, catalog version, sent time, expiry, and signature on every
  message. Maintain durable replay/high-water state.
- Authenticate first, authorize second, validate the probe plan third, then
  execute locally. A valid certificate is identity, not blanket permission.
- Apply per-device and per-tenant concurrency, bytes, jobs, and reconnect limits.
  A noisy or malformed device is quarantined without blocking the GUI or other
  devices.

### Probe catalog

Every probe is an immutable catalog entry such as
`device_lab.usb.posture/v1`. Its manifest fixes input schema, output schema,
platforms, required OS privilege, maximum runtime, maximum output bytes,
privacy fields, and catalog hash. The companion maps the ID to built-in Python
or native API code. The controller can never supply code, command lines,
PowerShell, shell fragments, dynamic imports, DLL paths, or plugin locations.

Catalog updates use signed releases and compatibility negotiation. Unknown,
revoked, mismatched, or downgraded catalog hashes are denied. All probes use a
deadline and cancellation token and run off the GUI thread. Failure or lack of
coverage is reported as `unknown`/`unsupported`, never as secure.

## Allowed and prohibited interface checks

| Interface | Allowed owner-authorized checks | Explicitly prohibited |
|---|---|---|
| USB/removable media | Local OS enumeration of attached device class, vendor/product IDs, removable-storage policy, autorun policy, driver version/signing, encryption posture if the OS exposes it, and connect/disconnect timestamps. File-system metadata only when the operator explicitly includes an enrolled volume. | Reading arbitrary file contents, executing anything, writing marker files to the device, mounting unmounted media, firmware commands, HID injection, BadUSB emulation, descriptor fuzzing, or exploiting drivers. |
| Ethernet | Local adapter/link state, negotiated speed, DHCP/static status, network category, firewall posture, driver/firmware version, and the companion's own listening-socket inventory with owning process and bind scope. | CIDR/host discovery, ARP poisoning, unauthenticated port scanning, packet capture by default, crafted packets, protocol fuzzing, credential guessing, exploit validation, or testing a device merely because it shares a cable/network. |
| Wi-Fi | Current association's security mode (for example WPA2/WPA3/enterprise), adapter/driver version, OS firewall/network-category posture, and privacy-tokenized SSID/BSSID metadata from the enrolled device's normal OS connection API. | Monitor mode, passive collection of nearby networks, raw 802.11 capture, deauthentication, handshake capture, password auditing, WPS attacks, rogue access points, evil-twin simulation, or packet injection. |
| Bluetooth | State of the local adapter, OS-recorded paired/bonded devices, trust/encryption flags exposed by the OS, active profile names, and driver/firmware version. | Inquiry scans for nearby non-paired devices, BLE address tracking, pairing attempts, PIN/passkey guessing, GATT/SDP fuzzing, impersonation, jamming, or radio injection. |
| HDMI / DisplayPort / USB-C display | Locally exposed connection type, display/adapter driver, EDID summary, resolution, HDR/HDCP status if the OS safely exposes it, and dock/adapter firmware identifiers. Report unsupported fields as unknown. | Treating a display cable as a management channel; CEC commands; EDID spoofing/injection; HDCP bypass; firmware reads/writes; display-content capture; or attempting to inspect the source/sink as a general computer. |
| Local ports/services | The enrolled companion reports its own listening sockets from local OS APIs, including process identity, loopback/private/public bind scope, protocol, and a privacy-safe product/version claim from installed software metadata. | Controller-originated banner grabbing, arbitrary connect sweeps, UDP probing, vulnerability exploitation, authentication attempts, or inferring “patched” solely because a port is closed. |

For a switch, router, television, phone, printer, or IoT device that cannot run
the companion, the first release may record operator-supplied inventory and
vendor-advisory matches only. It must label posture `unverified` and provide no
active test button. A future connector would require its own authenticated,
vendor-supported management API threat model.

## Finding and remediation semantics

Deterministic signed rules convert normalized facts to findings. Local AI may
summarize or explain evidence, but may not invent evidence, change severity,
authorize a probe, or generate an executable remediation. SSIDs, Bluetooth
names, USB labels, EDID names, service names, banners, and companion-supplied
text are untrusted data and possible prompt injection; display them escaped and
never place them in system instructions.

Each finding needs:

- a stable rule ID and rule-pack hash;
- the exact enrolled device and observation IDs;
- evidence age, clock quality, source integrity, and coverage state;
- severity, confidence, and an honest “observed / inferred / unverified” label;
- a vendor-neutral solution plus authoritative vendor-advisory references when
  available;
- an explicit statement when no safe automatic patch exists.

“Patch” initially means guidance or a previewed local companion action from a
small signed remediation catalog. Applying a patch requires a fresh controller
authorization **and** target-local confirmation, with preconditions, a backup or
rollback plan, bounded timeout, post-check, and signed result receipt. Never
auto-install firmware, driver, OS, firewall, Wi-Fi, Bluetooth, or network
changes. Never let the controller send arbitrary package names, URLs, scripts,
registry paths, commands, or shell text.

Imported remote findings always keep `response_authority=remote-observe-only`.
They cannot supply a controller-local PID/path/IP to SOAR. A remote remediation
job is scoped to its enrolled device and is consumed only by that device's
companion after local confirmation.

## Trust boundaries and abuse cases

| Abuse case | Required control |
|---|---|
| An operator assesses a device they do not own | Explicit owner/permission attestation for every session; target-local SAS confirmation; immutable actor/session audit; no discovery-to-test shortcut. |
| A copied invite enrolls an attacker | One-use short expiry, proof of possession, two-screen SAS, pending state, certificate binding, durable replay ledger. |
| MITM, replay, or protocol downgrade | Pinned mTLS, signed envelopes, connection sequence/high-water state, nonce and expiry, catalog/version binding, no fallback to plaintext/shared-key transport. |
| A compromised companion attacks the controller | Strict schema and size bounds, no HTML/rich-text interpretation, staging/quarantine, per-device quotas, background parsing, no controller-side execution, observe-only authority. |
| A compromised controller attacks companions | Built-in allowlisted probes only, device verifies signed plan/catalog/scope, target-local consent for changes, no arbitrary commands, per-probe least privilege. |
| Cross-device confused deputy | Tenant/device ID and public-key fingerprint bound into certificate, plan, job, result, receipt, authorization scope, and audit record; exact-device equality checks. |
| Peripheral identity spoof or hot-plug race | Treat VID/PID, MAC, EDID, labels, and names as descriptive, not identity; snapshot instance ID at start/end; report replacement/race as inconclusive. |
| A signed but compromised endpoint lies about posture | Signature proves origin, not truth. Label evidence self-reported; use freshness/coverage attestations; optionally add hardware-backed attestation in a later separately reviewed phase. |
| Nearby radio metadata exposes people/locations | Do not enumerate nearby radios; tokenize SSID/BSSID/MAC/device names with a per-tenant privacy key; omit raw values from default logs/exports. |
| Malicious names/banners inject the UI or AI | Normalize Unicode, strip controls, bound length, render as plain text, keep out of prompt instructions, and never use as a path, URL, module, or command. |
| Report flood or expensive probes freeze Angerona | Bounded queue, job concurrency of one per endpoint initially, deadlines, byte and row caps, streaming pagination, cancellation, and worker threads/processes outside Qt. |
| Stale evidence produces unsafe advice | Freshness TTL per probe, target clock-quality field, controller receipt time, stale/incomplete badge, and denial of remediation from stale evidence. |
| Export leaks identifiers or network layout | Redacted export by default, deterministic tokenization, explicit inclusion preview, retention controls, secure file mode, and audited export receipt. |
| Revoked device finishes an old job | Re-check device and credential state at dispatch, start, result ingestion, remediation approval, and receipt verification; revoke wins over cached authority. |

## Authorization model

Add narrow permissions rather than expanding the existing fleet operator role:

- `device-lab.device.read`
- `device-lab.enrollment.create`
- `device-lab.enrollment.approve`
- `device-lab.enrollment.revoke`
- `device-lab.probe.preview`
- `device-lab.probe.execute-passive`
- `device-lab.finding.read`
- `device-lab.export.create`
- `device-lab.remediation.preview`
- `device-lab.remediation.approve`
- `device-lab.remediation.execute`

Keep enrollment approval separate from invitation creation where multiple users
exist. Keep remediation approval separate from rule/catalog authorship. Auditors
remain read/export only. Deny rules take precedence. A “full setup” preset may
enable the local UI, but must not create a network listener, enroll a device, or
grant remediation permissions automatically.

## Audit and evidence contracts

Use canonical JSON with duplicate-key rejection and finite values. Recommended
documents:

### `angerona.device-lab-session/v1`

- `session_id`, `tenant_id`, `controller_device_id`, `target_device_id`
- `operator_principal_id`, `authorization_decision_id`, `owner_attested`
- `consent_method`, `consent_at`, `consent_expires_at`
- `requested_capabilities`, `approved_capabilities`
- `catalog_version`, `catalog_sha256`, `transport_binding_sha256`
- `created_at`, `expires_at`, `state`, `previous_record_hmac`, `record_hmac`

### `angerona.device-lab-probe-plan/v1`

- `plan_id`, `session_id`, `target_device_id`, `probe_id`, `probe_version`
- schema hashes, required privilege, timeout and output-byte limits
- exact interface category and privacy policy
- `issued_at`, `expires_at`, request nonce, controller signature
- no command, script, executable, dynamic-module, URL, credential, or free-form
  action field

### `angerona.device-lab-probe-result/v1`

- `result_id`, `plan_id`, `session_id`, `target_device_id`
- sequence, observed/start/end/received timestamps, clock quality
- status: `pass`, `finding`, `unsupported`, `denied`, `timeout`, `error`
- normalized observations, coverage, redaction counters, raw-artifact hashes
- catalog/rule hash, public-key fingerprint, endpoint signature
- controller receipt ID/HMAC and `response_authority=remote-observe-only`

### `angerona.device-lab-finding/v1`

- finding/rule IDs, severity, confidence, evidence classification and IDs
- description, impact, solution, authoritative references, patch availability
- first/last observed, evidence expiry, state and acknowledgement trail
- no secret material, raw SSID/BSSID/MAC, full username, full filesystem path,
  command line, document content, or network payload by default

### `angerona.device-lab-remediation-receipt/v1`

- immutable finding/device/precondition/catalog bindings
- controller authorization and target-local approval IDs
- preview digest, backup/rollback digest, bounded action ID
- started/finished time, result, post-check evidence, rollback status
- endpoint signature and controller receipt; never a free-form output dump

Suggested initial bounds: five-minute enrollment invite, fifteen-minute probe
plan, one concurrent probe per target, 64 KiB maximum normalized result, 500
observations per probe, 1,000 findings per session, and 30-day normalized
evidence retention. Raw OS command/API output should be parsed in memory and not
persisted. Limits should be lower where an interface needs less data.

## UI workflow

The Red Team console should add a resizable **Device Security Lab** tab with:

1. **Owned devices** — pending/active/quarantined/revoked state, key fingerprint,
   last signed contact, evidence freshness, and a visible revoke button.
2. **Enroll** — QR/SAS invitation, explicit permission statement, capability
   checklist, expiry countdown, and two-device confirmation.
3. **Probe plan** — interface cards for USB, Ethernet, Wi-Fi, Bluetooth,
   Display/HDMI, and local listening services. Each card explains exactly what
   will and will not be inspected. Default all remote probes off.
4. **Review & run** — immutable preview, target device fingerprint, expected
   duration/data size/privilege, and authorization receipt before Run.
5. **Live evidence** — non-blocking progress, cancellation, integrity/freshness
   badges, and explicit unsupported/unknown states.
6. **Weaknesses & solutions** — sortable findings with evidence, confidence,
   rule source, solution, patch guidance, and affected device.
7. **Remediation** — guidance by default; separate preview and target-local
   confirmation for catalogued changes; signed result and rollback evidence.
8. **Logs/export** — redacted, bounded, append-only session log and inclusion
   preview before export.

Closing the window must not cancel an in-progress audit without asking, and no
probe/result parsing may execute on the Qt main thread. A disconnected device is
shown as disconnected; it must not trigger aggressive retry or discovery.

## Phased delivery

### Phase 1 — safe local MVP

- Local OS-only passive adapters for the allowed checks above.
- Owner attestation, catalogued probe IDs, deterministic rules, redacted report,
  bounded audit/evidence, and guidance-only remediation.
- No listener, mesh, wireless discovery, remote import secret, or active patch.

### Phase 2 — signed offline companion evidence

- Ed25519 public-key enrollment with SAS and pending approval.
- Companion exports a short-lived signed evidence package; controller imports it
  after device/scope/freshness/replay verification.
- No private/symmetric device key is pasted or transferred.
- Still no remote job dispatch or listener.

### Phase 3 — authenticated hub-and-spoke

- Separate pinned-mTLS service, certificate lifecycle/revocation, typed probe
  jobs, durable replay/high-water state, scoped RBAC, quotas, and signed results.
- External security review and real Windows/macOS/Linux interoperability tests
  before enabling by default.

### Phase 4 — reviewed remediation

- Small signed cross-platform remediation catalog, target-local approval,
  rollback and post-check, policy separation, and fault-injection tests.
- No AI-generated or arbitrary remote actions.

Hardware attestation, vendor-management connectors, or remote routers/IoT
assessments are later independent projects and require new threat models.

## Mandatory negative and abuse tests

- Invite replay, expired invite, wrong SAS, wrong public key, duplicate device
  ID, key substitution, rotation without both proofs, revoked/quarantined peer.
- Untrusted CA, wrong hostname/device binding, TLS downgrade, plaintext fallback,
  sequence rollback, duplicate request ID, stale result, cross-tenant/device
  result, and job completion after revoke.
- Unknown probe ID/version/hash, altered plan after approval, injected command or
  URL field, catalog downgrade, oversized/deep/duplicate-key/non-finite JSON,
  compression bomb, partial frame, and slow client.
- Malicious SSID/device/EDID/service strings containing HTML, ANSI controls,
  path traversal, shell metacharacters, format strings, and prompt injection.
- USB hot-unplug/replacement, interface rename, suspend/resume clock jump,
  companion restart, controller restart, network loss, and cancellation during
  each probe.
- Queue saturation and 100-device reconnect storm without GUI freeze, unbounded
  thread growth, memory growth, database lockup, or loss of revoke priority.
- Proof that remote results cannot cause local SOAR actions and that a result for
  device A cannot authorize any operation on device B.
- Proof that default reports/exports contain no raw secret, credential, nearby
  radio inventory, full SSID/BSSID/MAC, username, document content, command line,
  or packet payload.
- Proof that unsupported or missing sensors yield unknown/degraded coverage,
  never a passing security result.

## Release gates

Do not describe the companion feature as available or enterprise-ready until:

1. Private device keys never leave their originating device.
2. Enrollment is pending + human-approved, replay-proof, expiring, and
   revocable.
3. A separate mTLS transport has passed protocol, parser, replay, downgrade,
   DoS, and cross-device authorization tests.
4. Only fixed catalog probes can run and all are demonstrably passive.
5. Remote evidence remains observe-only and isolated from local response.
6. Every action has a bounded signed plan, authorization decision, audit record,
   result, and receipt.
7. Privacy defaults and redacted export have automated regression tests.
8. Windows, Apple-silicon macOS, and Linux x86_64 behavior is tested on native
   runners; unsupported probes fail closed.
9. Remediation is guidance-only until separate preview, local confirmation,
   rollback, and post-check gates are complete.
10. Documentation says plainly that cable/radio visibility is not permission to
    test another device and that no offensive wireless/network capability is
    included.

This design can deliver a genuinely useful multi-device defensive lab without
turning Angerona into a scanner or remote execution framework. Its key invariant
is simple: **the enrolled endpoint inspects itself; the controller verifies,
correlates, explains, and audits.**
