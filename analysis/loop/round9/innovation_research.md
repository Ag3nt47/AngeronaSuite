# Round 9 Defensive Capability Gap Research — 2026-08-25

## Decision

Angerona is not short of broad feature names. The current tree already has a
credible local EDR/NDR/SOAR shape: full Sysmon event-range parsing, authenticated
restart cursors, ETW process telemetry, AMSI consumption, Defender telemetry,
process/file/network correlation, identity heuristics, signed detection
packages, OCSF 1.8 findings, Community ID, reversible Combat actions, cases,
forensic process triage, and a governed local model path. The highest-value next
work is to close specific evidence gaps that prevent existing engines from seeing
or correlating important Windows behaviors.

This report distinguishes **BUILT** from **PROPOSED** throughout. A proposal is
not a shipped capability or a product claim. All proposals are defensive,
local-first, bounded, and compatible with Angerona's signed-contract response
boundary. None adds exploitation, credential collection, offensive emulation,
hack-back, an arbitrary response shell, or an unsigned kernel component.

## Repository baseline: what is already built

| Capability | Status | Repository evidence |
|---|---|---|
| Sysmon 1–29 and 255 parsing, structured fields, Community ID, authenticated restart cursor | **BUILT** | `src/angerona/modules/sysmon_listener.py:38-68, 177-224, 235-359` |
| Security-channel 4688/4624/4672 collection | **BUILT, NARROW** | `src/angerona/modules/etw_listener.py:39, 72-143` |
| AMSI consumer for bus-provided script content | **BUILT, UPSTREAM GAP** | `src/angerona/modules/amsi_bridge.py:21, 310-365` expects 4104-style `script_block`, but no module opens `Microsoft-Windows-PowerShell/Operational` |
| Defender Operational telemetry | **BUILT** | `src/angerona/modules/av_telemetry_bridge.py:42, 207-253` |
| Scheduled-task/WMI/service persistence inventory | **BUILT, POLLING/NAME-ONLY** | `src/angerona/modules/persistence_sweep.py:10-20, 168-190`; slow surfaces run about every five minutes and retain only task/consumer names |
| Password-spray, repeated-failure, service-account-interactive, and privileged-new-source analytics | **BUILT, NARROW INPUT** | `src/angerona/core/identity_analytics.py:59-139` |
| ATT&CK heatmap and Sigma single-event subset | **BUILT, STALE/PARTIAL** | `src/angerona/core/attack_tracker.py:21` declares ATT&CK v14; `src/angerona/core/sigma_engine.py:1-8` explicitly says minimal/MVP and has no correlation runtime |
| Kernel posture/driver-set digest and Code Integrity channel availability | **BUILT, POSTURE ONLY** | `src/angerona/modules/kernel_posture_ledger.py:124, 229, 426` |
| Live high-severity process triage (memory strings, sockets, shell history) | **BUILT** | `src/angerona/modules/forensics.py:3-9, 96-171` |
| CycloneDX 1.5 SBOM shape and typed VEX statement | **BUILT, NOT A RISK ENGINE** | `src/angerona/core/release_assurance.py:127-187` |
| TPM database-key binding | **NOT BUILT** | `src/angerona/modules/hardware_crypto.py:169-189` explicitly calls the routine an outline and returns `False` |

## Selected immediate capability: App Control Decision Evidence Sensor

**Status: BUILT in v1.10.3.** This was the single clearest small/medium feature
with immediate defensive value. The initial tree only checked whether the Code
Integrity channel existed. The completed implementation now lives in
`core/app_control_evidence.py` and `modules/app_control_monitor.py`, with strict
parser/correlation, restart, privacy, clear/rollover, record-anchor, and timing-
race coverage in `test_app_control_evidence.py` and
`test_app_control_monitor.py`. The six implementation-audit loops at the end of
this report record how the original blockers were found and closed.

Microsoft's current App Control documentation, updated 2026-08-19, says:

- 3076 is the primary **audit would-block** event;
- 3077 is the primary **enforced block** event;
- 3089 contains one signature-information record per signature (or one
  `TotalSignatureCount=0` record for an unsigned file); and
- the System `Correlation ActivityID` is the supported join key.

Official contract sources:

- [Microsoft: App Control event IDs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)
- [Microsoft: App Control debugging and 3077/3089 field semantics](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting)

### Phase-1 sensor contract

**Source and authority.** A new Windows-only
`AppControlDecisionSensor(BaseModule)` reads
`Microsoft-Windows-CodeIntegrity/Operational` through the supported Windows
Event Log API. It is observational. Every emitted record contains
`response_authorized=False`; a Code Integrity event cannot itself bypass Combat
policy, exact-target revalidation, or signed response contracts.

**Block/audit event parsing (3076 and 3077).** Parse XML by exact named field,
never positional insertion order. Retain bounded typed values for:

- System provider, event ID, record ID, time-created, and normalized Correlation
  ActivityID;
- file name, parent/process name, requested signing level, block-level validated
  signing level, NT status;
- SHA-1/SHA-256 Authenticode hashes and flat hashes, each syntax-validated;
- policy name, PolicyId/PolicyGUID, policy hash;
- original filename, internal name, description, product, version,
  user-writable flag, and package family.

3076 maps to `disposition=audit_would_block`; 3077 maps to
`disposition=enforced_block`. These are OS decisions, not Angerona detections.
The sensor must preserve that difference verbatim.

**Signature parsing (3089).** Parse ActivityID, `TotalSignatureCount`, signature
index, hash, signature type, signature-level validated signing level,
verification error, publisher, issuer, PublisherTBSHash, and IssuerTBSHash. The
validated signing level on 3089 has different semantics from the validated
signing level on 3076/3077; use separate field names and never overwrite one
with the other.

**ActivityID join.** Normalize a syntactically valid GUID and join only within
the same channel and authenticated sensor boot generation. Accept either arrival
order. For signed files, completeness requires exactly one non-conflicting 3089
row for each index `0..TotalSignatureCount-1`, with all rows agreeing on total
count and block identity. For unsigned files, one 3089 row with total count zero
produces `signature_state=unsigned`. A block whose signature rows do not arrive
inside a short bounded window emits `completeness=partial`, lists missing
indices, and remains eligible for late enrichment; it is never labeled complete.

**Duplicate, reorder, and conflict behavior.** Deduplicate by channel + record
ID and a canonical event digest. An identical replay changes only a duplicate
counter. The same record ID with different content, repeated signature index
with different fields, conflicting total counts, cross-ActivityID data, or an
ActivityID with two incompatible block identities marks the group `untrusted`
and emits a sensor-integrity finding. No last-write-wins behavior is allowed.

**Authenticated cursor and pending state.** Reuse the purpose-separated HMAC,
atomic-write, and strict-schema pattern from `sysmon_listener.py`. Persist channel,
last fully emitted record ID, update time, boot generation, and a hard-bounded
set of incomplete ActivityID groups. Checkpoint only after individual typed
events reach the evidence pipeline. Suggested initial bounds: 256 pending groups,
64 signature rows per group, 60-second join window, 1 MiB event XML, 4 KiB per
text field, and a 4 KiB cursor envelope plus a separate bounded pending-state
file. Exact bounds should be benchmarked and constants tested.

**Clear, rollover, and restart.** On restart, authenticate both cursor and
pending groups before resuming. If the saved record is below the channel's
oldest record, above its current high watermark, or record numbering regresses,
emit an exact visibility-gap interval/reason. Mark pending joins partial, seek
to the oldest available record (not the current end), and continue without a
replay storm. Event 1102 from the Security log is not a substitute for this
channel-local continuity proof. Cursor or pending-state HMAC failure is
`untrusted`, not a fresh baseline.

**Health states.** Expose mutually clear operational states:

- `live`: channel readable, cursor authenticated, lag within budget;
- `available_idle`: channel readable but no relevant decision observed (not a
  claim that App Control is configured);
- `degraded`: parse errors, lag, pending-group pressure, truncation, or partial
  joins while some evidence still flows;
- `gap`: clear, rollover, record discontinuity, or dropped range;
- `blind`: channel absent, access denied, Windows event API unavailable, or no
  successful read within the liveness deadline; and
- `untrusted`: cursor/pending-state tamper, record-content conflict, impossible
  time, or schema conflict.

Policy presence/mode is separate posture: `confirmed_active`,
`confirmed_absent`, or `unknown`. An idle channel must not be used to infer
policy absence.

**Privacy and evidence bounds.** Exact paths remain only in protected local
evidence because later investigation may need them; ordinary UI and default
exports show basename plus keyed path token. Do not collect file content,
certificate blobs, command lines, usernames, or arbitrary neighboring events.
Publisher/issuer strings are bounded and sanitized. Public/fleet export carries
policy/file hashes, disposition, signature outcome, completeness, event time,
and privacy tokens under the existing export profile. Errors expose exception
class/reason code rather than raw XML or local paths.

### Required fixtures and acceptance cases

1. **Complete signed audit:** 3076 followed by two 3089 rows yields one
   `audit_would_block`, complete, two-signature decision.
2. **Complete enforced block, reversed order:** all 3089 rows arrive before 3077
   and still yield one complete `enforced_block` decision.
3. **Unsigned file:** 3077 plus one total-count-zero 3089 yields `unsigned`, not
   `missing signature`.
4. **Partial join:** one of three signature indices never arrives; expiry emits
   partial evidence with the exact missing index and health `degraded`.
5. **Duplicate replay:** identical block/signature events are idempotent and
   increment duplicate metrics without a second finding.
6. **Conflict:** same index/different publisher, same record/different digest,
   or different totals makes the group untrusted and response-ineligible.
7. **Cross-talk refusal:** two ActivityIDs for the same path/policy never merge;
   reused ActivityID across an authenticated boot generation never merges.
8. **Restart:** stop after a 3089, persist pending state, restart, receive 3077,
   and complete exactly once.
9. **Cursor tamper and channel clear:** HMAC failure becomes untrusted; rollover,
   clear, and saved-record-beyond-watermark create explicit gap records and
   resume from the oldest retained record.
10. **Bounds:** oversized XML/fields, more than 64 signatures, more than 256
    groups, malformed GUID/hash/integer/boolean, future timestamp, access denied,
    API absence, and a 100,000-event replay remain bounded and never block Qt.
11. **Privacy:** default UI/export contains no full path, username, raw XML,
    command line, or certificate material; protected local evidence preserves
    the exact admitted fields.
12. **Semantic regression:** block-level and signature-level signing fields stay
    separate; 3076 can never be displayed as an actual OS enforcement block.

### Explicit phase boundary

Phase 1 ends with read-only, truthful decision evidence and health/coverage. It
does **not** generate policies, enable App Control, change enforcement mode, add
allow rules, quarantine a blocked file, or infer maliciousness. Policy inventory,
proposal generation, audit-to-enforce eligibility, and rollback are later M/L
work after this sensor is reliable.

## Remaining ranked backlog

Impact is 1–5. Effort weights are S=1, S–M=1.5, M=2, M–L=2.5, L=3.
Impact/effort is only a sequencing aid.

| Rank | Proposal | Status | Impact | Effort | Impact / effort | Primary mode |
|---:|---|:---:|---:|:---:|---:|---|
| 1 | ATT&CK v19.2 versioned registry and migration | **PROPOSED** | 5 | S–M | 3.33 | Detect / Visualize / Audit |
| 2 | PowerShell Operational sensor with protected-content handling | **PROPOSED** | 5 | S–M | 3.33 | Detect / Harden |
| 3 | EPSS v5 + KEV + SSVC host-risk queue | **PROPOSED** | 4 | S–M | 2.67 | Harden / Prioritize |
| 4 | Event-driven Task Scheduler and BITS persistence sensor | **PROPOSED** | 4 | S–M | 2.67 | Detect / Respond |
| 5 | App Control policy inventory/audit-to-enforce lifecycle | **PROPOSED** | 5 | M | 2.50 | Harden / Respond |
| 6 | Browser credential and session-theft guard | **PROPOSED** | 5 | M | 2.50 | Detect / Respond |
| 7 | Windows authentication-protocol and ticket analytics | **PROPOSED** | 5 | M | 2.50 | Detect / Harden |
| 8 | Strict Sigma 2.1 correlation runtime | **PROPOSED** | 5 | M–L | 2.00 | Detect / Visualize |
| 9 | NTFS execution and deletion forensic timeline | **PROPOSED** | 4 | M | 2.00 | Investigate / Recover |
| 10 | Token-impersonation behavior chain | **PROPOSED** | 5 | L | 1.67 | Detect / Respond |
| 11 | TPM/VBS evidence checkpoints and measured-boot posture | **PROPOSED** | 4 | M–L | 1.60 | Harden / Audit |

---

## ATT&CK v19.2 versioned registry and migration

**Status: PROPOSED.** Replace the hand-maintained v14 heatmap taxonomy with a
digest-pinned ATT&CK v19.2 registry so the UI, detection packages, AARs, and
coverage claims use the same current object identities.

### Why now and expected value

ATT&CK v19 split the former Defense Evasion tactic into **Stealth** and
**Defense Impairment**. The August 2026 v19.2 agile release also added current
group/software content tied to token theft, CI/CD supply-chain compromise, and
phishing that induces users to execute attacker-controlled actions. Angerona's
`attack_tracker.py:21` still labels its order as Enterprise v14. That is not a
cosmetic mismatch: new tactic identities, revoked objects, Detection Strategies,
and Analytics cannot be represented truthfully in current coverage reports.

Primary sources:

- [MITRE ATT&CK v19.2 update, August 2026](https://attack.mitre.org/resources/updates/updates-august-2026/)
- [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/)
- [MITRE versioned STIX 2.1 data index](https://github.com/mitre-attack/attack-stix-data/blob/master/index.md)

### Build scope

- Add `core/attack_catalog.py` to load one vendored, exact version of the
  official Enterprise STIX 2.1 bundle. Store version, SHA-256, ingest time, and
  source URL; never load the moving `latest` object in production.
- Replace static tactic/name lookups in `attack_tracker.py` and
  `attack_coverage.py` with immutable registry views. Preserve revoked and
  deprecated IDs as historical aliases rather than silently remapping evidence.
- Extend detection-package validation to require a known active technique,
  Detection Strategy, or Analytic identifier for the pinned registry version.
- Add a migration report: old tactic, new tactic, changed technique, revoked ID,
  unmapped local detector, and unsupported data component.
- Update the ATT&CK GUI to show **observed**, **tested**, **respondable**, and
  **unsupported telemetry** independently. A technique name in a static catalog
  must not count as detection coverage.

### Acceptance tests

1. The vendored bundle digest and version are exact; unknown JSON fields are
   ignored only after size/depth/count admission.
2. All current detector tags resolve to one active or historical ATT&CK object.
3. v19 Stealth/Defense Impairment tactic membership renders correctly, while a
   v14 export remains reproducible as a historical snapshot.
4. Revoked IDs, duplicate external IDs, malformed STIX references, cyclic
   relationships, and oversized bundles fail closed.
5. Coverage totals are derived from registered sensors/tests/actions, never from
   the number of catalog objects.

### Safety and limits

The bundle is inert reference data. It cannot install code, create detections,
or authorize response. This provides current taxonomy and honest coverage—not
automatic detection of every v19.2 technique.

---

## PowerShell Operational sensor with protected-content handling

**Status: PROPOSED.** Collect event 4104 (and bounded 4103 metadata) from the
PowerShell Operational channel and feed exact, provenance-bearing script blocks
into the existing AMSI, Sigma, evidence, and correlation paths.

### Why now and expected value

Microsoft documents that Script Block Logging writes event 4104 to
`Microsoft-Windows-PowerShell/Operational`. Angerona's AMSI bridge already has a
handler for a `script_block` field and its comments say it arrives from 4104,
but no current module collects that channel. As a result, an existing analytic
path is largely disconnected from its highest-fidelity supported source.

Primary sources:

- [Microsoft PowerShell logging and event 4104](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1)
- [Microsoft PowerShell security features](https://learn.microsoft.com/en-us/powershell/scripting/security/security-features?view=powershell-7.6)

### Build scope

- Add a Windows-only `PowerShellOperationalSensor(BaseModule)` using the modern
  Windows Event Log subscription/query API and the same authenticated cursor
  pattern as `sysmon_listener.py`.
- Normalize provider, engine version, runspace, process ID, script block ID,
  message sequence, and bounded content. Reassemble multi-part 4104 messages only
  when every part, sequence, provider, and correlation identity matches.
- Route script content to `amsi_bridge` and the detection registry as untrusted
  evidence. Content must never be interpreted as a command to Angerona or ARIA.
- Treat Protected Event Logging ciphertext as an opaque, healthy protected
  record unless an operator has configured a local decryption certificate. Do
  not downgrade protection merely to make content readable.
- Add telemetry posture for channel absent, logging disabled, access denied,
  cursor rollback, log cleared, dropped, truncated, protected, and complete.
- Apply field-level privacy: raw script content remains local/case-scoped;
  routine dashboards show digest, classification, length, and redacted snippets.

### Acceptance tests

1. Single and multi-fragment 4104 fixtures reconstruct exactly once; missing,
   duplicate, reordered, or cross-runspace fragments remain incomplete.
2. An EICAR-style inert script fixture reaches AMSI without executing.
3. Cursor restart, rollover, clear, access-denied, protected-event, large-event,
   and flood fixtures produce explicit coverage state.
4. Prompt-like text, XML entities, control characters, secrets, and output that
   resembles a tool call remain inert and are redacted at export boundaries.
5. A 100,000-event replay stays within configured queue, memory, and latency
   budgets and never blocks the Qt thread.

### Safety and limits

Collection is read-only. Angerona should report whether logging is enabled but
must not silently enable Group Policy, transcription, or broad content logging.
Script logs can contain secrets; local retention and protected logging matter.

---

## EPSS v5 + KEV + SSVC host-risk queue

**Status: PROPOSED.** Turn the existing host-applicable KEV view into a
versioned prioritization queue that distinguishes active exploitation, near-term
exploit probability, host applicability, business impact, and VEX evidence.

### Why now and expected value

FIRST's EPSS v5 began publishing in June 2026 and estimates the probability that
a CVE will be exploited in the next 30 days. CISA states KEV should be an input
to vulnerability prioritization, while SSVC supplies a decision tree for action
based on exploitation and organizational impact. Angerona currently correlates
KEV and has a generic VEX type, but no EPSS ingestion or deterministic SSVC
decision record. This addition would improve remediation order without claiming
that a CVSS number alone equals risk.

Primary sources:

- [FIRST EPSS overview](https://www.first.org/epss/)
- [FIRST EPSS v5 data and version history](https://www.first.org/epss/data.html)
- [CISA SSVC guide](https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide%20508c.pdf)
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

### Build scope

- Extend `intel_sync.py` with one bounded daily EPSS CSV fetch. Retain source
  URL, redirect result, compressed and expanded sizes, SHA-256, model version,
  publish date, fetch time, and expiry. Prefer one daily bulk artifact over N+1
  API requests.
- Join EPSS only to CVEs already mapped to a privacy-minimized local component.
  A high EPSS score on software not installed locally cannot raise host risk.
- Add an SSVC decision record with typed operator context: exploitation state,
  technical impact, mission prevalence, exposure, safety impact, compensating
  control, decision, evidence IDs, author, timestamp, and expiry.
- Preserve separate columns for `KEV`, `EPSS probability`, `EPSS percentile`,
  `CVSS`, `host applicability`, `VEX status`, and `SSVC decision`. Do not collapse
  them into an unexplained magic score.
- Let KEV/critical SSVC decisions create a signed remediation proposal; actual
  patching remains under the existing exact plan, receipt, and rollback path.

### Acceptance tests

1. EPSS v4-to-v5 model boundaries are visible and never graphed as ordinary
   risk movement.
2. Stale, future-dated, truncated, decompression-bomb, duplicate-CVE, invalid
   probability, redirect, TLS, and digest failures preserve the last trusted
   snapshot and mark it stale.
3. KEV + installed + affected ranks above high EPSS + not installed; a valid,
   current `not_affected` VEX changes applicability but never deletes history.
4. Every queue decision is reproducible from the retained source revisions and
   typed context.

### Safety and limits

EPSS is probability, not impact or proof of exploitation. SSVC is a decision
framework, not an automatic patch command. No feed field may provide executable
remediation text.

---

## Event-driven Task Scheduler and BITS persistence sensor

**Status: PROPOSED.** Supplement five-minute, name-only persistence polling with
event-driven creation/change/deletion evidence and exact task/job attributes.

### Why now and expected value

MITRE's current T1053.005 strategy correlates task creation/modification/deletion
with execution context and the child launched by Task Scheduler. Microsoft
recommends Task Scheduler Operational events 106, 141, and 142 for intrusion
detection. BITS jobs can persist across reboot, transfer files, and execute a
completion command, yet Angerona currently only treats `bitsadmin` as a suspicious
string; it has no BITS job inventory or event source.

Primary sources:

- [MITRE ATT&CK T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [Microsoft Windows Event Forwarding intrusion-detection subscriptions](https://learn.microsoft.com/en-us/windows/security/operating-system-security/device-management/use-windows-event-forwarding-to-assist-in-intrusion-detection)
- [MITRE ATT&CK T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197/)

### Build scope

- Add a cursor-backed operational-channel sensor for Task Scheduler and
  BITS-Client. Normalize task/job GUID, name token, author/principal token,
  trigger type, run level, hidden flag, action executable identity, arguments
  digest, remote/local origin, timestamps, and lifecycle state.
- On an event, query the exact local object through supported read-only Task
  Scheduler/BITS COM APIs. Bind the returned object identity to the triggering
  event and revalidate after reading.
- Correlate task registration -> task start -> child process -> network/file
  activity. Correlate BITS create/modify -> transfer -> notify command -> child.
- Keep the current periodic inventory as a backstop and reconcile differences.
  An object seen only by polling or only by events becomes a visibility finding.
- Multi-signal, exact-identity findings may request Combat suspension/quarantine
  of the launched process/file. Deleting a task or BITS job requires a distinct
  response action with backup/export and exact Undo; do not overload file delete.

### Acceptance tests

1. Create/change/delete/start/complete sequences correlate across event and COM
   fixtures; hidden tasks and renamed jobs retain stable identity.
2. Benign Windows Update and browser updater fixtures remain low/noise through
   signer, path, principal, and schedule allow rules.
3. Name reuse, task replacement, event loss, cursor rollback, COM timeout,
   malformed XML, and job disappearance never target the replacement object.
4. The detector catches an inert task/BITS simulation without creating a real
   task, job, network transfer, or persistence mechanism in tests.

### Safety and limits

Sensors and inventory are read-only. Automated containment must target only a
verified child/file under an existing policy. Task/job deletion is reversible,
separately authorized, and never inferred from a suspicious name alone.

---

## App Control policy inventory and audit-to-enforce lifecycle

**Status: PROPOSED (later work after the selected sensor).** Once the phase-1
sensor above is proven, inventory active policy identities and measure
compatibility before any enforcement recommendation.

### Why now and expected value

Microsoft identifies event 3076 as an audit would-block, 3077 as an enforcement
block, and 3089 as correlated signature information. The Correlation ActivityID
is required to interpret why a file failed policy. Angerona currently checks
whether the Code Integrity channel exists and hashes the driver set, but it does
not consume these decision events or inventory active App Control policies.

Primary sources:

- [Microsoft App Control debugging: events 3076, 3077, and 3089](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting)
- [Microsoft configuring App Control and audit mode](https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-app-control-for-business)

### Build scope

- Add a cursor-backed Code Integrity/AppLocker sensor. Correlate 3076/3077 with
  all 3089 signature records by ActivityID; preserve requested/validated signing
  level, verification error, policy ID, publisher/issuer token, file hashes,
  package family, parent, and disposition.
- Inventory active base/supplemental policy IDs, version, mode, options, signer,
  deployment source, and last change. Treat unknown or unreadable policy state as
  degraded—not compliant.
- Add an App Control flight recorder that groups would-blocks by immutable file
  identity and business application, shows first/last seen and execution count,
  and marks missing signature fragments.
- Generate a proposed supplemental policy only through a strict data model. The
  proposal stays inert, signed, previewable, diffable, and rollback-bound.
- Enforcement eligibility requires a clean observation window, zero unresolved
  critical workload blocks, backup, supported edition, policy signature, reboot
  plan, recovery media, and post-boot verification. Initial delivery should stop
  at audit and proposal.

### Acceptance tests

1. Multi-signature 3089 records join the correct 3076/3077 and never cross an
   ActivityID or boot boundary.
2. Missing/duplicate signature records, mutable file names, replaced files,
   unsigned files, and conflicting policies remain explicit.
3. Policy generation is deterministic and rejects path-wildcard broadening,
   unknown XML, unsigned policy, downgrade, and non-reversible deployment.
4. A clean-machine application corpus runs in audit mode with measured false
   positives before enforcement can be enabled.

### Safety and limits

App Control can break Windows or line-of-business software. This is audit-first;
no silent policy enablement, no broad allow rule, and no claim of enforcement
until clean-machine/recovery testing exists.

---

## Browser credential and session-theft guard

**Status: PROPOSED.** Detect non-browser access to credential/cookie stores and
suspicious memory access to browser processes, then correlate that access with
process lineage and outbound activity.

### Why now and expected value

MITRE's 2025/2026 Detection Strategies specifically recommend correlating
browser credential-store access with `CryptUnprotectData`, process access, or
subsequent network behavior. Session cookie theft can bypass some MFA controls.
Angerona detects LSASS dumping but has no browser credential/cookie path model,
no targeted file-read telemetry, and no T1555.003/T1539 behavior chain.

Primary sources:

- [MITRE DET0037: suspicious browser credential-store access](https://attack.mitre.org/detectionstrategies/DET0037/)
- [MITRE DET0509: web session cookie theft](https://attack.mitre.org/detectionstrategies/DET0509/)
- [Microsoft event 4663 object access](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4663)

### Build scope

- Add a browser-store registry with exact per-browser roots, store roles, and
  expected signed browser/updater processes. Store only normalized root tokens,
  never cookie values, URLs, usernames, or database contents.
- Offer opt-in, narrowly scoped SACL creation for credential/cookie database
  files and collect 4656/4663 only for those roots. Preview the expected volume,
  save the original ACL, and support exact rollback.
- Correlate object access with Sysmon 1/10, signer/hash, process birth, browser
  state, DPAPI audit metadata when available, file-copy creation, archive
  creation, and outbound connection. One file read is evidence, not guilt.
- Add an immutable allow policy for supported browser processes and reviewed
  backup/password-manager software. Basename alone never establishes trust.
- A high-confidence chain may submit exact process suspend/isolate through
  Combat. Never delete a browser profile or invalidate cookies automatically.

### Acceptance tests

1. Chrome/Edge/Firefox store fixtures normalize without retaining profile names
   or content; unknown versions degrade gracefully.
2. Browser self-access, browser update, backup, indexer, AV scan, and password
   manager fixtures do not trigger a high-confidence chain.
3. Non-browser read -> DPAPI/process access -> archive/network sequence triggers;
   reordered, stale, cross-user, or replacement-identity sequences do not.
4. SACL preview/apply/rollback is exact, journaled, idempotent, and refused on an
   unsupported filesystem, reparse path, missing backup, or excessive event rate.

### Safety and limits

Never read, copy, decrypt, export, or display credentials/cookies. File auditing
is opt-in because it changes ACLs and can be noisy. Automated response targets
only a verified suspect process under an explicit policy.

---

## Windows authentication-protocol and ticket analytics

**Status: PROPOSED.** Expand identity telemetry from basic logon events into a
privacy-minimized graph of NTLM fallback, Kerberos encryption/ticket anomalies,
explicit credentials, DPAPI master-key activity, and credential-protection
posture.

### Why now and expected value

Microsoft documents Kerberos 4768/4769 fields that expose RC4 usage and accounts
that only support RC4. Advanced auditing also provides 4771/4776, explicit-logon
and DPAPI events. Credential Guard protects NTLM hashes and Kerberos TGTs but has
edition/hardware/compatibility conditions. Angerona's ETW listener currently
collects only 4688, 4624, and 4672, while `IdentityAnalytics` operates on a much
simpler success/source/account model.

Primary sources:

- [Microsoft advanced audit policy event map](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft detecting and remediating Kerberos RC4](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft Credential Guard overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/)

### Build scope

- Expand the Security-channel sensor with typed parsers for 4625, 4634, 4648,
  4768, 4769, 4771, 4776, 4692-4695, 5376/5377, and relevant session reconnect
  events. Use XML named fields, not positional `StringInserts` heuristics.
- Convert account SID/name, source, workstation, SPN, logon ID, ticket options,
  encryption types, process, and device into keyed local tokens before analytics.
- Add bounded rules for RC4 ticket use, downgrade/new encryption type, NTLM
  fallback by application/peer, impossible ticket-without-logon chains,
  privileged explicit credentials, DPAPI master-key backup/recovery, and
  Credential Guard/LSA protection drift.
- Domain-controller-only evidence should arrive through a separately configured
  Windows Event Forwarding/import contract. A standalone endpoint must show
  `domain evidence unavailable`, not infer that no ticket threat occurred.
- Generate an NTLM/RC4 compatibility report before hardening. Disabling legacy
  authentication remains an operator-approved GPO/MDM change outside ordinary
  Combat authority.

### Acceptance tests

1. Versioned XML fixtures for supported client/server editions parse exact named
   fields; missing fields remain unknown.
2. RC4 use, unsupported-encryption failure, password spray, ticket-without-logon,
   and explicit-credential chains trigger only inside typed time/entity windows.
3. Service accounts, local accounts, offline devices, clock skew, DC duplication,
   and forwarded-event replay have documented low-noise behavior.
4. All retained/exported identity fields remain pseudonymized and tenant-scoped;
   key rotation has an explicit correlation-break boundary.

### Safety and limits

No password, ticket, hash, DPAPI blob, or authentication secret is collected.
Angerona must not disable NTLM, RC4, Credential Guard exceptions, or delegation
automatically; compatibility and domain authority are external constraints.

---

## Strict Sigma 2.1 correlation runtime

**Status: PROPOSED (carried-forward gap, refreshed).** Extend the safe
single-event Sigma subset with a compiled, resource-admitted subset of the
official 2.1 correlation specification.

### Why now and expected value

Sigma 2.1 standardizes event-count, value-count, temporal, and ordered-temporal
correlations. Angerona's current matcher supports only simple selections and
boolean conditions over one flattened event. Most of the proposals above are
behavior chains; implementing each as bespoke Python would fragment field
mapping, testing, tuning, and provenance.

Primary sources:

- [Sigma 2.1 correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)
- [Sigma rule specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html)

### Build scope

- Add a strict compiler for four bounded correlation types: `event_count`,
  `value_count`, `temporal`, and `temporal_ordered`. Reject unsupported
  aggregations, unknown YAML tags, free-form backends, query strings, and
  extension code.
- Introduce a versioned Angerona Sigma taxonomy for process, file, registry,
  DNS, network, authentication, driver, sensor health, and response receipts.
- Compile each rule into fixed predicate and state plans with maximum windows,
  groups, distinct values, events, bytes, regex cost, late-event tolerance, and
  per-second evaluations. Required fields missing from a sensor produce
  `unsupported coverage`, not a false clean result.
- Admit only signed rule packages with source digest, compiler version, ATT&CK
  v19.2 IDs, fixtures, expected false positives, performance budget, expiry,
  staged activation, hot-rule circuit breaker, and rollback.
- Correlation findings may create typed proposals, but rules cannot grant
  response authority; the existing contract/broker re-derives authorization.

### Acceptance tests

1. Official-style fixtures for each supported correlation type match exact
   grouping, ordering, window, threshold, alias, and late-event behavior.
2. Alias collisions, missing fields, clock regression, high-cardinality groups,
   regex abuse, YAML bombs, duplicate IDs, and cyclic rule references fail
   closed or trip a bounded rule-only circuit breaker.
3. A million-event mixed replay demonstrates fixed memory and predictable CPU;
   one pathological rule cannot stall other detectors or the GUI.
4. A signed update canary-promotes, reports precision/latency deltas, and rolls
   back without losing the previous compiled rule set.

### Safety and limits

Sigma content is declarative and non-executable. Supporting a safe subset must
not be advertised as full Sigma compatibility. Community-rule quantity is not
detection quality; every active rule requires local fixtures and cost admission.

---

## NTFS execution and deletion forensic timeline

**Status: PROPOSED.** Build a read-only, case-scoped timeline from the USN
journal and selected execution artifacts so investigators can reconstruct files
that appeared, executed, renamed, or disappeared before Angerona raised an alert.

### Why now and expected value

Windows exposes `FSCTL_READ_USN_JOURNAL` and `FSCTL_ENUM_USN_DATA` for NTFS
change records. Velociraptor's maintained forensic documentation shows why USN,
Prefetch, Amcache, BAM, and related artifacts provide evidence of execution that
live process monitoring no longer has. Angerona's forensics module currently
captures live suspect-process memory strings, sockets, and shell history, but it
does not build a disk execution/deletion timeline.

Primary sources:

- [Microsoft NTFS change-journal operations](https://learn.microsoft.com/en-us/windows/win32/fileio/change-journal-operations)
- [Velociraptor evidence-of-execution reference](https://docs.velociraptor.app/docs/forensic/evidence_of_execution/)
- [Velociraptor Prefetch artifact](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.prefetch/)
- [Velociraptor Amcache artifact](https://docs.velociraptor.app/artifact_references/pages/windows.system.amcache/)

### Build scope

- Phase 1: implement a Windows-only read-only USN reader with an authenticated
  per-volume cursor containing volume serial, journal ID, next USN, last record,
  and checkpoint time. Detect journal deletion/recreation, wrap, unsupported
  filesystem, access denial, and volume identity change.
- Normalize reason flags, file reference/parent reference, timestamp, attributes,
  and a privacy-minimized path token. Resolve full paths lazily and only for a
  case time window or exact evidence target.
- Phase 2: add offline, bounded parsers for Prefetch and Amcache snapshots using
  copied case artifacts, never live mutable originals. Record parser version,
  source file digest, acquisition method, timestamps, and interpretation limits.
- Join filesystem events, Prefetch executions, Amcache first-seen records,
  Sysmon process/file events, YARA, and response receipts into the existing case
  timeline. Distinguish observed timestamp from inferred execution.
- Export content-addressed JSON/CSV evidence with custody metadata and redaction;
  never automatically collect an entire disk or all user files.

### Acceptance tests

1. Synthetic USN v2/v3 records, rename old/new pairs, deletion, hard links,
   journal wrap/reset, sparse batches, and volume replacement have deterministic
   results and explicit gaps.
2. Cursor restart is exactly-once where the journal permits; rollback/tamper is
   rejected and never silently seeks to the current end.
3. Prefetch/Amcache malformed, compressed, oversized, future-version, and
   timestamp-conflict fixtures remain bounded and preserve raw-source custody.
4. A case time window over millions of records stays within time/memory/disk
   budgets and avoids collecting unrelated path content.

### Safety and limits

Read-only forensic metadata can still be privacy-sensitive. Collection is local,
case-scoped, cancellable, and retention-bound. USN/Prefetch/Amcache provide
artifacts and inferences—not proof that a user intentionally executed malware.

---

## Token-impersonation behavior chain

**Status: PROPOSED.** Detect token duplication/impersonation and process creation
under an unexpected security context using process access, logon/session, API,
and lineage evidence.

### Why now and expected value

MITRE's DET0482 and DET0283, created in October 2025 and updated in May 2026,
describe a Windows behavior chain joining token APIs such as
`DuplicateTokenEx`, logon/session metadata, Sysmon ProcessAccess 10, and a child
running under a mismatched context. Angerona lists T1134/T1134.001 in its heatmap
and maps a hypothetical `token_elevation` event, but no current sensor emits that
event and no token-specific module exists.

Primary sources:

- [MITRE DET0482 Token Impersonation/Theft](https://attack.mitre.org/detectionstrategies/DET0482/)
- [MITRE DET0283 Access Token Manipulation](https://attack.mitre.org/detectionstrategies/DET0283/)

### Build scope

- Phase 1 (supported telemetry): correlate Security 4624/4634/4648/4672,
  Sysmon 1/10, process birth/parent, executable signer/hash, session/logon ID,
  integrity level, user SID token, privileges, and service identity.
- Phase 2 (capability-gated): investigate a supported ETW provider that supplies
  token API/assignment evidence on the exact Windows build. Do not invent a
  universal `ETW:Token` claim; provider/schema/access must be proven per build.
- Detect a bounded chain: unusual access to a privileged process/token source ->
  token duplication/assignment evidence when available -> new/existing process
  with mismatched principal/session/lineage -> privileged action or connection.
- Maintain exact signed allow rules for services, brokers, schedulers, security
  products, and accessibility components that legitimately impersonate.
- High-confidence response may suspend the exact newly created process through
  Combat. Host isolation requires additional corroboration and separate policy.

### Acceptance tests

1. Service control manager, Task Scheduler, UAC broker, IIS/service account, and
   remote administration fixtures establish the legitimate baseline.
2. Token-source access -> context switch -> child/connection sequence triggers;
   missing API evidence reduces confidence rather than fabricating completeness.
3. PID/token-handle reuse, process exit, session reconnect, Fast User Switching,
   clock skew, PPID spoofing, stale ETW schema, and protected-process denial do
   not bind unrelated entities.
4. Every supported Windows build has provider/schema fixtures and a visibility
   self-test; unsupported builds show partial coverage.

### Safety and limits

Observation only; never duplicate, open, steal, impersonate, or manipulate a
token. Full fidelity may require telemetry unavailable to an ordinary user-mode
process. No kernel hook or unsupported provider is justified merely to improve a
coverage percentage.

---

## TPM/VBS evidence checkpoints and measured-boot posture

**Status: PROPOSED.** Replace the current TPM outline with hardware-backed
checkpoint signatures and boot-state evidence so copied/rolled-back journals are
distinguishable from the current host's evidence chain.

### Why now and expected value

Microsoft's Platform Crypto Provider stores non-exportable keys in the TPM, and
Windows Measured Boot records firmware, bootloader, kernel, and early driver
measurements. TCG TPM 2.0 v185 was released in March 2026. Angerona's Combat and
EventBus journals are HMAC protected, but a compromised Administrator can copy
old software key material and an old journal together. `hardware_crypto.py`
explicitly leaves TPM sealing as an unimplemented outline.

Primary sources:

- [Microsoft CNG Platform Crypto Provider](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/cng-key-storage-providers)
- [Microsoft secure/measured Windows boot](https://learn.microsoft.com/en-us/windows/security/operating-system-security/system-security/secure-the-windows-10-boot-process)
- [TCG TPM 2.0 Library v185](https://trustedcomputinggroup.org/resource/tpm-library-specification/)

### Build scope

- Use Windows CNG `MS_PLATFORM_CRYPTO_PROVIDER` through a small reviewed native
  boundary to create a non-exportable signing key. Do not depend on Linux-focused
  `tpm2-pytss` for the Windows production path.
- Periodically sign the current EventBus/Combat journal root, segment number,
  boot generation, policy digest, application build digest, and prior checkpoint.
  Store public verification material and signed checkpoint beside the journal.
- Optionally record a privacy-minimized measured-boot/DHA posture assertion:
  Secure Boot, debug/test-signing, BitLocker, ELAM, and boot-counter state. Keep
  local verification distinct from Microsoft/Azure remote attestation.
- Maintain a software-HMAC compatibility mode, clearly labeled `software-root`.
  TPM enrollment, loss, motherboard replacement, Secure Boot change, recovery,
  and key rotation require explicit receipts and exported recovery metadata.
- Hardware evidence raises confidence but does not grant response authority.

### Acceptance tests

1. Fake CNG provider tests cover create/open/sign/verify/delete, non-exportable
   key behavior, ACL failure, TPM unavailable/cleared/locked, and key rotation.
2. Copying an old journal plus old software files after a newer TPM checkpoint is
   detected as rollback; a normal crash before the next checkpoint has a bounded,
   explicit uncheckpointed tail.
3. Boot counter change, motherboard/TPM replacement, firmware update, Secure Boot
   change, test-signing, and recovery workflows never destroy evidence silently.
4. Physical Windows testing proves shutdown, sleep/resume, BitLocker recovery,
   Windows Update, TPM firmware update, backup/restore, and uninstall behavior.

### Safety and limits

TPM integration can lock users out of evidence if recovery is poorly designed.
It must be optional until physical-host recovery testing passes. A TPM does not
make a Python user-mode EDR tamper-proof against Administrator/SYSTEM, and local
measured-boot parsing is not equivalent to independent remote attestation.

---

## Recommended implementation sequence

### Immediate S–M delivery

Implement the selected **App Control Decision Evidence Sensor** through the
phase-1 boundary only: read, correlate, persist continuity, expose health, and
test. Do not combine the sensor landing with policy deployment or enforcement.

### Phase A — current taxonomy and immediately usable telemetry

1. ATT&CK v19.2 registry/migration.
2. PowerShell Operational sensor.
3. EPSS/KEV/SSVC prioritization.
4. Task Scheduler/BITS event sensor.

These reuse existing cursors, evidence storage, signed content, AMSI, identity,
and UI primitives. They add high-value evidence without a new privileged binary.

### Phase B — prevention and behavior chains

5. App Control policy inventory and audit-to-enforce lifecycle.
6. Authentication-protocol/ticket analytics.
7. Browser credential/session guard.
8. Sigma 2.1 correlations, initially powering the reviewed chains above.

### Phase C — deeper DFIR and hardware trust

9. USN/Prefetch/Amcache case timeline.
10. Token manipulation, only at the fidelity the supported OS exposes.
11. TPM checkpoint prototype followed by physical recovery/soak testing.

## Non-proposals and claim discipline

- Do not add an exploit runner, credential dumper, real persistence simulator,
  arbitrary shell, remote scanner, hack-back capability, or EDR-evasion lab.
- Do not load an unsigned/custom kernel driver to improve visibility. Optional
  memory acquisition is a separate operator-led DFIR workflow and is not needed
  for this ranked plan.
- Do not market catalog membership, a Sigma rule count, or a simulation match as
  independent real-world detection efficacy.
- Do not silently enable Script Block Logging, SACLs, App Control enforcement,
  NTLM blocking, Credential Guard, or TPM sealing. Each changes privacy,
  compatibility, or recovery conditions and needs an explicit governed plan.
- Do not call the current OCSF 1.8 label, Community ID, Sysmon range, ARIA model
  pack, or Combat receipts missing; those capabilities are already built.

## Research conclusion

The strongest near-term upgrade is a **versioned detection spine**: current
ATT&CK objects, direct PowerShell/task/authentication evidence, and bounded Sigma
correlations, all tied to exact sensor coverage and signed content. That would
let Angerona prove not merely that it has a detector name, but which supported OS
event produced the evidence, which versioned analytic evaluated it, which fields
were missing, what response contract was admitted, and whether the response
postcondition actually closed the incident.

## Implementation audit — phase-1 App Control sensor (loop 2)

**Audit status: BUILT, but not yet contract-complete.** Read-only review of
`app_control_evidence.py`, `app_control_monitor.py`, and their two focused test
files on 2026-08-25. The implemented 3076/3077 disposition mapping, GUID
normalization, named-field parsing, 3089 ActivityID join in either in-process
arrival order, fixed Code Integrity channel, authenticated cursor, XML/field
bounds, observe-only authority, and clear/high-watermark health event are sound
phase-1 foundations. The focused test run is green: **11 passed**. Microsoft
confirms that 3076 is audit-would-block, 3077 is an enforced block, 3089 is one
row per signature (or one row with total zero when unsigned), indexes start at
zero, and ActivityID is the supported join key ([event IDs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations),
[field semantics](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting)).

### Must fix before calling phase 1 complete

1. **Fail malformed 3089 cardinality closed.** `_ready()` currently ignores an
   unparsable/missing `TotalSignatureCount` and defaults to one, so a row with
   `TotalSignatureCount=abc` and `Signature=0` can be labeled `complete`.
   Negative totals and impossible indexes are also not rejected. Validate the
   total and index as bounded integers, require one row for every exact index
   `0..total-1`, cap the total at 64, and emit `untrusted` for malformed,
   duplicate-critical-field, negative, out-of-range, or conflicting metadata.
   A total-zero row must expose `signature_state=unsigned`; signed completion,
   partial, and untrusted must remain distinct. Add table-driven fixtures for
   missing, text, negative, 65+, duplicate, and out-of-range values.

2. **Make reordered joins restart-safe.** Only the record cursor is persisted.
   If 3089 is consumed and checkpointed, the process restarts, and 3077 then
   arrives, the signature group is lost and the decision expires partial. Store
   a separate authenticated, atomic, schema-versioned, hard-bounded pending
   state (or replay an authenticated bounded look-back without duplicate
   findings). Acceptance: `3089 -> checkpoint -> new sensor instance -> 3077`
   completes exactly once, including tampered/truncated pending-state cases.

3. **Prove retention and channel-generation continuity.** The event-source
   contract exposes only the newest record ID, so it cannot detect a saved
   cursor that is older than the oldest retained record. Moreover, after a
   detected clear/regression, the correlator retains old `_seen_records`; reused
   record IDs in the new channel generation can be falsely marked conflicts.
   Query the oldest retained ID and a channel-generation marker where supported,
   report the exact missing interval, rotate/reset correlation and dedupe state
   on a proved generation change, and resume at the oldest retained record.
   Add stale-below-oldest and `old ID 1 -> clear -> new ID 1` fixtures.

4. **Enforce per-group memory bounds.** Group count and XML fields are bounded,
   but the signature-index dictionary and decision list for one ActivityID are
   not. Cap signatures at 64 and decisions at a small tested bound; overflow is
   `untrusted`/`bounded-eviction`, never silently complete. Exercise adversarial
   distinct indexes and repeated compatible decisions across multiple polls.

5. **Meet or narrow the privacy claim.** The event message uses a basename, but
   `details` retains exact `file_name`/`process_name`, the alert detail UI renders
   the full details object, and the generic OCSF mapper copies details into
   `unmapped`. A `sensitive_fields` label is metadata, not redaction. Before
   claiming the phase-1 privacy contract, either keep exact paths only in the
   protected evidence tier and give ordinary UI/default exports keyed tokens, or
   explicitly narrow the documented guarantee and block this sensor from
   unsanitized egress. Add UI, OCSF, audit-export, and IR-bundle privacy snapshots.

### Acceptable documented future hardening

- Provider-name validation, full timestamp/hash/Boolean/signing-level typing,
  and a formal health enum are valuable hardening after the five items above;
  the fixed channel and observe-only authority limit their immediate impact.
- Supporting multiple compatible per-policy block rows under one ActivityID
  should be tested against captured Windows fixtures before changing the join.
  Microsoft documents one 3076/3077 per blocking policy, but the reviewed
  documentation does not promise whether those policy rows reuse an ActivityID.
- Advancing an idle selected-event cursor to a safely observed channel watermark
  would prevent repeated scans when unrelated Code Integrity events dominate;
  this is a performance fix, not evidence-semantic completion.
- AppLocker 8028/8029/8038, `CiTool` policy inventory, policy deployment,
  audit-to-enforce eligibility, and automatic response remain phase-2 features.
  Their absence must not weaken or delay this read-only sensor's truthfulness.

## Loop 3 closure audit — App Control phase 1

**Verdict: four of five blockers are closed; channel-generation continuity has
one remaining correctness blocker.** The final focused run completed with
**30 passed in 2.55 seconds**.

| Phase-1 blocker | Closure evidence | Result |
|---|---|---|
| Strict 3089 cardinality | `app_control_evidence.py:384-425,485-513` rejects missing, duplicate, non-integer, negative, greater-than-64, and out-of-range count/index metadata; `:81-90` distinguishes unsigned/signed/partial/untrusted. The malformed-cardinality fixtures are at `tests/test_app_control_evidence.py:116-148`. | **CLOSED** |
| Restart-safe authenticated pending groups and save ordering | HMAC-bound atomic pending state is implemented at `app_control_monitor.py:261-339`; `_save_checkpoint()` writes pending correlation/dedupe state before advancing the cursor at `:468-480`; authenticated restore or retained-evidence replay is at `:486-513`. Restart, tamper, and pending-save-failure tests are at `tests/test_app_control_monitor.py:159-214,273-284`. | **CLOSED** |
| Oldest-retained/channel-clear continuity and dedupe reset | Oldest-retained range gaps and simple record-number regression call `flush_all()`/`reset()` and report the interval at `app_control_monitor.py:551-584`; the tested clear-to-empty case is closed. The refill-past-cursor case below is not. | **OPEN** |
| Per-group hard bounds | Constants and constructor clamps are at `app_control_evidence.py:17-22,320-331`; live decision/signature eviction is enforced at `:463-518`; imported state is bounded at `:640-715`. The one-ActivityID pressure fixture is at `tests/test_app_control_evidence.py:215-250`. | **CLOSED** |
| Privacy-safe EventBus/UI/export details | `CorrelatedDecision.details()` emits basenames, keyed path tokens, and a signature allowlist rather than exact paths at `app_control_evidence.py:54-146`; the sensor uses it at `app_control_monitor.py:391-404` and policy details are allowlisted at `:406-431`. Therefore the generic UI and OCSF mapper receive the sanitized object. The direct privacy fixture is at `tests/test_app_control_evidence.py:151-171`. | **CLOSED** |

### Remaining must-fix: detect clear-and-refill past the cursor

The persisted cursor contains only channel name and record number
(`app_control_monitor.py:191-219`), and the `EventSource` exposes only oldest,
newest, and `read_after` (`:39-43`). The continuity checks at `:551-584` infer a
clear only when the cursor is outside the current numeric range. That is
insufficient when the Code Integrity log is cleared and refills beyond the old
cursor before the next poll.

A read-only probe established an old cursor of 2, replaced the channel with new
records 1–4, and put a new 3077/3089 pair at records 1–2. The observed result was
`gap_reported=False`, `new_decision_seen=False`, and an advanced cursor of 4.
Thus records 1–2 from the new generation were silently skipped.

Persist and verify a channel-generation anchor, such as a canonical digest of a
retained anchor record plus the supported WEVT log identity/metadata available
on the target Windows versions. If the saved record exists with different
content, disappears while newer records remain, or the generation marker
changes, emit a gap, reset pending/dedupe state, and replay from the oldest
retained record. Add the exact probe as a deterministic fixture:
old 1–2, checkpoint 2, clear/refill new 1–4 before polling, then require a gap
and the new 1–2 decision exactly once. Until this passes, the sensor must not claim complete
channel-clear continuity, although its event parsing, correlation, bounds,
privacy, and ordinary restart behavior are phase-1 ready.

## Loop 4 verification — checkpoint anchor

**Status: the deterministic pre-poll clear/refill case is closed, but the same
continuity blocker retains a mid-poll race.** The focused App Control run is
green (**32 passed in 4.02 seconds**). Cursor schema v2 strictly requires an
HMAC-covered SHA-256 anchor (`app_control_monitor.py:216-298`), the Windows source
queries the exact record and hashes its rendered XML (`:126-148`), and the poll
compares the retained checkpoint anchor before replaying from the oldest record
on mismatch (`:673-701`). The regression at
`tests/test_app_control_monitor.py:295-327` correctly proves the originally
reported clear-and-refill-past-cursor scenario.

The remaining race is between that single anchor comparison and the subsequent
event query/checkpoint. After validation at `app_control_monitor.py:678-701`, the
sensor reads and emits rows at `:703-720`, then replaces the cursor and anchor at
`:723-729` through `_save_checkpoint()` (`:529-559`). It does not revalidate the
previous anchor or bind the newly saved anchor to the exact event snapshot that
was processed. If the channel clears after line 683 but refills past the cursor
before line 705, low-numbered records in the new generation are skipped and the
new high-record anchor is accepted.

A targeted read-only probe reproduced this sequence: validate old checkpoint 2,
clear/refill new records 1–4 immediately after `record_anchor(2)`, then allow
`read_after(2)`. Result: `gap_reported=False`,
`new_low_decision_seen=False`, cursor advanced to 4. The existing race test at
`tests/test_app_control_monitor.py:330-351` covers a clear between the oldest and
newest watermark calls, not a clear after anchor validation.

**Required closure:** obtain a consistency proof across validation and query.
At minimum, fetch the candidate rows without emitting them, revalidate the prior
checkpoint anchor immediately after the query, and abandon/reset/replay if it
changed. The new checkpoint must also be tied to the exact terminal record
snapshot admitted, rather than accepting a separately queried replacement with
the same record ID. Prefer a WEVT bookmark/query-generation mechanism when it can
surface `ERROR_EVT_QUERY_RESULT_STALE`. Add the exact mid-poll-clear probe as a
fixture. Until it passes, the pre-poll regression is fixed but full channel-clear
continuity remains **OPEN**.

## Loop 5 verification — staged-read continuity transaction

**Status: staged-read TOCTOU is closed; one final checkpoint-binding race remains.**
The focused sensor suite is green (**34 passed in 2.15 seconds**). The new path
stages raw rows without parsing/emitting (`app_control_monitor.py:775-777`),
revalidates the admitted anchor after the query (`:778-786`), samples and checks
the terminal record plus admitted anchor again (`:788-810`), and only then parses
and emits (`:812-828`). `ClearAfterFirstAnchorSource` and its regression at
`tests/test_app_control_monitor.py:64-79,348-385` cover the Loop 4 probe. Re-running
that probe now yields a gap before any staged emission, followed by a four-record
replay with the replacement decision exactly once.

The remaining boundary is inside `_save_checkpoint()`. It correctly compares
`expected_anchor` with the exact terminal record at
`app_control_monitor.py:548-567`, but after the pending-state write it queries
the terminal record again at `:580-590` and stores that new value without
comparing it to `expected_anchor`. A clear/refill between the comparison at line
561 and the second query at line 582 can therefore bridge generations: the
sensor has emitted old staged rows, but persists the replacement generation's
anchor and will trust it on the next poll.

A targeted probe flipped the channel immediately after the expected-anchor
comparison, replacing records 1–4 and refilling through record 6. Observed:
`gap_reported=False`, `new_low_seen=False`, cursor advanced to 6. This is narrower
than the staged-query regression but is the same truthfulness invariant.

**Exact closure:** when `expected_anchor` is supplied and validated, persist that
admitted value; do not replace it with a separately sampled digest. If a second
terminal query is retained after the pending write, compare it to
`expected_anchor` and fail the checkpoint on mismatch, then still store the
expected value so a clear after the final comparison is detected next poll.
Add a fixture that flips after the `_save_checkpoint` expected-anchor check and
asserts that low replacement records are replayed rather than skipped. Until
that passes, the staged-read work is correct but full continuity remains
**OPEN**.

## Loop 6 final closure — App Control continuity

**Status: CLOSED for the phase-1 contract and deterministic sensor model.** The
focused suite passes (**35 passed in 3.04 seconds**). `_save_checkpoint()` now
checks the admitted terminal anchor before the pending write, queries it again
after that write, rejects/reset-replays on disagreement, and persists the
original admitted digest rather than blessing a separately sampled generation
(`app_control_monitor.py:548-608`). `ClearDuringCheckpointSource` flips on the
exact post-admission boundary, and
`tests/test_app_control_monitor.py:404-447` proves the checkpoint is rejected and
the replacement generation is replayed from its oldest retained record.

The independent Loop 5 late-flip probe now reports a visibility gap, replays all
six replacement rows, emits `checkpoint-replacement.exe` exactly once, and ends
with an authenticated cursor at record 6. Together with the pre-poll replacement,
mid-query replacement, watermark race, retention-gap, pending-state restart,
cardinality, bounds, and privacy fixtures, this closes all five blockers from the
Loop 2 audit. No product-code blocker remains from this review.

This result is a deterministic implementation/fixture claim, not a physical-host
efficacy claim. A Windows soak should still exercise real WEVT rendering stability,
retention rollover, log clear under load, service restart, suspend/resume, and
access-denied transitions before marketing the sensor as field-proven.
