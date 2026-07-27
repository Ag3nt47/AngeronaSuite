# Innovation Ideas — Cycle 4, Round 1 (2026-07-27)

This is a defensive-only research and design brief for Angerona's local-first
Windows EDR/NDR/SOAR. It is ranked by expected **impact divided by effort**.
For a transparent comparison, impact is scored 1–5 and effort is weighted
S=1, M=2, L=3; range estimates use their midpoint. The score is directional,
not a delivery promise.

## Scope and non-duplication check

The current tree already has 63 auto-discovered modules; Windows Security,
Kernel-Process ETW and Sysmon bridges; WFP/packet/DNS sensors; process lineage;
RWX-memory scanning; ransomware entropy, rename, canary, delta-cache and VSS
protections; BYOVD signals; behavioral baselining; Evidence Lattice/Cortex
correlation; proof-required Purple Guard remediation; OCSF/D3FEND/Sigma
foundations; guarded local Ollama use; confirm-before-write ARIA actions; and
encrypted Remote Bridge transport. The earlier backlog also already covers
Trust Passports, a driver-hardening audit, central privacy receipts, typed
settings, release attestation, and evidence-taint enforcement.

The six proposals below do not relabel those features. They close different
gaps found in the current code:

- ransomware change detection still walks selected directories and compares
  snapshots instead of consuming the volume's native change stream;
- Windows identity-protocol fallback is not modeled, despite NTLM's removal
  trajectory;
- Sysmon EID 10 `CallTrace` is captured as text but is not scored as execution
  provenance, while non-Sysmon image-tampering evidence remains weak;
- local-model prompts are filtered, but the model runtime is not an OS-isolated
  security boundary and several call sites still bypass the guarded client;
- UDP/443 ownership exists, but QUIC is not identified or correlated as its own
  encrypted-transport lane; and
- the GUI, AI, sensors, and response surface still share an always-elevated
  application trust domain.

Deliberate exclusions: no custom kernel driver, no protected ETW Threat
Intelligence provider that Angerona cannot legitimately access as PPL, no
always-on whole-system stack sampling, no TLS/QUIC decryption, no credential
capture, and no offensive emulation or counterattack capability.

## Ranked shortlist

| Rank | Proposal | Impact | Effort | Impact / effort | Primary mode |
|---:|---|---:|:---:|---:|---|
| 1 | NTFS Journal Ransomware Pulse | 5.0 | S–M | 3.33 | Detect / Respond / Visualize |
| 2 | NTLM Exit Radar | 4.5 | S–M | 3.00 | Detect / Harden / Visualize |
| 3 | Stack-to-Image Provenance Fuse | 5.0 | M | 2.50 | Detect / Visualize |
| 4 | Local Model Airlock | 5.0 | M–L | 2.00 | Harden |
| 5 | QUIC Sightline | 3.8 | M | 1.90 | Detect / Visualize |
| 6 | Split-Token Angerona | 5.0 | L | 1.67 | Harden / Respond |

---

## 1. NTFS Journal Ransomware Pulse

**Pitch:** Replace repeated directory snapshots with a bounded reader of the
native NTFS USN change journal, detecting destructive file-change bursts earlier
while reading no file contents.

### Why now

MITRE's May 2026 update to Data Encrypted for Impact names high-frequency writes,
uncommon extensions, ransom notes, recovery tampering, and repeated
delete/replace behavior as a detection strategy. Windows already exposes the
ordered change records needed to measure those behaviors through
`FSCTL_READ_USN_JOURNAL`; the journal ID is an explicit integrity check that
changes if the journal is stopped, deleted, or recreated.

- [MITRE ATT&CK — Data Encrypted for Impact (T1486), v1.5, modified 2026-05-12](https://attack.mitre.org/techniques/T1486/)
- [Microsoft — FSCTL_READ_USN_JOURNAL](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_read_usn_journal)
- [Microsoft — Using the Change Journal Identifier](https://learn.microsoft.com/en-us/windows/win32/fileio/using-the-change-journal-identifier)

### Fit

Add `modules/usn_ransomware_sensor.py` as a Windows-only `BaseModule`. Feed its
normalized burst evidence to `modules/ransomware_heuristics.py`,
`modules/evidence_lattice.py`, `core/cortex.py`, and the existing incident/SOAR
path. Keep `smart_deception.py`, `shadowcopy_guard.py`, and `shadow_shield.py` as
independent corroborators. This is **Detect + Respond + Visualize**; the journal
sensor itself remains read-only.

**Data flow:** per-volume USN cursor and journal ID → `CLOSE`-qualified change
records → bounded per-parent/per-extension windows → aggregate
`ransomware_change_burst` evidence → Evidence Lattice/Cortex → existing SOAR
only when a separate trusted signal supplies a PID → compact Flight Recorder
receipt.

### Buildable design and phases

1. **Phase A — read-only sensor.** Open only explicitly configured fixed NTFS
   volumes, query the journal ID, and asynchronously read forward from a stored
   cursor. Track unique file IDs and reason masks for overwrite/extend,
   rename-old/rename-new, create, delete, and close. Never create, resize, or
   delete the system journal.
2. **Phase B — burst classifier.** Score change velocity, unique-file count,
   directory spread, novel-extension concentration, delete→create/rename pairs,
   and repeated small partial writes. Require `CLOSE` where possible to avoid
   overcounting one logical operation. Feed only aggregate evidence into the
   current lattice; retain the existing entropy and canary detectors as
   orthogonal signals.
3. **Phase C — controlled response.** Journal data has no PID, so it can raise a
   HIGH volume-level alarm but cannot identify or contain a process by itself.
   CRITICAL/automatic SOAR eligibility requires a PID-bearing second source:
   Sysmon file activity, a tripped decoy, ETW process evidence, shadow-copy
   tamper, or a known malicious process chain.

### Operator and UI value

Add a **Ransomware Pulse** strip to the incident timeline: changed files/second,
unique file IDs, affected protected roots, extension churn, and which
corroborator supplied process attribution. The operator sees
`Journal-only: alert, no process action` versus
`Corroborated: PID 1234 eligible for containment`. Persist root aliases and
counts by default, not raw personal filenames; raw paths remain memory-only
unless the operator opens a local incident detail.

### Tests

- Pure parser fixtures for USN_RECORD V2/V3, split buffers, malformed record
  lengths, UTF-16 names, cursor continuation, and journal-ID rollover.
- Synthetic windows proving benign compiler/package-manager bursts remain below
  threshold while wide overwrite+rename+extension churn crosses it.
- A gate proving journal-only evidence can never call SOAR or invent a PID.
- Restart/cursor tests proving no replay storm, and a journal-reset test that
  reports telemetry degradation without labeling the reset malicious.
- Performance gate on a large synthetic journal: bounded memory, no file-content
  reads, and no GUI-thread work.

### Effort and limits

**Effort: S–M.** `DeviceIoControl` structures can be implemented with `ctypes`
or a small signed native helper. First delivery should be NTFS on fixed local
volumes. It needs elevation and does not cover FAT/exFAT; ReFS requires its
versioned record support and should be separately gated. USN records do not
contain a responsible PID, and the design must say so visibly.

### Safety

Defensive-only and read-only. It never edits a journal, reads document contents,
creates encryption samples, or attempts ransomware behavior. No volume-level
signal alone may kill, suspend, quarantine, or block a process.

---

## 2. NTLM Exit Radar

**Pitch:** Build a local compatibility graph of where Windows still falls back
to NTLM, detect suspicious downgrade/relay conditions, and stage a reversible
audit-first path toward Kerberos or NTLM blocking.

### Why now

Microsoft announced in January 2026 that Windows is moving from NTLM
deprecation toward disabling NTLM by default, with enhanced auditing and
transition tools planned for Windows 11 24H2 and Windows Server 2025. Those
versions already support SMB-client NTLM blocking. MITRE's May 2026 update
continues to identify captured or relayed NTLM responses over SMB, LDAP, MSSQL,
and HTTP as a credential-access risk.

- [Microsoft — Advancing Windows security: Disabling NTLM by default (2026-01-29)](https://techcommunity.microsoft.com/blog/windows-itpro-blog/advancing-windows-security-disabling-ntlm-by-default/4489526)
- [Microsoft — Block NTLM connections on SMB](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-ntlm-blocking)
- [Microsoft — Configure Windows event auditing / NTLM event 8004](https://learn.microsoft.com/en-us/defender-for-identity/deploy/configure-windows-event-collection)
- [MITRE ATT&CK — Name Resolution Poisoning and SMB Relay (T1557.001), modified 2026-05-12](https://attack.mitre.org/techniques/T1557/001/)

### Fit

Add a read-only `modules/identity_protocol_monitor.py` `BaseModule` plus a pure
`core/ntlm_compat_graph.py`. Reuse the Event Log parser patterns in
`etw_listener.py` and `sysmon_listener.py`, network ownership from
`wfp_controller.py`, Evidence Lattice correlation, posture history, and vetted
reversible remediation plumbing. Put the UI card under **World View → Identity
Security** with a link from Resolve Center. This is **Detect + Harden +
Visualize**.

**Data flow:** NTLM Operational 8001–8004, Security 4624/4625, SMB client
connectivity/audit events, and optional Sysmon network events → normalized local
authentication edges → account pseudonym + server/service/protocol/result →
compatibility graph → downgrade/relay analytics and an operator-reviewed
hardening plan.

### Buildable design and phases

1. **Phase A — inventory.** Parse only existing local logs. Record source host
   class, destination, service/protocol, NTLM version when the event reliably
   supplies it, first/last seen, and count. Pseudonymize account names with a
   per-install keyed digest before persistence. Never store challenge/response
   material, password hashes, tickets, or credentials.
2. **Phase B — detection.** Raise a downgrade signal for a newly seen NTLM edge
   where Kerberos was previously normal, outbound authentication to an
   untrusted external address, NTLM shortly after LLMNR/NBT-NS activity, or an
   SMB signing/encryption regression. Attribute a process only when an exact
   PID/process GUID and tight time window are present; otherwise label the edge
   `process unknown`.
3. **Phase C — migration coach.** Generate an audit report listing dependencies
   and likely remediations (`Negotiate`, SPN/DNS correction, SMB NTLM block,
   narrow exception). On Windows 11 24H2/Server 2025, offer a separately
   confirmed, reversible `Set-SmbClientConfiguration -BlockNTLM` change only
   after a clean observation window. Global/domain NTLM denial stays manual and
   outside the MVP.

### Operator and UI value

The Identity card answers: **What still needs NTLM? What changed today? What
will break if I block it?** Show a local edge graph with protocol, destination,
last use, confidence, and exception expiry. A readiness meter is based on
observed dependencies, not an AI guess. The local model may explain an edge but
cannot enable a policy or manufacture an exception.

### Tests

- XML fixtures for 4624/4625 and NTLM 8001–8004, including missing fields,
  anonymous sessions, IPv6, local/workgroup, and domain cases.
- Deterministic graph tests for deduplication, keyed pseudonyms, expiry, and
  `unknown process` handling.
- Correlation tests that require the MITRE combination of name-resolution
  poisoning plus relay/downgrade evidence before CRITICAL.
- Dry-run/revert tests for the SMB-client setting with all PowerShell/host
  mutation stubbed.
- A privacy assertion that no raw account, challenge, response, ticket, or hash
  reaches SQLite, logs, AI prompts, or exports.

### Effort and limits

**Effort: S–M.** The event-log and posture machinery exists. Coverage depends on
local audit policy and OS version; domain-wide visibility would require
explicitly configured remote nodes and is not assumed. Some NTLM events do not
identify the originating process, so process attribution must remain
confidence-labeled. Windows 10 and standalone workgroups need compatible
guidance rather than a blanket "disable everything" message.

### Safety

Defensive-only. The module observes authentication metadata and proposes safer
configuration. It never captures reusable authentication material, probes
servers, coerces authentication, tests relay, or automatically disables a
protocol that could lock out the operator.

---

## 3. Stack-to-Image Provenance Fuse

**Pitch:** Turn call stacks and process-image identity into a high-confidence
answer to “did trusted code really make this sensitive access?” instead of
treating every process handle or RWX page equally.

### Why now

Microsoft's 2026 Sysmon guidance calls CreateRemoteThread low-volume/high-signal,
exposes a `CallTrace` for ProcessAccess, and identifies ProcessTampering EID 25
with hollowing/herpaderping. MITRE's May 2026 process-hollowing strategy focuses
on the suspended-process → unmap → write → set-context → resume chain.
Windows ETW can also attach call stacks to selected kernel events through
`TraceSetInformation`, and `GetMappedFileName` can identify the file backing a
mapped address.

- [Microsoft — Sysmon events (2026): ProcessAccess, CreateRemoteThread, ProcessTampering](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [MITRE ATT&CK — Process Hollowing (T1055.012), v2.0, modified 2026-05-12](https://attack.mitre.org/techniques/T1055/012/)
- [Microsoft — TraceSetInformation / TraceStackTracingInfo](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/nf-evntrace-tracesetinformation)
- [Microsoft — Memory-Mapped File Information / GetMappedFileName](https://learn.microsoft.com/en-us/windows/win32/psapi/memory-mapped-file-information)

### Fit

Add pure `core/stack_provenance.py` and an event-driven
`modules/stack_image_guard.py` `BaseModule`. Consume the `call_trace`,
`start_address`, `start_module`, source/target PID, access mask, and EID 25 fields
already emitted by `sysmon_listener.py`; on a high-suspicion trigger, enrich
with the existing executable-trust, process-allowlist, memory-scanner, and
process-provenance engines. Feed only the resulting evidence into Evidence
Lattice/Cortex and the incident timeline. This is **Detect + Visualize**.

**Data flow:** Sysmon EID 8/10/25 or a Memory Injection alert → frame tokenizer
and access-mask decoder → cached module path/signature/mapping identities →
optional targeted image check → provenance verdict with confidence and reasons
→ lattice/correlation → operator-visible compact stack.

### Buildable design and phases

1. **Phase A — score the telemetry already present.** Parse EID 10 `CallTrace`
   into ordered module+offset frames. Mark frames as system-signed,
   third-party-signed, unsigned, user-writable, missing/unbacked, or unresolved.
   Decode access rights and score only sensitive combinations such as
   VM_WRITE/VM_OPERATION/CREATE_THREAD/DUP_HANDLE against LSASS, Angerona,
   browsers, credential managers, or protected system processes.
2. **Phase B — image truth on trigger.** For the source and target PID, compare
   the canonical executable path with the `MEM_IMAGE` mapping that backs the
   main image; validate PE layout invariants and the mapped-file identity. Do
   not hash an entire relocated in-memory image and call normal relocations
   malicious. An executable private region, missing backing image, EID 25, or a
   remote-thread start outside known mapped code becomes independent evidence.
3. **Phase C — optional five-second ETW capture.** On supported systems and only
   after a strong precursor, start a small in-memory session for a narrow set of
   Process/Thread/Image kernel events with stack tracing, bounded by time,
   event count, and process filter. This is an enrichment path, not a permanent
   whole-host profiler; symbol download is never required for detection.

### Operator and UI value

Replace opaque “ProcessAccess CRITICAL” text with a **Why this stack is
suspicious** foldout:

`unsigned user-writable frame → ntdll → target LSASS; VM_WRITE; start address
not in a mapped image`.

Display basenames, signer, mapping class, and stable local digests by default.
Raw paths remain in memory for local drill-down and are excluded from routine
exports. A confidence badge distinguishes `Sysmon-confirmed tamper`,
`multi-signal provenance mismatch`, and `unresolved`.

### Tests

- Pure stack fixtures: normal Microsoft chain, signed security tool, JIT frame,
  unsigned AppData frame, missing module, malformed/truncated trace, WOW64, and
  access-mask combinations.
- PE/mapping fixtures proving relocations and legitimate hotpatch/JIT behavior
  do not create an image mismatch.
- Correlation gates requiring a sensitive access right plus untrusted frame (or
  independent EID 25) for CRITICAL; an unresolved stack alone is not malicious.
- Bounded-session tests for exact PID/event/time caps, stop-on-error, no symbol
  network access, and no registry change such as `DisablePagingExecutive`.
- Performance test showing signature/mapping results are cached by file ID,
  mtime, and digest rather than recomputed per frame.

### Effort and limits

**Effort: M.** Phase A uses data Angerona already collects. Phase B needs careful
Windows process/memory APIs and access-denied handling. Phase C is optional and
may need a small signed Rust/C helper; ETW stack availability varies, stacks can
be incomplete, protected processes may deny inspection, and JIT/security
products legitimately create unusual frames. Confidence must degrade rather
than silently infer.

### Safety

Defensive-only, targeted, and read-only. No thread suspension, memory write,
remote thread, injection, credential read, or full-memory dump is permitted.
The optional ETW trace is short, in memory, process-scoped, and never enables
dangerous diagnostic registry settings.

---

## 4. Local Model Airlock

**Pitch:** Put the local model behind an OS-enforced sandbox with no ambient
files, credentials, desktop, or network—so prompt filtering is not the only
boundary between untrusted telemetry and an elevated security suite.

### Why now

Microsoft documented an experimental Windows 11 `CreateProcessInSandbox` API in
June 2026. Its AppContainer mode is default-deny for system resources and
network, exposes explicit read-only/read-write paths, supports low integrity and
Win32k/UI restrictions, and fails rather than silently weakening an invalid
policy. NIST's GenAI profile identifies prompt injection and the possibility of
stealing data or running code as risks that require layered controls, not prompt
wording alone.

- [Microsoft — Create Process In Sandbox APIs (experimental, updated 2026-06-01)](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox)
- [Microsoft — AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation)
- [Microsoft — CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
- [NIST AI 600-1 — Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)

### Fit

Add `core/model_airlock.py` plus a small signed `native/model_host` helper.
First route every local-model caller through `engines/ollama_client.py`; current
direct callers in AI triage, briefings, coaching, CVE advice, evolution, and
posture hardening must not retain alternate unguarded HTTP paths. ARIA and the
assistant continue to use the existing deterministic action registry. Add the
airlock state to **World View → Local AI Deep Diagnostics**. This is core
**Harden**, not a `BaseModule`.

**Data flow:** deterministic feature extraction/redaction in the privileged
process → bounded typed request over stdio or a private authenticated pipe →
low-integrity isolated model worker → schema-limited text/JSON result →
post-inference redaction and validation → assistant/action policy. The model
never receives a capability to call Angerona actions.

### Buildable design and phases

1. **Phase A — one choke point.** Enforce a single guarded local-model client,
   block non-loopback model URLs by default, cap prompt/context/output, and mark
   model output `UNTRUSTED_GENERATED_TEXT`. Any failure uses the existing
   deterministic non-AI fallback; it does not silently call an unguarded
   backend.
2. **Phase B — downlevel airlock.** Launch a dedicated headless inference
   worker with a restricted token, low integrity, a Job Object with kill-on-
   close/CPU/RAM/child limits, no inherited handles, no desktop/clipboard, a
   clean environment, a read-only model directory, and one bounded scratch
   directory. Use stdio/private-pipe IPC so the worker needs no network.
3. **Phase C — Windows 11 sandbox.** When the experimental API is present and
   passes a startup self-test, use AppContainer with no network capabilities,
   `disallow_win32k_system_calls`, explicit model read-only and scratch
   read-write paths, and a unique Angerona sandbox identity. Because the API is
   experimental and GPU/runtime compatibility is unknown, this mode is
   version-gated. A signed dedicated llama.cpp-style worker may be required;
   Angerona must not grant broad filesystem/network capabilities merely to keep
   a legacy Ollama daemon working.

### Operator and UI value

The Local AI card reports independently verifiable properties:

- `Network: denied`, `Files: model read-only + scratch only`,
- `Token: low/restricted`, `Child processes: bounded`,
- `Backend: sandbox / restricted-token / legacy-disabled`,
- last containment self-test and model digest.

An explicit **Allow legacy local Ollama** escape hatch may exist for
compatibility, but it is off by default in high-security mode and clearly
states which boundary is lost.

### Tests

- A sandbox canary worker tries to read a DPAPI blob, settings, clipboard,
  arbitrary user document, environment secret, and external/loopback socket;
  every forbidden attempt must fail while model-file read and bounded scratch
  write succeed.
- Job tests prove child escape is denied/bounded, RAM/CPU/output limits trip,
  and closing the broker kills the whole worker tree.
- Routing test enumerates all model call sites and fails if one bypasses the
  guarded client.
- Prompt-injection fixtures prove a malicious event can influence prose but
  cannot produce a trusted action object or cross the action-policy boundary.
- Version/feature gates prove missing or changed experimental APIs fail closed
  to restricted mode or deterministic fallback, never unsandboxed execution.

### Effort and limits

**Effort: M–L.** Centralizing calls is M; a production-quality isolated backend
and GPU compatibility make the full feature M–L. `CreateProcessInSandbox` is
Windows 11-only, experimental, dynamically loaded from `processmodel.dll`, and
has no public header. AppContainer, model runtimes, GPU drivers, and loopback
servers may not compose cleanly, which is why stdio and a dedicated worker are
the preferred design rather than broad network exceptions.

### Safety

Defensive-only. The airlock reduces the model's authority and data access. It
does not ask the model to generate attacks, executable remediation, shell
commands, or offensive content. Model output remains advisory and can never
authorize its own privileged action.

---

## 5. QUIC Sightline

**Pitch:** Attribute QUIC/UDP 443 to a process and score its metadata without
decrypting traffic, closing a blind lane in beaconing, DNS, and Top Talkers.

### Why now

HTTP/3 carries HTTP semantics over QUIC and embeds TLS 1.3 at the transport
layer. Windows Server 2025 expands SMB over QUIC and records explicit client/
server connectivity events. Microsoft MsQuic provides manifested ETW with a
documented low-volume `Basic.Light` profile, connection events, and a stable
provider GUID. These are useful local metadata sources precisely because a
TCP-oriented or cleartext packet path cannot interpret encrypted UDP/443.

- [IETF/RFC Editor — RFC 9114: HTTP/3](https://www.rfc-editor.org/rfc/rfc9114.html)
- [Microsoft — SMB over QUIC](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-over-quic)
- [Microsoft MsQuic — Diagnosing Issues with MsQuic / ETW](https://microsoft.github.io/msquic/msquicdocs/docs/Diagnostics.html)
- [Microsoft — Sysmon events: UDP network connection and DNS Query telemetry](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)

### Fit

Add Windows-only `modules/quic_sightline.py` as a `BaseModule`. Reuse UDP
ownership from `wfp_controller.py`, Sysmon EID 3 and (after a narrow bridge
extension) EID 22, `network_protocol_decoder.py`, `beacon_detector.py`,
`net_interfaces.py`, threat-intel lookup, and Cortex. Show the protocol in
`gui/top_talkers.py` and incident timelines. This is **Detect + Visualize**.

**Data flow:** low-volume MsQuic connection ETW + SMB QUIC audit events + UDP
owner table + Sysmon DNS/network events → normalized
`pid/process/remote/port/interface/transport/start-stop/bytes-if-available` flow
→ local cadence/rarity/baseline analysis → NDRD/beacon/Cortex → metadata-only
incident receipt.

### Buildable design and phases

1. **Phase A — honest classification.** Identify Windows MsQuic connections and
   SMB-over-QUIC events directly. For other implementations (for example,
   browsers with a different QUIC library), label sustained UDP/443
   `probable_quic` only when flow shape and DNS timing support it. Never claim
   the Microsoft provider sees every QUIC implementation.
2. **Phase B — process-aware analytics.** Learn a bounded local baseline of
   process signer/path, destination prefix/domain token, interface, connection
   duration, byte bucket, and reconnect cadence. Flag a rare non-browser using
   UDP/443 only when joined with another signal such as unsigned/path drift,
   high-entropy DNS, a flagged destination, regular beacon cadence, or an
   anomalous parent.
3. **Phase C — protocol-aware UX.** Recognize SMB-over-QUIC client Event 30832
   and server Event 1913 where available, so legitimate secure file access is
   labeled rather than misclassified as generic C2. Add a QUIC lane to Top
   Talkers and the kill-chain view, with `confirmed`, `probable`, or `UDP only`
   confidence.

### Operator and UI value

The operator sees `browser → example → HTTP/3`, `System → file server → SMB over
QUIC`, or `unsigned child of script host → rare endpoint → probable QUIC,
regular 37 s cadence`. The UI explicitly says **payload not inspected**. Store
IP/domain tokens, coarse byte buckets, cadence, and signer/path identity; never
store packet bodies, TLS secrets, QUIC keys, URLs, or application content.

### Tests

- Synthetic MsQuic and SMB connectivity event fixtures, including manifest
  version drift and missing fields.
- UDP ownership reuse/PID-exit tests and DNS→flow time-window correlation.
- Classifier tests for ordinary browser HTTP/3, known SMB over QUIC, generic
  game/video UDP, VPN interfaces, and a rare periodic probable-QUIC flow.
- A confidence test proving UDP/443 alone cannot produce a QUIC-confirmed or
  CRITICAL verdict.
- Load test with high browser flow volume proving bounded per-process state,
  sampling, deduplication, and no raw packet/payload persistence.

### Effort and limits

**Effort: M.** UDP ownership and network correlation exist; the work is ETW
parsing, honest confidence labeling, and UI integration. MsQuic manifests and
event availability vary by Windows/runtime version, not all QUIC uses MsQuic,
NAT can obscure destination continuity, and some useful metadata may be absent.
The feature must degrade to `UDP only`, not infer an application protocol.

### Safety

Defensive-only and metadata-only. No decryption, TLS interception, key logging,
certificate substitution, traffic injection, replay, protocol fuzzing, or
content capture is proposed. Automatic network isolation still requires the
suite's existing corroboration and protected-process gates.

---

## 6. Split-Token Angerona

**Pitch:** Keep the operator UI and AI at medium integrity, move continuous
privileged sensing into a read-only service, and grant host-changing authority
only to an ephemeral, typed, operator-approved broker.

### Why now

Angerona currently documents that it always runs elevated, which makes every GUI,
connector, parser, and local-model bug part of the administrator trust domain.
Microsoft's Administrator Protection architecture (currently preview) is moving
Windows 11 toward deprivileged sessions, Windows Hello-approved just-in-time
elevation, isolated admin profiles, and destruction of the admin token when the
task ends. It also adds Microsoft-Windows-LUA ETW 15031/15032 for approved and
denied elevations. Ordinary UAC has the same core goal of limiting the access
malicious code has to administrator privileges.

- [Microsoft — Administrator Protection for Windows 11](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/administrator-protection/)
- [Microsoft — User Account Control overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/)
- [Microsoft — CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)

### Fit

This is an architectural core change, not a `BaseModule`. Split
`core/privilege.py`, autostart, module hosting, `core/action_policy.py`, IPC
Guard, SOAR/remediation actions, and the PySide GUI into explicit trust domains:

1. **Angerona UI/ARIA** — medium integrity, no privileged handles or secrets;
2. **Sensor service** — elevated/SYSTEM as required, read-only telemetry APIs,
   no Internet and no general host-change command surface; and
3. **Action broker** — short-lived elevated helper accepting only versioned
   typed operations already present in `action_policy`, then exiting.

This is **Harden + Respond**.

**Data flow:** sensor service → ACL-protected, bounded, one-way event stream →
medium-integrity UI/Flight Recorder view. UI action preview → canonical typed
manifest → separate UAC/Administrator Protection approval → ephemeral broker
revalidates target/policy/current state → vetted action → verification/rollback
receipt → broker destroys token and exits.

### Buildable design and phases

1. **Phase A — privilege inventory and read-only split.** Mark every module/API
   `USER`, `ELEVATED_READ`, or `ELEVATED_WRITE`. Move the GUI, ARIA, connectors,
   model, exports, and ordinary settings to the user process. Host only sensors
   that genuinely need privileged read access in an installed, digest-verified
   service. Preserve reduced-visibility user-mode operation when the service is
   absent.
2. **Phase B — remove writes from the service.** The sensor service publishes
   events but exposes no generic subprocess, PowerShell, registry, file, or
   firewall method. A separate signed action broker understands only fixed
   opcodes and typed fields (for example `isolate_pid`, `restore_firewall_rule`,
   `apply_vetted_registry_change`). It rejects shell strings, unknown versions,
   stale previews, PID reuse, path drift, and caller-supplied executable paths.
3. **Phase C — just-in-time authorization.** Each material host change launches
   the broker through UAC; when stable Administrator Protection is available,
   consume its 15031/15032 ETW receipts and Hello-backed approval. Bind the
   canonical preview digest to the broker request, re-evaluate action policy in
   the elevated process, verify/rollback, emit a signed receipt, and exit.

### Operator and UI value

The header gains a small **Privilege** chip:

`UI: standard | Sensors: protected/read-only | Actions: locked`.

An action preview explains why elevation is needed and exactly which typed
change will occur. Routine viewing, AI questions, triage, searches, and exports
never show a UAC prompt. Continuous detection keeps running if the GUI closes.
The World View trust-boundary diagram shows which process owns each capability
and its last integrity self-test.

### Tests

- Capability-matrix test fails if a USER component imports privileged write
  adapters or if the sensor service exposes an untyped mutation method.
- IPC adversary tests: malformed length, replay, stale nonce, PID reuse,
  alternate same-user client, path swap, unknown opcode, oversized payload,
  and event flood/backpressure.
- Broker tests prove shell/PowerShell text is impossible in the wire schema,
  action policy is re-run after elevation, target identity is revalidated, and
  rollback/receipt behavior is deterministic.
- Integration test runs the GUI medium-integrity against a stub sensor service,
  then proves read-only operation survives service loss without silently
  claiming full coverage.
- Windows-version gates for classic UAC versus Administrator Protection
  15031/15032; preview absence must not weaken authentication.

### Effort and limits

**Effort: L.** This touches startup, packaging, IPC, module ownership, actions,
and tests. It should be migrated by capability slice, beginning with an
unelevated read-only GUI against a compatibility service while the current
single-process mode remains a clearly labeled transition option. Administrator
Protection is preview/not universally deployed and changes profile/SSO
semantics, so it is an enhancement rather than a prerequisite. Some sensors may
need SYSTEM while others need only an administrator token; least privilege must
be measured, not assumed.

### Safety

Defensive-only and least-privilege. The broker exposes only Angerona's existing
vetted defensive actions, never arbitrary command execution. Each material
change remains previewed, interactively approved, revalidated, verified,
audited, and reversible where Windows permits. No offensive response,
counterattack, persistence implant, or credential use is added.

---

## Recommended delivery order

1. Build the USN reader/parser and journal-only safety invariant.
2. Ship NTLM inventory and the Identity card with no policy mutation.
3. Score existing Sysmon call traces before adding targeted image/ETW
   enrichment.
4. Centralize local-model calls immediately, then prototype the restricted
   worker and Windows 11 sandbox behind a feature gate.
5. Add confirmed MsQuic/SMB classification, then conservative probable-QUIC
   correlation.
6. Start the split-token migration with a written capability matrix and
   unelevated GUI prototype; do not combine the service/action-broker cutover
   into one release.

The first three proposals can deliver independent operator value without
changing Angerona's privilege model. The final three are architectural hardening
tracks and should remain gated until their containment and compatibility tests
pass on supported Windows versions.
