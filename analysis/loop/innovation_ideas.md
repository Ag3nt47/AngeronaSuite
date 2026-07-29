# Loop 1 Innovation Ideas — 2026-07-29

## Decision

This cycle should strengthen Angerona at the boundaries where an enterprise
operator must be able to ask, and prove:

1. What happened at the Windows kernel boundary without trusting an unshippable
   custom driver?
2. Did network containment take effect, remain scoped, and preserve recovery?
3. How much telemetry was lost or delayed?
4. Can AI-assisted investigation remain useful without gaining authority?
5. Can every important conclusion be traced to immutable source evidence?

The proposals below are ranked by expected impact divided by effort. They are
designs only; no product code is implemented here. They deliberately do not
re-propose Angerona's existing Cortex, Evidence Lattice, TECT canary, receipt
chain, OCSF exporter, WFP connection snapshot, or proof-carrying Purple Guard.

## Ranked shortlist

| Rank | Proposal | Effort | Primary mode | Why this cycle |
|---:|---|:---:|---|---|
| 1 | Windows Kernel-Boundary Posture Ledger | M | Detect / Harden / Visualize | High assurance without shipping a custom driver |
| 2 | Transactional WFP Containment with Independent Proof | M | Respond / Harden | Turns “rule created” into verified, reversible isolation |
| 3 | Telemetry Loss Accounting and Coverage SLOs | M | Detect / Visualize | Makes sensor blindness measurable instead of implicit |
| 4 | Deterministic Investigation Broker with Capability Leases | M | Harden / Respond | Useful autonomy with no model-derived authority |
| 5 | Evidence Reference Resolver and Claim Gate | M | Harden / Visualize | Forces AI, incident, and response claims to cite real records |
| 6 | Pktmon Counter Flight Recorder | S-M | Detect / Visualize | Adds low-payload network-path and drop evidence on demand |

---

## 1. Windows Kernel-Boundary Posture Ledger

**Pitch.** Build a read-only, user-mode ledger of driver loads, Code Integrity
decisions, HVCI/VBS state, vulnerable-driver controls, and kernel-telemetry
availability; keep Angerona's custom driver unavailable in production until its
separate assurance gates are met.

### Why now

Microsoft says attackers abuse legitimate signed but vulnerable drivers to gain
kernel access, recommends HVCI and the vulnerable-driver blocklist, and advises
audit-mode validation before enforcement because blocks can break devices or
cause a bugcheck:
[Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules).
Microsoft's 2026 Windows Driver Policy also uses an evaluation/audit phase and
records Code Integrity evidence before enforcement:
[The Windows Driver Policy](https://support.microsoft.com/en-us/windows/the-windows-driver-policy-ecd2a78c-750c-415d-93f2-e37302ce0443).

### Fit and file-specific implementation plan

- **Core:** add `src/angerona/core/kernel_posture.py` with a bounded typed
  `KernelPostureSnapshot`. It should distinguish `observed`, `not_configured`,
  `unavailable`, `access_denied`, and `unknown`; absence must never mean safe.
- **BaseModule:** add `src/angerona/modules/kernel_posture.py` (`windows`,
  `detect`) to consume documented Windows Security, System, and Code Integrity
  event channels; inventory only bounded driver metadata: service/image
  basename, SHA-256, version, publisher/result, first/last seen, and source event
  reference.
- **Existing boundary:** change no code this cycle, but an implementation should
  gate `src/angerona/modules/kernel_bridge.py` behind an explicit lab-only
  capability contract. Its current “park at 50%” state must not imply production
  coverage, and raw command lines must not enter ordinary INFO messages.
- **GUI:** add a “Kernel boundary” evidence card to
  `src/angerona/gui/dashboard_details.py` and Settings enterprise evidence view:
  HVCI/VBS, vulnerable-driver blocklist, ASR driver rule, Code Integrity channel
  health, recent driver decisions, and explicit limitations.
- **Export:** normalize findings through `core/sensor_events.py`; optionally emit
  OCSF-compatible findings through the existing `core/ocsf_export.py`.

Maps to `ENT-WIN-006/007/008` and `ENT-KRN-001/003`.

### Abuse cases and failure handling

- A signed malicious/vulnerable driver must not become “trusted” solely because
  Authenticode succeeds.
- A disabled or unreadable Code Integrity channel must produce a coverage gap,
  not a clean posture.
- A stale cached blocklist must display its observed timestamp and Windows build.
- No automatic WDAC/HVCI/ASR enforcement; incompatible drivers can interrupt
  boot or hardware.
- The optional custom driver must never be loaded, installed, or recommended by
  this module.

### Performance budget

- Event-driven after startup; inventory refresh no more than every 15 minutes.
- Startup scan: <= 250 ms CPU time, <= 2,000 retained driver observations.
- Steady state: <= 0.2% average CPU, <= 25 MiB private memory, <= 1 MiB/day
  metadata before retention compaction.

### Acceptance tests

- Fixtures cover allowed, audit-blocked, enforced-blocked, unsigned, vulnerable,
  access-denied, malformed XML, channel-disabled, and event-gap cases.
- A valid signature alone never clears a vulnerable/blocklisted finding.
- Unsupported Windows builds show `unavailable`, not 100% health.
- No raw command line, full user path, certificate private data, or driver bytes
  are retained.
- Module discovery and GUI remain healthy with no custom driver installed.

### Safety

Defensive and read-only. It inventories posture and explains supported Windows
controls. It does not load drivers, develop an exploit, bypass Code Integrity,
or provide vulnerable-driver weaponization guidance.

---

## 2. Transactional WFP Containment with Independent Proof

**Pitch.** Replace “firewall command returned success” with a typed containment
transaction: preflight, narrowly scoped rule, independent WFP evidence, expiry,
rollback, and a recovery-channel invariant.

### Why now

WFP supports per-application, per-user, and per-connection policy through the
Base Filtering Engine:
[About Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform).
Windows exposes allowed/blocked connection audits and WFP policy-change events:
[WFP auditing and logging](https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging).
On current Windows versions, Filter Origin and Interface Index improve the
explainability of 5152/5157 drop events:
[Filter Origin Audit Log](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation).

### Fit and file-specific implementation plan

- **Core:** add `src/angerona/core/action_contracts/network_isolation.py`.
  Contract fields: immutable action ID, canonical process identity
  `(pid,start_time,image_hash)`, destination/interface scope, duration,
  protected endpoints, preconditions, rollback deadline, idempotency key, and
  evidence references.
- **Respond engine:** adapt `src/angerona/modules/soar_engine.py` and
  `src/angerona/modules/soar.py` to stage this typed contract. Revalidate process
  identity immediately before mutation to defeat PID reuse.
- **WFP boundary:** extend `src/angerona/modules/wfp_controller.py` with
  read-side rule/filter enumeration and 5152/5157 correlation. Mutation should
  use a single supported Windows firewall/WFP adapter, never shell text assembled
  from model output.
- **Proof:** write the before state, requested change, OS result, independently
  observed filter origin, bounded negative/positive micro-probe outcome, expiry,
  and rollback result through `src/angerona/core/remediation_log.py`.
- **GUI:** preview exact scope and recovery exclusions in Resolve Center; show
  `STAGED -> APPLIED -> VERIFIED -> EXPIRED/ROLLED_BACK`, with `UNVERIFIED`
  remaining open.

Maps to `ENT-NET-006` and `ENT-SOAR-002/004/005/006/007`.

### Abuse cases and failure handling

- PID reuse cannot redirect a block to an unrelated process.
- Wildcard, loopback, DHCP, DNS resolver, Angerona IPC, and configured
  management/recovery endpoints are denied by default unless an explicit
  emergency policy names them.
- A forged EventBus “blocked” message is not proof; proof must reference an OS
  event or enumerated rule plus the bound action receipt.
- Timeout, restart, or partial failure must leave a discoverable lease that the
  recovery worker can roll back.
- An attacker cannot make a permanent block by submitting an extreme duration;
  policy caps it.

### Performance budget

- Preflight plus apply target: p95 <= 500 ms excluding OS audit delivery.
- Verification deadline <= 5 seconds; no polling faster than 250 ms.
- At most 128 active Angerona containment leases and 1,000 retained receipts.
- WFP success auditing remains off by default because Microsoft documents it as
  high volume; use narrowly filtered failure/policy evidence.

### Acceptance tests

- Deterministic tests cover PID reuse, duplicate retry, expired lease, restart
  recovery, rule-name collision, IPv4/IPv6, VPN interface change, missing audit
  privilege, full disk, and rollback failure.
- A synthetic containment is “verified” only when scope and OS evidence match.
- Recovery/management endpoints remain reachable in the network namespace test.
- Retrying one idempotency key creates no second rule.
- Forced process exit between preflight and apply fails closed.

### Safety

Defensive containment only. No packet modification, interception, credential
capture, persistence beyond the bounded lease, or arbitrary firewall scripting.

---

## 3. Telemetry Loss Accounting and Coverage SLOs

**Pitch.** Give every ETW/Event Log sensor a source cursor, queue watermark,
loss counter, freshness deadline, and explicit coverage state that follows each
derived detection.

### Why now

Microsoft documents bounded ETW buffers and that new events can be ignored when
real-time buffers fill:
[EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties).
ETW session tooling exposes “Events Lost” when allocated buffers are full:
[Tracelog Properties Display](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/tracelog-properties-display).
Microsoft also documents buffer callbacks for consumer-side buffer statistics:
[EVENT_TRACE_LOGFILEW](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew).

### Fit and file-specific implementation plan

- **Core:** add `src/angerona/core/telemetry_quality.py` with per-source bounded
  counters: session epoch, source cursor/bookmark, received, parsed, rejected,
  queue high-water, OS-reported loss, inferred sequence gaps, last event,
  last heartbeat, and clock discontinuity.
- **Sensors:** instrument `modules/etw_listener.py`,
  `modules/etw_realtime_sensor.py`, `modules/sysmon_listener.py`,
  `modules/av_telemetry_bridge.py`, and `modules/amsi_bridge.py`. Preserve each
  source's native meaning; never fabricate a universal loss number.
- **Event contract:** add a bounded `telemetry_quality_ref` to derived normalized
  events in `core/sensor_events.py`, pointing to a snapshot/epoch rather than
  copying large diagnostics into every event.
- **Cortex/ELAT:** allow `core/cortex.py` and
  `modules/evidence_lattice.py` to reduce confidence or mark “coverage degraded”;
  loss must not erase a true alert.
- **GUI:** World View shows freshness, OS loss, internal drops, and backlog by
  source. Alerts show the quality epoch that supported them.

Maps to `ENT-WIN-001/002` and the enterprise proof requirements.

### Abuse cases and failure handling

- An attacker flooding a provider cannot turn dropped events into a green sensor.
- Counter reset/restart creates a new epoch; it must not hide the prior gap.
- Clock rollback cannot make stale data appear fresh; use monotonic deadlines.
- Malformed events increment rejected counts without logging their unbounded raw
  contents.
- Unknown provider loss semantics are labeled unknown, not zero.

### Performance budget

- O(1) counter updates; no synchronous storage per event.
- <= 100 ns-scale Python bookkeeping is unrealistic as a claim; measured gate
  instead: <= 3% throughput regression at 50,000 synthetic events/minute.
- Flush aggregate quality snapshots at most every 5 seconds and on state change.
- <= 256 source epochs in memory and <= 10,000 persisted snapshots.

### Acceptance tests

- Deterministic overflow, queue saturation, parse rejection, bookmark resume,
  restart, clock rollback, subscriber stall, and source-disable fixtures.
- A loss burst changes coverage to degraded within 5 seconds.
- A later healthy epoch does not rewrite historical alert quality.
- Event throughput regression stays within 3% and GUI reads remain nonblocking.
- TECT canary health and loss accounting remain separate, complementary signals.

### Safety

Defensive observability only. It exposes blind spots and confidence limits; it
does not weaken providers, suppress events, or claim that loss identifies an
attacker.

---

## 4. Deterministic Investigation Broker with Capability Leases

**Pitch.** Let ARIA/local models propose bounded read-only investigations while
only deterministic code can issue short-lived, schema-validated tool leases;
response remains a separate human/policy-approved action.

### Why now

NIST's 2025 adversarial machine-learning taxonomy explicitly covers direct
prompt injection and AI supply-chain risks:
[NIST AI 100-2e2025, Adversarial Machine Learning](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2025.pdf).
NIST's Generative AI Profile treats prompt injection and over-reliance on model
output as risks requiring governance and evaluation:
[NIST AI 600-1, Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf).

### Fit and file-specific implementation plan

- **Core:** add `src/angerona/core/investigation_broker.py`. The immutable
  registry exposes read-only typed queries such as `event.lookup`,
  `process.snapshot`, `network.snapshot`, `evidence.resolve`, and
  `posture.read`; each has JSON schema, row/byte/deadline/rate/privacy budgets.
- **Policy:** make `src/angerona/core/action_policy.py` authoritative for broker
  admission only after shadow-mode equivalence tests. A lease binds tool,
  normalized arguments, evidence/case ID, requester, expiry, budget, and policy
  version.
- **ARIA:** adapt `core/assistant.py`, `core/copilot.py`, and
  `modules/ai_triage.py` so model output is an untrusted proposal. A deterministic
  parser chooses only registered tools; unknown fields and free-form commands
  fail closed.
- **Isolation:** execute higher-risk parsers in the existing worker/process
  isolation pattern, later using Job Objects/restricted tokens per
  `ENT-ISO-001/002/003`.
- **Audit:** record proposal, admission/denial, bounded result digest, citations,
  and budget use. Never store hidden chain-of-thought.

Maps to `ENT-AI-001/002/003/007/009` and `ENT-VIS-009`.

### Abuse cases and failure handling

- Prompt text inside email, web results, logs, filenames, or model output cannot
  mint a lease or widen a scope.
- A read tool cannot invoke a response tool transitively.
- Symlink/path traversal, PID reuse, oversized result, recursive query, tool
  fan-out, and timeout fail closed.
- Model unavailability yields deterministic “insufficient evidence”; it does not
  bypass policy.
- No voice-only approval and no generated PowerShell, Python, SQL, or firewall
  expression is executable.

### Performance budget

- Broker admission p95 <= 10 ms without model time.
- Default plan: <= 8 tool calls, <= 5 seconds wall time, <= 1 MiB total result,
  <= 500 rows, and no more than two concurrent plans.
- All queries use bounded indexes/snapshots and cancellation; no GUI-thread work.

### Acceptance tests

- Injection corpus includes hostile email, event message, webpage, Unicode
  confusables, nested JSON, tool-result poisoning, multilingual coercion, and
  “ignore policy” text.
- Fuzzed arguments never reach an unregistered callable or shell.
- Expired/replayed leases are rejected; identical approved read plans are
  deterministic over a fixed fixture.
- Every returned claim carries resolvable evidence references or explicitly
  says insufficient evidence.
- Response actions remain impossible through the investigation broker.

### Safety

Defensive investigation only. It offers cataloged reads, not unrestricted shell,
code execution, credential access, exploit generation, or autonomous destructive
response.

---

## 5. Evidence Reference Resolver and Claim Gate

**Pitch.** Introduce one bounded evidence-reference format so incident, AI,
containment, and compliance claims can be mechanically resolved to original
records and their transformations.

### Why now

NIST SP 800-86 emphasizes preserving and documenting digital evidence during
incident response:
[NIST SP 800-86, Guide to Integrating Forensic Techniques into Incident Response](https://csrc.nist.gov/pubs/sp/800/86/final).
OCSF provides an open, vendor-neutral schema intended to simplify consistent
security-event normalization:
[Open Cybersecurity Schema Framework](https://schema.ocsf.io/).

### Fit and file-specific implementation plan

- **Core:** add `src/angerona/core/evidence_refs.py` defining
  `EvidenceRef(source_kind, source_id, revision, observed_at, digest,
  transform_id, quality_epoch)`. IDs are opaque and privacy-minimized.
- **Storage:** add an append-only evidence index beside
  `core/storage.py`; resolve references against committed revisions only.
  Transform records bind input digests to redaction/normalization version and
  output digest.
- **Existing proof:** bridge, do not replace,
  `core/remediation_log.py`, `modules/provenance_graph.py`,
  `modules/evidence_lattice.py`, `core/ocsf_export.py`, and
  `shark/run_manifest.py`.
- **Claim gate:** `core/copilot.py`, `modules/ai_triage.py`, incident summaries,
  and compliance exports may label a sentence as `observed` only if all cited
  refs resolve and verify. Otherwise use `inferred`, `unverified`, or
  `insufficient evidence`.
- **GUI:** Alert/incident detail resolves a citation to a redacted source preview,
  collection time, quality state, transforms, and integrity result.

Maps to `DEF-005`, `ENT-CASE-002/003`, `ENT-AI-008`, and `ENT-COMP-002`.

### Abuse cases and failure handling

- Event text cannot claim another event's identifier.
- Deleted/expired evidence leaves a tombstone and retention reason; it cannot
  silently resolve to a newer row.
- Hash validity proves integrity, not truth; UI wording must preserve that
  distinction.
- Circular references, transform loops, oversized provenance chains, and
  cross-case access are rejected.
- Redaction transforms never expose the original through a preview or error.

### Performance budget

- Resolve one reference p95 <= 5 ms from a local index.
- At most 64 references per claim and 32 transformation hops.
- Batch GUI resolution <= 100 refs and <= 50 ms p95 from committed snapshots.
- Retention is policy-bounded; no automatic raw packet/content preservation.

### Acceptance tests

- Tests cover valid, missing, tampered, expired, wrong-revision, cross-case,
  transform-loop, redacted, and quality-degraded references.
- A model hallucinated ID cannot render as observed evidence.
- Modifying a stored source or transform invalidates dependent verification.
- OCSF export preserves the local reference without leaking local paths/identity.
- Existing remediation and drill receipt verification still passes unchanged.

### Safety

Defensive evidence handling only. The resolver neither executes evidence nor
equates integrity with maliciousness; previews remain bounded and non-executable.

---

## 6. Pktmon Counter Flight Recorder

**Pitch.** Use Windows' in-box Packet Monitor in counters-only, tightly filtered
mode to capture network-path health and drop reasons around a suspicious flow or
containment action without retaining payloads.

### Why now

Packet Monitor is an in-box Windows component that exposes cross-component packet
counts, drop detection/reasons, ETW/WPP integration, and circular or memory
modes:
[Packet Monitor overview](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon).
Microsoft recommends filters because unfiltered capture is noisy and documents
counters as a lower-cost alternative to log analysis:
[Pktmon command formatting](https://learn.microsoft.com/en-us/windows-server/networking/technologies/pktmon/pktmon-syntax).

### Fit and file-specific implementation plan

- **BaseModule:** add `src/angerona/modules/pktmon_counters.py` (`windows`,
  `observe/detect`) as an opt-in worker-backed sensor. Default to
  `--counters-only`; permit bounded drop-only ETL only with explicit diagnostic
  consent.
- **Isolation:** follow `modules/packet_sniffer.py` /
  `packet_sniffer_worker.py`: hidden worker, strict executable path, fixed argv
  grammar, Job Object, timeout, capped output, and cleanup.
- **Correlation:** attach a short recording to a network flow ID or containment
  action; retain component category, Tx/Rx/drop counts, last drop reason,
  filter digest, OS build, and time bounds—not packet bytes.
- **GUI:** expose “Capture network-path evidence (30 s)” from a flow/action
  detail, with an explicit overhead/privacy notice.

Maps to `ENT-NET-001/006` and improves response proof without a custom callout.

### Abuse cases and failure handling

- Never accept free-form pktmon arguments or executable paths.
- One Angerona-owned session at a time; detect foreign sessions without stopping
  them.
- Component IDs are boot/session-local and must not be treated as durable
  identity.
- Timeout, crash, privilege failure, or unsupported build yields an incomplete
  diagnostic, not “no drops.”
- No full packet capture, TLS interception, session keys, credential scanning,
  or remote destinations by default.

### Performance budget

- Default duration <= 30 seconds; <= 32 narrow filters; one concurrent session.
- Counters-only steady overhead target <= 1% CPU and <= 32 MiB worker memory,
  measured on the supported Windows matrix.
- Diagnostic ETL, if explicitly enabled, is circular and capped at 16 MiB with
  automatic deletion after derived metadata is committed.

### Acceptance tests

- Validate exact argv for IPv4/IPv6/TCP/UDP filters and reject injection tokens.
- Verify timeout/kill-on-close, foreign-session preservation, bounded files,
  unsupported build, privilege denial, malformed JSON, and cleanup after crash.
- Prove default output contains no payload bytes or credential values.
- Correlate a synthetic blocked flow to a bounded counter/drop record without
  declaring the WFP rule verified from pktmon alone.

### Safety

Defensive local diagnostics only. It is metadata-first, consent-gated, bounded,
and supplies no interception, evasion, offensive packet generation, or payload
collection capability.

---

## Recommended cycle cut

Implement the first three as the enterprise foundation:

1. **Kernel-Boundary Posture Ledger** gives honest coverage and a safe roadblock
   against prematurely shipping the custom driver.
2. **Transactional WFP Containment** provides the highest-value response proof.
3. **Telemetry Loss Accounting** makes all later detection evidence more
   trustworthy.

If capacity remains, build the Investigation Broker's deterministic registry and
lease verifier without wiring model-driven execution. The Evidence Reference
Resolver can then become the common proof substrate. Pktmon is a small,
independent diagnostic slice after the containment contract exists.
