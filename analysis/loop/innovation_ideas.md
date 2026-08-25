# Angerona Defensive Innovation and Open-Source Gap Review — 2026-08-25

## Decision

Angerona already has the essential shape of a local-first EDR/NDR/SOAR:
66 discovered modules, ETW and Sysmon process telemetry, WFP response,
authenticated evidence and action contracts, signed detection packages, cases,
Suricata/Zeek/OCSF imports, OCSF export, guarded osquery snapshots, YARA-X,
canary deception, ransomware rollback, and a typed local-AI broker. The useful
next step is not another broad feature list. It is deeper event continuity,
portable detection engineering, evidence attribution, response verification,
and supply-chain control.

This review compared the current tree with the official documentation for
Wazuh, Velociraptor, osquery/Fleet, Falco, Suricata, Zeek, Security Onion,
Sigma, YARA-X, OCSF, OASIS STIX/TAXII, Microsoft Windows telemetry, Ollama,
SLSA, and OWASP GenAI. The comparison deliberately does not propose features
Angerona already ships.

### Current-tree facts that shaped the ranking

- Sysmon Listener consumes event IDs 1, 3, 6, 8, 10, and 25, but not the
  high-value DNS, named-pipe, registry, WMI, and file events documented by
  Microsoft. It seeks to the end of the log at startup instead of resuming from
  an authenticated bookmark.
- ETW Realtime Sensor currently streams process creation only.
- Suricata import preserves community_id, while Zeek import and native Angerona
  flow events do not yet compute the same cross-tool flow identifier.
- OCSF export is a useful Detection Finding mapping, but it declares schema
  version 1.3.0 and does not emit the remediation and activity classes now
  available in the current OCSF schema.
- Kernel Posture Ledger records a driver-set digest, and Intel Sync has a small
  filename-oriented vulnerable-driver catalog. Neither forms a complete
  load-time signer, hash, version, Code Integrity, block-policy, and response
  evidence chain.
- YARA Scanner already uses YARA-X with compile-before-activate and a scan
  timeout. It does not have a rule-cost admission or hot-rule quarantine gate.
- AI Model Integrity Guard validates Ollama content-addressed blobs and a
  trust-on-first-use baseline. Angerona has no governed model or ARIA
  knowledge-pack installer with publisher provenance, resource admission,
  offline import, staged evaluation, and atomic rollback.
- ARIA already has typed outputs, evidence citations, tool validation,
  expiring authorization, and no raw shell tool. The remaining AI gap is
  stronger separation of untrusted retrieved data from control flow plus a
  repeatable security-quality evaluation gate.
- Linux has an optional privileged BCC/eBPF sensor. It does not yet have a
  signed CO-RE sidecar comparable to the modern eBPF deployment model.

## Ranked shortlist

Ranking uses impact divided by an effort weight: S=1, S-M=1.5, M=2, and L=3.
The score is a prioritization aid, not a delivery promise.

| Rank | Proposal | Impact | Effort | Impact / effort | Primary mode |
|---:|---|---:|:---:|---:|---|
| 1 | Community-ID Flow Fusion | 4 | S | 4.00 | Detect / Visualize |
| 2 | Restart-Safe Windows Event Continuity Sensor | 5 | S-M | 3.33 | Detect / Harden / Visualize |
| 3 | Evidence-Grade BYOVD Guard | 5 | S-M | 3.33 | Detect / Respond / Harden |
| 4 | ARIA Untrusted-Data Compartment and Eval Gate | 5 | S-M | 3.33 | Harden / Visualize |
| 5 | OCSF 1.8 Conformance and Remediation Export | 4 | S-M | 2.67 | Detect / Respond / Visualize |
| 6 | Sigma 2.1 Native Rule and Correlation Runtime | 5 | M | 2.50 | Detect / Visualize |
| 7 | Verified Stateful Containment Leases | 5 | M | 2.50 | Respond / Harden / Visualize |
| 8 | Governed Ollama Model and ARIA Pack Manager | 5 | M | 2.50 | Harden / Visualize |
| 9 | YARA-X Rule-Cost Admission | 3 | S-M | 2.00 | Detect / Harden |
| 10 | Journal-Backed Ransomware and Deception Attribution | 4 | M | 2.00 | Detect / Respond / Visualize |
| 11 | STIX/TAXII Intelligence Lifecycle | 4 | M | 2.00 | Detect / Harden / Visualize |
| 12 | Signed Linux CO-RE Sensor Sidecar | 4 | L | 1.33 | Detect / Harden |

---

## 1. Community-ID Flow Fusion

**Pitch.** Give native Angerona, Suricata, and Zeek observations one stable flow
identity so endpoint process evidence and NDR evidence join into a single
investigation timeline without IP-address guesswork.

### Why now

Suricata documents Community ID specifically as a predictable flow identifier
for matching records with tools such as Zeek. Its seed must be consistent
across tools. Zeek provides detailed connection and intelligence observations,
but source-specific IDs alone do not form a cross-sensor join.

Sources:
[Suricata 8 EVE Community Flow ID](https://docs.suricata.io/en/suricata-8.0.5/output/eve/eve-json-output.html),
[Zeek Intelligence Framework](https://docs.zeek.org/en/current/frameworks/intel.html).

### Fit

- **Core:** add a bounded Community ID v1 helper to security_interop and the
  normalized evidence contract. Preserve an incoming ID; otherwise compute it
  from canonical protocol, address, port, direction, and an explicitly
  configured seed.
- **Modules:** add community_id to Network Monitor, WFP Controller, packet
  decoder, and beacon evidence whenever a complete five-tuple exists.
- **Evidence Store / GUI:** group matching endpoint, Suricata, and Zeek records
  into one flow timeline. Show source count, process lineage, first/last seen,
  and any missing tuple fields. Never invent a join from partial data.
- **Mode:** Detect / Visualize.

### Effort

**S.** Pure user-mode normalization and UI grouping. IPv4/IPv6 normalization,
ICMP semantics, NAT, direction reversal, and seed migration need fixtures. A
Community ID proves tuple equivalence, not maliciousness or endpoint identity.

### Acceptance tests

1. Published Community ID test vectors produce exact expected identifiers for
   TCP, UDP, IPv4, IPv6, and reversed directions.
2. A synthetic Angerona flow, Suricata EVE row, and Zeek row join once when
   their tuples match and never join when one port differs.
3. Partial or malformed tuples remain separate with an honest not-computable
   reason.
4. A 100,000-row import stays bounded and demonstrates no quadratic join.

### Safety

Defensive and read-only. It captures no payload, scans no remote target, and
does not turn a flow match into automatic blocking without the existing
corroboration and response policy.

---

## 2. Restart-Safe Windows Event Continuity Sensor

**Pitch.** Expand Windows event coverage and persist authenticated bookmarks so
short-lived activity and events produced while Angerona restarts are not
silently lost.

### Why now

Microsoft identifies Sysmon DNS Query 22, File Create 11, Registry 12-14,
Named Pipe 17-18, WMI 19-21, Driver Load 6, Process Access 10,
CreateRemoteThread 8, and Process Tampering 25 as valuable security telemetry.
Microsoft also provides event-log bookmarks specifically to resume queries or
subscriptions after the last processed record. Velociraptor persists its event
table locally and buffers results while disconnected, illustrating why
endpoint monitoring must continue across control-plane loss.

Sources:
[Microsoft Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events),
[Microsoft Event Log bookmarks](https://learn.microsoft.com/en-us/windows/win32/wes/bookmarking-events),
[Velociraptor client monitoring](https://docs.velociraptor.app/docs/clients/monitoring/).

### Fit

- **BaseModule:** evolve Sysmon Listener into a selective Windows Event
  Continuity sensor. Add event IDs 11, 12-14, 17-22 and preserve the existing
  1/3/6/8/10/25 mappings. Collect Windows Security events only when the channel
  and audit policy provide them: 4624/4625, 4648, 4672, 4688, 4697, 4720-4726,
  4728/4732, 4740, 4768/4769/4771/4776, and service event 7045.
- **Core:** persist the last event record/bookmark per channel in an HMAC
  envelope. On rollover, clearing, missing bookmark, or permission loss, emit a
  visibility-gap event with start/end and reason instead of pretending
  continuity.
- **Correlation:** normalize process GUID, logon ID, account SID, target
  service, DNS query, named pipe, registry path, and WMI consumer into bounded
  attributes. Default collection excludes command lines and user display names
  unless the privacy setting already permits them.
- **GUI:** add channel coverage, current bookmark, lag, dropped/rolled-over
  count, and audit-policy availability to the telemetry coverage view.
- **Mode:** Detect / Harden / Visualize.

### Effort

**S-M.** The existing Sysmon XML parser and EventBus contract are reusable.
Event volume and event-field differences require edition/version gating and
per-event filters. Security-channel access requires elevation; missing auditing
is a visible limitation, not an installation side effect.

### Acceptance tests

1. Sanitized XML fixtures for every supported event ID map to exact normalized
   fields, severity, and ATT&CK tags.
2. Stop after record N, append N+1 through N+50, restart, and prove every new
   event is ingested exactly once.
3. Log clear, rollover, stale bookmark, access denied, malformed XML, and event
   flood each emit explicit coverage state without crashing or replay storms.
4. A noisy DNS/file fixture stays under configured CPU, queue, and evidence
   budgets; lower-value records shed before high-signal injection/driver events.

### Safety

Defensive and local. The sensor does not change audit policy automatically,
enable Sysmon, clear logs, query a remote host, collect credentials, or execute
commands found in event data.

---

## 3. Evidence-Grade BYOVD Guard

**Pitch.** Replace filename-only vulnerable-driver awareness with a complete
load-time evidence chain and a reversible, audit-first hardening plan.

### Why now

Microsoft explains that attackers abuse legitimate signed vulnerable drivers
for kernel execution. Its vulnerable-driver blocklist covers known
vulnerabilities, malicious signers, and behavior that circumvents the Windows
security model. Microsoft explicitly warns that blocking can break software or
devices and recommends audit-mode validation before enforcement. Sysmon Driver
Load event 6 carries signature and hash context.

Sources:
[Microsoft recommended driver block rules](https://learn.microsoft.com/en-us/windows/security/application-security/app-control-for-business/design/microsoft-recommended-driver-block-rules),
[Microsoft Sysmon Driver Load event](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events).

### Fit

- **Modules:** correlate Sysmon event 6 with Kernel Posture Ledger,
  Intel Sync, Code Integrity Operational events, loaded driver services, file
  hash, signer/certificate status, file version, first seen, and the current
  Microsoft block-policy state.
- **Core:** version the bundled vulnerable-driver intelligence by source
  release, digest, retrieval time, and expiry. Prefer exact hash/signer/version
  matches; filename-only matches remain weak evidence and cannot autonomously
  unload or delete a driver.
- **Response/Harden:** add a closed hardening plan that checks HVCI, ASR
  vulnerable-driver protection, and App Control audit results. Enforcement is
  offered only after a clean compatibility observation window, exact policy
  preview, a backup, OS support checks, and verified postconditions.
- **GUI:** show driver identity, why it matched, confidence, current protection,
  reboot requirement, compatibility warnings, and whether evidence is live or
  historical.
- **Mode:** Detect / Respond / Harden.

### Effort

**S-M** for evidence correlation and posture visibility; **M** if App Control
audit-to-enforce orchestration is included. Driver signatures and Code
Integrity field shapes vary by Windows version. Loaded drivers generally
cannot be safely removed without a reboot.

### Acceptance tests

1. Exact vulnerable hash/version, known-good same filename, unsigned driver,
   stale feed, and hash-unavailable fixtures produce distinct decisions.
2. A filename-only match can alert but cannot reach the response sink.
3. Audit-mode events generate a compatibility report; simulated enforcement is
   refused when the platform, backup, or postcondition proof is absent.
4. The Purple Guard BYOVD marker proves the whole detection path without
   loading any driver.

### Safety

Defensive only. Never load, exploit, patch, unload, or delete a driver. Never
ship a vulnerable driver or an unsigned kernel component. Policy enforcement
stays audit-first, reversible where Windows permits, and explicit about reboot
and blue-screen risk.

---

## 4. ARIA Untrusted-Data Compartment and Eval Gate

**Pitch.** Treat web pages, email, imported reports, model output, and retrieved
runbook text as tainted data that can inform a conclusion but can never rewrite
ARIA's control flow or tool authority.

### Why now

OWASP's current GenAI guidance lists prompt injection, supply-chain risk,
improper output handling, model denial of service, and excessive agency among
the central LLM application risks. CaMeL demonstrates a useful architectural
direction: extract trusted control flow separately and keep untrusted retrieved
data from changing program flow. Ollama structured outputs can enforce a JSON
schema, but schema validity alone does not establish authority.

Sources:
[OWASP GenAI LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/),
[Defeating Prompt Injections by Design](https://arxiv.org/abs/2503.18813),
[Ollama structured outputs](https://docs.ollama.com/capabilities/structured-outputs).

### Fit

- **Core AI Security Broker:** label every evidence item with origin, trust,
  sensitivity, and permitted data flow. Trusted operator intent selects a fixed
  read-only or response workflow before untrusted text enters the prompt.
- **Runbook RAG:** index only approved roots, record content digest and
  publisher, and return typed citations. Text that resembles instructions,
  tool calls, system prompts, or exfiltration requests remains quoted evidence.
- **ARIA:** use deterministic schemas at temperature zero for security
  conclusions. A model can select only registered typed tools already admitted
  by policy. Response Broker independently re-derives authorization from signed
  evidence; ARIA output is never the sole authority for a host mutation.
- **Eval gate:** maintain local fixtures for direct/indirect injection,
  malicious email/web content, forged evidence IDs, tool-name spoofing,
  oversized inputs, resource exhaustion, secret requests, and false citations.
  Compare candidate model and prompt-pack versions before activation.
- **GUI:** show data trust labels, citations, abstention, blocked control-flow
  attempts, token/resource budget, and active model/prompt-pack revision.
- **Mode:** Harden / Visualize.

### Effort

**S-M.** Most primitives already exist: typed output validation, evidence IDs,
tool validators, expiring authorization, RAG citations, and the Response
Broker. The work is provenance propagation, taint-policy enforcement, and a
reproducible eval corpus. No prompt-only defense should be claimed as complete.

### Acceptance tests

1. Every indirect-injection fixture may affect quoted findings but produces
   zero unauthorized tool calls and zero authority changes.
2. Unknown evidence IDs, extra schema fields, unsupported tools, replayed
   authorization, and expired requests fail closed.
3. A safe baseline task suite retains a defined quality floor while the hostile
   suite reaches zero unauthorized mutation.
4. Secrets, paths, URLs, IPs, and private context never leave the approved
   local/cloud boundary in egress tests.

### Safety

Defensive only. This does not add autonomous offensive agents, arbitrary tools,
shell access, exploit generation, credential access, or permission bypass.

---

## 5. OCSF 1.8 Conformance and Remediation Export

**Pitch.** Upgrade Angerona's OCSF layer from one Detection Finding mapper to a
validated, version-pinned contract covering observations, findings, and
response receipts.

### Why now

OCSF is an open, vendor-neutral event schema for producers, analytic systems,
and retained security data. The official repository's current release is 1.8.0
and includes event classes beyond Detection Finding, including remediation
activity introduced in earlier schema releases. Angerona currently labels its
mapping 1.3.0, so schema drift will increasingly reduce interoperability.

Sources:
[OCSF schema repository](https://github.com/ocsf/ocsf-schema),
[OCSF releases](https://github.com/ocsf/ocsf-schema/releases).

### Fit

- **Core:** pin an exact OCSF release digest and generate or vendor only the
  minimal schema fragments needed for Angerona classes. Map process, file,
  authentication, DNS/network, driver, detection finding, incident finding,
  and file/process/network remediation activity.
- **Evidence Store:** preserve producer schema version and original unmapped
  fields in bounded form. Import must validate against the declared version,
  not reinterpret unknown fields as healthy.
- **Response Broker / SOAR:** export requested, admitted, executed, verified,
  failed, rolled-back, and expired states as remediation activity with action
  and evidence correlation IDs.
- **GUI:** add a local conformance report listing supported classes, required
  field coverage, lossy mappings, and rejected records.
- **Mode:** Detect / Respond / Visualize.

### Effort

**S-M.** Mapping and validation are local and non-executable. The main work is
schema versioning, privacy redaction, backward compatibility, and deterministic
fixtures. OCSF does not solve transport, trust, or data retention by itself.

### Acceptance tests

1. Golden records validate against the exact pinned OCSF schema for every
   supported class.
2. Angerona event to OCSF to Angerona round trips preserve event ID, time,
   severity, process/flow identity, ATT&CK technique, and response state.
3. Unknown versions, missing required fields, oversized unmapped content, and
   formula-like export strings fail or sanitize deterministically.
4. No host identity, raw command line, path, or network address is exported
   when the privacy profile forbids it.

### Safety

Defensive and data-only. OCSF records are evidence, not executable commands.
Importing a remediation record cannot invoke a response.

---

## 6. Sigma 2.1 Native Rule and Correlation Runtime

**Pitch.** Let Angerona run a bounded, signed subset of portable Sigma rules and
ordered temporal correlations directly over its normalized evidence stream.

### Why now

Sigma 2.1 defines portable rules, filters, taxonomies, and standardized
correlations. Correlation types include event count, value count, temporal, and
ordered temporal proximity, with field aliases for different log sources. This
matches Angerona's evidence-lattice and kill-chain model but is not currently a
native detection-content format.

Sources:
[Sigma 2.1 specification](https://sigmahq.io/sigma-specification/),
[Sigma correlation rules specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html).

### Fit

- **Core:** implement a strict parser for a documented Sigma subset:
  selections, approved modifiers, boolean conditions, filters, ATT&CK tags,
  and the four bounded correlation types. Compile rules to an internal
  predicate plan; never execute generated query text or arbitrary YAML tags.
- **Evidence:** define an Angerona-to-Sigma field taxonomy for process, file,
  registry, DNS, network, authentication, driver, and response activity.
  Missing fields produce unsupported coverage, not a false non-match.
- **Detection registry:** package rules through the existing signed quarantine,
  validate, stage, activate, and rollback lifecycle. Record rule ID, source
  digest, compiler version, required fields, cost estimate, and expiry.
- **GUI:** add rule validation errors, required-sensor coverage, sample replay,
  performance cost, false-positive notes, and correlation timeline.
- **Mode:** Detect / Visualize.

### Effort

**M.** A safe subset is realistic; full Sigma backend parity is not. The
runtime needs bounded windows, group cardinality caps, eviction, clock-skew
handling, and deterministic modifier semantics. External pySigma may be used
only if hash-locked and release-reviewed; a small native subset reduces
dependency risk.

### Acceptance tests

1. Official-style fixtures for selection, filters, count, temporal, and ordered
   temporal rules produce exact positive and negative results.
2. Unsupported log source, field, modifier, correlation, YAML type, or
   excessive cardinality fails validation before activation.
3. A 100,000-event adversarial stream stays inside memory and latency budgets
   with exact expiry and no cross-host/group contamination.
4. Signed-package activation and rollback leave one authoritative rule revision
   and an authenticated receipt.

### Safety

Defensive only. Sigma content is declarative detection logic. No shell,
subprocess, network fetch, response command, offensive emulation, or
model-generated rule can become active without the existing signed lifecycle.

---

## 7. Verified Stateful Containment Leases

**Pitch.** Turn automatic containment into short-lived, evidence-bound leases
whose effect and rollback are both verified, so autonomy is fast without
becoming permanent unobserved outage.

### Why now

Wazuh distinguishes stateless actions from stateful responses that revert after
a configured interval, and warns that poorly implemented automatic response
can increase endpoint risk. Angerona already has richer response protections
than a generic response script system; the gap is a uniform lease and
postcondition contract across process, file, IP, and host-isolation actions.

Sources:
[Wazuh Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html),
[Wazuh incident-response use cases](https://documentation.wazuh.com/current/getting-started/use-cases/incident-response.html).

### Fit

- **Core Response Broker:** add a typed response recipe containing evidence
  minimums, exact target identity, precondition, action, postcondition,
  lease duration, renewal ceiling, rollback, rollback postcondition, protected
  targets, and failure escalation.
- **Adversary Combat / SOAR:** route automatic suspend, quarantine, IP block,
  and host isolation through the same recipe engine. A stronger action requires
  stronger independent evidence. Repeat triggers may renew within a bound;
  they may not silently convert a lease into a permanent change.
- **Flight recorder:** authenticate admitted, executing, verified, renewed,
  expired, rolled-back, rollback-failed, and manually retained states. The
  Watchdog resolves expired leases after GUI/core restart.
- **GUI:** show active containment, exact scope, reason, time remaining,
  observed effect, undo readiness, and recovery failure. Provide an emergency
  local-console rollback independent of ARIA.
- **Mode:** Respond / Harden / Visualize.

### Effort

**M.** Response Broker, WFP containment, quarantine, protected-process guards,
Watchdog, and receipts already exist. Each action adapter still needs a precise
postcondition and idempotent rollback. Network and process state can change
between admission and execution.

### Acceptance tests

1. Synthetic high-confidence evidence automatically applies each allowed
   action once, verifies the effect, expires, and verifies rollback.
2. Stale/mutated evidence, PID reuse, path replacement, protected targets,
   duplicate triggers, concurrent actions, restart mid-action, and replay fail
   closed without widening scope.
3. A failed postcondition triggers recovery; a failed recovery becomes a
   Critical operator-visible state and never reports success.
4. Kill-switch and local-console rollback work while Ollama, the GUI, and
   network access are unavailable.

### Safety

Defensive only. The catalog contains containment and recovery operations, not
arbitrary scripts. It cannot attack a remote machine, erase evidence, disable
security controls, kill protected/system processes, or expand beyond the exact
local target authorized by corroborated evidence.

---

## 8. Governed Ollama Model and ARIA Pack Manager

**Pitch.** Add one explicit installer for approved local models and
non-executable ARIA knowledge packs with provenance, digest pinning, resource
admission, offline transfer, evaluation, atomic activation, and rollback.

### Why now

Ollama exposes model pull, show, list, digest, format, parameter size,
quantization, license, capabilities, context length, and Modelfile parameters.
SLSA emphasizes verifying an artifact's digest, signature/provenance, trusted
builder identity, and expected build parameters. Velociraptor's Artifact
Exchange warns that community artifacts can fetch binaries or run code and are
not guaranteed safe; Angerona should not reproduce that trust model.

Sources:
[Ollama pull API](https://docs.ollama.com/api/pull),
[Ollama show model details](https://docs.ollama.com/api-reference/show-model-details),
[Ollama Modelfile reference](https://docs.ollama.com/modelfile),
[SLSA artifact verification](https://slsa.dev/spec/v1.2/verifying-artifacts),
[Velociraptor Artifact Exchange warning](https://docs.velociraptor.app/docs/artifacts/exchange_reference/).

### Fit

- **Core:** define a signed Model/ARIA Pack Manifest with package ID, publisher,
  exact Ollama model digest or file SHA-256, family, quantization, size,
  license digest, minimum Ollama version, capabilities, memory/VRAM/disk
  estimate, allowed source, prompt/runbook digests, eval profile, and rollback
  target.
- **Download:** only an explicit user action may pull. Force secure transport;
  never set Ollama's insecure option. Download to a confined staging area,
  enforce byte/time/free-space limits, verify content and metadata, scan
  archives safely, and refuse links, devices, path escapes, or executable
  knowledge-pack content.
- **Offline:** export/import a signed manifest plus content-addressed blobs on
  local media. Verify before any Ollama import. No network availability is
  required to validate, run evals, activate, or roll back.
- **Activation:** run the ARIA hostile/safe eval gate and a hardware smoke test,
  then atomically update the selected model/prompt/runbook revision. Preserve
  the last known-good revision and unload rejected candidates.
- **GUI:** an Approved Models and ARIA Packs page shows provenance, license,
  digest, size, hardware fit, capability, evaluation delta, active revision,
  rollback, and delete-unused action.
- **Mode:** Harden / Visualize.

### Effort

**M.** Ollama already supplies useful metadata but does not by itself establish
publisher provenance. An Angerona-approved catalog and signed manifest are
required. Exact RAM/VRAM use remains a measured estimate and must be gated by
the resource governor.

### Acceptance tests

1. Valid online pull, valid offline import, wrong digest, unknown publisher,
   altered manifest, license change, downgrade, oversized package, low disk,
   insufficient RAM, interrupted download, and archive escape fixtures all
   produce deterministic results.
2. Failed evaluation or smoke test leaves the active model unchanged and
   unloads/quarantines the candidate.
3. Power loss between staging and activation recovers to exactly one
   authenticated active revision.
4. A knowledge pack containing code, tool definitions, shell text marked as an
   executable action, external include, symlink, or network callback is refused.

### Safety

Defensive only. No arbitrary GitHub URL, automatic self-update, executable
skill, unsigned model, insecure Ollama pull, silent license acceptance, or
model-authored host action is permitted. Downloaded content can improve
analysis and guidance but cannot grant new tool authority.

---

## 9. YARA-X Rule-Cost Admission

**Pitch.** Measure candidate YARA-X rules before activation and quarantine rules
that exceed CPU, timeout, or match-volume budgets.

### Why now

YARA-X provides rule profiling to identify slow rules by total scan time. Its
Python Scanner supports explicit timeouts and match limits. Angerona already
uses those scanner controls; admission-time cost evidence is the missing
performance layer.

Sources:
[YARA-X rule profiling](https://virustotal.github.io/yara-x/blog/profiling-your-yara-rules/),
[YARA-X Python API](https://virustotal.github.io/yara-x/docs/api/python/).

### Fit

- **YARA Scanner / detection registry:** benchmark staged rule packages against
  a fixed benign corpus, pathological-size samples, and safe synthetic
  positives. Record compile time, bytes/sec, per-rule scan time, timeout count,
  match count, and memory high-water mark.
- **Admission:** reject global rules without a bounded purpose, excessive
  wildcard/regex cost, repeated timeouts, huge match volume, or regression
  beyond an approved performance envelope. Atomically activate only compiled
  and admitted rules.
- **Runtime:** maintain per-rule timeout/error counters. Automatically disable
  only the offending package revision after repeated budget breaches, preserve
  evidence, and restore the last known-good rules.
- **GUI:** show slowest rules, coverage contribution, last timeout, package
  revision, and rollback state.
- **Mode:** Detect / Harden.

### Effort

**S-M.** Scanner timeouts already exist. Portable per-rule profiling may require
the YARA-X profiling-enabled CLI or a controlled benchmark strategy when the
Python binding lacks equivalent counters. Cold-cache variability requires
relative thresholds and repeated runs.

### Acceptance tests

1. Known-fast, intentionally slow, excessive-match, compile-fail, and timeout
   fixtures are admitted or rejected as expected.
2. A rejected package never replaces active compiled rules.
3. Runtime repeated timeout quarantines only the offending revision and
   restores the prior rules without interrupting other sensors.
4. Benchmark work respects Chill Mode, cancellation, file-size, and wall-clock
   budgets.

### Safety

Defensive and file-scanning only. The corpus contains inert fixtures, not live
malware; rules cannot execute code, fetch data, or authorize remediation.

---

## 10. Journal-Backed Ransomware and Deception Attribution

**Pitch.** Use bounded NTFS journal events and high-value file telemetry to
attribute canary and encryption changes to process lineage instead of reporting
only that a file changed.

### Why now

osquery documents NTFS Journal event publishing for real-time Windows file
integrity monitoring. Microsoft Sysmon File Create records the responsible
process for file creation/overwrite. Angerona's ransomware and deception
modules already detect entropy, rename bursts, canary deletion/tampering, and
restore clean snapshots, but their polling path cannot always identify the
actor.

Sources:
[osquery File Integrity Monitoring](https://osquery.readthedocs.io/en/5.9.0/deployment/file-integrity-monitoring/),
[Microsoft Sysmon file-system events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events).

### Fit

- **BaseModule:** add an optional native NTFS Journal reader or fixed osquery
  event-table adapter for only approved local volumes and watched roots. Persist
  journal ID and USN cursor in an authenticated envelope and expose journal
  reset/wrap as a coverage gap.
- **Ransomware:** correlate rename/write/delete bursts with process GUID, parent
  lineage, signer/hash, target root, entropy change, Shadow Shield snapshot,
  and canary contact. Preserve ordering in a bounded incident window.
- **Deception:** give each decoy an opaque canary ID and signed manifest.
  Attribute trip events from journal/Sysmon evidence, immediately rotate the
  decoy set, and require a negative-control decoy to remain quiet before
  escalating to automatic containment.
- **Performance:** watch configured directories, not whole volumes; batch journal
  reads, deduplicate by volume/journal/USN, and move hashing to the existing
  bounded worker pool.
- **Mode:** Detect / Respond / Visualize.

### Effort

**M.** Native journal parsing is Windows-specific and volume journals can be
disabled, reset, or wrap. The guarded osquery bridge may be extended only with
fixed read-only queries; it must still reject caller SQL and automatic install.
Sysmon file events are valuable but may be noisy.

### Acceptance tests

1. Synthetic create/write/rename/delete sequences attribute exact process
   lineage and preserve order across restart without duplicates.
2. Journal wrap/reset, unsupported filesystem, removable-volume change,
   permission failure, and missing Sysmon correlation become visible coverage
   states.
3. Canary trip plus ransomware burst reaches the response recipe; canary-only,
   backup/indexer, and negative-control fixtures remain below automatic action.
4. A high-churn file workload remains within queue, memory, hash, and CPU
   budgets while high-signal canary events are never shed.

### Safety

Defensive and local. It does not enable a journal, alter audit policy, plant
decoys outside approved roots, inspect file contents beyond existing bounded
hash/entropy logic, or execute a suspected file.

---

## 11. STIX/TAXII Intelligence Lifecycle

**Pitch.** Replace flat IOC refreshes with versioned STIX relationships,
confidence, markings, expiry, and collection provenance while retaining
local-only correlation and offline caches.

### Why now

OASIS defines STIX as a machine-readable language for cyber threat intelligence
and TAXII as its HTTPS exchange protocol. STIX captures indicators plus
relationships and contextual objects; TAXII exposes collections, manifests,
versions, filtering, and pagination. Zeek's Intelligence Framework similarly
attaches source metadata and warns that larger intelligence sets increase CPU
cost.

Sources:
[OASIS STIX/TAXII documentation](https://oasis-open.github.io/cti-documentation/),
[OASIS TAXII 2.1 introduction](https://oasis-open.github.io/cti-documentation/taxii/intro.html),
[Zeek Intelligence Framework](https://docs.zeek.org/en/current/frameworks/intel.html).

### Fit

- **Intel Sync:** add an opt-in TAXII 2.1 client for explicitly configured,
  HTTPS-only collections. Bound pages, bytes, objects, relationships, and
  request time. Store server identity, collection ID, object version, received
  time, valid_from/until, confidence, marking, source, and content digest.
- **Core:** support a strict STIX subset: Indicator, Malware, Tool,
  Vulnerability, Attack Pattern, Course of Action, Relationship, and Marking
  Definition. Compile supported patterns to the existing hash/IP/domain/URL
  match indexes; unsupported pattern operators remain visible and inactive.
- **Correlation:** intelligence is context, never sole mutation authority.
  Response still requires fresh host/network evidence and existing policy.
- **GUI:** show feed health, provenance, freshness, expiry, markings, supported
  versus inactive objects, relationship graph, and last known-good offline
  cache.
- **Mode:** Detect / Harden / Visualize.

### Effort

**M.** STIX patterning is broad; a strict documented subset is essential.
Collections may require credentials, which remain in SecureStore. Large feeds
need incremental versions, tombstones, expiry, deduplication, and cost budgets.

### Acceptance tests

1. OASIS-style bundles, relationships, markings, pagination, versions, expiry,
   malformed patterns, server truncation, replay, and clock skew produce exact
   lifecycle state.
2. Network failure retains the last verified cache and labels it stale; it does
   not erase active local intelligence.
3. Unsupported objects/operators cannot enter match indexes or trigger action.
4. Marked or privacy-restricted intelligence never appears in an export that
   lacks the required handling level.

### Safety

Defensive intelligence consumption only. No IOC is probed, contacted, scanned,
sinkholed, or attacked. TAXII is opt-in and inbound data never becomes code or
automatic response authority.

---

## 12. Signed Linux CO-RE Sensor Sidecar

**Pitch.** Replace the Linux BCC-only ceiling with an optional signed,
resource-bounded CO-RE eBPF sidecar that emits the existing normalized event
contract.

### Why now

Falco's default modern eBPF driver uses CO-RE and is included with the binary,
avoiding per-kernel probe builds on supported systems. Falco also distributes
rules and plugins as OCI artifacts and documents compatibility/version
requirements. osquery notes that event-based process and socket auditing is
powerful but can add CPU and event volume, so explicit budgets and host testing
are required.

Sources:
[Falco modern eBPF download and driver model](https://falco.org/docs/setup/download/),
[Falco plugin compatibility](https://falco.org/docs/concepts/plugins/usage/),
[osquery process and socket auditing](https://osquery.readthedocs.io/en/stable/deployment/process-auditing/).

### Fit

- **Native sidecar:** a minimal memory-safe Rust or reviewed C/libbpf binary
  observes process exec/exit, file execution, outbound connection, and selected
  security-relevant syscalls. It emits length-delimited, versioned local IPC
  records; it accepts no target, filter language, command, or response action
  from the wire.
- **eBPF module:** verify Authenticode-equivalent package signature where
  available, file SHA-256, manifest, architecture, kernel/BTF support, protocol
  version, and privilege boundary before launch. Normalize into the existing
  Linux sensor event contract.
- **Resource governor:** bound ring size, event rate, batch size, field lengths,
  CPU, memory, and drop policy. Expose produced, consumed, kernel-lost, user-
  dropped, malformed, and restart counts.
- **Packaging:** release only reviewed, reproducible target binaries with
  provenance and exact hashes. Keep rootless Observe as the default fallback.
- **Mode:** Detect / Harden.

### Effort

**L.** Requires native build, Linux kernel/BTF/version testing, privilege
separation, signed release artifacts, and target-runner CI. Containers and
namespaces complicate process/network identity. Unsupported hosts remain on
rootless or BCC modes with an honest capability contract.

### Acceptance tests

1. Supported-kernel VM matrices prove exec/connect capture, process identity,
   event ordering, restart, protocol negotiation, and clean unload.
2. No BTF, old kernel, wrong architecture, altered binary, wrong signature,
   protocol mismatch, privilege failure, and ring overflow fail to explicit
   degraded states.
3. A 100,000-event stress run reports exact loss counters, respects resource
   budgets, and does not block the GUI/core.
4. Fuzzed IPC records cannot crash the consumer, allocate unbounded memory, or
   invoke any action.

### Safety

Defensive observation only. No exploit, packet injection, process manipulation,
remote scanning, arbitrary BPF program, unsigned driver/module, or hidden
persistence. Rootless Observe remains available; privileged telemetry is an
explicit operator deployment.

---

## Cross-project comparison and disposition

| Project / standard | Mature pattern reviewed | Angerona disposition |
|---|---|---|
| Wazuh | Triggered and stateful active response | Reuse Angerona's stronger typed broker; add verified leases, not arbitrary scripts |
| Velociraptor | Persistent client event tables, offline buffering, artifact ecosystem | Add restart-safe bookmarks; reject bulk unreviewed executable artifacts |
| osquery / Fleet | Evented host tables, portable queries, scheduled differential state | Keep fixed read-only bridge; add bounded journal telemetry, never caller SQL |
| Falco | Modern CO-RE eBPF, versioned plugins/rules | Long-term signed Linux sidecar; preserve rootless fallback |
| Suricata / Zeek | Community ID, rich flow/intelligence context | Add stable cross-sensor flow joins and versioned intelligence |
| Security Onion | Cases, escalation, analyzers, node/EPS/staleness visibility | Cases already exist; deepen sensor continuity, lag, loss, and performance UX |
| Sigma | Portable detection and temporal correlation | Add a strict signed subset over normalized evidence |
| YARA-X | Safe compiled scanning, timeouts, rule profiling | Keep current scanner; add admission and hot-rule rollback |
| OCSF | Versioned vendor-neutral event/remediation classes | Upgrade the existing mapper and validate exact schema contracts |
| Ollama / SLSA | Model metadata plus artifact provenance verification | Build an approved, digest-pinned, resource-gated, rollback-safe manager |

## Recommended implementation sequence

1. Community-ID flow fusion, Windows event continuity, BYOVD evidence, and ARIA
   compartment/eval work deliver the highest impact per effort.
2. OCSF conformance provides the stable field contract needed before building
   Sigma correlations and broader STIX/TAXII interchange.
3. Stateful containment leases should land before any additional unattended
   response recipe.
4. The model/ARIA pack manager must land before exposing any in-app model or
   skill download surface.
5. YARA-X admission and journal attribution can then deepen performance and
   ransomware/deception quality.
6. The CO-RE sidecar remains a separately reviewed native release project with
   target-runner evidence, not a Python-only increment.

## Explicit non-goals

- No offensive tooling, exploit creation, credential theft, evasion, attack
  infrastructure, hack-back, remote scanning, or weaponized adversary module.
- No arbitrary shell/script response, downloaded executable skill, bulk GitHub
  artifact import, unverified model, insecure Ollama pull, or silent update.
- No new unsigned Windows kernel driver. ETW Threat Intelligence access that
  requires protected-process privileges must not be claimed from an ordinary
  elevated user-mode process.
- No automatic security-policy weakening, GPO/MDM reversal, driver deletion,
  log clearing, audit-policy mutation, or permanent containment without an
  explicit retained-policy decision.
- No claim of 100 percent attack coverage. Completion means passing the stated
  positive, negative, continuity, resource, and rollback tests with limitations
  visible.
