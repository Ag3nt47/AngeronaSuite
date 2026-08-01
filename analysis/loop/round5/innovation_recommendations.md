# Round 5 Innovation Recommendations — Next Enterprise Tranche

Date: 2026-08-01

Scope: research and design only; no product code, policy, rule, or host state was
changed.

## Decision

The next local enterprise tranche should deepen evidence quality at five seams,
not add another broad subsystem. The recommendations below are all offline-first,
Windows user-mode additions. They require no Angerona kernel component, no cloud
service, no payload interception, no arbitrary query or script execution, and no
automatic security-policy enforcement.

Ranking uses ordinal **enterprise impact / effort**, with S=1, M=2, L=3 and
midpoints for mixed sizes. Implementation risk is shown separately on a 1–5
scale, where lower is better. The same five items retain this order under a
value/risk check; both quotients are prioritization heuristics, not delivery
estimates.

| Rank | Proposal | Gap class | Impact | Effort weight | Impact / effort | Risk | Value / risk | Effort | Mode |
|---:|---|---|---:|---:|---:|---:|---:|:---:|---|
| 1 | App Control Policy Evidence Ledger | Roadmap-confirmed, runtime-verified gap | 5 | 1.5 | 3.3 | 1 | 5.0 | S–M | Detect / Harden / Visualize |
| 2 | Signed Local Model Admission + ML-BOM | Newly sharpened trust gap | 4 | 1.5 | 2.7 | 1 | 4.0 | S–M | Harden / Visualize |
| 3 | ClickFix and LOLBin Behavior-Chain Pack | Newly identified detection-content gap | 5 | 2.0 | 2.5 | 2 | 2.5 | M | Detect / Respond |
| 4 | Detection Contract v2: ATT&CK v19 + Sigma 2.1 | Roadmap-confirmed standards gap | 5 | 2.5 | 2.0 | 3 | 1.7 | M–L | Detect / Harden / Visualize |
| 5 | ZTDNS/ECH-Aware Name-to-Flow Evidence | Newly identified Windows/NDR gap | 4 | 2.0 | 2.0 | 3 | 1.3 | M | Detect / Harden / Visualize |

## Existing capability versus genuine gap

This distinction matters because Angerona already has many of the required
primitives.

| Existing, keep and reuse | Concrete missing behavior established by code inspection |
|---|---|
| HMAC-authenticated EventBus, bounded async evidence ingestion, typed hunts/cases, causal graph, and evidence claims | No versioned ATT&CK v19 object registry and no bounded multi-event Sigma correlation semantics |
| Digest/signature-gated detection packages with fixtures and a single-event Sigma subset | Package schema accepts ATT&CK technique IDs only; it cannot express Detection Strategy, Analytic, Data Component, field mapping, correlation, or evidence-graded coverage |
| Sysmon bridge for event IDs 1/3/6/8/10/25, Security 4688/4624/4672 collection, AMSI scanning, process lineage, and NDR | No RunMRU registry evidence, executable-staging/ADS/DNS/WMI Sysmon events, PowerShell channel collector, or ClickFix-specific temporal chain |
| Kernel posture ledger for Secure Boot, VBS/HVCI, boot flags, driver-set drift, and whether the Code Integrity channel exists | No App Control policy identity/options/mode ledger and no 3076/3077/3089/3099/3114 or AppLocker script/MSI event consumption |
| AI Model Integrity Guard hashes Ollama blobs and the AI broker records provider/model/version | Model trust is TOFU; a new blob is automatically pinned and there is no signed admission record, model/prompt/runtime binding, or ML-BOM |
| DNS-name entropy detector and privacy-minimized process-to-IP flow analytics | No authoritative Windows DNS acquisition, resolver/protocol posture, TTL-bounded DNS-to-flow join, or ZTDNS state/evidence |

Local evidence for those conclusions:

- `core/sigma_engine.py:1-8` explicitly calls itself a minimal, non-full-spec
  matcher. `core/detection_packages.py:164-170` accepts technique IDs and exactly
  one `sigma-subset` detection.
- `modules/sysmon_listener.py:33-39` lists only six event IDs, and its reader
  starts at the end rather than keeping a durable bookmark
  (`modules/sysmon_listener.py:248-264`).
- `modules/kernel_posture_ledger.py:119-127` checks only whether the Code
  Integrity channel is available; the snapshot contains no policy or decision
  events (`modules/kernel_posture_ledger.py:220-230`).
- `modules/ai_model_integrity.py:11-16` documents TOFU and line 163 pins a
  newly seen blob automatically.
- `modules/network_protocol_decoder.py:10-12` consumes whatever DNS strings
  happen to reach EventBus, while `core/network_behavior.py:23-27` models a
  process and destination IP but no DNS or resolver evidence.

The earlier unimplemented NTFS Journal, NTLM Exit, call-stack, model-airlock,
QUIC, and split-token proposals were not relabeled as new work. Production
mTLS/OIDC, Authenticode custody, HA/DR, external assessment, and physical-host
soaks also remain important, but they are external gates rather than safely
completable local product additions.

---

## 1. App Control Policy Evidence Ledger

**Pitch.** Turn the existing “Code Integrity channel exists” bit into a
read-only, evidence-linked view of which App Control policies are active, what
mode/options they use, and what Windows actually audited or blocked.

### Why now

Windows Server 2025 includes a Microsoft default App Control policy and exposes
audit and enforcement modes. Microsoft documents event 3076 as the primary
audit-mode would-block event, 3077 as the enforced block, 3089 as correlated
signature evidence, and 3099 as policy activation; current Windows also exposes
Dynamic Code Security evidence such as 3114.

- [Configure App Control for Business by using OSConfig — Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/security/osconfig/osconfig-how-to-configure-app-control-for-business)
- [Understanding App Control event IDs — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations)
- [Understanding App Control event tags — Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-tag-explanations)

### Fit

- **Core:** add a pure `core/app_control_evidence.py` parser and bounded state
  model. Store policy ID/name, activation event, mode, option bits, observed
  Windows build, channel cursor/quality reference, and a digest of normalized
  policy metadata. Treat `unknown`, `not configured`, `audit`, `enforced`,
  `activation failed`, and `unreadable` as different states.
- **BaseModule:** add a Windows-only passive collector for
  `Microsoft-Windows-CodeIntegrity/Operational` plus the AppLocker MSI/Script
  channel. Initially support 3076, 3077, 3089, 3095–3105, and 3114; correlate
  signature records only through the OS Activity ID. Use the shared telemetry
  quality/evidence ingestion path rather than writing synchronously.
- **Existing seams:** emit `InventoryCategory.APPLICATION_CONTROL` records from
  `core/asset_inventory.py`; attach source references through the evidence store
  and show policy/decision history in Enterprise Settings and incident detail.
- **Product behavior:** provide an audit-impact export and drift warning only.
  Do not synthesize allow rules, merge policy XML, or switch audit/enforcement.

### Effort, dependencies, and limits

**S–M.** Requires documented event XML fixtures across supported Windows 10/11
and Server builds and a resumable Event Log cursor. Policy fields vary by build,
so unsupported tags must remain preserved as bounded opaque metadata or marked
unknown. App Control not being configured is posture evidence, not proof of
compromise.

### Acceptance gates

- Correctly distinguish audit would-block, enforced block, policy activation,
  refresh failure, and missing/unreadable channels.
- Correlate 3089 signature records only to a matching Activity ID and never
  treat “signed” as “allowed” or “safe.”
- Survive channel clear, duplicate/reordered events, malformed XML, policy ID
  reuse, restart, and unsupported Windows builds without reporting green.
- Bound retained decisions and path material; tokenize or redact user paths in
  exports.

### Safety

Defensive and read-only. It observes Windows enforcement evidence and policy
drift. It never enables/disables App Control, creates an allow rule, executes a
blocked file, or provides bypass instructions.

---

## 2. Signed Local Model Admission + ML-BOM

**Pitch.** Replace model trust-on-first-use with offline signature verification
and an auditable bill of materials before a model can influence security triage.

### Why now

NIST's March 2025 adversarial-ML taxonomy formalizes poisoning, evasion, abuse,
and lifecycle risk. OpenSSF now publishes a model-signing specification for a
detached, PKI-agnostic signature, and CycloneDX 1.7 (October 2025) supports an
ML-BOM and attestation/provenance structures.

- [NIST AI 100-2 E2025 — Adversarial Machine Learning](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [OpenSSF Model Signing Specification](https://github.com/ossf/model-signing-spec)
- [CycloneDX specification and ML-BOM support](https://github.com/CycloneDX/specification)

### Fit

- **Core:** add `core/model_admission.py` with a narrow, bounded verifier for an
  Angerona model-admission manifest. Bind every Ollama blob digest, model
  manifest/Modelfile digest, family/version, quantization, prompt-template
  version, runtime version, source, license, intended use, and expiry to an
  approved signing identity. Reuse Angerona's explicit Ed25519 trust roots and
  revocation pattern; do not introduce online keyless verification at runtime.
- **AI boundary:** extend `ModelProvenance` in `core/ai_security_broker.py` with
  the admitted manifest digest. All local inference clients must ask admission
  before generation. `unapproved`, `revoked`, `changed`, or `unreadable` models
  fall back to deterministic non-model output; they do not become “clean.”
- **AMIG:** keep chunked blob hashing as continuous runtime integrity evidence,
  but remove its authority to establish trust by auto-pinning unknown content.
- **Interop/GUI:** export a privacy-safe CycloneDX 1.7 ML-BOM for the exact local
  model/runtime set and show admission identity, verification time, expiry, and
  known limitations in Enterprise Settings.

This is deliberately separate from the previously proposed **Local Model
Airlock**. The Airlock is runtime process/network/filesystem isolation; this
proposal answers whether a specific model artifact and inference configuration
were approved at all. Either can be implemented independently, and neither is
counted as delivery of the other.

### Effort, dependencies, and limits

**S–M.** The first version should verify a small Angerona profile, not implement
every OpenSSF/CycloneDX feature. Existing installations need a visible
`unapproved legacy model` migration state and an explicitly reviewed offline
admission import. Initial hashing can be expensive for multi-gigabyte blobs and
must run in a bounded worker with cached file identity.

### Acceptance gates

- Reject altered blobs, missing/extra blobs, wrong model name, wrong prompt
  template/runtime binding, expired/revoked signer, duplicate JSON fields, and
  oversized manifests.
- A new Ollama blob never becomes trusted merely because its filename contains
  its SHA-256 or because the current user can rewrite the baseline.
- Model unavailability or rejection leaves detection and deterministic triage
  operational and creates one bounded health finding, not an alert storm.
- The exported ML-BOM validates against the pinned offline schema and contains
  no paths, usernames, tokens, prompts, or model responses.

### Safety

Defensive supply-chain verification only. It never trains, modifies, probes,
downloads, or executes a model and never grants a model response authority to
run a host action.

---

## 3. ClickFix and LOLBin Behavior-Chain Pack

**Pitch.** Detect user-pasted Run-dialog execution as a chain—RunMRU change,
trusted utility launch, script/file staging, and network activity—rather than as
a brittle command-line keyword.

### Why now

Microsoft reported in August 2025 that ClickFix was affecting thousands of
enterprise/end-user devices daily and recommended hunting RunMRU plus LOLBins
such as PowerShell, `mshta`, `rundll32`, `wscript`, `curl`, and `wget`. In
February 2026 Microsoft documented the CrashFix evolution using browser
disruption, a renamed Python runtime, and scheduled-task persistence. Sysmon
15.21 exposes the needed passive evidence classes, including registry, ADS,
WMI, DNS, and executable-file creation events.

- [Think before you Click(Fix) — Microsoft Threat Intelligence, August 2025](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [CrashFix deploying a Python RAT — Microsoft Defender Research, February 2026](https://www.microsoft.com/en-us/security/blog/2026/02/05/clickfix-variant-crashfix-deploying-python-rat-trojan/)
- [Sysmon v15.21 events — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### Fit

- **Sensor:** extend the user-mode Sysmon/Event Log consumer to normalize only
  selected configured events: Registry 12–14 (especially RunMRU), ADS/MOTW 15,
  configuration 16, WMI 19–21, DNS 22, and executable detection 29. Add a real
  PowerShell Operational collector for 4103/4104 when enabled. Angerona must not
  install or reconfigure Sysmon; a pre-existing Sysmon installation is an
  optional telemetry dependency, with native registry notification/Security/
  PowerShell channels as the reduced fallback.
- **Core analytic:** use a bounded five-minute state machine keyed by user
  session plus immutable process identity. Correlate a RunMRU value feature set
  with `explorer.exe`/shell ancestry, a LOLBin or renamed interpreter, then
  script/ADS/executable staging or a new DNS/network destination. Preserve exact
  evidence references and explicit missing-signal state.
- **Privacy:** inspect RunMRU/script text transiently, retain only a keyed digest,
  bounded feature flags (LOLBin, encoding, URL/IP, suspicious extension,
  non-ASCII lure marker), and a redacted preview when local policy permits.
- **Detection content:** ship it as a signed package with benign admin, failed
  Run invocation, accessibility/tooling, localized text, and high-volume
  fixtures. It is the first recommended consumer of Detection Contract v2.
- **Response:** create a Resolve Center recommendation to scan the exact staged
  artifact or contain the immutable process identity through the existing
  Response Broker. No automatic action from RunMRU alone.

### Effort, dependencies, and limits

**M.** Best fidelity needs a suitably configured, separately administered
Sysmon; Angerona's component remains user mode and passive. PowerShell content
availability depends on enterprise logging policy. RunMRU is strong context but
not proof of maliciousness, and legitimate administrators use the Run dialog.

### Acceptance gates

- Positive replays cover PowerShell, `mshta`, `rundll32`, script host, renamed
  interpreter, fileless, staged-file, and scheduled-task variants.
- Negative replays cover ordinary Run-dialog launches, administrative scripts,
  failed commands, software installers, developer tooling, localization, and a
  browser crash without a later execution chain.
- PID reuse, out-of-order events, missing Sysmon, disabled PowerShell logging,
  log clear, duplicate events, and queue loss cannot create a high-confidence
  chain.
- No raw clipboard content, full script block, credential, or unbounded RunMRU
  value is persisted or exported.

### Safety

Defensive detection and existing typed response only. It does not reproduce a
ClickFix command, create a lure, install Sysmon, execute a sample, or expose
offensive LOLBin recipes.

---

## 4. Detection Contract v2: ATT&CK v19 + Sigma 2.1

**Pitch.** Make Angerona's detection packages express versioned defensive
objectives, bounded temporal correlations, and proof states instead of counting
static technique rows as coverage.

### Why now

ATT&CK v18 replaced technique-page detections with Detection Strategies and
Analytics. ATT&CK v19.1 is current as of May 2026, has 15 Enterprise tactics
after splitting Defense Evasion into Stealth and Defense Impairment, and contains
697 Detection Strategies and 1,758 Analytics. Sigma 2.1, released in August
2025, standardizes event/value counts, temporal and ordered-temporal
correlations, grouping, field aliases, filters, and aggregate types.

- [MITRE ATT&CK v19 April 2026 update](https://attack.mitre.org/resources/updates/)
- [MITRE ATT&CK STIX 2.1 release data](https://github.com/mitre-attack/attack-stix-data)
- [Sigma Correlation Rules Specification 2.1](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html)

### Fit

- **Core registry:** add a strict offline importer for a pinned ATT&CK v19.1
  STIX 2.1 bundle. Retain release version/digest and only the bounded fields
  needed for tactics, techniques, Detection Strategies, Analytics, and Data
  Components. There is no runtime web fetch.
- **Package schema v2:** add explicit `attack_version`, Detection Strategy and
  Analytic IDs, Data Components, normalized field mappings, correlation/filter
  objects, privacy class, and replay expectations. Schema v1 remains readable;
  it is never silently upgraded or granted v2 coverage.
- **Correlation engine:** initially implement only `event_count`, `value_count`,
  `temporal`, and `temporal_ordered`, with fixed comparison operators, windows,
  group fields, and aliases. Set hard limits on window duration, candidate
  events, groups, values, and rule fan-in. Do not compile to SQL or accept a
  query language.
- **Replay:** run positive, benign/negative, corrupt/partial, reordered/lost, and
  high-volume fixtures against immutable evidence snapshots. Record rule,
  package, ATT&CK bundle, field-map, fixture, and engine digests.
- **GUI/coverage:** replace the single static percentage with explicit states:
  `source available`, `analytic loaded`, `fixtures passed`, `observed locally`,
  and `response verified`. A missing Data Component or degraded telemetry makes
  the analytic unavailable; it does not become a blind “pass.”

### Effort, dependencies, and limits

**M–L.** Phase 1 should deliver the versioned ATT&CK registry and honest coverage
states; phase 2 adds the four bounded Sigma correlation types. Percentile/sum/
average correlations, general Sigma conversion, remote backends, and automatic
content downloads stay out of this tranche. Existing field names need a small,
versioned mapping catalog.

### Acceptance gates

- Import the pinned ATT&CK v19.1 bundle reproducibly, reject unknown/revoked/
  oversized objects, and prove that the 15-tactic model is not folded back into
  the old 14-tactic layout.
- Reject missing referenced rules, cyclic references, unsupported correlation
  types, excessive windows/cardinality, unsafe regex/YAML constructs, and field
  aliases without a declared normalized target.
- Replays are deterministic across order permutations allowed by the contract;
  loss/degradation is visible in the result.
- Coverage cannot become “tested” without passing fixtures or “verified” without
  an independently verified response receipt.

### Safety

Defensive, declarative detection-as-code only. Packages cannot contain Python,
PowerShell, SQL, shell commands, response authorization, or model-selected
executable logic.

---

## 5. ZTDNS/ECH-Aware Name-to-Flow Evidence

**Pitch.** Correlate Windows DNS decisions to process-owned connections and
surface Zero Trust DNS posture without decrypting DNS, TLS, QUIC, or payloads.

### Why now

Microsoft documented Zero Trust DNS (ZTDNS) in November 2025 for Windows 11
Enterprise/Education: it combines the Windows DNS client with WFP, forces trusted
DoH/DoT resolution, and permits only resolved or explicit destinations while
logging connection attempts. In March 2026, RFC 9849 standardized TLS Encrypted
Client Hello, further reducing the reliability of passive SNI-based attribution.

- [Zero Trust DNS — Microsoft Learn, updated November 2025](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/zero-trust-dns/)
- [RFC 9849 — TLS Encrypted Client Hello, March 2026](https://www.rfc-editor.org/rfc/rfc9849.html)

### Fit

- **Core:** add `core/dns_flow_evidence.py`, a fixed-memory, TTL-aware joiner for
  normalized DNS results and process network flows. Retain resolver/protocol,
  response code, answer tokens, TTL/expiry, source evidence reference, and
  telemetry-quality epoch. Domain names are HMAC-tokenized at rest; raw names
  exist only in the bounded in-memory detection path when local policy permits.
- **BaseModule:** add a Windows-only read-side collector for documented DNS
  client events/ETW and supported ZTDNS/DoH/DoT configuration state. Distinguish
  `unsupported edition`, `not configured`, `configured`, `degraded`,
  `unreadable`, and `unknown`; Windows 11 Enterprise/Education gating is shown
  explicitly.
- **NDR:** enrich `core/network_behavior.py` findings with a DNS evidence
  reference, not the raw name. Detect policy drift, unapproved resolver/protocol
  use, and—at low confidence only—a new external connection with no matching
  fresh resolution when the source claims complete coverage. Caches, Hosts,
  proxies, VPNs, literals, and shared/CDN answers are explicit benign
  explanations.
- **WFP/GUI:** correlate ZTDNS attempted-connection evidence with existing WFP
  visibility and show `resolved and permitted`, `explicit exception`, `blocked`,
  or `unattributed`. Do not enable ZTDNS or modify WFP/DNS policy.

### Effort, dependencies, and limits

**M.** Full ZTDNS posture is edition/version gated and may require event/provider
research on each supported Windows build. DNS events can be absent because of
application-local resolvers or caches. ECH means the inner SNI is intentionally
unavailable; Angerona must label that limit instead of trying to infer or decrypt
it. This proposal is narrower than the prior QUIC Sightline idea: no QUIC
fingerprinting is included.

### Acceptance gates

- Deterministic fixtures cover A/AAAA/CNAME, cache/TTL expiry, answer reuse,
  IPv4/IPv6, process/PID reuse, proxy/VPN, direct-IP connection, resolver drift,
  ZTDNS block, duplicate/reordered events, and loss/unavailable states.
- Absence of a DNS join never alone raises High/Critical or authorizes a block.
- Raw qnames, browsing history, DNS payloads, SNI, certificates, and packet bytes
  are absent from persisted/exported evidence.
- Unsupported Windows editions show `unsupported`, not insecure or healthy.

### Safety

Defensive observation only. It performs no DNS poisoning, interception,
decryption, resolver change, WFP mutation, packet capture, or traffic generation.

## Recommended tranche cut

1. Deliver **App Control Policy Evidence Ledger** and **Signed Local Model
   Admission** first; both are high-value, low-risk, independent read-side trust
   improvements.
2. Land Detection Contract v2's ATT&CK registry and proof-state schema before
   shipping the ClickFix pack broadly. The ClickFix analytic can be developed in
   parallel against a bounded purpose-built state machine, then become the first
   correlation-package acceptance case.
3. Keep ZTDNS/ECH evidence behind a Windows-edition/build feature gate until
   provider availability, privacy, VPN/proxy behavior, and false-unattributed
   rates are measured on physical hosts.

No proposal should advance to automatic enforcement in this tranche. A later
human/remediation decision can select implementation work after the external
release gates and representative Windows compatibility testing are funded.
