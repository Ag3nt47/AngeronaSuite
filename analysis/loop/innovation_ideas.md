# Angerona Cycles 31-33 Enterprise-Pattern Innovation Review — 2026-08-30

## Delivered bounded programs

Three research tracks were selected because they extend Angerona's local-first
architecture without adding offensive behavior, arbitrary remote execution, or
an unsupported enterprise-parity claim.

1. **Fleet Fabric Lab / Fleet Center.** OpAMP, Elastic Fleet, Wazuh, SPIRE, and
   Velociraptor informed a local governed design for sealed enrollment grants,
   durable device bindings, bounded health evidence, and desired-versus-effective
   rollout evaluation. Remote transport, dispatch, HA, distributed quotas, and
   production mTLS coordination remain proposed, not shipped.
2. **DetectionForge.** Google SecOps retrohunt/observability, Elastic rule
   preview/history and `detection-rules`, and Microsoft Sentinel execution
   health informed immutable replay cohorts, active-candidate diffs, an
   alert-inert shadow lane, chained quality receipts, and exact promotion or
   rollback. The shipped scope is local governed evaluation.
3. **AegisPath.** Microsoft and Tenable attack-path guidance, FIRST EPSS, CISA
   KEV, and NIST CSF 2.0 informed evidence-bound exposure graphs, bounded
   confirmed/speculative paths, choke points, inert breakpoint simulations,
   and explainable priority. It does not claim exploitability, breach
   probability, reachability proof, or remediation proof.

All three programs expose clickable evidence in Local SOC and retain explicit
loss, freshness, provenance, authority, and resource limits. Full adversarial,
performance, QA, and trust-boundary disposition is in
`analysis/loop/cycles31-33-summary.md` and the `cycle31` through `cycle33`
records below it.

## Proposed / backlog after v1.13.0

- Independently administered fleet identity, transport, key rotation,
  distributed quota, HA, and remote policy dispatch.
- Out-of-process detection evaluation with forcible CPU/time termination and an
  independent ledger/rollback anchor.
- Externally signed exposure-provider manifests and absence evidence, plus a
  bounded backend job interface for very large counterfactual runs.
- Clean-machine deployment, long-running scale/false-positive trials, and
  independent efficacy evaluation for all three programs.

---

# Angerona Cycle 26 Defensive Innovation Review — 2026-08-28

## Decision

Recent public reporting does not justify adding offensive simulation, exploit
delivery, credential collection, or an unsigned kernel component to Angerona.
It does justify strengthening the boundaries between controls. Advanced
intrusions increasingly abuse legitimate administration, trusted providers,
identity control planes, routers, DNS, and out-of-band hardware while trying to
make ordinary endpoint activity look normal.

The ten proposals below are defensive designs only. They are ranked by
estimated impact divided by effort and deliberately extend existing Angerona
controls instead of duplicating them. Source-reported attribution is context,
not a detection output: Angerona must label behavior and evidence, never infer a
state, agency, sponsor, or person from a technique match.

### Current-tree gap map

- `LSASS Credential-Access Guard` detects command-line and artifact patterns
  around credential dumping, while `Persistence Sweep` checks common autoruns.
  Neither currently inventories Windows authentication extension points such
  as LSA notification packages and network providers as a complete
  file/signer/ACL baseline.
- `AV Telemetry Bridge`, `Audit Log Integrity Guard`, `API Patch Detector`,
  `Self Integrity`, ETW, Sysmon, and process polling provide overlapping
  signals, but there is no explicit completeness-aware witness quorum that
  detects one source going selectively blind.
- `Network Trust Monitor` records privacy-tokenized DNS/DHCP/route/gateway
  drift. It does not independently witness selected DNS answers or perform
  bounded fast-flux analytics over DNS and flow history.
- `Identity Session Guard` already understands device-code, new-device, RMM,
  and privilege-transition evidence, but its collector mode is intentionally
  `supplied-evidence-only`; it has no first-party, least-privilege Entra audit
  connector.
- `Temporal Tradecraft Correlator` covers selected SSH, network-path, and
  log-clear sequences. The deterministic fast path still relies heavily on
  individual command/process indicators rather than completeness-aware native
  administration sequences.
- `Peripheral and DMA Posture` and `USB Monitor` cover DMA and removable media,
  not an enrolled topology of HID, composite USB-network, and console devices.
- ARIA has typed tools, bounded RAG, signed plugin lifecycle, evidence IDs, and
  an independent response broker. There is not yet one runtime manifest binding
  the model, prompt, retrieval corpus, tool schemas/descriptions, connector
  permissions, agent identities, and approval semantics.
- Guided Auto Adapt has an immutable, restorable Windows Firewall baseline.
  Other security-control posture is not represented as equivalently restorable;
  that boundary must remain explicit.

## Ranked shortlist

Effort weights are S=1, S-M=1.5, M=2, M-L=2.5, and L=3. Impact is a relative
1–5 estimate. Ties are ordered by implementation readiness and breadth.

| Rank | Proposal | Impact | Effort | Impact / effort | Primary mode |
|---:|---|---:|:---:|---:|---|
| 1 | Windows Authentication Extension Integrity Guard | 5 | S-M | 3.33 | Detect / Harden / Visualize |
| 2 | Security-Control Drift Witness and Safe Recovery Plans | 5 | S-M | 3.33 | Detect / Harden / Respond |
| 3 | ARIA Runtime Supply-Chain and Consent Proof | 5 | S-M | 3.33 | Harden / Visualize |
| 4 | Completeness-Aware Sensor Witness Quorum | 5 | M | 2.50 | Detect / Harden / Visualize |
| 5 | Independent DNS Path Witness and Fast-Flux Guard | 5 | M | 2.50 | Detect / Harden / Visualize |
| 6 | Trusted Administration and RMM Provenance Ledger | 5 | M | 2.50 | Detect / Harden / Visualize |
| 7 | Native Administration Sequence Correlator | 4 | M | 2.00 | Detect / Visualize |
| 8 | Out-of-Band Console and HID Topology Guard | 4 | M | 2.00 | Detect / Harden / Visualize |
| 9 | Least-Privilege Entra Identity Evidence Connector | 5 | M-L | 2.00 | Detect / Visualize |
| 10 | Edge Control-Plane Evidence Intake | 5 | L | 1.67 | Detect / Harden / Visualize |

---

## 1. Windows Authentication Extension Integrity Guard

**Pitch.** Detect unauthorized changes to Windows authentication extension
points before a legitimate logon or password-change path becomes a durable
credential-interception surface.

### Why now

Microsoft Incident Response reported in May 2026 that a stealthy intrusion
abused a trusted third-party management relationship and legitimate management
software, then registered authentication components on domain infrastructure.
The important defensive lesson is not the campaign's specific artifact names;
it is that trusted delivery and legitimate authentication extensibility can
hide persistence from malware-centric controls.

Sources:

- [Microsoft — Undermining the trust boundary: Investigating a stealthy intrusion through third-party compromise](https://www.microsoft.com/en-us/security/blog/2026/05/12/undermining-the-trust-boundary-investigating-a-stealthy-intrusion-through-third-party-compromise/)
- [MITRE ATT&CK — Modify Authentication Process](https://attack.mitre.org/techniques/T1556/)

### Fit

- **New Windows `BaseModule`:** `AuthenticationExtensionGuard`, with fixed,
  read-only collectors for the bounded Windows authentication provider,
  notification-package, security-package, and password-filter surfaces.
- **Core:** stable-read each referenced file and bind normalized registry
  location, ordered value, absolute canonical path, SHA-256, Authenticode and
  catalog result, signer identity, file version, owner, and ACL digest into an
  authenticated host baseline. A missing or unreadable surface is `unknown`,
  never healthy.
- **Existing modules:** send exact file identity and registry-delta evidence to
  `Persistence Sweep`, `LSASS Guard`, `File Integrity`, `App Control Monitor`,
  and the incident graph. Do not read LSASS memory.
- **GUI:** a clickable Authentication Boundary view showing the extension
  point, evidence source, previous/current digest, signer, governed file path,
  completeness, and operator enrollment history.
- **Mode:** Detect / Harden / Visualize. Response remains a reviewed recovery
  plan; Angerona must not automatically remove an authentication component.

### Effort

**S-M.** Windows only. Requires elevation for complete evidence and careful
Windows-version/domain-controller gating. The first release should observe and
compare only; safe reversal needs a separately reviewed adapter and reboot/
recovery testing.

### Assurance profile

- **Confidence:** High that the tradecraft matters; first-party incident
  response plus ATT&CK. Detection confidence is high only for an authenticated
  change from an enrolled complete baseline.
- **Data/privacy cost:** Low to moderate. Retain file and signer metadata and
  keyed path tokens by default; reveal full governed paths only in the local
  detail view. Never retain credentials or authentication buffers.
- **False-positive risk:** Security software, credential providers, smart-card
  middleware, and planned domain maintenance legitimately change these
  surfaces. Require a maintenance/enrollment receipt and do not classify a new
  signed component as malicious solely because it is new.

### Buildable acceptance tests

1. Fixture matrices cover an unchanged baseline, an added package, order
   change, path replacement, signer change, ACL change, missing file, linked
   path, partial registry read, and Windows-version variation.
2. A same-name/same-signer file with a different digest remains a change.
3. An incomplete first capture cannot become the trusted baseline.
4. Synthetic changes create an incident and review plan but invoke no mutation
   sink, DLL load, credential access, or process injection.

### Safety

Defensive and read-only in the initial implementation. No credential capture,
LSASS memory access, authentication hooking, DLL injection, payload creation,
or automated deletion. The proposal records and validates OS configuration; it
does not demonstrate how to abuse it.

---

## 2. Security-Control Drift Witness and Safe Recovery Plans

**Pitch.** Expand Angerona's host baseline from firewall recovery into an
honest, completeness-aware view of critical protection settings, with each
future repair independently gated and reversible.

### Why now

Microsoft documents that attackers attempt to disable or alter security
features, and that Defender tamper protection covers real-time protection,
behavior monitoring, cloud protection, security-intelligence updates, and
selected exclusion settings. Microsoft's 2026 Storm-2949 report also describes
an intrusion that attempted to weaken endpoint protections and clear local
forensic evidence before establishing remote access.

Sources:

- [Microsoft Learn — Protect security settings with tamper protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- [Microsoft — How Storm-2949 turned a compromised identity into a cloud-wide breach](https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/)

### Fit

- **Core `host_adaptation`:** add a separate *observational protection-posture
  manifest* for Defender state, tamper protection, exclusions policy, ASR
  posture, HVCI/Credential Guard/LSA protection, relevant security services,
  PowerShell logging, and audit-policy coverage. Keep it distinct from the
  currently restorable Firewall artifact.
- **Existing modules:** consume typed facts from `AV Telemetry Bridge`,
  `Platform Attestation Guard`, `Kernel Posture Ledger`, `Audit Log Integrity
  Guard`, and `Posture Hardening`. Resolve contradictions as `conflict` rather
  than choosing the most favorable source.
- **Guided Auto Adapt:** offer audit and simulation immediately. A future
  setting-specific repair is eligible only after a dedicated provider,
  compatibility check, pre-change recovery point, exact confirmation,
  postcondition, compensation, and startup reconciliation are proven for that
  setting. Never label the entire posture restorable because Firewall is.
- **GUI:** clickable per-control status with source, authority, last-known-good,
  current value, policy owner (local/GPO/MDM/unknown), conflict, recovery
  support, and reboot impact.
- **Mode:** Detect / Harden / Respond.

### Effort

**S-M** for observation and drift; **L** if all controls are made restorable.
Windows edition, third-party AV, GPO/MDM ownership, and Defender for Endpoint
licensing create real unknown states. Start with observation and one narrowly
proven adapter at a time.

### Assurance profile

- **Confidence:** High for the need; Microsoft platform guidance and incident
  evidence. Individual local-setting truth may be moderate when enterprise
  policy owns the setting.
- **Data/privacy cost:** Low. Store policy values, source and timestamps—not
  Defender detections, file contents, or tenant secrets.
- **False-positive risk:** Troubleshooting mode, AV migration, policy refresh,
  and approved maintenance can create temporary drift. Track policy owner and
  declared maintenance windows, and distinguish `blocked change`, `effective
  drift`, and `collector disagreement`.

### Buildable acceptance tests

1. Complete, incomplete, contradictory, GPO-owned, MDM-owned, unsupported, and
   third-party-AV fixtures never collapse into one healthy boolean.
2. A simulated setting change produces an exact plan and no writes.
3. A stale approval, post-review drift, failed recovery capture, or ambiguous
   policy owner blocks apply.
4. Every enabled mutation adapter proves its pre-state, post-state,
   compensation, restart reconciliation, and accurate restorable-scope label.

### Safety

Defensive hardening only. No silent policy changes, no automatic weakening, no
Defender exclusion creation, no GPO/MDM override, and no claim that a local
baseline defeats Administrator, SYSTEM, kernel, or whole-host rollback.

---

## 3. ARIA Runtime Supply-Chain and Consent Proof

**Pitch.** Bind every active AI component and every approved action to one
signed runtime manifest so retrieved text, tool descriptions, plugins, or
model-generated summaries cannot launder authority.

### Why now

Microsoft's June 2026 agentic-AI red-team taxonomy recommends SBOM coverage for
tool dependencies, provenance verification for plugins and MCP servers,
version pinning for external tool definitions, verifiable agent identity,
context provenance, and consent UX derived from actual underlying actions.
Those recommendations sharpen the gap beyond ordinary prompt-injection
filtering.

Source:

- [Microsoft — Updating the taxonomy of failure modes in agentic AI systems: What a year of red teaming taught us](https://www.microsoft.com/en-us/security/blog/2026/06/04/updating-taxonomy-failure-modes-agentic-ai-systems-year-red-teaming-taught-us/)

### Fit

- **Core AI Security Broker:** construct a canonical runtime manifest binding
  model digest, prompt-template digest, Defense Memory/RAG corpus digest,
  plugin manifests, MCP endpoint identity, exact tool JSON schemas and
  descriptions, connector permission set, egress policy, and registered agent
  identities.
- **Capability and plugin lifecycle:** treat a natural-language description or
  permission change as a new revision requiring staging, evaluation, and
  activation; existing signed code identity alone is insufficient.
- **Consent:** derive the human-readable approval from the typed tool calls and
  exact targets, split compound actions, display reversibility/blast radius,
  and sign a short-lived approval over the canonical call set. Model-authored
  prose is never the source of the consent description.
- **Inter-agent path:** authenticate any local agent handoff and bind its role,
  capabilities, parent request, expiration, and evidence IDs. Self-asserted
  role names grant nothing.
- **GUI:** clickable Runtime Trust view with active component revisions,
  permission delta, tainted context count, blocked authority transitions, and
  approval-frequency warnings.
- **Mode:** Harden / Visualize.

### Effort

**S-M.** Existing typed tools, capability manifests, plugin lifecycle, release
SBOM, evidence IDs, and response authorization are reusable. The challenge is
canonical cross-component binding and migration without pretending that a
manifest makes model behavior deterministic.

### Assurance profile

- **Confidence:** High for the design direction; first-party red-team findings.
- **Platform:** Cross-platform core and GUI.
- **Data/privacy cost:** Low. The manifest contains digests, schemas,
  permissions, and identities, not prompt contents or user evidence. Retain
  only bounded taint metadata for sessions.
- **False-positive risk:** Legitimate prompt, model, or plugin updates will
  require re-evaluation. Provide clear revision diffs and atomic rollback
  rather than allowing mutable components to change silently.

### Buildable acceptance tests

1. Changing only a tool description, prompt, connector scope, RAG digest, or
   MCP identity invalidates the prior runtime manifest.
2. A compound action is decomposed into exact calls; approving a summary cannot
   authorize an omitted or changed call.
3. Retrieved text and peer-agent messages cannot alter tool schemas, roles,
   egress policy, or response authority.
4. Replay, stale approval, self-asserted role, capability disclosure probe,
   context flooding, and approval-fatigue fixtures produce zero unauthorized
   mutation and bounded audit output.

### Safety

Defensive governance only. No autonomous offensive agents, arbitrary shell,
exploit generation, credential tooling, covert capability discovery, or
permission escalation.

---

## 4. Completeness-Aware Sensor Witness Quorum

**Pitch.** Detect selective blinding by comparing independent observations of
the same host activity while refusing to call ordinary collection loss an
intrusion.

### Why now

State-sponsored living-off-the-land activity is intended to blend into normal
administration and evade common logging. Microsoft also describes endpoint
tampering as a multi-control problem rather than one setting, and recommends
monitoring sensor health. Angerona already has multiple user-mode witnesses;
the missing control is explicit, loss-aware disagreement analysis.

Sources:

- [CISA joint advisory AA24-038A — PRC state-sponsored actors compromise U.S. critical infrastructure](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [Microsoft Learn — Protect your organization from the effects of tampering](https://learn.microsoft.com/en-us/defender-endpoint/tamper-resiliency)

### Fit

- **Core:** add a bounded witness ledger keyed by process birth identity,
  service identity, and event channel/record. Record source generation,
  freshness, coverage interval, loss counter, filter scope, and privilege.
- **Modules:** compare ETW, Security 4688, Sysmon process events, process
  polling, Defender, Code Integrity, Audit Log Guard, and `Self Integrity`
  where two or more are genuinely expected to overlap.
- **Decision model:** `corroborated`, `single-source`, `expected-unobserved`,
  `coverage-gap`, `source-conflict`, and `possible-selective-blinding`. Absence
  can contribute to a finding only when the source proves complete coverage
  for that interval.
- **GUI:** a clickable Sensor Witness matrix with source generation, lag,
  drops, last record, permissions, disagreement, and exact evidence lineage.
- **Mode:** Detect / Harden / Visualize.

### Effort

**M.** Windows-first. Requires persistent bookmarks/cursors and normalized
process birth identities. A user-mode quorum is defense in depth, not
tamper-proofing against Administrator/SYSTEM or kernel authority.

### Assurance profile

- **Confidence:** High that selective defense impairment matters; moderate that
  a given disagreement is hostile without corroboration.
- **Data/privacy cost:** Moderate. Duplicate source metadata can increase local
  volume. Deduplicate by event identity, retain bounded normalized facts, and
  keep command line collection optional/redacted.
- **False-positive risk:** Audit-policy changes, boot races, event rollover,
  provider filters, queue pressure, sleep/resume, and permissions routinely
  create gaps. Those states must produce `coverage-gap` before any threat
  label.

### Buildable acceptance tests

1. Exact overlap, expected non-overlap, source delay, rollover, dropped events,
   restart, sleep/resume, and permission loss map to distinct states.
2. A synthetic selectively missing process observation raises only when the
   witness declares the interval complete.
3. PID reuse and reordered events never join without matching process birth.
4. A sustained 100,000-event test remains bounded and reports every internal
   drop rather than silently degrading.

### Safety

Observation and integrity assessment only. No kernel hooks, undocumented ETW
Threat Intelligence claim, process injection, stealth collection, or automatic
containment from negative evidence alone.

---

## 5. Independent DNS Path Witness and Fast-Flux Guard

**Pitch.** Detect both local resolver-path manipulation and rapidly changing
malicious infrastructure using privacy-bounded DNS, route, and flow evidence.

### Why now

The UK NCSC reported in April 2026 that APT28 compromised routers and changed
DHCP/DNS settings to redirect selected traffic through actor-controlled DNS,
enabling adversary-in-the-middle credential and token theft. NSA and partners'
2025 fast-flux advisory separately warns that rapid DNS infrastructure churn is
a continuing gap and recommends layered DNS, network, and threat-intelligence
analytics.

Sources:

- [UK NCSC — APT28 exploit routers to enable DNS hijacking operations](https://www.ncsc.gov.uk/news/apt28-exploit-routers-to-enable-dns-hijacking-operations)
- [NSA — Fast Flux as a National Security Threat](https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4143636/nsa-and-partners-issue-guidance-on-fast-flux-as-a-national-security-threat/)

### Fit

- **Network Trust Monitor:** retain current DNS/DHCP/gateway drift and add an
  explicitly enrolled DNS-path policy. A first capture made after compromise
  is `unverified`, not trusted merely because it stays stable.
- **New cross-platform `BaseModule`:** `DNSIntegrityGuard` consumes bounded DNS
  query/answer events plus normalized flows. Calculate per-domain churn,
  TTL distribution, address/prefix/ASN diversity, name-server change,
  answer-to-flow consistency, and process context over fixed windows.
- **Independent witness:** optionally compare only operator-enrolled synthetic
  canary names or selected critical service names through one separately
  approved, pinned reference resolver. This is off by default, rate limited,
  and records a disagreement—not a claim that either resolver is truthful.
- **Intel Sync:** combine heuristic evidence with signed reputation/feed age;
  heuristics alone cannot authorize blocking. CDN/anycast and split-horizon
  exceptions are explicit, expiring policy records.
- **GUI:** clickable DNS Path view with resolver source, network profile,
  query-token, answer set, TTL/churn, related process/flow, witness result,
  source loss, and why a CDN-safe decision was made.
- **Mode:** Detect / Harden / Visualize.

### Effort

**M.** Cross-platform analytics; Windows collection can begin with supported
Sysmon/DNS Client evidence. ASN enrichment needs a versioned offline database
or optional feed. Independent resolution creates a real privacy/egress
boundary and must remain optional.

### Assurance profile

- **Confidence:** High for the threat; government reporting. Moderate for
  endpoint-only fast-flux classification because legitimate CDNs behave
  similarly.
- **Data/privacy cost:** High if raw domains are retained. Default to keyed
  domain tokens plus public-suffix class and coarse ASN/prefix; raw local detail
  requires explicit retention. Synthetic canaries minimize independent-query
  disclosure.
- **False-positive risk:** CDNs, anycast, VPNs, captive portals, failover,
  split-horizon DNS, travel, and privacy relays. Require profile-aware history,
  several analytic features, and no autonomous block from churn alone.

### Buildable acceptance tests

1. Fixtures distinguish stable DNS, legitimate CDN churn, split-horizon/VPN,
   selective answer divergence, resolver drift, and single/double-flux-like
   synthetic behavior without embedding live malicious infrastructure.
2. Missing answers, event loss, stale ASN data, and failed witness egress stay
   unknown and never become clean or malicious by default.
3. Raw domain retention and independent queries remain off in a fresh install.
4. A 100,000-answer window uses bounded memory and deterministic eviction.

### Safety

Defensive observation only. No DNS poisoning, sinkhole operation, credential
interception, remote probing, or automatic broad blocking. The optional witness
performs ordinary, rate-limited resolution of operator-approved names only.

---

## 6. Trusted Administration and RMM Provenance Ledger

**Pitch.** Treat an approved signer or management product as the start of a
trust decision, not proof that every session and child action is authorized.

### Why now

Microsoft's 2026 incident report describes abuse of a legitimate enterprise
management platform operated through a compromised third-party relationship.
CISA's 2025 SimpleHelp advisory documents downstream compromise through an
unpatched RMM product. These cases support behavior and provenance controls
around trusted tools, not name-based bans.

Sources:

- [Microsoft — Undermining the trust boundary: Investigating a stealthy intrusion through third-party compromise](https://www.microsoft.com/en-us/security/blog/2026/05/12/undermining-the-trust-boundary-investigating-a-stealthy-intrusion-through-third-party-compromise/)
- [CISA AA25-163A — Ransomware actors exploit unpatched SimpleHelp RMM](https://www.cisa.gov/sites/default/files/2025-06/aa25-163a-ransomware-simplehelp-rmm-compromise.pdf)

### Fit

- **New `BaseModule`:** `TrustedAdministrationGuard` inventories RMM,
  deployment, backup, monitoring, remote-support, and automation services using
  fixed local service/software/App Control evidence.
- **Core provenance ledger:** bind product/service identity, executable hash,
  signer, version, service account class, installation receipt, approved
  controller token, maintenance window, expected child-process classes,
  tokenized egress destinations, and update provenance.
- **Existing modules:** correlate with `Identity Session Guard`, `App Control
  Monitor`, `Persistence Sweep`, `Process Egress Guard`, `Process Monitor`, and
  the incident graph. A signed binary with an unexpected controller/session,
  child lineage, version, or destination becomes anomalous without declaring
  the vendor malicious.
- **GUI:** clickable Administration Trust view showing approved owner,
  third-party relationship, active version, exposure/KEV status, session
  receipt, process lineage, egress token, and maintenance context.
- **Mode:** Detect / Harden / Visualize.

### Effort

**M.** Windows-first with partial cross-platform inventory. Authoritative
session provenance requires vendor or administrator evidence; when absent,
Angerona can report local behavior only. Product identification must not rely
solely on filename.

### Assurance profile

- **Confidence:** High for the tradecraft, high for exact local drift, and
  moderate for session authorization without an external management receipt.
- **Data/privacy cost:** Moderate. Management product, service identity, child
  process class, timing, and destination tokens can reveal operations. Do not
  retain full remote commands or operator content.
- **False-positive risk:** Emergency support, upgrades, monitoring scripts, and
  new service-provider infrastructure. Use explicit maintenance windows,
  version migrations, and learned candidates requiring human enrollment.

### Buildable acceptance tests

1. Approved binary/approved controller, same signer/new hash, stale version,
   unknown controller, unexpected child class, novel destination, missing
   session receipt, and maintenance-window fixtures remain distinct.
2. A signer match alone never suppresses behavioral evidence.
3. Missing external provenance lowers evidence grade and cannot become a
   fabricated unauthorized-session claim.
4. No test or production path captures remote commands, screen contents, or
   credentials.

### Safety

Defensive inventory and correlation only. No exploitation of RMM, remote
session initiation, command replay, credential use, vendor impersonation, or
automatic removal of legitimate management software.

---

## 7. Native Administration Sequence Correlator

**Pitch.** Detect suspicious chains of ordinary Windows administration events
without depending on malware names or publishing offensive command recipes.

### Why now

The joint Volt Typhoon advisory describes long-lived access using valid
accounts, strong operational security, and living-off-the-land techniques.
The UK-led 2025 logistics advisory also highlights credential guessing,
phishing, and abuse of mailbox permissions across a targeted campaign. These
patterns reward ordered, identity-aware correlation rather than isolated tool
alerts.

Sources:

- [CISA joint advisory AA24-038A — PRC state-sponsored actors compromise U.S. critical infrastructure](https://www.cisa.gov/sites/default/files/2024-03/aa24-038a_csa_prc_state_sponsored_actors_compromise_us_critical_infrastructure_3.pdf)
- [UK NCSC — Russian intelligence campaign targeting western logistics and technology organisations](https://www.ncsc.gov.uk/news/uk-partners-expose-russian-intelligence-campaign)

### Fit

- **Temporal Tradecraft Correlator:** add bounded Windows sequence families for
  unusual remote/privileged logon, native administration activity, service or
  task creation, WMI subscription change, script-host evidence, outbound
  connection, persistence drift, and audit impairment.
- **Core:** use normalized event kinds and process/logon/session birth
  identities—not free-form command-line regex—as the primary join. Every edge
  records time bound, evidence grade, source completeness, and alternative
  benign explanations.
- **Fast Path:** retain single-event high-confidence controls, but use them as
  corroboration rather than the sequence schema itself.
- **GUI:** clickable actor-neutral timeline showing each event, source, join
  basis, coverage gap, confidence contribution, and the exact rule revision.
- **Mode:** Detect / Visualize.

### Effort

**M.** Windows-first. Requires broader restart-safe event coverage and privacy-
bounded script/logon metadata. Some events depend on Sysmon, PowerShell, or
Security audit policy and must be capability-gated.

### Assurance profile

- **Confidence:** High for LOTL relevance; moderate for any individual local
  sequence because administrators legitimately use the same facilities.
- **Data/privacy cost:** Moderate to high if command text is stored. Prefer
  typed event categories, signer/path tokens, identity tokens, and bounded
  features; full command text remains off or locally redacted.
- **False-positive risk:** software deployment, help-desk work, domain
  administration, backup, and incident response. Require ordered multi-source
  evidence, maintenance context, peer-group rarity, and operator feedback.

### Buildable acceptance tests

1. Synthetic benign administration, ordered suspicious chain, reordered
   events, PID/LUID reuse, missing source, maintenance window, and replay after
   restart have deterministic outcomes.
2. One process name or one command token cannot satisfy a multi-event rule.
3. Sequence memory, fan-out, and retention stay bounded under an event storm.
4. The rule pack contains only defensive event schemas and synthetic markers,
   not runnable intrusion commands or payloads.

### Safety

Defensive correlation only. No command generation, credential guessing,
remote execution, persistence creation, mailbox access, or autonomous response
from actor attribution.

---

## 8. Out-of-Band Console and HID Topology Guard

**Pitch.** Detect unexpected keyboard/mouse, composite USB-network, and console
topology changes that can create a control path below ordinary endpoint remote-
access telemetry.

### Why now

Microsoft Incident Response reported in December 2025 that compromised user
accounts associated with a North Korean remote-worker scheme connected PiKVM
devices to employer workstations, providing persistent out-of-band control and
an egress path that could bypass traditional EDR visibility. Microsoft
recommends monitoring for unapproved devices of this class.

Sources:

- [Microsoft — Imposter for hire: How fake people can gain very real access](https://www.microsoft.com/en-us/security/blog/2025/12/11/imposter-for-hire-how-fake-people-can-gain-very-real-access/)
- [Microsoft Learn — Enumerate installed devices safely with PnP/SetupAPI](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/enumerating-installed-devices)

### Fit

- **Peripheral and DMA Guard / USB Monitor:** add a read-only PnP provider using
  supported Configuration Manager or SetupAPI enumeration, not direct registry
  assumptions.
- **Topology model:** enroll keyed tokens for present HID, keyboard, mouse,
  monitor, USB composite, USB network, dock, and bus-parent relationships.
  Record class, driver signer/version, arrival generation, location path token,
  and approved owner—never keystrokes or screen content.
- **Correlation:** join unexpected topology changes with new network adapters,
  route/DNS changes, logon/session anomalies, sleep/resume, and physical-device
  installation evidence. The module cannot prove who controls a device or what
  happens outside the host.
- **GUI:** clickable Device Control Path view with topology, class, driver,
  first/last seen, enrollment, related network change, and limitations.
- **Mode:** Detect / Harden / Visualize.

### Effort

**M.** Windows-first. Device classes, docks, accessibility hardware, VMs, and
sleep/resume require substantial field fixtures. Blocking HID installation is
out of scope for the first version because it can lock out the operator.

### Assurance profile

- **Confidence:** High for the reported risk; moderate that generic device
  topology uniquely identifies out-of-band control.
- **Data/privacy cost:** Moderate. Hardware instance/location identifiers can
  fingerprint a user. Store keyed tokens by default and show raw identifiers
  only locally with explicit detail access.
- **False-positive risk:** docks, KVM switches, accessibility devices, gaming
  peripherals, virtualization, firmware updates, and port changes. Require
  enrollment and topology/process/network corroboration; never classify by
  vendor ID alone.

### Buildable acceptance tests

1. PnP fixtures cover known device, new HID, composite HID/network, dock,
   phantom device, missing property, sleep/resume reorder, and driver change.
2. Direct registry enumeration is absent; only present-device PnP evidence can
   claim current attachment.
3. Device identifiers are tokenized in EventBus/public views.
4. No automatic block, device disable, keystroke capture, screen capture, or
   firmware interaction occurs.

### Safety

Defensive inventory only. It does not emulate input, operate a KVM, capture a
screen, monitor keystrokes, disable accessibility devices, or probe device
firmware.

---

## 9. Least-Privilege Entra Identity Evidence Connector

**Pitch.** Turn Identity Session Guard's supplied-evidence contract into an
optional, first-party, cursor-safe Entra audit feed without making cloud access
the default.

### Why now

Microsoft's 2026 Storm-2949 report shows a compromise expanding through self-
service password reset abuse, MFA method changes, application identities, and
legitimate cloud management features. Microsoft Graph exposes Entra directory
audit records for user, app, device, group, PIM, identity-protection, and
password-management activity and documents `AuditLog.Read.All` as the least
privileged permission for this API.

Sources:

- [Microsoft — How Storm-2949 turned a compromised identity into a cloud-wide breach](https://www.microsoft.com/en-us/security/blog/2026/05/18/storm-2949-turned-compromised-identity-into-cloud-wide-breach/)
- [Microsoft Graph — List directoryAudits](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0)

### Fit

- **New optional core connector:** explicit tenant enrollment, delegated or
  application identity, `AuditLog.Read.All` only for the first release,
  protected token custody, fixed Microsoft endpoint, normal TLS validation,
  bounded paging, durable cursor, retry budget, and visible throttling/loss.
- **Admission:** normalize only fixed schemas for MFA/authentication-method
  change, password reset, privileged role, app/service-principal credential,
  device registration, and consent changes. Tokenize tenant/user/app/device
  identities before EventBus publication; omit token bodies and secrets.
- **Identity Session Guard:** consume broker-authenticated evidence with source
  tenant, record ID, event time, ingestion time, cursor generation, and
  completeness. Correlate with local logon, device-code, RMM, and process
  evidence without treating cloud IP geolocation as proof.
- **GUI:** clickable Cloud Identity Coverage view showing consent scope,
  cursor/lag, tenant token, event category, affected identity tokens, evidence
  lineage, and revoke/disconnect control.
- **Mode:** Detect / Visualize.

### Effort

**M-L.** Cross-platform connector with Windows-focused correlation. Requires an
Entra work/school tenant, admin consent to a broad read permission, secure OAuth
token lifecycle, national-cloud endpoint support, throttling, retention, and
licensing tests. It is unavailable for personal Microsoft accounts under this
API contract.

### Assurance profile

- **Confidence:** High for the threat and authoritative audit source; cloud
  logs still do not prove user intent or attribution.
- **Data/privacy cost:** High. Directory audit data identifies people, apps,
  devices, IPs, and administrative changes. Default off; least fields; local
  encryption; privacy tokens; short retention; no cloud-to-cloud forwarding
  without separate consent.
- **False-positive risk:** help-desk resets, onboarding, app rotation, PIM, and
  normal device registration. Require privileged-target context, temporal
  chains, known automation identities, and maintenance/change receipts.

### Buildable acceptance tests

1. Consent absent, token missing, wrong tenant, wrong audience, expired token,
   pagination replay, throttling, partial page, schema drift, national-cloud
   mismatch, and revocation all fail to explicit coverage states.
2. Only documented least-privilege scope is accepted for the first version;
   any extra requested permission is visible and rejected by policy.
3. Raw identities, access tokens, refresh tokens, and IPs never enter public
   EventBus summaries or exports.
4. Disconnect revokes local use and wipes protected connector credentials while
   preserving bounded audit receipts.

### Safety

Read-only and opt-in. No password reset, MFA registration, user disabling,
role change, mailbox access, Graph enumeration outside fixed audit endpoints,
or automated cloud response.

---

## 10. Edge Control-Plane Evidence Intake

**Pitch.** Admit signed, typed network-device change and health evidence so a
compromised router or firewall cannot remain an invisible external assumption.

### Why now

CISA and partners reported in 2025 that PRC state-sponsored actors were
modifying routers, abusing trusted network relationships, and using network-
device capabilities for durable access. Their hardening guidance recommends
scrutinizing configuration changes, centrally retaining configurations,
monitoring management connections and accounts, and off-device logging. The
2026 NCSC DNS-hijacking report reinforces that an endpoint's inherited network
settings can be downstream evidence of a compromised edge device.

Sources:

- [CISA AA25-239A — Countering Chinese state-sponsored actors' compromise of networks worldwide](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
- [CISA/NSA/FBI and partners — Enhanced Visibility and Hardening Guidance for Communications Infrastructure](https://www.cisa.gov/resources-tools/resources/enhanced-visibility-and-hardening-guidance-communications-infrastructure)
- [UK NCSC — APT28 exploit routers to enable DNS hijacking operations](https://www.ncsc.gov.uk/news/apt28-exploit-routers-to-enable-dns-hijacking-operations)

### Fit

- **Core evidence contract:** define a vendor-neutral, fixed schema for device
  identity token, firmware/version posture, config digest/revision, typed
  account/ACL/protocol/route/DNS delta, management-login receipt, flow summary,
  collector generation, completeness, and loss. Raw configurations and
  credentials are not accepted.
- **Personal Sentinel authority:** optionally countersign evidence from one
  explicitly enrolled edge adapter and provide monotonic sequence/freshness.
  A receipt proves only source and continuity, not firmware integrity.
- **Network Trust Monitor / Device Security Lab / SIEM:** correlate edge deltas
  with endpoint DNS/DHCP/route/gateway changes, exposure/KEV posture, and
  management sessions. Missing source logs or rollback becomes a coverage
  finding.
- **Adapters:** separately reviewed, read-only adapters may consume an
  operator-supplied signed export or existing authenticated syslog/API feed.
  Angerona never discovers devices, accepts router credentials, or issues
  configuration commands.
- **GUI:** clickable Edge Evidence view showing enrolled source, evidence
  grade, revision, changed category, management origin token, firmware/KEV
  status, continuity, and explicit limits.
- **Mode:** Detect / Harden / Visualize.

### Effort

**L.** Vendor schemas, secure export, clock/freshness, external key custody,
device lifecycle, rollback, and realistic lab fixtures are substantial. Begin
with the vendor-neutral contract and one offline signed-export adapter, not a
generic network-management client.

### Assurance profile

- **Confidence:** High for the threat and need; high for a cryptographically
  admitted change record, but low for device truth after privileged firmware
  compromise without independent attestation.
- **Platform:** Angerona core is cross-platform; target adapters depend on the
  separately administered edge device.
- **Data/privacy cost:** High if configurations or addresses are retained.
  Accept typed deltas and keyed topology/account tokens, cap flow summaries,
  and reject secrets/raw configuration by schema.
- **False-positive risk:** planned firmware upgrades, failover, route changes,
  ISP maintenance, DHCP renewal, and administrator changes. Require change-
  management receipts, device generation, redundancy context, and no automatic
  endpoint isolation from a single edge delta.

### Buildable acceptance tests

1. Valid signed revision, replay, rollback, gap, mixed device identity, stale
   time, malformed delta, oversized export, raw secret/config field, and
   unknown adapter version fixtures have deterministic outcomes.
2. A valid signature never upgrades incomplete device evidence to healthy.
3. Endpoint and edge events correlate only through an enrolled device/path
   token and compatible time/generation.
4. Tests prove zero active discovery, credential storage, configuration write,
   remote command, or firmware claim.

### Safety

Defensive evidence intake only. No router exploitation, port scanning,
credential testing, packet interception, configuration mutation, remote shell,
traffic redirection, or hack-back.

---

## Recommended implementation order

1. Land the Authentication Extension Guard and observational Security-Control
   Drift Witness first; both close specific Windows blind spots with no new
   network authority.
2. Bind ARIA's runtime components and consent semantics before expanding any
   AI/plugin/agent integration surface.
3. Build the witness quorum, then use its completeness states as a prerequisite
   for Windows native-administration sequence detections.
4. Add DNS query/answer continuity and privacy tokens before enabling fast-flux
   windows or an optional independent resolver witness.
5. Reuse those identity, process, and network contracts for the trusted-
   administration ledger and out-of-band device topology guard.
6. Treat the Entra connector and edge evidence adapter as separate opt-in
   integration projects with their own threat models, permission reviews, and
   deployment acceptance.

## Explicit non-goals

- No offensive tooling, intrusion instructions, exploit code, credential
  collection, persistence creation, evasion implementation, hack-back, remote
  scanning, or weaponized adversary module.
- No unsupported attribution. Behavior can resemble source-reported tradecraft
  without proving a state, service, organization, group, or person.
- No automatic blocking from a heuristic, negative-space signal, signer name,
  DNS churn, device vendor ID, cloud IP, or external report alone.
- No raw router configuration, private key, authentication token, password,
  keystroke, screen content, remote command, or LSASS memory collection.
- No new unsigned kernel component and no claim that user-mode telemetry can
  resist Administrator, SYSTEM, kernel authority, compromised firmware, or a
  privileged whole-host rollback.
- No expansion of the existing Firewall-only restorable baseline by wording.
  Each additional mutation class must independently prove capture, apply,
  postcondition, rollback, restart recovery, and scope.
