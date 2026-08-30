# Cycle 27 / Round 1 — upstream comparison and defensive innovation

Date: 2026-08-28
Research cutoff: 2026-08-28
Mode: official primary sources only; defensive research and design; no product or host changes

## Executive result

The highest-value Cycle 27 upgrade is not another detector. It is a bounded
**Capability Assurance Ledger v1** that makes Angerona distinguish runtime
health from evidence quality and security efficacy. Every capability row would
show, from one atomic snapshot, whether required evidence is present, fresh,
complete, loss-free, provenance-bound, and locally or externally witnessed.
Any value below full runtime health would retain the exact bounded reason,
trusted repository-relative source path, and source line; the GUI would make
those cells clickable and highlight the implicated line in red. A reported
`100%` would remain exactly what it is today—module-reported runtime health—not
a claim of complete detection or resistance to every attacker.

This recommendation comes from a consistent upstream pattern:

- Falco, Tetragon, Zeek, Suricata, and Security Onion make dropped or missing
  telemetry an explicit operational signal instead of silently treating the
  surviving events as complete.
- Sigma ships content in maturity tiers and requires attribution, rather than
  treating every admitted rule as equally production-ready.
- osquery and Fleet make applicability, platform, version, scheduling, and
  resource behavior explicit.
- Microsoft recommends audit-first staged policy deployment, and signed App
  Control policies use versioned, tamper-resistant authority rather than an
  unreviewed trust-on-first-use baseline.
- Current CISA, Microsoft, ATT&CK, and D3FEND material shows why this matters
  against advanced tradecraft: legitimate tools, edge-device compromise,
  stolen identity tokens, trusted software channels, and monitoring gaps can
  all make a superficially green endpoint misleading.

The proposed MVP is read-only and local-first. It adds no collector, kernel
component, network request, privileged mutation, response action, or automatic
trust decision.

## Method and honesty boundaries

The comparison uses current project documentation, repositories, release
pages, standards, and vendor/government research. It compares concrete
engineering patterns, licensing, and integration constraints—not stars,
market share, or popularity. The source dates below are publication, release,
or page last-modified dates where the publisher exposes one; every source was
also checked on 2026-08-28.

Angerona's current documented surface is the v1.12 line with 81 statically
discovered modules, validated v12 capability contracts, Guided Auto Adapt,
firewall-only recovery baseline, typed governed response, ATT&CK 19.2,
constrained OCSF 1.8 and Sigma subsets, Windows Protect, optional Linux eBPF
Observe, and macOS Observe preview. This document does not propose features
already present under another name.

The following distinctions are mandatory:

1. **Module health is not efficacy.** A module can be alive and internally
   healthy while its upstream sensor is lossy, its content is immature, or the
   relevant attack leaves no observable evidence.
2. **Unknown is not clean.** Missing, stale, unsupported, untrusted, or
   incomplete evidence must remain explicit.
3. **A local baseline is not rollback proof.** HMAC and protected ACL custody
   detect many local changes, but a privileged whole-host snapshot rollback
   requires a TPM-backed or independent witness to detect.
4. **A comparison is not compatibility.** Referencing an upstream pattern does
   not claim wire, schema, content, fleet, or enforcement parity.
5. **Research is actor-neutral.** Public state-sponsored case studies motivate
   defensive controls; they do not establish attribution for any Angerona
   observation.

## Upstream capability and integration comparison

| Upstream | Current official pattern | Concrete Angerona disposition / gap | License and integration constraint |
| --- | --- | --- | --- |
| **osquery 5.23.1 / Fleet 4.90** | osquery packs declare platform, minimum version, shard, discovery conditions, interval, snapshot/differential behavior, and watchdog treatment. Fleet policies add explicit targeting, vulnerability inventory, KEV/EPSS filters, first-failure versus continuous automation, retry bounds, and patch policies. | Angerona correctly keeps its osquery path fixed, local, read-only, and bounded, and v12 contracts already declare platform/lifecycle/resource fields. It does not expose per-control applicability, last evaluation, content revision, or a common evidence-quality state in every Capability Center row. Fleet-scale management is out of scope. | osquery is `Apache-2.0 OR GPL-2.0-only`; Fleet is mostly MIT with separately licensed premium features. Prefer clean-room contract ideas and documented APIs; do not copy premium content. Sources: [osquery configuration and packs](https://osquery.readthedocs.io/en/stable/deployment/configuration/) (checked 2026-08-28), [osquery 5.23.1 release](https://github.com/osquery/osquery/releases/tag/5.23.1) (2026-06-24), [Fleet GitOps](https://fleetdm.com/docs/configuration/yaml-files) and [Fleet automations](https://fleetdm.com/guides/automations) (checked 2026-08-28), [Fleet 4.90 release index](https://fleetdm.com/releases) (2026-08-05; updated 2026-08-24). |
| **Wazuh 4.14** | Syscollector keeps per-agent software/OS/hotfix inventory; Vulnerability Detection correlates it with CTI, distinguishes Active and Solved findings, and supports a downloaded offline CTI repository. Security Configuration Assessment and Active Response are separate capabilities. | Angerona has local CVE inventory/advice and typed response, but no versioned offline vulnerability-content admission ledger that can prove feed digest, age, source, affected local package identity, and before/after resolution. Angerona should retain its safer exact-action response contracts rather than add generic response scripts. | Wazuh source and rules are GPLv2 under its repository terms. A feed format or content import requires separate license/provenance review. Sources: [Vulnerability Detection architecture](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html), [offline vulnerability repository](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/configuring-scans.html) (checked 2026-08-28), [Wazuh v4.14.5](https://github.com/wazuh/wazuh/releases/tag/v4.14.5) (2026-04-23), and [Wazuh license](https://github.com/wazuh/wazuh/blob/main/LICENSE). |
| **Velociraptor** | The endpoint stores its client event table locally, starts event queries at client launch, buffers results while offline, forwards after reconnect, and exposes structured artifact/collection and offline-collector workflows. | Angerona already has durable SIEM/Remote outboxes and local forensic tools. It lacks a single bounded, declarative offline evidence-collection recipe with exact artifact provenance, resource/privilege limits, and a signed custody manifest. It should not add arbitrary VQL, a remote hunt plane, or an auto-download artifact exchange. | Core is AGPLv3; documentation has separate licensing. Treat designs as comparison input, not code/content for inclusion. Sources: [Client Monitoring](https://docs.velociraptor.app/docs/clients/monitoring/) (checked 2026-08-28), [offline collector documentation](https://docs.velociraptor.app/docs/file_collection/bulk/) (checked 2026-08-28), and [core license](https://github.com/Velocidex/velociraptor/blob/master/LICENSE). |
| **Falco 0.44** | Falco exposes monotonic kernel-side event/drop counters, rate and percentage metrics, drop categories, and configurable actions when syscall events are lost. Its modern eBPF path is shipped with the userspace release, while rule and driver components are versioned separately. | Angerona's optional Linux eBPF path is honestly not universal, but a module can still appear operational without a normalized, first-class counter showing kernel/ring/user-queue loss and reset. Angerona needs a sensor-loss contract before it considers broader Linux coverage. | Apache-2.0. Integration should be an optional, fixed-schema observe adapter—not bundled kernel code and not enforcement parity. Sources: [Falco dropping-events diagnostics](https://falco.org/docs/troubleshooting/dropping/) (published 2025-10; checked 2026-08-28), [dropped-event actions](https://falco.org/docs/concepts/event-sources/kernel/dropped-events/), [release architecture](https://github.com/falcosecurity/falco/blob/master/RELEASE.md), and [Falco 0.44.0](https://github.com/falcosecurity/falco/releases/tag/0.44.0) (2026-05-26). |
| **Tetragon 1.7** | TracingPolicy supplies explicit hook, selector, action, and domain ownership; current metrics expose ring-buffer loss, queue loss, missing process information, exporter drops, cache pressure, policy load state, and enforcement notification loss. Persistent gRPC policies distinguish desired from recovered state. | Angerona should borrow the completeness vocabulary and desired/observed distinction. It should not claim Tetragon's kernel or Kubernetes enforcement. A future adapter must require broker authentication, fixed schemas, exact producer version, monotonic sequence, loss counters, and a no-response-authority boundary. | Apache-2.0. Kernel/version gating and privileged external deployment remain operator responsibilities. Sources: [TracingPolicy](https://tetragon.io/docs/concepts/tracing-policy/) (last modified 2026-05-21), [metrics](https://tetragon.io/docs/reference/metrics/) (checked 2026-08-28), [persistent policies](https://tetragon.io/docs/concepts/enforcement/persistent-grpc-policies/) (2026-07), and [v1.7.0](https://github.com/cilium/tetragon/releases/tag/v1.7.0) (2026-04-29). |
| **OpenEDR** | The public repository describes Windows base-event telemetry, process hierarchy, local recording, policy compilation, MITRE mapping, and endpoint-local alert policy. | Angerona already has process lineage, local telemetry, and typed detection/response. The useful comparison lesson is process/file trajectory navigation and a compile receipt for admitted policy—not wholesale agent or driver integration. | The current repository is under the **Comodo Available Source License (CASL)**, which restricts charging/distribution and is not a permissive open-source integration license. No code, rules, binaries, or implementation detail should be copied. Sources: [OpenEDR repository](https://github.com/ComodoSecurity/openedr) and [CASL license](https://github.com/ComodoSecurity/openedr/blob/main/LICENSE.md) (checked 2026-08-28). |
| **Security Onion 2.4 / Zeek 8.2 / Suricata 8.0** | Security Onion Grid puts Capture Loss, Zeek Loss, Suricata Loss, disk pressure, and rule-load status next to clickable historic metrics. Zeek computes and logs capture gaps; Suricata exposes kernel drops and TCP reassembly gaps. Network metadata, alerting, full packet capture, and case/hunt pivots remain distinct. | Angerona has local NDR views, packet and protocol modules, and governed click-through details, but lacks a normalized capture/decoder/export loss lineage that can reduce downstream assurance. Full PCAP storage and Security Onion fleet parity are out of scope. | Security Onion and Elastic components use ELv2; Zeek is BSD; Suricata is GPLv2. Integrate only stable documented fields through an optional external adapter after license review. Sources: [Security Onion Grid health](https://docs.securityonion.net/en/2.4/grid.html), [Connect API health fields](https://docs.securityonion.net/en/2.4/api/), [Zeek capture-loss log](https://docs.zeek.org/en/current/reference/logs/capture-loss-and-reporter.html), and [Suricata statistics](https://docs.suricata.io/en/latest/performance/statistics.html) (checked 2026-08-28). |
| **Sigma r2026-04-01** | Official release packages separate Core, Core+, Core++, emerging-threat, hunting, and all-rules content by rule type, level, and status. Stable/test and experimental content are not presented as equivalent. DRL 1.1 requires author attribution, including in match output. Correlation specification 2.1.0 defines stable/test/experimental/deprecated/unsupported states. | Angerona deliberately evaluates a constrained Sigma subset and atomically rejects mixed unsupported batches. The missing layer is a package/content maturity ledger: source revision, digest, license/author, supported semantics, required logsource, compile result, negative tests, last match, false-positive/tuning state, and active/degraded disposition. | Sigma rule content is DRL-1.1, not MIT; author attribution must survive admission and match display. Sources: [Sigma release packages](https://github.com/SigmaHQ/sigma/blob/master/Releases.md), [r2026-04-01 repository release](https://github.com/SigmaHQ/sigma/releases/tag/r2026-04-01) (published 2026-04-28), [DRL-1.1](https://github.com/SigmaHQ/Detection-Rule-License), and [Correlation Rules Specification 2.1.0](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html) (2025-08-02). |
| **OCSF 1.8** | OCSF is a versioned Apache-2.0 event schema with typed objects and semantic versioning. The current 1.8.0 release provides normalized evidence/observable structures. | Angerona already pins a constrained OCSF 1.8 Detection Finding preview and correctly refuses a full-compatibility claim. The next useful step is a per-export compatibility receipt showing exact schema/profile, validation result, redaction, truncation, loss, and unsupported fields—not broader unverified mapping. | Apache-2.0. Preserve source version and do not imply upstream certification. Sources: [OCSF schema repository](https://github.com/ocsf/ocsf-schema), [OCSF 1.8.0](https://github.com/ocsf/ocsf-schema/releases/tag/1.8.0) (2026-03-18), and [license](https://github.com/ocsf/ocsf-schema/blob/main/LICENSE). |
| **OpenTelemetry semantic conventions 1.44** | The event model distinguishes occurrence `Timestamp` from receiver `ObservedTimestamp`, uses explicit event names and severity guidance, and marks individual semantic attributes stable or development. | Angerona can improve its export envelopes by separating occurred, observed, and admitted times and attaching schema/stability identifiers. This is a narrow interoperability aid, not a claim that EventBus or exporters implement the complete OpenTelemetry SDK/Collector protocol. | Apache-2.0. Treat development semantic attributes as version-gated. Sources: [Semantic Conventions 1.44.0](https://opentelemetry.io/docs/specs/semconv/) and [event conventions](https://opentelemetry.io/docs/specs/semconv/general/events/) (checked 2026-08-28). |
| **MITRE ATT&CK 19.2 / D3FEND 0.24** | ATT&CK 19.2's first Agile release added current identity-token, CI/CD, software-supply-chain, and user-execution activity. D3FEND supplies a machine-readable defensive knowledge graph, inferred ATT&CK/countermeasure mappings, and artifact/sensor/technique taxonomies. | Angerona is already pinned to ATT&CK 19.2, so no version bump is needed. Its heatmap can be made more honest by showing which D3FEND countermeasure, artifact, and sensor assumptions support each claimed defensive mapping and where the mapping is only planned or evidence-limited. | MITRE data and marks remain subject to MITRE terms; pin exact downloaded content and record license/terms metadata before redistribution. Sources: [ATT&CK August 2026 Agile update](https://attack.mitre.org/resources/updates/updates-august-2026/) (2026-08-06), [ATT&CK data/tools](https://attack.mitre.org/resources/attack-data-and-tools/), [D3FEND resources 0.24.0](https://next.d3fend.mitre.org/resources/) (2026-07-31), and [D3FEND ontology resources](https://next.d3fend.mitre.org/resources/ontology/). |
| **Microsoft Security Baselines / ASR / App Control** | The Security Compliance Toolkit publishes versioned Windows baselines. ASR has Off, Block, Audit, Not configured, and Warn states, with audit-first guidance for non-standard rules and per-rule exclusions. App Control recommends audit-first deployment rings; signed policies require Secure Boot, resist admin tampering, and reject lower policy versions by boot failure. | Angerona's enrolled recovery baseline intentionally covers Windows Firewall only. It lacks a read-only, versioned view of broader Microsoft baseline/ASR/App Control drift and therefore must not imply full-host reset. A safe advisor can compare and simulate, but initial implementation must never enable ASR/App Control, create exclusions, or sign/deploy policies. | Microsoft package/document terms apply; use official downloads as operator-supplied reference inputs and store only permitted normalized results. Sources: [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319) (published/updated 2026-02-23), [Windows 11 25H2 baseline](https://techcommunity.microsoft.com/blog/microsoft-security-baselines/windows-11-version-25h2-security-baseline/4456231) (2025-09-30), [ASR overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview) (updated 2026-08), [App Control deployment](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide), and [signed-policy anti-tamper](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering). |

## Advanced-tradecraft implications for defensive design

This section extracts defensive requirements only. It intentionally omits
intrusion procedures, exploit code, credentials, bypass recipes, and target
selection.

### A green endpoint can sit behind a compromised path

Microsoft's April 7, 2026 research describes compromised SOHO routers changing
DNS behavior and selectively enabling adversary-in-the-middle activity.
Microsoft's July 31, 2026 CaptiveCrunch report combines traffic manipulation,
device-code abuse, token theft, and malware delivery on captive networks.
CISA AA25-239A documents long-lived compromise of edge/network devices and
warns that response sequencing and investigative confidentiality matter.

Design consequence: network-path trust, DNS provenance, identity assurance,
and endpoint module health must remain separate. Auto Adapt must not infer that
a healthy local detector makes a hostile first hop or stolen cloud session
safe. References: [Microsoft SOHO router/DNS research](https://www.microsoft.com/en-us/security/blog/2026/04/07/soho-router-compromise-leads-to-dns-hijacking-and-adversary-in-the-middle-attacks/)
(2026-04-07), [Microsoft CaptiveCrunch](https://www.microsoft.com/en-us/security/blog/2026/07/31/captivecrunch-midnight-blizzard-targets-travelers-worldwide-for-malware-delivery-and-credential-theft/)
(2026-07-31), and [CISA AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a)
(2025-08-27; revised 2025-09-03).

### Legitimate administration can be malicious context

CISA's living-off-the-land guidance explains that built-in tools and ordinary
administration can blend into routine activity and evade default logging. An
indicator-only or binary-reputation-only detector is therefore insufficient.

Design consequence: Angerona should weight ordered identity, process birth,
parentage, exact target, network path, policy drift, and evidence continuity;
it should not label a signed binary or administrator context benign by itself.
Reference: [CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
(2024-02-07; joint advisory).

### Content provenance is part of endpoint defense

ATT&CK 19.2 explicitly added CI/CD and software-supply-chain activity in its
first Agile update. Sigma's release packaging and licensing further show that
detection content has source, revision, maturity, and attribution semantics.

Design consequence: a rule/model/query package is untrusted data until its
digest, schema, source, license, supported semantics, dependencies, and tests
are admitted atomically. Content must never define a tool or grant response
authority. References: [ATT&CK 19.2 update](https://attack.mitre.org/resources/updates/updates-august-2026/)
(2026-08-06) and [Sigma release packages](https://github.com/SigmaHQ/sigma/blob/master/Releases.md)
(checked 2026-08-28).

### Detection cannot prove complete eviction

CISA AA25-239A notes that partial response can cause sophisticated operators to
conceal or preserve access elsewhere and that defenders may need coordinated,
simultaneous action after understanding scope.

Design consequence: Angerona's automatic actions should remain exact,
reversible where possible, and bounded. The suite should present an incident
scope checklist and unresolved-evidence state, not claim that one process kill,
file quarantine, or firewall change fully evicted an adversary. This reinforces
the existing no-hack-back and human-reviewed response authority.

## Ranked buildable proposals

Rank is qualitative impact divided by expected effort for Angerona's local,
single-host architecture. No rank is an efficacy guarantee.

### 1. Capability Assurance Ledger v1 — **M**

**Pitch.** Make every capability row answer “what is actually proven right
now?” from one atomic, clickable, source-backed snapshot.

**Why now.** Falco and Tetragon expose multiple loss and missing-context
counters; Security Onion puts capture/decoder loss directly in operator health
views; Sigma separates content maturity. Sources: [Falco drop metrics](https://falco.org/docs/troubleshooting/dropping/),
[Tetragon metrics](https://tetragon.io/docs/reference/metrics/), [Security Onion
Grid](https://docs.securityonion.net/en/2.4/grid.html), and [Sigma packages](https://github.com/SigmaHQ/sigma/blob/master/Releases.md)
(all checked 2026-08-28).

**Fit.** Extend the existing `BaseModule.operational_snapshot()`/capability
contract presentation through a read-only core assurance projection and the
Capability Center/Module Inspector GUI. Fields should include runtime health,
exact reason/evidence, expected versus observed dependency, freshness budget
and age, loss state/count/reset, source trust, baseline trust, implementation
version versus contract version, last self-test result/time, and content
maturity where applicable. This is **Detect + Visualize**; it does not change a
module's behavior.

**Effort / limits.** M. The MVP should project only evidence modules already
publish. Missing fields are `unknown`, not guessed. It must use one immutable
snapshot per row, bounded strings/cardinality, and canonical typed sort keys.
Trusted local file viewing stays confined to the repository root; the public
link is constructed only from the fixed canonical repository and a validated
relative path/positive line number. The implicated line is highlighted dark
red, while the surrounding context remains bounded and read-only.

**Safety.** Defensive-only and read-only. No privileged call, sensor enablement,
baseline write, network request, response action, arbitrary path opening, or
automatic trust promotion.

### 2. Detection Package v2 Trust and Maturity Ledger — **M**

**Pitch.** Admit detection content as a versioned, testable package whose
provenance, maturity, dependencies, and limits remain visible at every match.

**Why now.** Sigma's current release process packages stable/test and
experimental content differently, validates packages, and requires DRL author
attribution in output. ATT&CK 19.2 can update between major releases under the
new Agile cadence. Sources: [Sigma Releases.md](https://github.com/SigmaHQ/sigma/blob/master/Releases.md),
[DRL-1.1](https://github.com/SigmaHQ/Detection-Rule-License), and [ATT&CK Agile
update](https://attack.mitre.org/resources/updates/updates-august-2026/)
(2026-08-06).

**Fit.** Add a data-only package manifest around the existing constrained Sigma,
YARA/YARA-X, and future curated query paths. Core admission would bind exact
digest, source URL/revision, acquired time, license, authors, rule IDs,
supported evaluator features, required logsources, ATT&CK version, compile
receipt, negative/canary fixture results, false-positive notes, and
stable/test/experimental/local status. Modules consume immutable compiled
plans; GUI displays package and per-rule state. **Detect + Harden + Visualize.**

**Effort / limits.** M. Do not expand Sigma syntax in the first increment.
Unsupported features fail closed; a mixed invalid package admits nothing.
Package upgrades are explicit and reversible at the content-selection layer,
not executable downloads.

**Safety.** Data-only detection logic cannot define Python, PowerShell, tools,
remediation, network fetch behavior, or response authority. No offensive
content generation or execution.

### 3. Cross-sensor Completeness and Loss Quorum — **M/L**

**Pitch.** Prevent a detector from reporting high assurance when its required
ETW, Event Log, packet, eBPF, queue, or exporter evidence is stale or lossy.

**Why now.** Tetragon enumerates ring-buffer, queue, export, cache, missing
process, and enforcement-notification loss; Falco can alert or exit on syscall
loss; Zeek and Suricata expose capture and reassembly gaps. Sources: [Tetragon
metrics](https://tetragon.io/docs/reference/metrics/), [Falco dropped-event
actions](https://falco.org/docs/concepts/event-sources/kernel/dropped-events/),
[Zeek capture loss](https://docs.zeek.org/en/current/reference/logs/capture-loss-and-reporter.html),
and [Suricata statistics](https://docs.suricata.io/en/latest/performance/statistics.html).

**Fit.** Create a core `SensorEvidenceState` with producer identity/version,
sequence epoch, records seen, records lost, counter reset, expected cadence,
last observed/admitted times, completeness, and reason. Modules declare which
sensor states are required versus optional; the assurance projection derives
`complete`, `degraded`, `unknown`, or `inactive` without changing the module's
raw health. Existing Sysmon, ETW, eBPF, packet, EventBus, SIEM, and Remote
bridges are initial adapters. **Detect + Harden + Visualize.**

**Effort / limits.** M for the core contract plus a small set of existing
producers; L to cover every sensor. Never infer zero loss from an absent
counter. Counter resets require a new epoch and visible continuity break.

**Safety.** Observe-only. Loss can lower assurance or recommend review, but can
never automatically authorize containment, process termination, firewall
mutation, or kernel configuration.

### 4. Defensive Efficacy Evidence Packs — **M**

**Pitch.** Replace “we have a rule” confidence with inert, reproducible evidence
that the expected pipeline detects positive fixtures, rejects negative
controls, and preserves response gates.

**Why now.** Sigma packages are validated and reviewed but still distinguish
experimental content; osquery tells operators to performance-test packs; MITRE
D3FEND maps countermeasures to the artifacts and circumstances under which they
apply. Sources: [Sigma package validation](https://github.com/SigmaHQ/sigma/blob/master/Releases.md),
[osquery pack guidance](https://osquery.readthedocs.io/en/stable/deployment/configuration/),
and [D3FEND About](https://d3fend.mitre.org/about/).

**Fit.** Add repository-owned, data-only fixtures for normalized event shapes,
ordered sequences, expected finding codes, explicit non-match controls,
freshness/loss variants, and expected proposal/approval boundaries. The
existing non-destructive red-team/chaos/self-test harness runs them offline and
emits a signed/hash-bound result manifest. Capability Inspector links the most
recent compatible pack result. **Detect + Harden + Visualize.**

**Effort / limits.** M. Fixtures must be synthetic and contain no exploit,
credential, persistence, shell payload, or remote target. Passing proves only
the tested deterministic path and version, not real-world prevention.

**Safety.** Inert defensive event simulation only. It never executes attack
commands, creates persistence, changes host security settings, or reaches a
remote system.

### 5. Offline Vulnerability Baseline and Fix Verification — **M**

**Pitch.** Give disconnected hosts a provenance-bound vulnerability snapshot
and show why a CVE is active, unknown, ignored, or verified resolved.

**Why now.** Wazuh supports an offline CTI repository and tracks Active/Solved
inventory states; Fleet prioritizes with KEV and EPSS and verifies exposure over
time. Sources: [Wazuh offline configuration](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/configuring-scans.html),
[Wazuh inventory behavior](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html),
and [Fleet vulnerability controls](https://fleetdm.com/docs/configuration/yaml-files).

**Fit.** Extend the CVE/fast-path core with explicit operator-supplied feed
admission: exact digest, schema, source, release time, license, maximum age,
bounded record count, and an atomic receipt. Match against stable local
software/OS/hotfix evidence, retain the exact evidence and comparison reason,
and verify after-change state. **Detect + Harden + Visualize.**

**Effort / limits.** M. A separate feed builder or operator obtains content;
Angerona does not scrape arbitrary sites. Unknown version semantics and stale
feeds remain unknown. CVE ignore remains reviewable and cannot alter inventory.

**Safety.** No exploitability testing, package installation, auto-patching, or
downloaded executable content. Fix advice stays proposal-only until an existing
typed authority separately approves an exact action.

### 6. Read-only Microsoft Baseline / ASR / App Control Drift Witness — **M/L**

**Pitch.** Compare the host to an exact operator-selected Microsoft reference
without pretending Angerona's firewall baseline is a whole-host restore point.

**Why now.** Microsoft published Windows 11 25H2 and Windows Server 2025 v2602
baseline packages; ASR and App Control explicitly use audit-first staged
deployment, and signed App Control policies bind anti-tamper behavior to Secure
Boot and non-decreasing versions. Sources: [Security Compliance Toolkit](https://www.microsoft.com/en-us/download/details.aspx?id=55319)
(2026-02-23), [ASR overview](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview),
and [signed App Control policies](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/use-signed-policies-to-protect-appcontrol-against-tampering).

**Fit.** Add an operator-supplied baseline parser/normalizer in core, a read-only
posture module, and a clickable drift view. Bind the admitted reference to
exact product/version/digest and distinguish `recommended`, `configured`,
`effective`, `conflicted`, `unsupported`, and `not observed`. An authenticated
local journal records review. An optional future TPM/external witness can hold
the monotonic digest/sequence; without it the GUI says `local-only, rollback
not independently witnessed`. **Harden + Visualize.**

**Effort / limits.** M for read-only comparison of a small allowlisted setting
subset; L for safe, version-gated breadth or an external witness. Do not parse
or apply arbitrary scripts from the toolkit. Do not auto-enroll the current
host as known good.

**Safety.** Initial version performs no registry, policy, ASR, App Control,
Secure Boot, Defender, service, firewall, exclusion, signing, or reboot change.
It cannot reset the host.

### 7. Staged ASR / App Control Adaptation Advisor — **M/L**

**Pitch.** Turn broader Windows hardening into explicit audit evidence and an
immutable proposal rather than a one-click high-risk mutation.

**Why now.** Microsoft recommends Audit before Block/Enforce for non-standard
ASR rules and App Control deployment rings, and ASR Warn behavior is
version/mode dependent. Sources: [ASR modes and audit guidance](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
and [App Control deployment guide](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/deployment/appcontrol-deployment-guide).

**Fit.** Later extend Guided Auto Adapt with one new **assessment-only** choice:
collect effective ASR/App Control state, show edition/version support,
conflicting authority, audit event count, candidate exclusions, boot/recovery
prerequisites, and a no-write simulation. Any real enforcement would require a
future separately reviewed signed-policy authority outside this proposal.
`posture_hardening`, `app_control_monitor`, and GUI adaptation pages are the
natural consumers. **Harden + Visualize.**

**Effort / limits.** M for read-only audit/proposal; L and an external deployment
authority for mutation. Candidate exclusions must never be auto-accepted.

**Safety.** No automatic block mode, policy signing/deployment, exclusion,
reboot, boot-policy change, or bypass. Model/RAG output cannot define or approve
the plan.

### 8. Bounded Offline IR Collector Manifest — **M**

**Pitch.** Produce a reviewable, one-shot local evidence bundle without adding
an arbitrary artifact language or remote hunt channel.

**Why now.** Velociraptor demonstrates the operational value of autonomous
offline collection and local buffering, while also exposing detailed profiling
because collectors can consume excessive time or memory. Sources: [Velociraptor
Client Monitoring](https://docs.velociraptor.app/docs/clients/monitoring/) and
[offline collector debugging](https://docs.velociraptor.app/docs/troubleshooting/debugging/)
(checked 2026-08-28).

**Fit.** Add a fixed allowlist of existing Angerona read-only collectors to the
forensics/evidence core. A recipe declares collector IDs, platform,
permissions, byte/file/time/process budgets, redaction, output schema, and
expected completeness. Output is a bounded archive plus hash manifest,
occurred/observed/admitted times, partial/failure reasons, and custody receipt.
The GUI offers checkboxes and estimated cost. **Detect + Visualize.**

**Effort / limits.** M. No user-provided command, Python, VQL, glob outside
governed roots, recursive whole-disk collection, or network upload. Encryption
can use existing protected-secret facilities only after explicit design.

**Safety.** Evidence collection only; no credential/private-key contents,
memory dumping, process injection, remote access, persistence, exploitation, or
host mutation.

### 9. D3FEND-backed Countermeasure Evidence Graph — **M**

**Pitch.** Let an ATT&CK heatmap cell explain which defensive technique,
artifact, sensor, and limitation support it.

**Why now.** D3FEND 0.24 publishes ontology/data files and cross-framework
views; ATT&CK 19.2 adds targeted Agile updates. CISA AA25-239A itself maps
mitigations to D3FEND countermeasures. Sources: [D3FEND 0.24 resources](https://next.d3fend.mitre.org/resources/)
(2026-07-31), [D3FEND ontology](https://next.d3fend.mitre.org/resources/ontology/),
[ATT&CK 19.2](https://attack.mitre.org/resources/updates/updates-august-2026/),
and [CISA AA25-239A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-239a).

**Fit.** Build a pinned, data-only mapping from curated Angerona capability IDs
to D3FEND defensive techniques, required artifacts/sensors, ATT&CK techniques,
and evidence state. Add clickable graph/detail views and export. Labels must be
`implemented`, `observed`, `evidence-limited`, or `planned`; no coverage
percentage implies efficacy. **Detect + Harden + Visualize.**

**Effort / limits.** M for curated mappings and UI; L for automated ontology
ingestion. Start with a small reviewed subset and exact upstream version/digest.

**Safety.** Defensive taxonomy and visualization only. Do not expose offensive
procedures, generate attack plans, or use mappings to auto-authorize response.

### 10. Loss-aware external Linux sensor adapter — **L**

**Pitch.** Improve Linux Observe coverage by consuming a separately operated
Falco/Tetragon-compatible evidence bridge without shipping or controlling a
kernel component.

**Why now.** Falco and Tetragon provide mature eBPF observability plus explicit
loss/resource metrics, but each is kernel/version/privilege sensitive and has a
larger authority surface than Angerona's Python runtime. Sources: [Falco kernel
events](https://falco.org/docs/concepts/event-sources/kernel/), [Falco drop
metrics](https://falco.org/docs/troubleshooting/dropping/), [Tetragon
TracingPolicy caution](https://tetragon.io/docs/concepts/tracing-policy/), and
[Tetragon metrics](https://tetragon.io/docs/reference/metrics/).

**Fit.** Define a broker-authenticated, fixed-version, fixed-schema local
envelope for process/file/network observations and producer health. Bind each
record to producer identity/version, boot/sequence epoch, loss counters,
capture/admission time, and declared policy digest. `ebpf_sensor`,
`linux_observe`, process/network modules, and the assurance ledger consume it.
**Detect + Visualize.**

**Effort / limits.** L. Requires separately packaged and administered upstream
sensor, OS/kernel gates, least-privilege socket custody, backpressure tests, and
license review. Begin with replayed fixtures; live integration is optional and
off by default.

**Safety.** Observe-only adapter. Angerona cannot load tracing policies, attach
probes, invoke upstream enforcement, issue signals, or treat adapter evidence
as response authority.

### 11. OCSF / OpenTelemetry export compatibility receipts — **M**

**Pitch.** Make every normalized export state exactly which schema semantics,
timestamps, redactions, and losses it actually satisfied.

**Why now.** OCSF 1.8 is versioned and typed; OpenTelemetry 1.44 distinguishes
event occurrence from observation and marks conventions by stability. Sources:
[OCSF 1.8](https://github.com/ocsf/ocsf-schema/releases/tag/1.8.0),
[OpenTelemetry semantic conventions 1.44](https://opentelemetry.io/docs/specs/semconv/),
and [event semantics](https://opentelemetry.io/docs/specs/semconv/general/events/).

**Fit.** Extend SIEM/Remote export metadata with exact profile/schema version,
source event revision, occurred/observed/admitted/exported times, redaction and
truncation fields, validation digest/result, retry generation, duplicate
possibility, and loss state. Add a bounded receipt viewer. **Visualize +
Harden.**

**Effort / limits.** M. Preserve the current constrained OCSF subset. OTel
attribute mappings marked development are opt-in and version-pinned; do not
claim Collector/OTLP support without implementing and testing it.

**Safety.** Export metadata only. Existing consent, redaction, destination,
egress, and secret boundaries remain mandatory; no connector is enabled by
default.

## Recommended bounded Cycle 27 visionary MVP

Implement **Capability Assurance Ledger v1** only. It directly supports the
maintainer's requirement that every sub-100 module explain itself with exact
source evidence, while addressing the upstream lesson that “healthy” and
“complete” are different claims.

### Proposed contract

Use one immutable, bounded snapshot per capability refresh:

| Field | Required behavior |
| --- | --- |
| `capability_id`, `module_name` | Existing canonical identities only. |
| `implementation_version`, `contract_version` | Display separately; never rewrite every implementation to v12. |
| `runtime_status`, `runtime_health_pct` | Existing atomic module state. `100` means only reported runtime health. |
| `runtime_reason` | Mandatory bounded reason for `<100`; no empty or generic invented reason. |
| `source_state`, `source_path`, `source_line`, `source_sha256` | Present only when provenance is proven from canonical repository source; otherwise explicit unavailable. |
| `dependency_state` | `satisfied`, `partial`, `missing`, `unsupported`, or `unknown`, with bounded reason. |
| `freshness_state`, `age_seconds`, `budget_seconds` | Missing/invalid clocks are unknown; never coerce to fresh. |
| `loss_state`, `lost_records`, `sequence_epoch` | `not_exposed` differs from zero; reset creates a new epoch/continuity break. |
| `baseline_trust` | `none`, `provisional`, `reviewed_local`, `externally_witnessed`, `stale`, or `tampered`. Never infer external witness. |
| `content_maturity` | `not_applicable`, `local`, `experimental`, `test`, `stable`, or `unsupported`; initially populated only by modules that already prove it. |
| `selftest_state`, `selftest_at`, `selftest_detail` | Last compatible result; stale or absent is explicit. |
| `assurance_state`, `assurance_reasons` | Derived as `proven`, `degraded`, `unknown`, or `inactive`. It is not a percentage and does not alter runtime health. |

### GUI behavior

- Capability Center columns use typed sort keys for health, assurance,
  freshness age, loss, maturity, version, and platform—not lexicographic display
  strings.
- Every row is clickable. Health, assurance, loss, baseline, dependency, and
  maturity cells open the relevant bounded detail section directly.
- A sub-100 health cell shows the exact reason in its tooltip and detail pane.
- A proven repository path is clickable in a governed local viewer. The exact
  implicated line is dark red; no source is executed and context is bounded.
- The public source link is constructed only as
  `https://github.com/Ag3nt47/AngeronaSuite/blob/main/<validated-relative-path>#L<positive-line>`.
  External, absolute, traversal, link/reparse-backed, mutable-origin, or
  unproven paths never become links.
- Full runtime health still displays the evidence-quality fields. The UI states
  plainly: `Runtime health is not detection-efficacy certification.`
- Refresh consumes one atomic snapshot and never combines fields from different
  module generations.

### Acceptance gates

1. Every discovered capability has a bounded assurance snapshot and stable
   typed sort row.
2. Every `<100` runtime health record has a non-empty exact reason; proven
   repository callsites have correct relative path, positive line, and digest.
3. Forged code filenames, monkey-patched callables, external files, absolute
   paths, traversal, symlinks/reparse points, hard links, and mutable source
   identities cannot create a trusted link.
4. Red highlight selects only the implicated line, and viewers cap bytes,
   lines, nesting, and refresh work.
5. Concurrent health/lifecycle updates cannot produce a mixed-generation row.
6. `not_exposed`/`unknown` loss never renders as zero or complete.
7. `100%` does not suppress unknown/degraded dependency, freshness, loss,
   baseline, maturity, or self-test state.
8. No MVP path performs a privileged operation, network fetch, baseline write,
   module restart, response action, or host change.

## Cycle 28–30 candidates

| Cycle | Candidate | Why this order |
| --- | --- | --- |
| **28** | Cross-sensor Completeness and Loss Quorum, then read-only Microsoft baseline/ASR/App Control drift witness | The Cycle 27 ledger provides the UI and contract needed to expose loss and baseline trust honestly. Start read-only; do not broaden Auto Adapt mutation authority. |
| **29** | Detection Package v2 ledger and Offline Vulnerability Baseline; optionally prototype the Linux adapter against replayed fixtures only | Content provenance/maturity and offline freshness can reuse the assurance contract. Live eBPF integration should wait until loss, identity, resource, and lifecycle semantics are tested. |
| **30** | Defensive Efficacy Evidence Packs, D3FEND evidence graph, and OCSF/OTel compatibility receipts | These are release-evidence and explanation layers. They are most useful after module, sensor, and content contracts stabilize, and they strengthen the final “how do we know?” answer without claiming certification. |

The Offline IR Collector Manifest and staged ASR/App Control advisor remain
valuable backlog candidates. They should not displace closure, performance,
clean-host, or publication gates in the consolidated v1.12.1 maintenance
release.

## What this does—and does not—prove against real attackers

The proposals improve the quality of the evidence Angerona can present. They
cannot prove that defensive patches are “enough” against every real attacker.
Confidence should be expressed as layered, falsifiable claims:

- exact code and content versions were reviewed and tested;
- inert positive and negative fixtures exercised the intended pipeline;
- sensor continuity, loss, freshness, and dependency state were visible;
- response authority stayed typed, exact, durable, and human governed;
- rollback and witness boundaries were disclosed;
- independent adversarial review found no remaining known High/Critical issue
  in the tested scope;
- full regression, static, packaging, clean-install, and publication gates
  passed for the exact released commit.

That is materially stronger than a green dashboard, but it remains evidence
about a bounded build and threat model—not a guarantee, certification, or
substitute for supported enterprise EDR, independent penetration testing,
hardware-rooted trust, backups, identity controls, network controls, and an
incident-response plan.

## Ranked shortlist

1. **Capability Assurance Ledger v1 — M:** core + GUI; separate runtime health
   from evidence completeness and make every degradation exactly explainable.
2. **Detection Package v2 Trust and Maturity Ledger — M:** constrained
   Sigma/YARA/query content; provenance, maturity, dependencies, tests, and
   attribution survive admission and match display.
3. **Cross-sensor Completeness and Loss Quorum — M/L:** normalize ETW/log/eBPF/
   packet/queue/export loss so unknown or lossy evidence cannot look complete.
4. **Defensive Efficacy Evidence Packs — M:** synthetic positive/negative
   pipeline fixtures with version-bound receipts and no operational attack
   behavior.
5. **Offline Vulnerability Baseline and Fix Verification — M:** provenance-
   bound disconnected feed, exact local evidence, and active/resolved/unknown
   state without auto-patching.
6. **Read-only Microsoft Baseline / ASR / App Control Drift Witness — M/L:**
   broader host-posture truth without expanding the firewall-only restore
   claim.
7. **Staged ASR / App Control Adaptation Advisor — M/L:** audit and immutable
   proposal first; no enforcement or exclusion automation.
8. **Bounded Offline IR Collector Manifest — M:** fixed read-only collectors,
   explicit budgets, redaction, and custody—not arbitrary VQL or commands.
9. **D3FEND-backed Countermeasure Evidence Graph — M:** connect ATT&CK cells to
   required artifacts, sensors, defensive techniques, and honest limitations.
10. **Loss-aware external Linux sensor adapter — L:** optional authenticated
    observe bridge to a separately administered sensor, never kernel control.
11. **OCSF / OpenTelemetry compatibility receipts — M:** exact schema,
    timestamp, redaction, validation, duplicate, and loss disclosures per
    export.
