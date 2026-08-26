# Angerona Security Suite

Angerona is a local-first defensive security workbench that combines Endpoint
Detection and Response (EDR), Network Detection and Response (NDR), Security
Orchestration, Automation, and Response (SOAR), digital forensics, MITRE ATT&CK
validation, and a local Ollama-backed assistant in one PySide6 desktop
application.

[![CI](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/ci.yml/badge.svg)](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/ci.yml)
[![Security](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/security.yml/badge.svg)](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/security.yml)
![Windows](https://img.shields.io/badge/Windows-Protect-0078D6)
![macOS](https://img.shields.io/badge/macOS-Observe-555555)
![Linux](https://img.shields.io/badge/Linux-Observe%20%2B%20optional%20eBPF-FCC624)
![Python](https://img.shields.io/badge/Python-3.10--3.13-3776AB)
![License](https://img.shields.io/badge/License-MIT-green)

Current version: **v1.10.3**

[Master Manual](Angerona_Master_Manual.docx) ·
[Current capabilities](ANGERONA_CAPABILITIES.md) ·
[Architecture](docs/architecture.md) ·
[Security](SECURITY.md) ·
[Contributing](CONTRIBUTING.md)

## Capability map

### Detect and correlate

- Windows ETW, WMI/CIM, AMSI, Windows Filtering Platform (WFP), Defender,
  Security log, and Sysmon telemetry.
- The actor-neutral **SSH Surface / Key / Tunnel Guard** inventories bounded
  OpenSSH configuration and Include graphs, public-key fingerprints, custody,
  services, listeners, authentication evidence, and normalized forwarding
  activity. It never collects private keys, probes a listener, or attempts a
  login.
- The Windows **Audit Log Integrity Guard** detects explicit clear events,
  audit-policy or logging-service changes, retention and generation gaps,
  record reuse, and authenticated cursor tampering. It does not clear, restore,
  or alter Windows logs.
- The **Zero-Trust Network Path Monitor** treats every active physical Wi-Fi and
  Ethernet path as untrusted by default and compares tokenized route, gateway,
  Domain Name System (DNS), Dynamic Host Configuration Protocol (DHCP), profile,
  and interface-generation evidence across restarts.
- Process lineage, file integrity, persistence, memory-injection, credential-
  access, shadow-copy tamper, ransomware, C2 cadence, USB, vulnerable-driver,
  deception, YARA/YARA-X, and network behavior detections.
- Evidence Lattice multi-sensor fusion, Telemetry Expectation Contracts, MITRE
  ATT&CK mapping, incidents, cases, causal timelines, and authenticated local
  evidence storage.
- Suricata, Zeek, OCSF, Community ID, guarded read-only osquery snapshots, and
  privacy-minimized asset/SBOM views.

### Contain and recover

- Exact-target network blocks, executable isolation, process suspension or
  termination, file quarantine, deception, host isolation, and verified rollback.
- Protected-process and protected-system boundaries, process creation-time and
  executable revalidation, literal peer binding, signed action contracts, and
  truthful receipts.
- Action history, Undo selected, Undo all, startup recovery, mutation-circuit
  breakers, and explicit recovery-required records when compensation cannot be
  proven.

### Investigate and validate

- Live Alerts, Resolve Center, SOAR Queue, Scan Center, Flow Dashboard / Local SOC,
  case management, bounded threat hunts, evidence custody, ATT&CK heatmap, Top
  Talkers, threat intelligence, and forensic exports.
- A sanitized **Live Defense Activity** dashboard card shows coarse module state
  and at most five recent public EventBus summaries. It is operational activity,
  never source code, hidden model reasoning, or chain-of-thought.
- Non-destructive Red Team and Shark Attack campaigns with After-Action Reports.
  Simulations use bounded reversible markers rather than exploits or persistence.
- A repeatable maximum Adversary Combat validation batch proves detection,
  contract admission, response closure, cleanup, and journal integrity.

### Assist locally

- ARIA local chat and runbook retrieval, local security briefing, typed tools,
  provider controls, optional voice and gesture navigation, and explicit egress
  consent for any cloud connector.
- A governed, strict-schema, canonical-SHA-256-pinned **ARIA Defense Memory**
  gives local retrieval quick capability, usage, defensive-control, and
  actor-neutral tradecraft context. It is data-only and cannot define tools or
  authorize actions; only selected bounded, redacted excerpts are eligible for
  an already authorized cloud fallback.
- Approved model/knowledge-pack lifecycle: provenance and digest checks, resource
  admission, bounded staging, evaluation, activation, rollback, and removal.
- Model output is advisory evidence unless a separate deterministic control path
  authorizes a typed action. Arbitrary model-authored PowerShell is inert.

### Personal Sentinel network path

The intended defense-in-depth topology is:

`Angerona host -> operator-controlled Personal Sentinel gateway/firewall -> upstream/ISP router -> Internet`

Angerona ships the explicit, fail-closed **attestation client** for one enrolled
private HTTPS default gateway. Normal certificate and hostname validation,
certificate pinning, nonce/freshness checks, an expected policy digest, optional
mutual TLS, complete IPv4/IPv6 route evidence, and unchanged pre/post route
context can label that exact path `gateway-attested`. The label does not trust an
endpoint, identity, application, destination, upstream router, or firmware, and
the client provides no router discovery, credentials, management, routing, or
firewall mutation.

## Use cases

- Windows home lab or self-hosted endpoint defense.
- Blue-team and purple-team learning with visible ATT&CK evidence.
- Local, privacy-conscious investigation and incident-response practice.
- Defensive monitoring for SSH persistence, log-clearing or continuity loss,
  and suspicious Wi-Fi/Ethernet infrastructure drift without agency attribution.
- Detection engineering, response-contract, secure-SDLC, and portfolio work.
- Research platform for governed local AI, an operator-controlled intermediate
  firewall, and reversible defensive automation.

## Platform support

| Platform | Current contract | Boundary |
| --- | --- | --- |
| Windows | **Protect** | Full supported telemetry and governed response path; runs elevated in user mode and ships no unsigned kernel driver. |
| macOS | **Observe preview** | Privacy-minimized process/flow observation and shared core; no Endpoint Security or Network Extension enforcement claim. |
| Linux | **Observe + optional eBPF** | Rootless process/flow/posture observation; BCC/eBPF is an explicit privileged supplement, not a shipped universal CO-RE sensor. |

## 🚀 One-click Windows install

For a tagged Windows release, download
`Angerona-<version>-win64-setup.exe` and its adjacent SHA-256 file from
[Releases](../../releases), verify the digest and GitHub attestation, then
approve the UAC prompt. Setup installs the application, shortcuts, uninstaller,
and guided configuration. **No Python or terminal is required.**

The portable ZIP remains available through `Install-Angerona-Release.bat` and
re-verifies its embedded release manifest. The published installer is not
currently backed by an Authenticode publisher certificate, so Windows may show
**Unknown Publisher**.

For a reviewed Windows source deployment:

```powershell
git clone https://github.com/Ag3nt47/AngeronaSuite.git
cd AngeronaSuite
.\Install-Angerona.bat
```

For development:

```powershell
python -m pip install -e ".[dev]"
python -m pytest -q
python tools/selfcheck.py
```

For guarded GitHub synchronization, use `push-to-github.bat` and
`pull-from-github.bat`. Push scans the exact staged patch with a pinned,
SHA-256-verified Gitleaks binary before committing. Pull scans incoming commits
before a fast-forward merge and refuses dirty trees, divergent history,
credential-bearing/non-HTTPS remotes, submodule recursion, and unreviewed
workflow changes.

Linux and macOS release archives use `Install-Angerona-Release.sh`. Source
installation uses `install-angerona.sh`; Linux also supports a local-user
headless service. See the Master Manual for platform-specific prerequisites,
data paths, rollback, and uninstall procedures.

Source/development runtime data uses the checkout's sibling `AngeronaData` directory.
Packaged Windows installs prefer protected `D:\AngeronaData` and use
protected `%ProgramData%\Angerona` only when D: is unavailable. Cloud
integrations are optional and off by default. Public screenshots are generated
demonstrations: all displayed telemetry, identifiers, timestamps, and counts are
synthetic.

The optional Personal Sentinel client is enrolled by creating
`<AngeronaData>/config/personal_sentinel_gateway.json` with schema version 1,
the exact local `interface_id`, a private-literal HTTPS `endpoint_url`, and the
expected `certificate_sha256` and `policy_digest`. File absence or rejection
leaves every path untrusted. A compatible gateway service/appliance is not
bundled; see the Master Manual before enrollment.

## Validation status

The current v1.10.3 tree produced the following local evidence on Windows:

- 1,465 pytest cases collected across 208 files: **1,460 passed, 5 expected
  host-capability skips, 0 failed**.
- **321/321** product Python files compiled; Ruff passed.
- **73/73** module files imported; native discovery constructed **71/71**
  modules; all **58/58** zero-argument compatibility hooks were valid.
- Standalone core/Shark self-tests: **22/22**. Module harness: **50 passed, 0
  failed, 21 expected skips**, plus the EventBus pipeline passed.
- Direct and batch selfcheck: **26/26** each.
- Deterministic Combat negative controls: **128/128**.
- Auto-contain Red Team launches arm all **13/13** simulation-only detector
  contracts before the first marker and fail closed if activation cannot be
  persisted.
- Live maximum campaign: winning round **52/52 detections, 52/52 responses,
  13/13 contracts, 13/13 verified closures**, with resilience PASS. Cleanup left
  zero active reversible actions, zero recovery requirements, zero marker files,
  zero tagged probe processes, and an intact journal. The preceding round reached
  100% detection but failed response/closure gates, so the harness rejected it
  and continued automatically.

These results are strong project evidence, not an independent certification or
a claim of complete attack coverage.

## Honest limits

- Angerona is an advanced home-lab, learning, and portfolio security suite; it is
  not yet a drop-in replacement for a commercially supported, independently
  evaluated, distributed enterprise EDR/XDR platform.
- Cycle 23 closed 15 of 16 actor-neutral findings. The remaining Medium is an
  external dependency: filesystem rollback resistance requires a separately
  administered monotonic high-water service or policy-bound hardware authority.
  Without one, audit and network state are locally authenticated with a
  Hash-based Message Authentication Code (HMAC) but report
  `local-authenticity-only` and `independent_freshness_verified=false`.
- A separate older non-blocking defense-in-depth Medium remains: path-wide
  program firewall rules would be stronger with a retained operating-system
  process handle and bounded executable-file identity lease across the action.
- Personal Sentinel currently provides only a pinned direct HTTPS attestation
  client. The gateway appliance/server and routing role, firmware or measured-
  boot attestation, and independent monotonic authority are not built.
- Live Defense Activity exposes sanitized public operational summaries, not
  actively executing source, private AI reasoning, or chain-of-thought.
- State-grade tradecraft research is actor-neutral. Angerona reports observable
  technique patterns and makes no agency or state attribution claim.
- Long elevated soak testing, physical sleep/resume, clean-machine installer and
  uninstall matrices, publisher signing/notarization, native Linux/macOS artifact
  acceptance, fleet-scale throughput, false-positive baselines, and third-party
  efficacy evaluation remain external gates.
- Optional cloud, messaging, SIEM, threat-intelligence, and peer integrations may
  transmit selected data only when separately configured and authorized. Local-
  only operation remains the default.
- Angerona is user-mode, is not tamper-proof against a compromised
  Administrator/SYSTEM principal, and ships no production kernel driver.
- No hack-back, remote exploitation, credential theft, arbitrary response shell,
  downloaded executable skill, unverified model, or unsigned kernel component is
  part of the product.

## What is current in v1.10.3

- **State-grade-pattern defensive coverage:** the new SSH, audit-log integrity,
  and zero-trust physical-network guards translate publicly documented advanced
  persistence, telemetry suppression, tunneling, and router-path manipulation
  patterns into local, bounded, observe-only evidence without actor attribution.
- **Personal Sentinel client boundary:** an explicitly enrolled, pinned HTTPS
  client can attest one exact intermediate-gateway route. Competing, incomplete,
  changed, or dual-stack-bypass paths fail closed; endpoints remain untrusted.
- **Live operational visibility:** the dashboard now includes a redacted,
  revision-gated activity card for recent public EventBus/module state. It is
  deliberately not a debugger or a private-reasoning display.
- **ARIA Defense Memory:** a pinned, strict-schema defensive reference is loaded
  into local runbook retrieval so ARIA can answer common Angerona capability,
  usage, control, and tradecraft questions without treating the memory as code.
- **Continuity hardening:** audit and network state use authenticated paired
  documents, stable non-reparse reads, fail-closed completeness, revision gates,
  and an injectable independent-high-water contract. The separately operated
  authority needed for independent freshness remains deferred.
- **Governed Adversary Combat and receipt-bound SOAR:** exact-target local
  response remains constrained by typed policy, signed contracts, durable
  intent, verified postconditions, exact Undo, and crash-recovery circuits.
- **App Control and Windows telemetry evidence:** read-only Code Integrity,
  Security, OpenSSH, Sysmon, ETW, and related evidence retain explicit source
  completeness and cannot authorize response by themselves.
- **Measured Cycle 23 performance:** idle audit checkpoint work fell 97.6%; SSH
  process enumeration fell 90.9% on the measured host; declared-bound network
  snapshot sanitization fell 93.3%; and bounded per-user SSH token expansion
  improved 99.4%. Security cadence and freshness/route/anchor checks were not
  reduced. Round 3 deliberately applied no optimization because the candidates
  did not justify added complexity.

Detailed three-round evidence and primary sources are in
[`analysis/loop/cycle23/summary.md`](analysis/loop/cycle23/summary.md).

MIT licensed. See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md), and
[SUPPORT.md](SUPPORT.md).

**Final Cycle 23 verification.** Current v1.10.3 passes **1460 tests with 5 intentional platform skips**; static discovery reports **71 modules**.

<!-- ANGERONA_DOC_STATUS tests=1460 skips=5 modules=71 -->
