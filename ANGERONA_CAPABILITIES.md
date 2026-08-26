# Angerona Capabilities

Current status: **v1.10.3**. This is a present-tense capability and use-case
summary. Operating detail is in the [Master Manual](Angerona_Master_Manual.docx).

## Core proposition

Angerona is a local-first EDR/NDR/SOAR and DFIR workbench for Windows-focused
home labs, defensive research, purple-team practice, and security-engineering
portfolios. It brings telemetry, detection, investigation, response, recovery,
local AI, and validation into one native desktop application.

## Current capabilities

### Endpoint and network visibility

- Windows ETW, WMI/CIM, AMSI, WFP, Defender, Windows Security log, and Sysmon
  coverage, including Sysmon event IDs 1-29 and 255 with an authenticated cursor.
- Read-only Windows App Control/Code Integrity evidence for audit would-block and
  enforced-block decisions, strict ActivityID-to-3089 signature correlation,
  authenticated restart state, record-bound clear/rollover detection, and
  privacy-minimized default details. The sensor observes OS decisions; it does
  not modify policy or grant response authority.
- Process lineage, file integrity, persistence, memory injection, LSASS access,
  shadow-copy tamper, ransomware, beacon/C2 cadence, removable media,
  vulnerable-driver, deception, YARA/YARA-X, and network behavior detection.
- Community ID v1 flow identity, OCSF 1.8 mappings, Suricata and Zeek evidence,
  guarded read-only osquery snapshots, cases, timelines, and ATT&CK mapping.
- HMAC-authenticated EventBus records and retained evidence; signed action
  records use an HMAC hash chain.

### State-grade-pattern hardening

- The actor-neutral **SSH Surface / Key / Tunnel Guard** observes bounded
  OpenSSH configuration and Include graphs, public-key fingerprints, configured
  key/CA/principals sources, file and parent custody, server/client processes,
  listeners, fixed-provider authentication evidence, and normalized forwarding
  activity. It collects no private keys or credentials, does not retain or
  publish full command lines or raw endpoints, and attempts no login.
- The Windows **Audit Log Integrity Guard** observes explicit Security/System/
  Sysmon clear or tamper indicators, audit-policy and logging-service changes,
  generation/retention gaps, record reuse, provider/channel mismatch, and
  authenticated cursor damage. Retained evidence is replayed within bounds;
  staged observations are published only after generation-consistent commit.
- The **Zero-Trust Network Path Monitor** treats every active physical Wi-Fi and
  Ethernet path as untrusted regardless of profile/location. Purpose-specific
  tokens preserve restart-safe DNS, DHCP, route, gateway, profile, interface,
  and path-addition drift without retaining raw local identifiers.
- The **Personal Sentinel Gateway client** can attest one explicitly enrolled
  private HTTPS default gateway with normal TLS/hostname validation, an
  additional certificate pin, nonce/freshness, expected policy digest, optional
  mutual TLS, complete IPv4/IPv6 route evidence, and pre/post route-context
  equality. Competing, incomplete, changed, or bypass routes fail closed.
- Audit and network stores expose local authenticity separately from optional
  independent freshness. The client contract for a monotonic external
  high-water authority exists; the separately administered service or
  policy-bound hardware implementation does not.

### Autonomous defensive response

- Adversary Combat can automatically block an exact peer, isolate an exact
  executable, suspend or terminate a verified process, quarantine an exact file,
  activate deception, and apply governed host isolation.
- Authority is typed and narrow: signed response contracts bind the allowed
  action, process birth, executable identity, file, peer, and escalation scope.
- Durable fsynced intents, verified postconditions, exact Undo, startup recovery,
  idempotency, compensation, and mutation-circuit breakers make response state
  visible and recoverable.
- Protected/system processes and ambiguous evidence are refused. Weak or
  cross-entity signals cannot silently widen into whole-host action.
- SOAR and operator surfaces delegate to Combat and reconcile signed receipts;
  queued or submitted work is never presented as verified success.

### Local AI and ARIA

- Local Ollama-backed triage, runbook retrieval, security briefings, and typed
  assistant tools.
- Typed-only confirmation for consequential ARIA actions. Voice, gestures,
  callbacks, retrieved text, model output, and untrusted content cannot confirm
  host mutation.
- Governed `aria-defense-llama3` pack with exact manifest/blob verification,
  bounded resource admission, evaluation, activation, rollback, and removal.
- Call-time Ollama loopback listener, process-birth, executable-path/signature,
  route, redirect, proxy, and response-size attestation.
- Knowledge packs are non-executable. Model-authored posture output is inert
  advice and cannot become arbitrary PowerShell or grant itself new tools.
- The bundled **ARIA Defense Memory** is a strict-schema, bounded, data-only
  capability/usage/defense/tradecraft reference pinned to its canonical SHA-256
  digest. Local runbook retrieval can answer common Angerona questions from it;
  it defines no tools and authorizes no action. Only selected, bounded, redacted
  `angerona://defense-memory` excerpts are eligible for an already authorized
  cloud fallback.

### Investigation and operations

- Classic defensive dashboard plus Flow Dashboard / Local SOC.
- Live Alerts, Resolve Center, SOAR Queue, Scan Center, Top Talkers, threat-
  intelligence review, cases, legal hold, bounded hunts, custody verification,
  local asset/SBOM views, audit export, and detection-content lifecycle.
- MITRE ATT&CK heat, coverage, and top-technique views with honest unsupported
  and partial states.
- Source Sandbox confines inert proposals and rejects runtime installers,
  path escapes, untrusted links, and automatic production deployment.
- Every functional Settings tab has a tab-aware code-sandbox button that opens
  its registered implementation files in an isolated editable copy and jumps to
  the tab's UI builder. Sandbox saves never rewrite installed source.
- Finite fleet credentials, protected secret custody, authenticated loopback
  fleet preview, signed packages, and privacy-minimized exports.
- The **Live Defense Activity** dashboard card displays at most five sanitized
  public EventBus summaries plus coarse module status. It never reads event
  details, source code, raw telemetry, private model reasoning, or
  chain-of-thought.

### Validation and purple teaming

- Non-destructive Red Team and Shark Attack campaigns use bounded reversible
  markers rather than live exploits, credential theft, or persistence.
- After-Action Reports correlate each stage to raw detections, signed response
  receipts, remediation state, cleanup, and fresh-rerun closure.
- Maximum Combat validation is repeatable from a batch entry point and exercises
  negative controls, live detections, automatic actions, Undo/cleanup, and
  journal integrity.

### Resilience and performance

- Watchdog, safe-mode backoff, bounded queues, dead-letter durability, resource
  governance, Chill mode, and off-thread GUI work.
- Measured wins on the frozen tree: runbook RAG 25.5x real / 4.38x synthetic;
  ETW cache peak allocation 92.2% lower; Upgrade Console submission about
  0.036 ms; literal loopback validation 2.16x faster; ransomware normalization
  6.91x faster; network novelty expiry 1.88x faster.
- Cycle 23 measurements: unchanged audit checkpoints 42.189 ms to 1.001 ms
  (97.6%); SSH process enumeration 41.050 ms to 3.726 ms (90.9%); maximum-bound
  clean network snapshot handling 1,319.25 us to 88.70 us (93.3%); and maximum-
  size SSH per-user token expansion 213.317 ms to 1.335 ms (99.4%). Detection
  cadence and freshness, anchor, completeness, and route checks were retained.

## Personal Sentinel topology and enrollment

`Angerona host -> operator-controlled Personal Sentinel gateway/firewall -> upstream/ISP router -> Internet`

The current product supplies the **client**, not the gateway appliance/server
or routing role. Enrollment is an explicit
`<AngeronaData>/config/personal_sentinel_gateway.json` document with schema
version 1, the exact local interface, a private-literal HTTPS endpoint, and the
expected certificate SHA-256 and policy digest. Missing or rejected enrollment
leaves all paths untrusted. The client never discovers or manages a router and
stores no router credential. A positive result describes only the exact
observed path; it does not establish endpoint, identity, application,
destination, upstream-router, or firmware trust.

## Platform contract

| Platform | Current use |
| --- | --- |
| Windows | **Protect:** full supported telemetry and governed response in elevated user mode; no unsigned kernel driver ships. |
| macOS | **Observe preview:** privacy-minimized shared-core process and flow visibility; no native enforcement claim. |
| Linux | **Observe + optional eBPF:** rootless process/flow/posture monitoring with an explicit privileged BCC/eBPF supplement. |

## Proven status

- Full pytest: **1,460 passed / 5 expected host-capability skips / 0 failed**
  from 1,465 collected tests in 208 files.
- Compile: **321/321**. Ruff passed; **73/73** module files imported; static
  discovery and manager construction report **71/71 modules**.
- Compatibility registration: **58/58** valid. Standalone core/Shark self-
  tests: **22/22**. Module harness: **50 passed / 0 failed / 21 expected skips**,
  plus a passing EventBus pipeline.
- Direct and batch selfcheck: **26/26** each.
- Guarded GitHub push/pull: pinned Gitleaks verifies staged or incoming changes
  before commit/merge; the helper verifies the scanner digest, permits only
  credential-free GitHub HTTPS remotes, and keeps pulls fast-forward-only.
- Combat negative controls: **128/128**.
- Auto-contain Red Team runs pre-arm the complete **13/13** simulation-only
  validation detector pack and fail closed if it cannot be persisted.
- Live maximum campaign winning round: **52/52 detection, 52/52 response,
  13/13 contracts, 13/13 verified closure**, resilience PASS, clean post-run
  state, and valid signed journal. A preceding imperfect response round was
  rejected and automatically rerun.

## Best-fit use cases

- Advanced Windows home lab and self-hosted defensive workstation.
- Blue-team, SOC, DFIR, detection-engineering, and MITRE ATT&CK learning.
- Safe purple-team validation of detections and response contracts.
- Defensive investigation of SSH persistence/tunnels, erased or discontinuous
  Windows logs, and suspicious Wi-Fi/Ethernet path drift without actor
  attribution.
- Local-AI security research with explicit provenance and authority boundaries.
- Operator-controlled intermediate gateway/firewall experiments using a
  separately implemented compatible attestation endpoint.
- Security-engineering portfolio demonstrating GUI, telemetry, response,
  recovery, testing, secure supply chain, and honest cross-platform contracts.

## Honest limits

- Not independently certified, externally benchmarked, or validated at
  commercial fleet scale; not a drop-in replacement for a supported enterprise
  EDR/XDR platform.
- Cycle 23 closed **15 of 16** findings. The remaining Medium is an external
  dependency: without a separately administered monotonic high-water service or
  policy-bound hardware authority, audit/network state is local-authenticity-
  only and is not independently fresh. The in-memory test authority and compact
  Personal Sentinel receipt are not represented as independent custody.
- One older non-blocking defense-in-depth Medium also remains: retain an OS
  process handle and a bounded executable-file identity lease across path-wide
  program firewall work.
- The Personal Sentinel appliance/server, routing role, firmware/measured-boot
  attestation, and external monotonic authority are proposed or deferred—not
  shipped. Gateway attestation never grants implicit endpoint trust.
- Research and detection language is actor-neutral; observed tradecraft is not
  an agency or state attribution.
- Publisher signing/notarization, clean-machine release matrices, long elevated
  soaks, physical sleep/resume, native Linux/macOS artifact acceptance,
  third-party efficacy testing, and field false-positive data remain external
  gates.
- No offensive payloads, hack-back, remote exploitation, credential theft,
  arbitrary response shell, downloaded executable skills, unverified model
  pulls, or unsigned kernel component.
