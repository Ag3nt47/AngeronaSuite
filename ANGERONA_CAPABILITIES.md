# Angerona Capabilities

Current status: **v1.10.2**. This is a present-tense capability and use-case
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
- Process lineage, file integrity, persistence, memory injection, LSASS access,
  shadow-copy tamper, ransomware, beacon/C2 cadence, removable media,
  vulnerable-driver, deception, YARA/YARA-X, and network behavior detection.
- Community ID v1 flow identity, OCSF 1.8 mappings, Suricata and Zeek evidence,
  guarded read-only osquery snapshots, cases, timelines, and ATT&CK mapping.
- HMAC-authenticated EventBus records and retained evidence; signed action
  records use an HMAC hash chain.

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

## Platform contract

| Platform | Current use |
| --- | --- |
| Windows | **Protect:** full supported telemetry and governed response in elevated user mode; no unsigned kernel driver ships. |
| macOS | **Observe preview:** privacy-minimized shared-core process and flow visibility; no native enforcement claim. |
| Linux | **Observe + optional eBPF:** rootless process/flow/posture monitoring with an explicit privileged BCC/eBPF supplement. |

## Proven status

- Full pytest: **1,258 passed / 3 intentional skips / 0 failed** from 1,261
  collected tests in 197 files.
- Compile: **308/308**. Ruff/import/discovery/duplicate gates: pass.
- Self-tests: **46 module + 20 core/Shark + 15 ARIA passed**, with zero genuine
  failures; direct and batch selfcheck: **26/26** each.
- Dependency audit: **no known vulnerabilities**.
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
- Local-AI security research with explicit provenance and authority boundaries.
- Security-engineering portfolio demonstrating GUI, telemetry, response,
  recovery, testing, secure supply chain, and honest cross-platform contracts.

## Honest limits

- Not independently certified, externally benchmarked, or validated at
  commercial fleet scale; not a drop-in replacement for a supported enterprise
  EDR/XDR platform.
- No open Critical/High/Medium release blocker in the final audit. One non-
  blocking defense-in-depth Medium remains: retain an OS process handle and a
  bounded executable-file identity lease across path-wide program firewall work.
- Publisher signing/notarization, clean-machine release matrices, long elevated
  soaks, physical sleep/resume, native Linux/macOS artifact acceptance,
  third-party efficacy testing, and field false-positive data remain external
  gates.
- No offensive payloads, hack-back, remote exploitation, credential theft,
  arbitrary response shell, downloaded executable skills, unverified model
  pulls, or unsigned kernel component.
