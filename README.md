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

Current version: **v1.10.2**

[Master Manual](Angerona_Master_Manual.docx) ·
[Current capabilities](ANGERONA_CAPABILITIES.md) ·
[Architecture](docs/architecture.md) ·
[Security](SECURITY.md) ·
[Contributing](CONTRIBUTING.md)

## 🚀 One-click Windows install

For a tagged release, download `Angerona-<version>-win64-setup.exe` and its
adjacent SHA-256 file from [Releases](../../releases). Verify the digest and
GitHub build attestation, then open the Setup executable and approve the Windows
UAC prompt. It installs the bundled application, shortcuts, uninstaller, and
guided setup. **No Python or terminal is required.**

The release ZIP remains the portable/manual-verification fallback. Extract it
and run `Install-Angerona-Release.bat`; that path verifies its embedded
executables against `release-files.sha256` before installation. Releases are not
currently Authenticode publisher-signed, so Windows may show **Unknown
Publisher** even when the checksum and GitHub attestation are valid.

## What is current in v1.10.2

- **Governed Adversary Combat:** unattended local defensive response can block a
  peer, isolate an exact executable, suspend or terminate a verified process,
  quarantine an exact file, activate deception, or isolate the host when a typed
  policy and signed response contract authorize that scope. Every mutation uses a
  durable intent, Hash-based Message Authentication Code (HMAC) hash-chain
  journal, verified postcondition, exact Undo, and crash-recovery circuit.
- **Receipt-bound SOAR:** approved work is delegated to Combat through signed,
  idempotent requests. Submitted, verified, failed, timed-out, recovered, and
  undone states remain distinguishable; a request is not reported as successful
  merely because it was queued.
- **Local ARIA and governed model packs:** ARIA uses typed tools, evidence-backed
  runbook retrieval, typed-only confirmation for consequential actions, and an
  approved `aria-defense-llama3` pack whose manifest and Ollama blobs are verified
  before activation. Downloaded knowledge remains non-executable and cannot grant
  itself host authority.
- **Windows telemetry continuity and interoperability:** Sysmon event IDs 1-29
  plus 255, an authenticated restart cursor, Community ID v1 flow identity, and
  OCSF 1.8 mappings improve continuity and evidence exchange.
- **Hardened trust boundaries:** Ollama is re-attested at call time to an approved
  loopback listener, process birth, and executable path. Source Sandbox stages
  inert files, runtime installers are not accepted, and fleet credentials have a
  finite lifecycle and protected custody.
- **Measured performance improvements:** runbook scoring is 25.5x faster on the
  real index (4.38x on the synthetic corpus); ETW cache peak allocation is 92.2%
  lower in the stress case; Upgrade Console I/O submission returns in about
  0.036 ms; loopback validation is 2.16x faster; ransomware directory
  correlation is 6.91x faster; and network novelty expiry is 1.88x faster.

## Capability map

### Detect and correlate

- Windows ETW, WMI/CIM, AMSI, Windows Filtering Platform (WFP), Defender,
  Security log, and Sysmon telemetry.
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
- Non-destructive Red Team and Shark Attack campaigns with After-Action Reports.
  Simulations use bounded reversible markers rather than exploits or persistence.
- A repeatable maximum Adversary Combat validation batch proves detection,
  contract admission, response closure, cleanup, and journal integrity.

### Assist locally

- ARIA local chat and runbook retrieval, local security briefing, typed tools,
  provider controls, optional voice and gesture navigation, and explicit egress
  consent for any cloud connector.
- Approved model/knowledge-pack lifecycle: provenance and digest checks, resource
  admission, bounded staging, evaluation, activation, rollback, and removal.
- Model output is advisory evidence unless a separate deterministic control path
  authorizes a typed action. Arbitrary model-authored PowerShell is inert.

## Platform support

| Platform | Current contract | Boundary |
| --- | --- | --- |
| Windows | **Protect** | Full supported telemetry and governed response path; runs elevated in user mode and ships no unsigned kernel driver. |
| macOS | **Observe preview** | Privacy-minimized process/flow observation and shared core; no Endpoint Security or Network Extension enforcement claim. |
| Linux | **Observe + optional eBPF** | Rootless process/flow/posture observation; BCC/eBPF is an explicit privileged supplement, not a shipped universal CO-RE sensor. |

## Install and run

For a tagged Windows release, download the Setup executable and adjacent SHA-256
file from [Releases](../../releases), verify the digest and GitHub attestation,
then approve the UAC prompt. The published installer is not currently backed by
an Authenticode publisher certificate, so Windows may show **Unknown Publisher**.

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

## Validation status

The frozen v1.10.2 tree produced the following local evidence on Windows:

- 1,260 pytest cases collected across 197 files: **1,257 passed, 3 intentional
  skips, 0 failed**.
- **308/308** Python files compiled; Ruff, imports, module discovery, duplicate
  checks, direct selfcheck, and batch selfcheck passed.
- Module self-tests: **46 genuine passes, 0 genuine failures**, plus 13 expected
  inactive results and 8 platform/operator skips. Core/Shark: **20/20**. ARIA:
  **15/15**. Dependency audit: **no known vulnerabilities**.
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
- The current red-team audit has no open Critical, High, or Medium release
  blocker. One non-blocking defense-in-depth Medium remains: path-wide program
  firewall rules would be stronger with a retained OS process handle and bounded
  executable-file identity lease across the full action interval.
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

## Use cases

- Windows home lab or self-hosted endpoint defense.
- Blue-team and purple-team learning with visible ATT&CK evidence.
- Local, privacy-conscious investigation and incident-response practice.
- Detection engineering, response-contract, secure-SDLC, and portfolio work.
- Research platform for governed local AI and reversible defensive automation.

MIT licensed. See [LICENSE](LICENSE), [SECURITY.md](SECURITY.md), and
[SUPPORT.md](SUPPORT.md).

**Final Cycle 8 verification.** Frozen v1.10.2 passes **1257 tests with 3 intentional platform skips**; static discovery reports **67 modules**.

<!-- ANGERONA_DOC_STATUS tests=1257 skips=3 modules=67 -->
