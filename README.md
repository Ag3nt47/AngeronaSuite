# Angerona Security Suite

A local security workbench for seeing what happened, following the evidence and
reviewing a governed response. Angerona combines Endpoint Detection and Response
(EDR), Network Detection and Response (NDR), Security Orchestration, Automation,
and Response (SOAR), forensics and defensive practice in one desktop application.

**For home labs, defenders, researchers and security-engineering portfolios.**
Deterministic defense works without an AI model; optional local AI helps explain
evidence and propose next steps.

## Current development: v1.14.0

[Download and installation choices](#choose-your-installation) ·
[Release downloads](https://github.com/Ag3nt47/AngeronaSuite/releases) ·
[Latest changes](CHANGELOG.md) ·
[Master Manual](Angerona_Master_Manual.docx) ·
[Security flow and review map](docs/security-flow.md)

[![CI](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/ci.yml/badge.svg)](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/ci.yml)
[![Security](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/security.yml/badge.svg)](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/security.yml)
![License](https://img.shields.io/badge/License-MIT-green)

[![Angerona dashboard demonstration with fixed synthetic data and no host actions](assets/screenshots/dashboard-demo.png)](assets/demo/angerona-demo.gif)

[Play the 45-second application demonstration](assets/demo/angerona-demo.gif):
dashboard, scrolling alerts, SpywareGuard, Settings, MITRE ATT&CK, SOAR and scans.

**DEMO:** actual Qt interface with fixed examples; all displayed telemetry,
identifiers, timestamps and counts are synthetic. No host scan or response is
performed to create this demonstration.

[![Verified startup, evidence collection, governed response and independent recovery with Ring 3 limits](assets/security-flow-overview.png)](docs/security-flow.md)

## Latest maintenance

This v1.14.0 maintenance update adds independent startup recovery, clearer
failure diagnostics and storage admission limits. Dashboard sections minimize
individually and start open except Module health. STOP unloads local AI and
retires owned helpers/watchdogs; automatic recovery honors the recorded stop.
The updated master manual maps the security boundaries and recovery paths.

## Suite at a glance

- **Endpoint evidence:** process, file, memory, identity, persistence and
  removable-media observations, with explicit missing or stale coverage.
- **Network visibility:** connection, protocol, wireless, ARP and beacon
  analysis through the available platform sensors.
- **Scans and detection:** Scan Center, YARA matching, memory-injection checks,
  behavioral rules and correlated exposure or tradecraft evidence.
- **Investigation and forensics:** SentinelLens graphs, MITRE ATT&CK technique
  and evidence views, cases, timelines and supported captures connect observations.
- **Governed response:** SOAR queues supported exact-target quarantine,
  process and network operations under policy, with recorded outcomes and Undo.
- **SpywareGuard:** surveillanceware evidence review and governed response,
  subject to its published preview and platform prerequisites.
- **Integrity and provenance:** source, model, audit, IPC and enrolled UGCAP
  checks; independent witness authority requires its own deployment.
- **Defensive practice:** benign validation, deception and canary exercises
  produce labeled receipts; synthetic markers cannot authorize host actions.
- **Optional AI:** local Ollama explanations and manual sanitized preview/Send
  assist review; model text has no response authority.
- **Operations and recovery:** resource controls, watchdogs, storage warnings,
  safe startup alternatives and preserved-edit recovery decisions.
- **Integration and review:** module contracts, optional intelligence/fleet/SIEM
  connections and bounded read-only Live AI Review.

Static discovery includes **86 modules**. Declared platforms, modes, dependencies,
response authority and actual live coverage differ.
[Capability register](ANGERONA_CAPABILITIES.md) ·
[Complete built-in source inventory](docs/security-flow.md#built-in-capability-source-inventory).

## Choose your installation

| Platform and purpose | Start here | Authority and availability |
| --- | --- | --- |
| Windows signed installed release | [Check Releases for an accepted signed package](https://github.com/Ag3nt47/AngeronaSuite/releases) | Use an available trusted-publisher MSIX and its adjacent SHA-256 file. Signed Protect, native service acceptance and clean-VM release gates remain separate requirements. |
| Windows source development | [Clone this repository](https://github.com/Ag3nt47/AngeronaSuite), then run `Install-Angerona.bat` as your ordinary user | Unelevated Observe/development in Chill Mode. Source startup cannot create signed installed Protect authority. |
| macOS 14+ source | [Start-Angerona-macOS.command](Start-Angerona-macOS.command) | Observe preview; Intel, Apple Silicon and Rosetta detection. [Prerequisites](docs/NATIVE_INSTALL.md). |
| Linux source | [Start-Angerona-Linux.sh](Start-Angerona-Linux.sh) | Observe with optional explicitly configured eBPF. [Prerequisites and native scope](docs/NATIVE_INSTALL.md). |

**Estimated download and disk space** — app and reviewed runtime, before optional
AI models or accumulated security data. GB below means decimal gigabytes.
These are planning ranges, not measurements of published release archives.

| Installation | Estimated first download | Estimated app/runtime disk use |
| --- | --- | --- |
| Windows signed package, when available | Pending a measured release build; use the accepted asset's listed size | Pending measurement; allow several GB for separate runtime extraction and installation/upgrade staging |
| Windows source setup | 0.35–0.60 GB | 1–2 GB |
| macOS source setup | 0.50–0.75 GB | 1.5–3 GB |
| Linux source setup | 0.30–0.50 GB | 1–2 GB |

The current Windows dependency wheels total about **300 MB downloaded / 840 MB
expanded**; source estimates also allow for the checkout. The platform inputs
are listed in the [Linux](release/locks/posix/source/linux-x86_64.manifest.json),
[Apple Silicon](release/locks/posix/source/macos-arm64.manifest.json) and
[Intel macOS](release/locks/posix/source/macos-x86_64-base.manifest.json)
wheel manifests. OS prerequisites, Intel macOS
Xcode/Rust/OpenSSL builds, Git history, retained backups and evidence are extra.
Windows source repair requires **5 GiB free**: a 2 GiB reserve plus 3 GiB working
capacity. Its one retained previous runtime can add another runtime's disk use.

**Optional models are separate:** [Llama 3 8B](https://ollama.com/library/llama3:8b)
adds about **4.7 GB** for model weights alone, plus the Ollama runtime. Other
models vary. The [small English Vosk speech model](https://alphacephei.com/vosk/models)
adds about **40 MB of download** when not already bundled. No LLM is required
for deterministic defense.

When an accepted signed release is available, its Windows package is
`Angerona-<version>-win64.msix`. Protect requires the signed installed authority;
unelevated source runs in Observe/development scope.

A release tag or unsigned download does not establish publisher trust. A trusted
signed release needs no Python or terminal setup. Portable ZIPs
are upgrade-only; the classic Setup wrapper is not a public first-install path.
The project does not claim Microsoft Store distribution.

For Windows source:

1. Clone the canonical repository into your development directory.
2. Run `Install-Angerona.bat` without elevation to create the reviewed runtime.
3. Run `start-angerona.bat`. Start with the dashboard's actual coverage state,
   then enable the modules and integrations you need.

Use dashboard **STOP** or **Quit** from the tray for a clean stop; closing the
window can leave the engine running. A shared Ollama server and downloaded
models remain; configured model residency is unloaded. Automatic recovery stays
stopped until an explicit launch. [Startup recovery](docs/safe-startup-recovery.md) explains safe
alternatives, logs and held conditions.

## How the security flow works

The [full flow and attack-surface matrix](docs/security-flow.md) connect each
boundary to implementation and regression entry points. A visible dashboard,
fresh sensor evidence and authority to act are separate states. Imported logs,
URLs, AI prose and review notes remain untrusted data.

Angerona is user-mode and ships no production kernel driver. Ring 3 code does
not gain kernel immunity through UAC, signing or cryptographic checks. Hostile
administrator, kernel, firmware, hypervisor and compromised-OS threats remain
outside any universal protection claim. Windows Filtering Platform (WFP) and
other OS integrations still require their actual platform, privilege and
deployment prerequisites. [Architecture](docs/architecture.md) · [Security](SECURITY.md).

## Privacy, recovery and drive usage

Cloud integrations are optional and off by default. Optional AI, intelligence,
fleet and witness integrations have their own endpoint and consent boundaries.
The separately controlled public GitHub fallback for source startup defaults on;
it downloads verified public code and uploads no host evidence or preserved edits.
Manual AI consultation shows a bounded sanitized preview before explicit Send.
[AI privacy](docs/ai-consult-privacy.md).

Normal Windows source data is under
`%LOCALAPPDATA%\Angerona\SourceData`. Historical protected elevated-source
custody uses the checkout's sibling `AngeronaData` directory; the normal source
launcher refuses elevation. Packaged Windows data prefers `D:\AngeronaData`,
with protected `%ProgramData%\Angerona` fallback according to installed authority.
Credentials, baselines, audit journals, cases and disposable caches have separate
retention. Hash-based Message Authentication Code (HMAC) verification of record
bytes does not alone establish producer truth.
[Data and key boundaries](docs/key-and-communication-integrity.md).

File recovery has configurable cache/reserve controls and visible storage
warnings. Startup work has separate quotas: source snapshots preserve original
edits, logs rotate, and disk-pressure holds stop new work. Full capacity never
justifies silently evicting unreviewed edits or clearing protected evidence.
Some direct dashboard/native-installer logs still need retention review.
[Storage budgets and limits](docs/safe-startup-recovery.md#capacity-and-retention).

Safe Startup tries fixed verified alternatives and keeps a separate recovery
interface available when app code or Qt fails. Automatic recovery and GitHub
source fetches are individually controlled in Settings. Every candidate repeats
trust/runtime/readiness gates; an open recovery window does not mean protection
is active. [Recovery guide](docs/safe-startup-recovery.md).

## More application views

| Investigation and response | Capability views |
| --- | --- |
| [![SentinelLens synthetic hunt graph](docs/screenshots/angerona-v1.12-sentinel-lens.png)](docs/screenshots/angerona-v1.12-sentinel-lens.png) | [![Local SOC Fleet Center DetectionForge and AegisPath synthetic views](docs/screenshots/angerona-v1.13-enterprise-programs.png)](docs/screenshots/angerona-v1.13-enterprise-programs.png) |
| [![Main dashboard public synthetic demonstration](docs/screenshots/dashboard-public-demo.png)](docs/screenshots/dashboard-public-demo.png) | [![SpywareGuard application with synthetic DEMO detections](docs/screenshots/angerona-spywareguard-preview.png)](docs/screenshots/angerona-spywareguard-preview.png) |
| [![Human-reviewed SOAR queue](docs/screenshots/angerona-v1.11-soar-review.png)](docs/screenshots/angerona-v1.11-soar-review.png) | [![Scan Center](docs/screenshots/angerona-v1.11-scan-center.png)](docs/screenshots/angerona-v1.11-scan-center.png) |
| [![Optional orbital dashboard with synthetic data](docs/screenshots/dashboard-orbital-demo.png)](docs/screenshots/dashboard-orbital-demo.png) | All views use synthetic public demonstrations. They are not live coverage, efficacy or scale benchmarks. |

## Guides and current work

- [Master Manual](Angerona_Master_Manual.docx): operating reference, complete
  security flow, all built-in source entries and recovery decisions.
- [Safe Startup](docs/safe-startup-recovery.md): alternatives, diagnostics,
  preserved edits, optional GitHub egress and honest storage limits.
- [Live AI Review](docs/live-debug-harness.md): opt-in bounded read-only diagnosis;
  [interaction map](analysis/live-debug-2026-10-22/interaction-map.md).
- [UGCAP and Enclave Mesh](docs/ugcap-enclave-mesh.md): explicit known-clean
  enrollment, fresh integrity evidence and separately deployed witness authority.
- [SpywareGuard](docs/spyware-guard.md): surveillanceware evidence review and
  governed response with explicit preview/prerequisite limits.
- [Hardware and self-check](docs/hardware-and-selfcheck.md), [native setup](docs/NATIVE_INSTALL.md),
  [v1.14 acceptance register](docs/releases/v1.14-security-integration.md).

Native process-bound egress, signed privileged-service deployment and independent
witness/backup authorities retain separate acceptance gates. Passing source
tests cannot deploy those authorities or prove field detection rates.
Broader v1.15 remains incomplete.

## Validation and contributing

Historical release evidence: **Final Cycle 34 verification.** The gate on
`7eef1f0a0c400b34f170cbd1463cd3c6a454de3b` passes **2882 tests with 15 intentional platform skips**.
This is a dated checkpoint, not the current revision's result or live coverage.
[Retained maintenance history](analysis/public-maintenance-history.md) preserves
the previous README and its scoped measurements;
[the issue map](analysis/live-debug-2026-10-22/README.md) records further evidence
and remaining work.

For a configured development environment, run the focused checks relevant to
your change, then the required integration/self-check gates. Preserve skips and
coverage gaps. Maintainer publication must verify canonical public `main`, a
clean worktree and byte-identical tracked README assets.

[Contributing](CONTRIBUTING.md) · [Writing modules](docs/writing-modules.md) ·
[Report security issues](SECURITY.md) · [Changelog](CHANGELOG.md) · [MIT license](LICENSE)

<!-- ANGERONA_DOC_STATUS tests=2882 skips=15 modules=86 -->
