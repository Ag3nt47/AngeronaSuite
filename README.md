# Angerona Security Suite

Angerona brings local security telemetry, investigation and governed response
into one desktop workbench. It combines Endpoint Detection and Response (EDR),
Network Detection and Response (NDR), Security Orchestration, Automation, and
Response (SOAR), digital forensics, defensive ATT&CK exercises and an optional
local Ollama assistant.

Built for home labs, defensive research, learning and security-engineering
portfolios. Start with the dashboard, inspect the evidence behind an alert,
and use the configured response controls when their prerequisites are ready.

[![CI](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/ci.yml/badge.svg)](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/ci.yml)
[![Security](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/security.yml/badge.svg)](https://github.com/Ag3nt47/AngeronaSuite/actions/workflows/security.yml)
![Windows](https://img.shields.io/badge/Windows-Protect-0078D6)
![macOS](https://img.shields.io/badge/macOS-Observe-555555)
![Linux](https://img.shields.io/badge/Linux-Observe%20%2B%20optional%20eBPF-FCC624)
![Python](https://img.shields.io/badge/Python-3.10--3.13-3776AB)
![License](https://img.shields.io/badge/License-MIT-green)

Current version: **v1.13.0** · [Capabilities](ANGERONA_CAPABILITIES.md) ·
[Master Manual](Angerona_Master_Manual.docx) · [Security](SECURITY.md)

## Dashboard and major features

| v1.13.0 enterprise-pattern Local SOC programs | SentinelLens local-first hunt graph |
| --- | --- |
| [![Angerona v1.13.0 Fleet Center, DetectionForge, and AegisPath synthetic Local SOC views](docs/screenshots/angerona-v1.13-enterprise-programs.png)](docs/screenshots/angerona-v1.13-enterprise-programs.png) | [![Angerona v1.12.1 SentinelLens synthetic threat-hunting graph](docs/screenshots/angerona-v1.12-sentinel-lens.png)](docs/screenshots/angerona-v1.12-sentinel-lens.png) |
| Main defensive dashboard | Human-reviewed SOAR queue |
| [![Angerona v1.11.0 main dashboard](docs/screenshots/angerona-v1.11-dashboard.png)](docs/screenshots/angerona-v1.11-dashboard.png) | [![Angerona v1.11.0 SOAR review](docs/screenshots/angerona-v1.11-soar-review.png)](docs/screenshots/angerona-v1.11-soar-review.png) |
| Scan Center |  |
| [![Angerona v1.11.0 Scan Center](docs/screenshots/angerona-v1.11-scan-center.png)](docs/screenshots/angerona-v1.11-scan-center.png) |  |

These are reproducible public demonstrations. All displayed telemetry,
identifiers, timestamps, and counts are synthetic.

## What's new

The [September 23 deep review](analysis/deep-review-20260923/README.md) completed
three rounds of adversarial review, bug testing and targeted remediation:

- **Less idle and burst work.** Unconfigured detection callbacks skip payload
  processing; oversized nested input is rejected before expansion. A fixture
  measured 94% less idle callback time. A blocked-reader GUI fixture reduced
  1,001 queued wake callbacks to one while processing all retained serious
  events in two reads. These are component measurements, not whole-PC promises.
- **Visible local-AI startup.** Launch, restart and explicit self-tests prepare
  the trusted local Ollama service asynchronously and show stage percentages.
  A real Windows cold start reached 100% in 16.44 seconds with zero models loaded.
- **Stronger lifecycle and input checks.** Fixed retired memory-ring writes,
  lost Lab completion messages, ambiguous Ollama endpoint ownership and service
  paths. Keyword-only command observations no longer wake deep threat work.
- **Native source launchers.** Guided Linux and Intel/Apple Silicon Mac setup
  now validates a staged runtime before replacing launchers. Native CI results
  remain separate from the Windows checks performed for this review.
- **Optional Analysis Lab setup.** VMware setup and pinned analyzer controls
  are implemented. Native Lab execution is still blocked by the configuration
  custody check on tested Workstation 25; see the explicit limit below.

The earlier [machine-module update](analysis/round-20260921/README.md) remains:
unused or unsupported modules stay off and outside the running/enabled count.
Restart Angerona to load these changes. [Earlier maintenance records](analysis/loop/LOOP_LOG.md).

## What you can do

- **Observe and investigate:** inspect process, file, memory, removable-media,
  authentication and network evidence; correlate events in SentinelLens;
  review alerts, scan results, source provenance and recorded coverage gaps.
- **Respond under policy:** use exact-target quarantine, process and network
  controls with typed authority, durable journals, verified outcomes and Undo
  where supported. The deterministic response worker operates without Ollama;
  model narrative alone cannot authorize containment.
- **Practice and inspect:** run benign defensive validation, compare evidence
  with curated ATT&CK mappings, review pinned GitHub source archives as text,
  and inspect local Fleet Fabric, DetectionForge and AegisPath lab programs.
- **Assist locally:** ask the optional Ollama-backed assistant for explanations.
  Model approval, source provenance and response permissions remain separate.

Windows sources include event logs, Defender, process and file telemetry, and
Windows Filtering Platform (WFP) integration. Individual collection and response
features depend on platform, permissions, configuration and trusted evidence.
[Architecture and boundaries](docs/architecture.md).

## Choose your installation

| Platform | Starting point | Current scope |
| --- | --- | --- |
| Windows | Signed release package, or `Install-Angerona.bat` for source development | Protect requires the signed installed authority; unelevated source runs in Observe/development scope. |
| macOS 14+ | [Start-Angerona-macOS.command](Start-Angerona-macOS.command) | Observe preview; one launcher detects Intel, Apple Silicon and Rosetta. |
| Linux x86_64 | [Start-Angerona-Linux.sh](Start-Angerona-Linux.sh) | Observe, with optional explicitly configured eBPF; reviewed native CI target is Ubuntu 24.04. |

For a tagged Windows release, use its `Angerona-<version>-win64.msix` and adjacent
SHA-256 file from [Releases](../../releases). Windows must trust the provisioned
package publisher. Installing a trusted signed Windows release needs
no Python or terminal. Release signing and clean-VM acceptance remain release gates;
the repository does not claim Microsoft Store deployment. The portable ZIP is
upgrade-only, and the classic Setup wrapper is not a public first-install path.

For Windows source setup, clone the repository and run `Install-Angerona.bat`
as your ordinary user. It installs locked dependencies and refuses an elevated
terminal. `start-angerona.bat` uses [Safe Startup](docs/safe-startup.md) to prepare
and launch the dashboard in Chill Mode, with visible repair guidance on failure.

Mac/Linux source setup needs Python 3.12 and guides prerequisite installation.
Intel Mac additionally builds pinned cryptography 50 with Xcode Command Line
Tools, Rust and OpenSSL; Apple Silicon uses reviewed wheels. Linux setup checks
Qt graphics/font libraries and validates real offscreen widget rendering before
publishing a launcher. Failed installation preserves the previous runtime.
[Native setup, prerequisites and recovery](docs/NATIVE_INSTALL.md).

Intel and Apple Silicon macOS and Ubuntu source installation passed their native
CI lanes, including the Intel dependency build and actual offscreen GUI rendering.
See the [CI follow-up](analysis/deep-review-20260923/publication-followup.md).
Visible desktop operation is a separate check. Source-runtime locks are complete;
older full POSIX release-build locks still need dependency-graph repair.

## Modules, resource use and local AI

Static discovery reports **84 modules** in the Windows catalog. Runtime counts
show **running / enabled for this machine**, excluding unsupported, disabled
and unconfigured optional integrations. Failed expected sensors and paused
configured modules remain visible; quiet telemetry does not prove irrelevance.
USB and WLAN guards keep watching for future device or link arrivals.

Chill Mode limits optional analytical and presentation work while retaining its
configured protection paths. The catalog is not a recommendation to activate
all modules, and a running count is not a protection score. Module details expose
availability, health and the reason for an inactive state.

Ollama service percentages describe completed startup checks. **100% means the
local service and inventory passed validation; it does not approve or load a
model.** Inference still needs the exact installed model and a fresh approved
attestation. Automatic startup requires a recognized trusted installation;
user-owned or symlinked POSIX installation paths may be refused. Missing AI leaves
deterministic detection and authorized response available. Protected Windows
launches use a checked normal-user token; that elevated handoff has fixture
coverage and still needs native acceptance. Hostile telemetry is treated as data;
failed neutralization skips the
optional narrative request. [Startup evidence](analysis/deep-review-20260923/ollama-startup.md).

## Optional Analysis Lab

Analysis Lab is intended for bounded source analysis with pinned Bandit and
Gitleaks inside a disposable offline VMware appliance. The GUI, catalog,
preparation, cancellation and redacted report/history controls are implemented.
They do not establish that native guest execution works.

**Current limit:** tested Workstation 25.0.1 cannot open the generated VMX while
its write/delete protection is held. Read-only and bounded direct-start trials
also failed. The protection stays intact, no analyzer receipt was accepted,
and Run stays gated until both real analyzer readiness checks pass.
[Native acceptance and remaining work](analysis/deep-review-20260923/native-acceptance.md).

VMware is optional and adds installation, disk and guest-memory costs. Skip it
if you only need Angerona monitoring, response or source review. Full Setup's
optional Lab flow opens Broadcom's official portal; account/compliance approval
may be required. Select the downloaded installer for vendor verification and
interactive Windows elevation. A separate confirmed action sets the verified
Authorization Service to Manual and starts it. Then prepare the runtime and
check readiness. Installation or service startup alone never enables Run.
[Lab design and implementation status](docs/design/red-team-github-tool-library.md).

## Data, trust and limits

Unelevated Windows source launches use `%LOCALAPPDATA%\Angerona\SourceData`.
Protected elevated-source state uses the checkout's sibling `AngeronaData` directory.
Packaged Windows installs prefer `D:\AngeronaData`, with protected
`%ProgramData%\Angerona` as fallback when D: is unavailable.
Cloud integrations are optional and off by default.

Angerona is user-mode and ships no production kernel driver. It cannot promise
tamper resistance against compromised Administrator/SYSTEM or kernel authority,
recover events deleted before collection, or prove full-history rollback without
an independent witness. This is not an independently certified commercial EDR
or a claim of complete detection coverage. Local fleet/research programs and
curated standards mappings do not imply enterprise or upstream-feature parity.

Imported source and external analyzer reports have no native response authority.
Personal Sentinel is a separately administered reference authority, not a router
appliance. No offensive intrusion, arbitrary response shell or hack-back is a
product capability. See [Security](SECURITY.md) and [capability limits](ANGERONA_CAPABILITIES.md).

## Validation and development

The [three-round record](analysis/deep-review-20260923/README.md) links findings,
fixes, benchmarks, native acceptance and the final module inventory. All 84
catalog entries are accounted for: 66 module self-tests passed, 18 had explicit
optional/platform prerequisites, and the separate event-pipeline test passed.
Skips are not passing live-sensor tests. The Windows review's reconciliation of
the aggregate run and focused reruns records **3,972 passes, 19 skips and no
unresolved failures** across 3,991 collected cases. The raw aggregate run and
its three corrected fixture/documentation failures remain documented separately;
this is not a claim that the entire suite was rerun in one all-green execution.
Native CI results and subsequent installer corrections are recorded in the
[publication follow-up](analysis/deep-review-20260923/publication-followup.md).

For an existing development environment:

```powershell
python -m pytest -q
python tools/selfcheck.py
python tools/validate_documentation_drift.py
```

Contributions: [Contributing](CONTRIBUTING.md) · [Architecture](docs/architecture.md) ·
[Research comparison and proposed follow-ups](analysis/deep-review-20260923/visionary-comparison.md).
Maintainer publication uses `python tools/publish_github_update.py`, which checks
canonical fast-forward publication and the public bytes of every README image.

Historical release evidence: **Final Cycle 34 verification.** The gate on commit
`7eef1f0a0c400b34f170cbd1463cd3c6a454de3b` passes **2882 tests with 15 intentional platform skips**.
This is the earlier release record, not the September 23 full-suite result.
[Historical validation details](analysis/loop/LOOP_LOG.md).

<!-- ANGERONA_DOC_STATUS tests=2882 skips=15 modules=84 -->
