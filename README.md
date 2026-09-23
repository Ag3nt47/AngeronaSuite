# Angerona Security Suite

Angerona brings local security telemetry, investigation and governed response
into one desktop workbench. It combines Endpoint Detection and Response (EDR),
Network Detection and Response (NDR), Security Orchestration, Automation, and
Response (SOAR), digital forensics, defensive ATT&CK exercises and an optional
local Ollama assistant.

Built for home labs, defensive research, learning and security-engineering
portfolios. Follow an alert from its sensor evidence to a verified response,
review the action, and undo supported changes. Automatic defense follows your
configured policy and works without an AI model.

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

The [September 23 maintenance upgrade](analysis/upgrade-20260923/README.md)
repairs a real detection-to-response gap and reduces repeated background work:

- **Automatic, verifiable file containment.** Real YARA detections now carry
  exact content identity into the live response worker. Native Windows tests
  verified automatic quarantine, signed results and Undo for inert files and
  ZIPs, without Ollama or manually dispatching an action. Shark reports also
  recognize the actual registered detector's evidence.
- **Less repeated scanning.** Shared process snapshots avoid duplicate OS
  collection, and unchanged files reuse bounded YARA scan results. A 48-file
  fixture fell from 2,557 ms to 67 ms on repeated scans; this is a component
  measurement, not a whole-PC speed or long-term stability claim.
- **Automatic alert cleanup.** Runtime alert archives default to 30 days and
  a 256 MiB target. Change or disable cleanup in **Settings → System**; signed
  evidence, response journals and recovery data are excluded.
- **Protection beyond the window.** The opt-in detached engine keeps running
  after its console closes. It exposes live module readiness, response state,
  events and controls through authenticated local communication.
- **More testable defenses.** Enroll AI instruction and tool files for drift
  checks, run an encrypted restore drill, and compare detection rules against
  labelled benign and suspicious events. [Usage and limits](analysis/upgrade-20260923/usage.md).

The earlier [QEMU Analysis Lab and Ollama startup work](analysis/continuation-20260923/README.md)
and [native Mac/Linux source launchers](docs/NATIVE_INSTALL.md) remain available.
Unused or unsupported modules stay off and outside the running/enabled count.
Restart Angerona to load changes. [Review, tests and remaining work](analysis/upgrade-20260923/validation.md).

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

Publisher signing and Apple notarization credentials are **not configured** in
this maintenance environment. Trusted installer publication remains pending;
the source launchers below are the available development setup path.

For a tagged Windows release with signing provisioned, use its `Angerona-<version>-win64.msix` and adjacent
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

To try the separate protection engine from an installed source environment, run
`python -m angerona --engine-console`. Closing this console leaves the engine
running; **Stop protection** is a separate explicit control. This is an optional
ordinary-user console, with a smaller interface than the full workbench.
Per-user automatic startup is available through `tools/manage_engine.py`.
It does not establish privileged service protection or survive every sign-out.
[Engine setup and resource measurements](analysis/upgrade-20260923/usage.md).

Ollama service percentages describe completed startup checks. **100% means the
local service and inventory passed validation; it does not approve or load a
model.** Inference still needs the exact installed model and a fresh approved
attestation. Automatic startup requires a recognized trusted installation;
user-owned or symlinked POSIX installation paths may be refused. Missing AI leaves
deterministic detection and authorized response available. Protected Windows
launches require a checked normal-user token. Native testing exposed a linked-token
type mismatch; a compatibility change supports tokens with sufficient authority,
but elevated startup remains unverified after a cancelled UAC request.
Hostile telemetry is treated as data;
failed neutralization skips the optional narrative request.
[Startup evidence](analysis/continuation-20260923/ollama-native.md).

## Optional Analysis Lab

Analysis Lab checks a copy of your source with pinned **Bandit 1.9.4** and
**Gitleaks 8.30.1** inside a disposable, offline QEMU guest. It looks for Python
security issues and exposed secrets; it does not execute the submitted source.
Reports are redacted and cannot authorize host response. The current backend
requires **64-bit Windows on Intel/AMD and a normal, non-administrator Angerona
session**. Monitoring, automatic defense and Ollama work without it.

Open **Full Setup → Optional Analysis Lab**, or the Lab's setup button. Choosing
setup downloads the reviewed QEMU 11.1.0 installer (about **197 MiB**) if needed,
opens its normal installer/license and Windows administrator prompts, and
configures a protected **122 MiB** Lab runtime. Keep the vendor installer's
default location and allow **2 GiB free disk space**. An exact matching QEMU
installation can be reused. **Skip** leaves setup unchanged. The distributor's
certificate is expired; Angerona verifies the exact reviewed download and
runtime files against pinned hashes. [Runtime provenance](analysis/continuation-20260923/qemu-design.md).

After setup, choose **Prepare runtime**, then **Check readiness**. Installation
alone never enables Run: both real analyzer fixtures must pass for the current
runtime. Native Windows checks passed for both analyzers, including their
expected findings and isolation checks.

Each requested job uses one virtual CPU and **768 MiB guest RAM**, with a
five-minute deadline, a **2 GiB host-process memory limit** and a **25% host-CPU
cap**. There is no guest disk, external network adapter or host folder share.
The VM stops when the job ends; no Lab VM runs in the background while idle.
Normal Windows paging and crash dumps still apply to host memory.

Separate VMware setup remains available for users who want Workstation.
VMware is not required for this Lab: its tested backend remains blocked by
Workstation's need to write its configuration, and that protection has not been
relaxed. [Continuation results and limits](analysis/continuation-20260923/README.md).

## Data, trust and limits

Unelevated Windows source launches use `%LOCALAPPDATA%\Angerona\SourceData`.
Protected elevated-source state uses the checkout's sibling `AngeronaData` directory.
Packaged Windows installs prefer `D:\AngeronaData`, with protected
`%ProgramData%\Angerona` as fallback when D: is unavailable.
Cloud integrations are optional and off by default.

Disposable `diagnostics/runtime_alerts.log` copies rotate at 4 MiB. Background
cleanup removes eligible closed archives by age and total-size target, with
adjustable limits of 1–3,650 days and 8–16,384 MiB. Pinned or inaccessible files
can leave storage above the target; the settings panel shows cleanup status.
Turning cleanup off allows archives to grow. It never sweeps the whole data
directory or deletes signed event/action records, cases, backups or exports.

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

The final upgrade regression suite passed **4,303 tests with 20 skips**.
The [validation record](analysis/upgrade-20260923/validation.md) separates native
automatic-containment checks, module self-tests and component benchmarks.
Its isolated selfcheck passed all 26 phases; SelfTestRunner reported 66 module
passes, one separate event-pipeline pass and 18 explicit prerequisite skips.
Skips do not establish live coverage.

The prior [continuation record](analysis/continuation-20260923/validation.md)
reconciles 4,107 passes and 18 skips from a full baseline plus fixture
corrections. Both real Lab readiness fixtures and an end-to-end scan passed.
Elevated Ollama acceptance remains open; 24-hour/7-day stability and trusted
installer acceptance are also outstanding.

The earlier [three-round review](analysis/deep-review-20260923/README.md)
accounts for all 84 modules: 66 self-tests passed, 18 had explicit optional or
platform prerequisites, and the separate event-pipeline test passed. Skips are
not passing live-sensor tests. Its full-suite reconciliation, component
benchmarks and subsequent [native CI results](analysis/deep-review-20260923/publication-followup.md)
remain linked evidence for their respective checkpoints.

For an existing development environment:

```powershell
python -m pytest -q
python tools/selfcheck.py
python tools/validate_documentation_drift.py
```

Contributions: [Contributing](CONTRIBUTING.md) · [Architecture](docs/architecture.md) ·
[Research comparison and proposed follow-ups](analysis/upgrade-20260923/comparison.md).
Maintainer publication uses `python tools/publish_github_update.py`, which checks
canonical fast-forward publication and the public bytes of every README image.

Historical release evidence: **Final Cycle 34 verification.** The gate on commit
`7eef1f0a0c400b34f170cbd1463cd3c6a454de3b` passes **2882 tests with 15 intentional platform skips**.
This is the earlier release record, not the September 23 full-suite result.
[Historical validation details](analysis/loop/LOOP_LOG.md).

<!-- ANGERONA_DOC_STATUS tests=2882 skips=15 modules=84 -->
