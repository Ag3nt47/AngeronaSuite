# 🛡️ Angerona — Cyber Security Suite

**Local-first EDR / NDR / SOAR for Windows — MITRE ATT&CK detection, YARA, ETW/AMSI/WFP telemetry, and local-AI triage. No cloud. No kernel driver.**

![Platform](https://img.shields.io/badge/platform-Windows-0078D6)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)
![GUI](https://img.shields.io/badge/GUI-PySide6%2FQt-41CD52)
![EDR·NDR·SOAR](https://img.shields.io/badge/EDR·NDR·SOAR-endpoint%20defense-1f6feb)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Local AI](https://img.shields.io/badge/AI-local%20Ollama-000000)
![License](https://img.shields.io/badge/license-MIT-green)

A modular, local-first endpoint security suite for Windows with a clean native
desktop GUI. Angerona runs elevated in user mode and pulls kernel-sourced
telemetry through Windows' supported APIs (ETW / WMI / AMSI / WFP) — no custom
kernel driver required — so it is powerful **and** safe to install.

<!-- Add a real screenshot/GIF here — a dashboard image is the single biggest driver of stars.
     Drop a PNG at docs/screenshots/dashboard.png (recommended ~1280px wide) and it will render below. -->
![Angerona dashboard](docs/screenshots/dashboard.png)
<sub>*Live dashboard: module health, alerts, threat level, and ATT&CK heatmap. (Replace `docs/screenshots/dashboard.png` with your capture.)*</sub>

> **Privacy & safety first.** Everything runs locally on your machine. The AI
> triage engine uses a local Ollama model by default; cloud escalation is opt-in
> and only fires if you supply your own API keys. No secrets are ever committed
> to this repository.

---

## ✨ Features

- **Native desktop GUI** (PySide6/Qt) — dashboard, live alerts, module control, settings.
- **Drop-in module system** — add a single `.py` file to `modules/` and it appears in the app. No core changes.
- **Local AI triage** — security events are explained and scored by a local LLM (Ollama `llama3`), with optional cloud escalation.
- **Core protections, ported from the original Angerona engines:**
  - File Integrity Monitoring (FIM)
  - Process / parent-lineage monitoring
  - Network connection monitoring + packet inspection
  - YARA signature scanning
  - Memory / forensic scanning
  - LSASS credential-dumping detection (Mimikatz/procdump/comsvcs MiniDump)
  - C2 beacon detection (regular-cadence outbound callbacks)
  - Shadow-copy / recovery-tamper guard (ransomware precursor)
  - Removable-media / USB monitor (with autorun.inf flagging)
  - Active deception (canary files & honeytokens)
  - Flight-recorder persistence (tamper-evident SQLite ledger)
- **Shark Attack red-team drill** — an unannounced, non-destructive adversary simulation that exercises detect-and-respond end to end, with a live Offense Monitor, an animated swimming-shark indicator, and an optional AI Flight-Instructor narration.
- **After-Action Report + Attempt Fix** — every drill produces a report; the **Attempt Fix** button asks the local AI for a remediation and (with your confirmation) applies it.
- **Posture Hardening (self-healing)** — records exploited weaknesses, drops its health as a visible warning, and stages review-gated PowerShell/registry remediations.
- **Active defense (SOAR)** — under a corroborated attack, Angerona auto-contains the offending process (suspend → kill on repeat) and **isolates its network** with a hidden firewall rule, so it can't reach a C2 even if resumed. A protected-process allowlist and 2-signal corroboration keep Windows itself safe.
- **Incident kill-chain timeline** — related alerts are grouped per process and laid out along the ATT&CK chain (Recon → … → Impact) so you can see how far an attack got, with severity and progress. Double-click a technique for its MITRE page.
- **One-click IR triage bundle** — snapshot processes, connections, users, recent alerts and incidents into a timestamped ZIP for incident response / after-action review.
- **Scheduled AI security briefing** — a daily plain-English summary (alert volume, top techniques, incidents, containment) via the local model, with a deterministic fallback so a briefing is always produced.
- **Threat Intel — CVE ignore & AI fix advisor** — ignore un-actionable CVEs (too vague / no fix) so they stop inflating the threat level, kept with a revertable per-ID history. The local AI compares each CVE to your system and, where a scriptable fix exists, offers **❗ Apply** (confirm-then-execute, with a one-click **↩ Revert**). A **Mass Flag & Ignore** button clears the no-fix CVEs in one go.
- **Multi-process resilience ecosystem** — core, Watchdog, sensor scanner and Black Box run as separate programs that keep each other alive (auto-restart, no duplicate instances), so one crashing can't take the others down.
- **Watchdog Monitor** — supervises every module and auto-restarts any that crash (throttled), keeping the suite resilient.
- **World View** — a deep-transparency telemetry dashboard: host↔suite resource matrix, a telemetry-blinding detector, and live Ollama diagnostics (VRAM, tokens/sec).
- **Auto-update from GitHub Releases** — one click to pull the latest signed build.
- **Elevated user-mode access** — UAC elevation on launch for full-system visibility, without the risk of an unsigned kernel driver.

## 🆕 What's new in v1.7

- **Four new detection modules** — LSASS credential-dumping (T1003.001), C2 beaconing (T1071/T1571), shadow-copy/recovery tampering (T1490, a ransomware precursor), and removable-media/USB (T1091/T1200). The suite now auto-discovers **60 modules**.
- **Active-defense network isolation** — when SOAR contains a corroborated threat it also blocks that process's outbound traffic with a hidden firewall rule, turning a "suspend" into real containment.
- **Incident kill-chain timeline** — per-process ATT&CK-ordered incident view (🎯 Forensics), with severity, progress, and MITRE links; exportable to JSON.
- **One-click IR triage bundle** — 🎯 Forensics ▸ collect a timestamped forensic ZIP (processes, connections, users, events, incidents).
- **Scheduled AI security briefing (BRIEF)** — daily local-AI briefing with a deterministic fallback, written to `shared_logs/daily_briefing.*`.
- **CVE ignore / revert + local-AI fix advisor** — ignore un-actionable CVEs (kept with per-ID history) so they no longer raise the threat level; the local model proposes scriptable fixes with confirm-then-execute **Apply** and auto-captured **Revert**, plus **Mass Flag & Ignore** for the no-fix ones.

## 🆕 What's new in v1.3.0

- **Threat Posture score** — a composite 0–100 security indicator under the brand (active threats + module health + KEV exposure + ATT&CK heat); click for a breakdown.
- **Eco Mode on by default** — fast, responsive launch; turning it off wakes heavy scanners **one at a time** (no more startup freeze).
- **Adaptive Resource Governor** — automatically slows heavy, non-security-critical module loops when the machine is under load (and speeds them back up when idle), in both Eco and normal mode. The real-time protection path is never throttled.
- **Black Box recorder (auto-launched)** — a separate, strictly read-only diagnostic process (`blackbox_recorder.py`) that starts with Angerona and survives even if the main suite deadlocks. Tray-resident, with live crash/error tailing, host telemetry graphs, suite-health & event-bus liveness, thread-state, memory profiler, config-drift, and a one-click diagnostic `.zip` bundle. It watches both the app folder and your per-user data dir, so it captures **why** Angerona crashed (unhandled exceptions, native faults, UI stalls, module quarantines) and every CRITICAL alert. Toggle in Settings ▸ Performance; put an icon on your Desktop with `create-blackbox-launcher.ps1`.
- **Crash resilience** — global crash logging (exceptions, native faults, Qt-fatal, UI stalls), a fully guarded UI refresh so a data flood can't take the window down, and a memory-aware Adaptive Resource Governor that hard-throttles heavy modules before the machine thrashes.
- **Mobile Response Bridge (Signal, opt-in)** — E2EE remote control from your phone via `signal-cli`: `HELP`, `STATUS`, `DIAG`, `ECO ON/OFF`, `LOCKDOWN <PIN>`, and token+PIN-gated `KILL`/`SUSPEND`/`ROLLBACK`/`MUTE`. DPAPI-wrapped PIN, single-use expiring tokens, spoof logging. Configure in Settings ▸ Mobile Integration.
- **Linux eBPF sensor node (opt-in)** — a headless-Linux `BaseModule` using BCC to hook `execve`/`tcp_sendmsg` in-kernel and forward events to the Windows GUI over the Remote Bridge; degrades gracefully without BCC/root.
- **Confidential Compute (Intel SGX / Gramine)** — optional: run the suite inside an SGX enclave (`angerona.manifest.template`) so the in-memory flight cache and IPC key are hardware-protected; `core/sgx_guard.py` detects the enclave and encrypts the MEMC cache.
- **Live-Fire Sandbox & Editor** — isolate all sensors and view/edit/hot-reload any module's `.py` behind an AST syntax gate, with revert + history.
- **Online AI consult (Claude-first)** — Threat-Intel "Consult AI" / CVE "AI Proposed Solution" build a full fix/patch you can save; alert "Research" with a follow-up chat. Falls back through OpenAI/OpenRouter/Gemini/local Ollama.
- **Alert actions everywhere** — Allow/Block/Analyze/Research on alert detail windows and module alert feeds.
- **Awareness panels** — clickable status chips → full module window; a per-module resource-intensity row; **Top Talkers** outbound-network view; CRITICAL tray notifications; module sort by On/Off, Status, Category.
- **New console commands** — `intel`, `consult`, `resources`.
- **Deception hygiene** — honeytokens/canaries are hidden (`HIDDEN|SYSTEM`); the red-team drill auto-cleans all markers so it never litters your machine.
- **UX fixes** — reliable panel-resize dragging; Settings-button errors now surface instead of failing silently.

## 🚀 Quick start (from source)

```bat
install.bat   :: creates venv + installs dependencies (PySide6, etc.)
run.bat       :: self-elevates and launches the GUI
```

Optional: `create-launcher.ps1` puts an **Angerona** shortcut on your desktop.
If instances ever pile up, `kill-all-angerona.bat` force-stops them all.

## 📦 Install (release build)

Download the latest `Angerona-Setup.exe` (or portable `Angerona.exe`) from the
[Releases](../../releases) page and run it. The app self-elevates on launch.

## 🧩 Writing a module

Drop a file in `modules/` that subclasses `BaseModule`. See
[`docs/writing-modules.md`](docs/writing-modules.md). Minimal example:

```python
from angerona.core.module_base import BaseModule, Severity

class PingModule(BaseModule):
    name = "Heartbeat"
    description = "Emits a heartbeat event every 30s."
    category = "Diagnostics"

    def run(self):
        while not self.stopping:
            self.emit("Heartbeat OK", severity=Severity.INFO)
            self.sleep(30)
```

## 🏗️ Architecture

See [`docs/architecture.md`](docs/architecture.md). In short: independent
**modules** run on background threads and publish events to a thread-safe
**EventBus**; the bus persists alerts to the **flight-recorder** store and feeds
the **GUI**, which polls for updates. A **ModuleManager** discovers and
supervises modules; an **updater** checks GitHub for new releases.

## 🔐 Security model

- Runs as Administrator (UAC prompt on launch) for full visibility.
- Telemetry via **ETW, WMI/CIM, AMSI, WFP** — kernel-sourced data through
  Microsoft-supported interfaces. A documented `KernelSensor` seam exists if a
  *signed* driver is ever added; no unsigned driver ships here.
- Secrets live only in a local, git-ignored `.env`. Never commit keys.

## 🔁 Reproducible checkout & first GitHub push

Only source is committed — all local, build, and runtime state (`venv/`,
`__pycache__/`, `*.db`, `logs/`, `diagnostics/`, `remediations/`, `.env`) is
git-ignored. To publish a clean, reproducible repository:

```bat
powershell -ExecutionPolicy Bypass -File cleanup.ps1   :: purge rebuildable junk
git init
git add .
git commit -m "Angerona v1.0.0"
git branch -M main
git remote add origin https://github.com/<you>/angerona.git
git push -u origin main
```

A fresh clone reproduces the app with just `install.bat` (creates the venv and
installs the pinned dependencies from `pyproject.toml` / `requirements.txt`),
then `run.bat`. No machine-specific paths or secrets are committed — supply your
own keys in a local `.env` (see `.env.example` if present).

> This repository is **`AngeronaSuite/`** only. The older Rich-terminal prototype
> that lives beside it (`agent.py` / `ui.py` at the parent folder) is a separate,
> superseded project and is **not** part of this repo — keep it out of the commit.

## 🔎 Keywords & GitHub Topics

Angerona is a Windows **EDR / NDR / SOAR** platform for **endpoint detection and response**,
**network detection**, **threat hunting**, and **incident response** — with **MITRE ATT&CK**
mapping, **YARA** scanning, **ETW / AMSI / WFP / Sysmon** telemetry, **ransomware** and
**LSASS credential-dumping** detection, **C2 beacon** detection, and **local-LLM (Ollama)**
alert triage. Built in **Python** with a **PySide6** desktop GUI.

**Copy these into the repo's _About ▸ Topics_ field** (Settings not required — it's the gear next to *About*):

```
edr ndr soar endpoint-security blue-team threat-hunting incident-response
mitre-attack yara etw amsi sysmon ransomware-detection c2-detection
malware-detection windows-security siem ollama local-llm python pyside6 security-tools
```

> Topics are the #1 on-platform discovery lever — a search for `edr` or `mitre-attack` can
> only surface Angerona if these are set. Also fill in the one-line **About** description with
> the tagline at the top of this README.

## 📄 License

MIT — see [LICENSE](LICENSE).
