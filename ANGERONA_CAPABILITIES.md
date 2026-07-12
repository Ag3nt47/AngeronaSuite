# ANGERONA — Capabilities & Design Reference

> **Living document.** This is the canonical list of Angerona's design and every
> capability it has. It is updated with each round of changes — see the
> [Changelog](#changelog) at the bottom.

Angerona is a modular, local-first endpoint security suite for Windows with a
native desktop GUI. It runs elevated in user mode and pulls kernel-sourced
telemetry through Windows' supported APIs (ETW / WMI / AMSI / WFP) — no custom
kernel driver — so it is powerful **and** safe to install. AI runs locally via
Ollama; cloud escalation is opt-in.

---

## 1. Architecture

A strict, small core; everything else is a **module**. Modules never import each
other — they communicate only through the **EventBus**.

```
   Modules (threads) ──publish──► EventBus (ring) ──► FlightRecorder (SQLite)
                                      │                       │
                                      ▼                       ▼
                            GUI (polls 1.5s)        StatusReporter (status.txt/json)
```

| Layer | Location | Responsibility |
|-------|----------|----------------|
| Entry / elevation | `__main__.py`, `core/privilege.py` | UAC elevation, app boot |
| Wiring | `app.py` | Build services + window, lifecycle |
| Event bus | `core/eventbus.py` | Thread-safe pub/sub + recent ring |
| Module API | `core/module_base.py` | `BaseModule`: threading, health, `self_test()` |
| Supervisor | `core/module_manager.py` | Auto-discover + start/stop modules |
| Config | `core/config.py` | Settings, paths, theme, `.env` |
| Storage | `core/storage.py` | Flight-recorder ledger (with details) |
| Threat calc | `core/threat.py` | Calibrated threat level (no false highs) |
| Status export | `core/status_report.py` | Live `diagnostics/status.txt` + `.json` |
| Console backend | `core/commands.py` | Commands + AI + SQL hunting |
| Self-test | `core/selftest.py` | Per-module drills + pipeline check |
| Hidden exec | `core/win.py` | Run child processes with no popup windows |
| Telemetry | `telemetry/sensors.py` | Process/connection sampling; `KernelSensor` seam |
| GUI | `gui/` | Window, panels, dialogs, theme engine |
| Modules | `modules/` | Security capabilities (auto-discovered) |
| Engines | `engines/` | Original Angerona code, held for reference |
| Updater | `updater/` | GitHub Releases version check |

---

## 2. Security Modules (55)

Each module reports a **health %** and state (OK / degraded / critical / failed /
off) and exposes a **self-test**.

| Module | Category | What it does |
|--------|----------|--------------|
| **File Integrity Monitor** | Integrity | SHA-256 baselines watched dirs; alerts on create/modify/delete |
| **Process Monitor** | Processes | Flags suspicious spawns (Office→shell), exec from temp/downloads |
| **Network Monitor** | Network | New external connections; alerts only on suspicious ports; 1/min rollup (loopback ignored) |
| **Packet Sniffer** | Network | scapy DPI for cleartext secrets on the wire (needs Npcap) |
| **YARA Scanner** | Signatures | Bundled `yara64.exe` + rules scan Downloads/Temp; silent execution |
| **AI Triage (Ollama)** | AI | Local LLM explains/scores serious events; self-heals health on model availability |
| **Cloud CTI Escalation** | AI | Opt-in Gemini second opinion on CRITICAL events (your key only) |
| **Active Deception** | Deception | Canary files / honeytokens; alerts on tamper |
| **Forensics Capture** | Forensics | On serious events: memory strings, sockets, shell history → case folder |
| **SOAR Automation** | Response | Playbooks: recommend, or opt-in auto-suspend on CRITICAL |
| **Posture Hardening** | SOAR | Self-healing loop: tails the after-action report, records SUCCESS/low-detection techniques into `agent_memory.db:system_weaknesses` (drops health <50), stages a deterministic (temp 0) Ollama PowerShell/registry remediation per `<mitre>.ps1` — review-gated, never auto-run; powers the AAR **Attempt Fix** button + a custom-patch sandbox (AI-Assisted / Direct-Native) |
| **Watchdog Monitor** | Resilience | Supervises every module; auto-restarts any that crash (status `error` / dead thread), throttled to 3 tries then a CRITICAL alert. Gets the ModuleManager via `bind_manager()` |
| **Memory Time-Machine (MTM)** | Performance | Lock-light SPSC `mmap` ring + per-PID sliding hash cache; forwards only the *delta* of newly-observed process strings to the LLM queue, cutting triage token/VRAM overhead >80% |
| **API Patch / Anti-Blinding (APID)** | Integrity | Reads pristine `ntdll`/`kernel32` from `System32`, compares export prologues against live memory; flags `E9`/`FF 25`/`68…C3` inline hooks (sensor blinding) as CRITICAL to `soar_events.json`. Read-only — never hooks or unhooks |
| **Provenance Graph (PROV)** | Forensics | Builds a typed PROC/FIM/NET provenance DAG from the flight recorder + live events; `ancestry(pid)` finds root cause, `subtree(pid)` maps the downstream blast radius |
| **Speculative Triage (SPEC)** | Performance | Detects high-risk early markers (unknown process from temp/AppData/Downloads) and pre-warms Ollama with a snapshot so the final verdict returns with no cold-start delay |
| **Upstream Threat Intel (INTL)** | Threat Intel | Correlates the CISA KEV catalog (inbound-only fetch, no host data egress) against this host's OS + running services; stages review-gated remediation + MITRE mapping to `upstream_threats.json` — never auto-applies. On explicit operator approval, runs a Judgment mock-footprint test and promotes the detection rule only if the suite proves interception (BLOCKED) |
| **Network Protocol Deep Decoder (NDRD)** | Network | Decodes DNS query names and scores per-label Shannon entropy / length / digit-ratio to flag DGA beacons and DNS-tunneling exfiltration |
| **ETW Core Listener (ETWG)** | Telemetry | Captures process-creation (4688) + logon (4624/4672) from the Windows Security channel (ETW-backed) via `win32evtlog`, republishing to the bus; psutil process-diff fallback |
| **In-Memory Flight Cache (MEMC)** | Performance | Bounded `sqlite3 :memory:` mirror of the flight recorder (warmed from disk + live bus), serving fast SELECT-only reads of hot events to cut disk I/O |
| **Zero-Trust Local IPC Guard (AUTH)** | Integrity | HMAC-SHA256 challenge/response auth on loopback `127.0.0.1:65432`; default-deny, per-install `os.urandom` key, logs unsigned/invalid peers as possible local spoofing |
| **Anti-Suspension Heartbeat (FRZ)** | Resilience | Writes a nanosecond mmap heartbeat every 500 ms; companion Go watchdog (`frz_watchdog.exe`) independently monitors the PID — if the clock freezes >2 s while alive (thread-suspension attack), triggers emergency network isolation + hard-kills the interpreter |
| **Telemetry Canary Drills (DRILL)** | Resilience | Fires `cmd /c REM <UUID>` canaries every 60 s and expects ETWG to echo the 4688 event within 6 s; consecutive misses escalate to CRITICAL "telemetry blinding" — detects `ntdll!EtwEventWrite` hook or Security-channel suppression. Also runs a 10-minute G2 sensor coverage check: emits MEDIUM if any named sensor module has been silent on the bus for ≥10 min (2-min startup warmup) |
| **Monolithic Packaging (HERMETIC)** | Resilience | Tracks whether Angerona is running as the signed PyOxidizer monolithic binary; reports hardening gap if running as loose .py; `trigger_build()` opens a review-gated build terminal (PyOxidizer + signtool) |
| **Indirect Syscall Bridge (SYS)** | Response | Wraps `syscall_bridge.pyd` to route SOAR containment (terminate/suspend/resume) via indirect NT syscalls — SSN read from on-disk ntdll, jumps past any hooked function stubs to the `syscall;ret` gadget; ctypes/psutil fallback if .pyd not compiled |
| **Sysmon Event Bridge (SYSL)** | Telemetry | Forwards Sysmon XML events (EIDs 1/3/6/8/10/25 — process create/network/driver/CreateRemoteThread/ProcessAccess/ProcessTamper) from the Microsoft-Windows-Sysmon/Operational channel via `win32evtlog`; maps to MITRE techniques and republishes rich events on the bus |
| **Memory Injection Scanner (MINJ)** | Integrity | VirtualQueryEx RWX memory scanner across all accessible processes (T1055); JIT allowlist for known-good modules; 60-second dedup window; flags private RWX pages as HIGH injection candidates |
| **Ransomware Heuristics (RANS)** | Integrity | Dual-sensor: (1) Shannon entropy ≥7.9 on new/modified files (encrypted content signature); (2) mass-rename watchdog on user folders (extension-change spike). Emits HIGH on hit, CRITICAL on compound signal. Read-only — never suspends without explicit SOAR opt-in |
| **WFP Controller (WFPC)** | Network | iphlpapi `GetExtendedTcpTable`/`UdpTable` singleton; queries both `AF_INET` (IPv4) and `AF_INET6` (IPv6) to build a PID→port map — BL-17 loopback fix ensures `::1` Ollama traffic is never misidentified as external. 5-second TTL cache |
| **AMSI Bridge (AMSI)** | Integrity | Consumes `AmsiScanBuffer` result events (NOT patching AMSI — read-only); flags AMSI_RESULT_DETECTED as CRITICAL; uses an EICAR string probe as the self-test health check |
| **WLAN Monitor (WLAN)** | Network | Evil-twin detection: diffs `netsh wlan show networks` BSSID/SSID every 60 s; flags a new BSSID for a known SSID as HIGH (potential rogue AP) |
| **ARP Watchdog (ARPW)** | Network | Diffs the ARP cache every 30 s; flags MAC changes on a known-IP as HIGH (potential ARP poisoning / MITM). Optional scapy promiscuous sniffer for passive ARP monitoring |
| **AV Telemetry Bridge (AVTB)** | Telemetry | Consumes Windows Defender Operational log events (EIDs 1116 detection / 1117 action taken / 5001 real-time disabled) via `win32evtlog`; `Get-MpThreatDetection` PowerShell fallback; republishes Defender detections on the bus with MITRE mapping |
| **Dynamic Resource Governor (DRES)** | Performance | Raises the Angerona process to `HIGH_PRIORITY_CLASS` when CPU/memory load spikes, reverts to `NORMAL_PRIORITY_CLASS` after a 60-second cool-down; ensures EDR telemetry is not starved under adversarial load |
| **Kernel Bridge (KRNL)** | Telemetry | DeviceIoControl client for `AngeronaSensor.sys` (kernel/AngeronaSensor/ — optional signed driver); reads a PsSetCreateProcessNotifyRoutineEx ring buffer from kernel space for high-fidelity process events that bypass usermode hooking. Degrades gracefully if driver not loaded |
| **Fast-Path Interceptor (FPTH)** | Detection | 17-rule deterministic IOC library: Mimikatz CLI, PsExec, shadow-copy deletion, AMSI-bypass strings, LSASS dump, net user /add, reg.exe SAM export, encoded PowerShell, certutil decode, BITSAdmin transfer, scheduled-task abuse, WMI persistence, regsvr32 squiblydoo, mshta remote script, DLL side-loading path, RunDLL32 LOLBin, AppData/Temp executable launch. Any match emits CRITICAL immediately — bypasses Ollama triage for zero-latency response |
| **AI Model Integrity Guard (AMIG)** | AI Defense | Trust-on-first-use SHA-256 baseline of local Ollama model blobs; re-hashes each pass and raises CRITICAL on any post-baseline tampering/poisoning before the suite trusts a model for inference |
| **TUNE (Behavioral Tuner)** | Performance | Learning Engine + Safe-Path Interceptor: builds a 3-way `behavioral_baseline` (hash + parent→child lineage + /24-subnet+port) over a silent 7-day audit window; downgrades perfect known-good matches to INFO before Ollama triage; exports Ring-0 offload rules for WFPC/kernel sensor |
| **CHAOS (Security Chaos Harness)** | Resilience | Security chaos engineering "bug killer": periodically fires SAFE synthetic probes (cooperative APID drill signal, high-entropy DNS, EICAR write) and verifies the expected detector echoes on the bus within a timeout; missing echo → blind-sensor alert |
| **Compliance Mapper (CMAP)** | Compliance | Cross-references every MITRE-tagged bus event against NIST SP 800-53 controls and DoD STIG baselines, compiling `diagnostics/compliance_report.json` as auditor/eMASS-consumable evidence of which controls the running defenses actually enforce. Read-only, no network I/O |
| **Counter-Agentic Detection (CAGT)** | Detection | Cognitive-layer detector for autonomous/agentic malware — looks for the behavioural signature of an LLM reasoning loop (inference-latency rhythm between spawned commands + discovery→action chain + anomalous local model-port access) rather than static hashes/IPs. Detection-only by design; no offensive/active-response capability |
| **Linux eBPF Sensor (EBPF)** | Sensor | Headless-Linux node sensor using BCC: inline eBPF hooks on `execve` and `tcp_sendmsg` with kernel-side noise drop, republished as Angerona events. Opt-in; frees BPF maps on stop; healthy-inert on Windows |
| **ETW Real-Time Process Sensor (ETWR)** | Telemetry | Event-driven process capture via the Microsoft-Windows-Kernel-Process ETW provider (pywintrace) — closes the multi-second blind spot polling sensors leave for processes that spawn and exit inside a poll gap; complements ETWG's Security-channel (4688) capture |
| **Self-Hardening Evolution Engine** | Resilience | Turns a red-team verification bypass into an auto-generated YARA signature, closing the specific detection gap a drill just proved |
| **Hardware-Rooted Integrity (HWID)** | Integrity | DPAPI-wraps the AUTH IPC key to a user/host-bound sidecar (win32crypt → ctypes fallback, verifies round-trip); outlines TPM 2.0 sealing of the DB key. Inert (no crash) off-Windows |
| **Mobile Response Bridge (MOB_BRDG)** | Response | Opt-in E2EE remote orchestration over Signal (`signal-cli`); DPAPI-wrapped PIN; token-gated remote HELP/STATUS/DIAG/ECO/LOCKDOWN/KILL/SUSPEND/ROLLBACK/MUTE commands from the operator's own number only, with alert digesting and TTL-swept single-use tokens |
| **Persistence Sweep** | Persistence | Baselines and monitors autorun surfaces — Run/RunOnce + Winlogon Shell/Userinit, startup folders, services, scheduled tasks, WMI event consumers; escalates encoded-PS/LOLBin + Winlogon hijack to CRITICAL, user-writable paths to HIGH. Read-only enumeration, maps T1547/T1053/T1543/T1546 |
| **Remote Bridge (RBRG)** | Integrity | Secure multi-node telemetry forwarding — SENDER polls the bus and forwards HIGH/CRITICAL to a main PC, RECEIVER authenticates peers via shared-key HMAC challenge/response. OFF by default; refuses to open a socket without an explicit shared key + peer/port |
| **Adaptive Resource Governor (GOV)** | Performance | Samples this process's CPU every 5s and, under sustained load, raises `BaseModule._throttle` on heavy non-critical modules (up to 8× slower cadence); relaxes back to 1× as load drops. Never throttles the real-time protection path; cooperative only, fail-open |
| **HEAL (Self-Debugging Co-Pilot)** | Resilience | Tails crash snapshots, packs traceback + source into a constrained Ollama prompt, `ast`-validates the returned code, and stages the fix to `staged_patches/` (never overwrites live code) plus a HIGH alert — human-gated "Apply Patch" in the GUI |
| **Shadow Shield (SHDW)** | Response | Ransomware file shielding: delta version cache (`trigger_rollback()` restores pre-encryption copies) plus quiet VSS snapshots (WMI/`vssadmin`). Never deletes shadow copies |
| **SIEM Forwarder (SIEM)** | Integration | Translates EventBus detections to ArcSight CEF and ships them over Syslog (UDP/TCP) to a SOC/XDR estate (Splunk, Sentinel, QRadar, Elastic). Opt-in and disabled by default — inert until `ANGERONA_SIEM_HOST` is configured |
| **Smart Deception (SDEC)** | Deception | Hyper-contextual honeytokens: samples real Documents *names* only, has local Ollama invent blended decoy filenames, drops them into Desktop/Documents/%APPDATA%; any touch → CRITICAL. Static fallback list if Ollama is down |
| **Active Response SOAR Engine** | Response | Opt-in automated containment: terminates the offending process and rolls back its file artifact on real CRITICAL alerts, with a self-kill guard that never targets Angerona's own PID |
| **Storage Hygiene Enforcer (SHYG)** | Maintenance | Detects Angerona runtime data stranded at the default `%LOCALAPPDATA%` location when `ANGERONA_DATA` points elsewhere (e.g. an F: drive); alerts by default, collision-safe auto-migrate opt-in via `ANGERONA_STORAGE_AUTOMIGRATE=1` |

**Adding a module:** drop one `.py` defining a `BaseModule` subclass into
`modules/` or `%LOCALAPPDATA%\Angerona\modules\`. See `docs/writing-modules.md`.

---

## 3. Interactive Console

Bottom-of-dashboard console (and a programmatic entry point). Commands:

```
help                         list commands
ps [n]                       top processes by memory
find <name>                  find PIDs by name
kill / suspend / resume <pid>   containment (audited)
prio <pid> <low|normal|high>    process priority
conns [pid]                  active connections
tree <pid>                   process + children
modules                      list modules + status
module <name> <on|off|restart>   control a module
threat                       current posture
incidents [n]                correlated incidents, risk-scored (newest first)
incident <id>                full timeline of one incident
coverage                     MITRE ATT&CK detect/simulate/remediate heatmap
remlog [n]                   remediation action audit log — newest n entries
remlog <T####>               filter remediation log by MITRE technique ID
test [module]                self-test / stress drill (all or one)
query <SELECT ...>           SQL threat hunting (read-only)
ask <question>               local AI; any non-command text → AI
clear                        clear the console
```

**SQL threat-hunting tables:** `processes(pid,name,exe,ppid,username,mem_mb)`,
`connections(pid,status,laddr,raddr,lport,rport)`, `ports(pid,proto,laddr,lport)`.

---

## 4. Self-Test / Stress Harness

- Header **"Run Self-Test"** button or `test` command.
- Runs each module's `self_test()` (timeout-guarded) + an event-pipeline check.
- Produces a PASS/FAIL grid and raises failure notifications.
- Showcase drill: **YARA generates an EICAR test file and confirms detection**
  (inject an issue → verify the response). Per-module test button in the inspector.

## 5. Health Indicators

Every module shows a live **health %** beyond just running/stopped:
green (OK ≥90), yellow (degraded 50–89), orange (critical <50), red (failed),
grey (off) — in the modules table, the bottom status strip (with tooltips), and
the inspector. AI Triage self-heals to 100% automatically once `llama3` is pulled.

## 6. Threat Calibration

Threat level reflects **real detections only** (HIGH/CRITICAL from security
modules, last 10 min). Operational notices (Ollama offline, YARA unconfigured,
routine connections) and self-test/console output never raise it. Idle = **SECURE**.

---

## 7. UI & Themes

- **Title:** centered, uppercase **ANGERONA**, geometric/mono font.
- **Single-screen layout:** stat cards · Modules | Live Alerts · Console · bottom status strip.
- **Drill-down alerts:** click any alert → modal with full record + **SHA-256 fingerprint**.
- **Module inspector:** description, health, per-module event feed, enable/disable/restart, self-test.
- **World View (🌐 button):** live 6-step operational flowchart — ① CAPTURE → ② DETECT → ③ AI TRIAGE → ④ RESPOND → ⑤ ATTACK → ⑥ SELF-HARDEN → loop. Compact 2×3 grid; colour-coded header bands; bezier arrowheads with edge labels; live metric badges per node. Host telemetry panel (Resource Matrix, Telemetry Saliency, Ollama diagnostics) toggleable below.
- **ATT&CK Heatmap (🔥 button):** 14-tactic × N-technique live matrix; cells coloured dark→blue→amber→red by time-decaying hit score. Click any cell for full technique detail + recent event IDs. 5-second auto-refresh.
- **Theme engine (Settings):**
  - **Modern Cyber** — dark, sharp edges, neon blue/orange accents.
  - **Retro CRT Terminal** — green phosphor on black, monospace.
  - **Slate** — neutral blue-grey, professional enterprise feel.
  - **Custom accent** — hex tint override on any theme.
- **Threat Intel Dashboard (🛡 THREAT INTEL button):** non-modal dialog showing CISA KEV matches correlated to this host — 8-column table (CVE ID, Vendor, Product, MITRE, Ransomware campaign, Due Date, Required Remediation, Action), alternating rows, ransomware-campaign entries highlighted red, overdue dates red / imminent amber. "Stage for Review" per-row opens a confirmation dialog — review-gated, never auto-applies. Button pulses red/amber in the header when INTL has active alerts.
- **CVE Deep Analysis Window (🔍 Deep Analysis):** two-panel dialog launched from the Threat Intel Dashboard. Left panel: scrollable `CveCard` widgets sorted ransomware-first → driver/kernel → rest; each card shows the NVD hyperlink, DRIVER/KERNEL badge (keyword-matched), RANSOMWARE badge, date/due/remediation/matched-token grid. Right panel: AI fix pane powered by local Ollama (`llama3`, 60s timeout) — "⚡ Generate AI Analysis" spawns a daemon thread, delivers the result via Qt Signal (never touches widgets from off-thread); structured CISA fallback when Ollama unavailable. No host data egress — reads only the local `upstream_threats.json`.
- All console/code panels use **Fira Code** (was Consolas); all `QTableWidget` instances have alternating row colours.
- No popup console windows (yara64/netstat run hidden).

---

## 8. Security Model

- Elevated user mode (UAC on launch); kernel-sourced telemetry via ETW/WMI/AMSI/WFP.
- Optional `AngeronaSensor.sys` signed kernel driver (DeviceIoControl ring buffer); no unsigned driver ships.
- **HMAC-signed EventBus:** every published event carries a per-session HMAC-SHA256 signature (`BusAuthority`); consumers can verify authenticity. Bus backpressure drops INFO events at ≥85% ring occupancy to prevent flooding.
- **Judgment Gate:** staged remediation scripts are SHA-256-stamped; `execute_remediation` re-verifies the hash before running — on-disk swap after review is blocked.
- **SOAR Corroboration:** CRITICAL escalations require corroboration from a second sensor module + System32 allowlist gate before containment actions are taken.
- Secrets only in git-ignored `.env`.
- Tamper-evident flight-recorder ledger; every event persisted with a hashable record.
- Dead-Letter Queue writes are file-locked (`msvcrt.locking` / `fcntl.flock`) to prevent concurrent corruption.

## 9. Distribution

- Clean repo, MIT license, `.gitignore` excludes secrets.
- `install.bat` / `run.bat` / `start-angerona.bat` (one-click) / `build.bat` (PyInstaller).
- GitHub Actions builds the `.exe` and publishes a Release on each `v*` tag.
- In-app auto-updater checks GitHub Releases.

## 10. Data Locations

`%LOCALAPPDATA%\Angerona\` — flight-recorder DB, settings, logs, drop-in modules,
`diagnostics/status.txt` + `status.json` (live full-state snapshot), forensic case folders.

---

## Roadmap (planned, not yet implemented)

These are designed-for but queued for the next phases:

- **Enterprise World View — Process Lineage & Causal Trees** — QGraphicsScene parent→child provenance tree with PROV ancestry/subtree, IOC colouring, time-scrub slider.
- **Enterprise World View — Network Topology & Lateral Movement** — live host/peer node graph from NDRD + Network Monitor events; lateral-move vector arrows.
- **Enterprise World View — Identity & Entity Convergence (ITDR)** — account timeline aggregating ETWG logon events, privilege-change spikes, and lateral-move correlation.
- **Enterprise World View — Automated Playbook Progress** — swimlane progress chart over active incident playbook steps; MTTR rolling average.
- **AI Command Hub** — dedicated panel aggregating Angerona + auxiliary-agent insight, live "understanding" stream, predictive health.
- **Ollama self-healing loop** — auto-analyze logs and restart failed modules.
- **In-app dependency installer** — module detail page checklist + confirm-before-install (path/params prompt).
- **System rollback** — track a flagged process's file/registry changes and undo them.
- **Dynamic threat animation** (shark), high-tech shield logo + per-module icons.
- **Remote mobile integration** — see `docs/mobile-blueprint.md`.

---

## Changelog

- **v1.6.1 (remediation-routing fix, selfcheck grid assertions, cold-start self_test parity, syntax warnings)**
  - **Fixed — remediation misrouting (`modules/remediation_actions.py`):** `RegistryHardeningAction._matches()` used a bare `"t1562"` substring match, which also covers T1562.011 (script-block-logging defense evasion) and so shadowed AMSI-bypass alerts before they could reach `DefenderHardeningAction`. Narrowed to require the specific `t1562.011` sub-technique or explicit script-block/logging keywords; T1562/AMSI-bypass now correctly routes to Defender hardening.
  - **Fixed — stale selfcheck assertions (`tools/selfcheck.py`):** two assertions still checked the old 7-node single-row World View flow; updated to the current 6-node 2×3 grid (`capture/detect/triage/respond/attack/harden`).
  - **Fixed — cold-start `self_test()` parity (6 modules):** AMSI Bridge, Dynamic Resource Governor, Memory Injection Scanner, Sysmon Event Bridge, TUNE, and WFP Controller now fall back to `super().self_test()` when not yet started, reporting the same graceful "stopped" status as the rest of the module set instead of a spurious failure.
  - **Fixed — two `SyntaxWarning`s:** unescaped backslash sequences in string literals at `posture_hardening.py:615` and `ransomware_heuristics.py:25`.
  - **Docs:** module capability table corrected from 36 to the actual 55 auto-discovered `BaseModule` subclasses (19 previously undocumented modules added — AMIG, TUNE, CHAOS, CMAP, CAGT, EBPF, ETWR, Evolution Engine, HWID, MOB_BRDG, Persistence Sweep, RBRG, GOV, HEAL, SHDW, SIEM, SDEC, Active Response SOAR Engine, SHYG).
  - Verified: `tools/selfcheck.py` — 26/26 PASS.

- **v1.6.0 (Group 5 — CVE Analysis Window + GUI polish)**
  - **CVE Deep Analysis Window (`gui/cve_analysis_window.py`):** new two-panel `CveAnalysisWindow(QDialog)`. Left: scrollable `CveCard` widgets — NVD hyperlink, DRIVER/KERNEL badge (product/vendor/name/remediation keyword scan for driver/kernel/.sys), RANSOMWARE badge, detail grid, sorted ransomware-first → driver → rest. Right: `QPlainTextEdit` AI fix pane; "⚡ Generate AI Analysis" button spawns daemon thread `CVE-AI-analysis`; `_ai_done = Signal(str)` delivers the Ollama response to the Qt main thread (no direct widget writes from background thread). Ollama: `127.0.0.1:11434/api/chat`, 60s timeout, `llama3` model. `_fallback_analysis()` generates structured CISA text when Ollama unavailable. AI system prompt: senior Windows security engineer, prioritised remediation, driver-specific kernel mitigations, ransomware CVEs first, plain English. `showEvent()` reloads CVEs on each open.
  - **GUI polish (`gui/pages.py`, `gui/theme.py`):** `MONO_FONT_FAMILY = "Fira Code"` exported from `theme.py`; all `QFont("Consolas", 10)` → `QFont("Fira Code", 10)` across all console/log/code panel widgets. `setAlternatingRowColors(True)` added to all `QTableWidget` instances (ThreatWindow, ModulesPanel, CollisionView, SharkMonitorDialog). `QTableWidget::item:alternate` QSS rule added to all themes via `build_qss()`.
  - **pages.py tail-truncation fix:** G5-B replace_all edit clipped the last 5 lines of `SettingsDialog._apply()`; repaired by appending the missing `_autostart.sync(...)` + `_check()` tail.

- **v1.5.0 (Group 4 — UI/UX overhaul + Threat Intel Dashboard)**
  - **Slate theme (`gui/theme.py`):** third built-in theme — neutral blue-grey with `#94a3b8` text, `#1e3a5f` alternate rows, `#0f172a` panel background. `THEMES` dict restructured with per-theme `alt_row`/`chip_h` keys consumed by `build_qss()` via `setdefault()`. New QSS rules: `QHeaderView::section` with uppercase text + bottom accent border, `QScrollBar:horizontal`, `QToolTip` with dark background + border.
  - **Threat Intel Dashboard (`gui/threat_intel_page.py`):** `ThreatIntelDashboard(QDialog)` — non-modal, 8-column CISA KEV table (CVE, Vendor, Product, MITRE, Ransomware, Due Date, Required Remediation, Action), 60-second auto-refresh. Ransomware-campaign entries coloured #ef4444 red; due dates within 14 days amber, overdue red. "Stage for Review" per-row confirms in QMessageBox then optionally calls `intl_module.confirm()` — review-gated, never auto-applies. `🔍 Deep Analysis` button (purple) creates/raises `CveAnalysisWindow`. `self._cve_analysis_dlg: CveAnalysisWindow | None` singleton pattern prevents duplicate windows.
  - **Pulsing THREAT INTEL button (`gui/main_window.py`):** `🛡 THREAT INTEL` button added to the header; `_update_threat_intel_pulse()` runs every 1s tick, checks `INTL.alert_pending`, and alternates red (#ef4444) / amber (#f59e0b) style — 2-second full visual cycle with zero additional timers.
  - **Non-blocking INTL fetch (`modules/intel_sync.py`):** `run()` now offloads the 30s urllib GET + correlation to a daemon thread `INTL-fetch` via `threading.Event`; main loop waits in 1-second cancellable slices so `self.stopping` is always respected during network I/O. 45-second hard-timeout ceiling.

- **v1.4.0 (Groups 2 & 3 — sensor layer + bus hardening)**
  - **9 new G2 sensor modules:** SYSL (Sysmon XML bridge, EIDs 1/3/6/8/10/25), MINJ (VirtualQueryEx RWX scanner, T1055, JIT allowlist, 60s dedup), RANS (Shannon entropy ≥7.9 + mass-rename watchdog), WFPC (iphlpapi PID→port map, IPv4+IPv6 dual-stack, 5s TTL cache — BL-17 IPv6 loopback fix), AMSI (AmsiScanBuffer consumer, read-only), WLAN (evil-twin BSSID diff), ARPW (ARP cache diff + optional scapy), AVTB (Defender Operational EID 1116/1117/5001 + PS fallback), DRES (HIGH_PRIORITY_CLASS escalation under load).
  - **2 new G3 hardening modules:** KRNL (DeviceIoControl client for AngeronaSensor.sys kernel ring buffer; graceful degradation if driver absent), FPTH (17-rule deterministic IOC library — Mimikatz/PsExec/shadow-copy/AMSI-bypass/LSASS-dump/encoded-PS/etc.; emits CRITICAL immediately, bypasses Ollama for zero-latency response).
  - **HMAC-SHA256 EventBus signing (`core/eventbus.py`):** `BusAuthority` signs every published `Event` with a per-session `os.urandom(32)` key via HMAC-SHA256; `verify_event()` for downstream consumers. Uses `dataclasses.replace()` on frozen Event to attach the signature without mutation.
  - **EventBus backpressure:** ring occupancy ≥85% → INFO events are dropped (not queued) with a one-per-30s warning; prevents unbounded memory growth under flooding.
  - **DLQ TOCTOU fix (`core/storage.py`):** Dead-Letter Queue write uses `msvcrt.locking(LK_NBLCK)` (Windows) / `fcntl.flock(LOCK_EX)` (POSIX) to prevent concurrent DLQ writers from corrupting the JSON file. `_dlq_write_exclusive()` is a module-level function (not nested inside the class).
  - **SOAR Corroboration Engine:** SOAR now cross-checks CRITICAL alerts against at least one corroborating module before escalating — reduces false positives from single-sensor noise. System32 allowlist gates containment actions.
  - **DRILL sensor-coverage check:** `canary_drill.py` added a 10-minute periodic check that scans `bus.recent(500)` for G2 module names; any module silent ≥600s emits MEDIUM "sensor coverage gap" after a 120-second startup warmup.
  - **BL-17 IPv6 loopback fix (`modules/wfp_controller.py`):** added `AF_INET6=23` queries with `MIB_TCP6ROW_OWNER_PID` / `MIB_UDP6ROW_OWNER_PID` ctypes structs; `result.setdefault()` gives IPv4 precedence for dual-stack sockets. Ollama loopback on `::1:11434` is now correctly attributed to its PID.

- **v1.3.0 (World View redesign + Live ATT&CK Heatmap)**
  - **World View flowchart redesign (`gui/flow_window.py`, `core/flow_metrics.py`):** rebuilt from a 7-node single-row layout (1460 px wide — `fitInView` scale 0.68 made 11pt text render at 7.5pt, invisible) to a compact 2×3 grid (~780 px, scale ~0.9, text readable). Maps the 6-step operational cycle: ① CAPTURE · ② DETECT · ③ AI TRIAGE · ④ RESPOND · ⑤ ATTACK · ⑥ SELF-HARDEN → loop. Each node has a colour-coded header band (blue=defensive, purple=AI, red=adversarial, green=self-hardening), 12pt bold white title, 8pt muted subtitle, and a live metric badge. Edges are bezier cubics with filled-triangle arrowheads clipped to the node boundary, plus edge-label text (events / alerts / score / gate / weakness / fixed ↺). `flow_metrics.py` supplies live data keyed to the six step IDs (capture/detect/triage/respond/attack/harden).
  - **Live MITRE ATT&CK Heatmap (`core/attack_tracker.py` + `gui/attack_heatmap.py`):** singleton `AttackTracker` subscribes to every EventBus event via `init_tracker().on_event` (wired in `app.py`, same pattern as `RemediationLog`). Tags are extracted three ways: (1) explicit `mitre_tags`/`mitre`/`attack_ids` attrs; (2) `_ETW_TAG_MAP` — 38 event-kind → technique-ID mappings; (3) `_PROC_MAP` — 22 process-name → technique-ID inferences including LSASS target detection. `TechniqueHeat` dataclass stores hit counts with 24-hour logarithmic time decay (`heat` = 0.0–1.0). 86 techniques catalogued across 14 MITRE ATT&CK Enterprise v14 tactics; catalog pre-populated on startup so the matrix is always complete. Non-modal `AttackHeatmapWindow`: 14 tactic columns with per-tactic colour-coded headers (slate/navy/burnt-orange/purple/forest/amber/indigo/crimson/teal/deep-navy/violet/ocean/rust/deep-red), clickable technique cells on a dark→blue→amber→red heat ramp with 3px bottom heat-intensity bar and hover highlight, 5-second QTimer refresh. Bottom detail panel shows technique ID, full name, tactic, hit count, heat score (4 decimal places), last-seen timestamp, and last 10 event IDs on click. Stats bar shows active technique/tactic counts and hottest technique in real time. "Reset counts" button clears all heat. `🔥 ATT&CK MAP` button added to main window header alongside `🌐 WORLD VIEW`.

- **v1.2.0 (remediation log + GUI fixes)**
  - **Remediation audit log (`core/remediation_log.py`):** every call to `apply_remediation()` now writes a structured row to a `remediation_log` table in `flight-recorder.db` — timestamp, calling module (`trigger`), MITRE technique, action key + title, outcome (`applied`/`skipped`/`dry_run`/`rolled_back`/`error`), post-apply verification result, host-level flag, and the full `apply()` return dict as JSON. Singleton initialised in `app.py` alongside FlightRecorder. `posture_hardening.apply_vetted_remediation()` passes `trigger="PostureHardening"` for provenance. Queryable via `remlog [n]` and `remlog <T####>` console commands — tabular output with outcome icons (✔ applied, ↩ rolled-back, – skipped, · dry-run, ✖ error), verify flag, and caller label. Bounded at 10,000 rows with amortised trim, matching FlightRecorder discipline.
  - **Post-self-test crash guard (`modules/sys_bridge.py`):** `self_test()` now returns `True` (degraded) when `syscall_bridge.pyd` is compiled but SSN resolution fails — the ctypes fallback is still functional, so the "fix now?" dialog no longer triggers a module restart that could native-crash via the C extension.
  - **World View node labels (`gui/flow_window.py`):** `_NodeItem` now renders two separate `QGraphicsTextItem` children — 11pt bold white title + 8pt muted slate subtitle — visible at `fitInView` zoom. Node height bumped 90→100 px.
  - **Inline host telemetry (`gui/flow_window.py` + `gui/worldview_page.py`):** the three World View cards (Resource Matrix, Telemetry Saliency, Local AI/Ollama) are now embedded directly in `FlowWindow` below the detail panel; "Host telemetry ▲/▼" toggles the panel. Ollama HTTP moved off the GUI thread in both `FlowWindow` and `WorldViewDialog` via `_OllamaWorker(QThread)` + `Signal` — eliminates "Not Responding" freezes. `closeEvent` joins the worker thread cleanly.

- **v1.1.0 (360° hardening + reliability + AI firewall)** — Large multi-part round, each change validated by a headless self-check (`tools/selfcheck.py`, run via `run-selfcheck.bat`).
  - **Bug fix (high impact):** the PE export-table parser used the PE32 DataDirectory offset (+96) for PE32+ binaries too, so on 64-bit hosts **APID** parsed zero ntdll exports — its inline-hook / anti-blinding detection was silently dead. Fixed (+112 for PE32+); now resolves the watched exports.
  - **Self-hardening:** `core/hardening.py` applies process-mitigation policies to Angerona's own process (ExtensionPointDisable, ImageLoad no-remote/no-low-IL, ASLR) at startup; ACG opt-in (`ANGERONA_HARDEN_AGGRESSIVE=1`); MicrosoftSignedOnly intentionally NOT applied (would block Qt/PySide6 DLLs).
  - **Judgment Gate:** staged remediation scripts are SHA-256-stamped on write; `execute_remediation` re-hashes and refuses to run a tampered script (CRITICAL via edr_logger). A new **attempted-fixes log** (`diagnostics/remediation_attempts.log`) records every AI remediation decision (script preview, hash, staged/executed/blocked, verification) so the model's choices are auditable.
  - **Ring 1 Driver-Intel Shield:** INTL bundles an offline BYOVD vulnerable-driver blocklist + `is_known_bad_driver()`; FIM watches `System32\drivers`, classifies any `.sys`/known-bad driver write as CRITICAL via a direct INTL lookup; the shark drill gained a **benign** BYOVD driver-drop technique (marker only — nothing is loaded or registered).
  - **Anti-TOCTOU + perf:** `core/jitter.py` adds `os.urandom` ±15% jitter to the DRILL canary and FRZ heartbeat loops; Ollama `keep_alive` added to the hot triage paths.
  - **SOAR safety:** Active Response SOAR now refuses to terminate Angerona's own process (self-kill guard); a running drill temporarily lowers its response threshold so it actually remediates the benign markers (AAR now shows remediation).
  - **Forensics UI:** clickable dashboard stat cards → detail windows (Alerts / Critical / Modules / Threat with review-gated Attempt-fix / Harden); a **blast-radius tree** (`build_blast_tree(pid)` over PROV ancestry/subtree) and a **Shark-vs-Shield collision view** (maps the detecting module → ring, BLOCKED/MISSED per technique). Reachable from a dashboard **FORENSICS** menu and the Threat drill-down.
  - **Unified Red Team Simulation:** the separate Shark and Red-Team buttons are replaced by one **red** RUN RED TEAM SIMULATION button + config dialog: scenario selection (Shark / APT), difficulty (recursive phases), target directory, and a **custom-technique library** (scrollable, view/edit/delete, persisted) — custom text is written as an inert marker, never executed. Shark/sword animations removed.
  - **Reliability:** RUN SELF-TEST runs off-thread and, on failures, prompts to fix (re-enables/restarts affected modules) and always writes `diagnostics/selftest_failures.json`; a **UI watchdog** (`core/uiwatchdog.py`) dumps all thread stacks to `diagnostics/not_responding.log` if the GUI thread ever stalls; the console **spinner** is now capitalized + enlarged (`WORKING…`).
  - **Two-pane Live Offense Monitor:** left = offense test run + results, right = Flight Instructor coaching (analogy/technical registers).
  - **Analyst console:** added `netstat`, `contain`/`isolate`, `sessions`/`whoami`, `timeline`, `iocs`, `search`/`grep`, `hashes`/`sha256`, `uptime`, `env`, `report`.
  - **AI firewall (`engines/ai_guardrail.py`):** an optional LLM interception proxy in front of Ollama — prompt-injection heuristics, token/DoS limits, an immutable hardened system-prompt wrapper, PII/secret/system-path output redaction, and a JSON audit log (`diagnostics/ai_security_audit.log`). Pure-logic core is unit-tested; FastAPI/uvicorn imported lazily.
  - **Dynamic hardware patch (`core/hw_profile.py`):** pynvml VRAM profiling → tiered execution config (GTX 1060/6 GB → `gemma:2b`, batch 4096, ctx 4096, explicit pool-clear hook; scales up to `llama3:8b` on larger cards), CPU-tier fallback.
  - **Sprint-1 threat-model remediations (BL-02/03/08):** a per-session guardrail token (`ai_guardrail.check_token`) so only the suite can drive the model through the guardrail; a single guarded Ollama client (`engines/ollama_client.py`) that all model calls should route through, with `neutralize_telemetry()` delimiting/defusing attacker-influenced telemetry before it reaches the model (wired into `ai_triage`); and a **TOCTOU-closed Judgment Gate** — `execute_remediation` now reads the script once, verifies that read against the stamp, and runs the exact verified bytes from a locked temp copy, so an on-disk swap after review can't change what executes.
  - **Startup fix:** installers/launcher (`install.bat`, `start-angerona.bat`) resolve a real Python via the `py` launcher, sidestepping the Microsoft Store `python.exe` stub that blocked a fresh Windows setup.
- **v1.0.0 (Phase 3)** — **Four hardening modules** + **performance subsystem**: **FRZ** Anti-Suspension Heartbeat (mmap heartbeat + Go watchdog binary; freeze detection → network isolation + interpreter kill); **DRILL** Telemetry Canary Drills (benign subprocess canaries + EventBus echo verification → blinding detection); **HERMETIC** Monolithic Packaging (PyOxidizer config + build bat + runtime status reporter; signed binary = health 100%); **SYS** Indirect Syscall Bridge (C extension `syscall_bridge.pyd` resolves SSN from on-disk ntdll, builds inline `mov rax/jmp` stubs to bypass hooked DLL exports for terminate/suspend/resume; ctypes fallback). Performance: **GPU Entropy Pipeline** (`core/gpu_entropy.py` — PyTorch CUDA batched Shannon entropy for NDRD + Packet Sniffer, NumPy + pure-Python fallbacks); **Async GUI Architecture** (`gui/telemetry_worker.py` — TelemetryWorker QThread + UIBatchFlusher QTimer 100 ms + ConsoleQueryWorker per-query thread).
- **v1.0.0 (Phase 2d)** — **Four platform-extension modules** (same dual `BaseModule`+`register()` contract, in `src/angerona/modules/`): **NDRD** Network Protocol Deep Decoder (DNS query-name Shannon-entropy scoring → DGA / DNS-tunneling flags); **ETWG** ETW Core Listener (process-creation 4688 + logon 4624/4672 from the Windows Security channel via `win32evtlog`, psutil fallback); **MEMC** In-Memory Flight Cache (bounded `sqlite3 :memory:` mirror of the flight recorder with warm-from-disk + live bus append, SELECT-only reads); **AUTH** Zero-Trust Local IPC Guard (HMAC-SHA256 challenge/response on loopback `127.0.0.1:65432`, default-deny, per-install key). Also extended **INTL** with a Judgment **verification pass**: after explicit operator approval, `confirm()` runs one mock-footprint test via `angerona.shark.verify` and promotes the rule to active only if interception is proven (BLOCKED). Verified: NDRD/MEMC/AUTH self-tests pass (AUTH via a live loopback HMAC handshake), ETWG 4688 decode + INTL technique-extraction/promote-gate validated.
- **v1.0.0 (Phase 2c)** — **Five infrastructure drop-in modules** added to `src/angerona/modules/` (each a `BaseModule` subclass that also exposes the `CODE/NAME/state/health_pct/self_test()`+`register()` contract): **MTM** Memory Time-Machine (lock-light SPSC `mmap` ring + per-PID sliding hash cache → forwards only the delta of new process strings, >80% token cut); **APID** API Patch / Anti-Blinding Detector (stdlib PE parse of pristine `ntdll`/`kernel32` vs live-memory export prologues → flags `E9`/`FF 25`/`68…C3` inline hooks to `soar_events.json`, read-only); **PROV** Provenance Graph (typed PROC/FIM/NET DAG over the flight recorder + live bus, `ancestry`/`subtree`/`blast_radius`); **SPEC** Speculative Triage Pre-Warm (early-marker detection → Ollama `keep_alive` context pre-warm, offline-safe); **INTL** Upstream Threat Intel Sync (inbound-only CISA KEV correlation vs host OS/services → review-gated remediation + MITRE mapping in `upstream_threats.json`, never auto-applies). All five verified: compile clean + logic self-tests pass; SPSC ring round-trip confirmed.
- **v1.0.0 (Phase 2b)** — **Swimming shark** indicator next to Initiate Shark Attack (now bobs, flicks its tail, faces its swim direction and leaves a bubble wake — was a flat slide). New **Posture Hardening** module: tails the after-action report, records any SUCCESS / low-detection technique into `agent_memory.db:system_weaknesses` as VULNERABLE, drops its health below 50 (orange/red strip), and stages a deterministic (temperature 0) Ollama-generated PowerShell/registry remediation to `remediations/<mitre>.ps1` — review-gated, never auto-run, plus an AI-Assisted / Direct-Native custom-patch sandbox. New **World View** dashboard (🌐 header button): host↔suite resource matrix (psutil), telemetry saliency / blinding detector, and live Ollama diagnostics (VRAM, tokens/sec, queue). Desktop **launcher** (`create-launcher.ps1`) + an `llms.txt` master-context so tooling targets this app, not the legacy terminal prototype.
- **v1.0.0 (Phase 2a.4)** — YARA self-test now two-stage: if the active ruleset doesn't fire, a SECONDARY scan with a minimal standalone EICAR rule confirms the engine works and PASSES the test (so one broken rule in rules.yar can't falsely fail the capability); yara's compile stderr is surfaced for debugging.
- **v1.0.0 (Phase 2a.3)** — STOP button upgraded to a true HARD KILL of every Angerona instance (terminates stacked copies too, since it runs elevated); added `kill-all-angerona.bat`, a self-elevating external nuke for when instances pile up.
- **v1.0.0 (Phase 2a.2)** — Fixed: clicking a module row didn't open the inspector (the avatar prefix broke the name lookup in the click handler; now uses the stored module name).
- **v1.0.0 (Phase 2a.1)** — Red **STOP** button (top-right) that confirms, stops all modules, and fully exits (no tray) — a one-click kill switch.
- **v1.0.0 (Phase 2a)** — Single-instance guard (closing to tray no longer lets a relaunch stack a second instance — the root cause of multiplying YARA scan windows); console self-test/command **spinner**; AI module inspector gained **API Keys** and **Help** tabs (keys saved to local .env, live within ~30s; full setup-instructions window); per-module **avatar icons** in the table and status strip; **threat animation** overlay (shark sweep + red flash) fires on confirmed HIGH+ threats.
- **v1.0.0 (Phase 1 hotfix)** — YARA EICAR detection rule simplified to a no-escaping marker so the self-test reliably passes; YARA scan scoped to Downloads at a 5-min interval to cut invocations; confirmed all yara/netstat calls route through hidden execution.
- **v1.0.0 (Phase 1 UI/feature round)** — Theme engine (Modern Cyber + Retro CRT + custom accent), centered uppercase title; yara64 silent execution; threat-level calibration (no false highs); alert drill-down modal with SHA-256 fingerprint; SQL threat-hunting console; network-monitor noise reduction. This document created.
- **v1.0.0 (initial)** — Core framework, 10 modules, console + AI + IR tools, SOAR, self-test harness, module health %, status reporter, GitHub CI/updater.
