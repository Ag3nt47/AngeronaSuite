# Live triage and first fixes — 2026-11-11

Scope: a read of the running v1.15.0 source instance and its
diagnostics, followed by four small source changes. Nothing here was run on
Windows; the changes passed only a Python syntax check and a standalone run
of the new watchdog-threshold and Ollama-budget assertions on Linux. They are
uncommitted and unpublished until the focused and full gates pass.

## Findings

| Area | Finding | Status |
| --- | --- | --- |
| Response authority | `protect_authority()` refuses host mutation for an unfrozen source run. The live instance is unelevated source, so Adversary Combat (maximum/terminate/isolate) is held. | By design. Act-first needs the installed, signed package run elevated. No code change. |
| Ollama exposure | `%LOCALAPPDATA%\Ollama\server.log` shows `Listening on [::]:11434`: `OLLAMA_HOST` is a wildcard, so the unauthenticated API is reachable from the network and Angerona refuses the listener. | Real exposure. `tools/Start-AngeronaOllama.ps1 -FixHostBinding` sets loopback. |
| Ollama startup | Ollama 0.40.16 (non-default install path) spent about five minutes in GPU discovery (three 90-second timeouts, then CPU) and `/api/version` took 11-16 s. Angerona's fixed 30 s budget ended at "80% Timed out". | Budget now 90 s, 30-120 s via `ANGERONA_OLLAMA_STARTUP_SECONDS`; the launch script pre-starts Ollama and waits up to seven minutes. The GPU discovery failure itself is not diagnosed. |
| Black Box "UI NOT RESPONDING" | Recent samples are inside `BlackBoxWindow()` construction (imports under PySide's `feature_imported` hook), 5-10 s, before the first event-loop beat. | Startup budget of 45 s before the first beat; the ordinary 5 s threshold is unchanged afterwards. Startup itself is not faster. |
| Black Box restart 13:37 | Both supervisors recorded the process probe as dead once and one restart. | Cause unknown. |
| FIM coverage | `%USERPROFILE%\Documents` is a link on this profile; the scanner correctly refuses it as a watch root. | Default roots now come from the shell known-folder record, falling back to the old path. Unverified on the host. |
| Main-window stalls | 40 samples since Nov 6; 28 show the main thread inside `app.exec()` with no Python frame. | Not attributable from these samples (native Qt work, GIL or CPU contention among ~143 threads). Open. |
| Red Team run 2026-11-10 | 52/52 steps ran, 2 failed, scoring withheld (0/50 credited). | Needs a fresh run; the two failed steps were not identified here. |
| Shark run 2026-11-10 | 6/8 detected and contained; the outbound exfiltration burst was missed. | Open. |
| Alert volume | 23,309 alerts in 24 h with 0 active critical; T1071 and T1059 each repeat 256 times in the briefing window. | Producer not identified. Tune before any automatic process action is armed. |
| Defender bridge | "record numbering regressed or the channel was cleared". | Not investigated. |
| Uncommitted work | 13 modified files under `tests/` predate this session. | Not reviewed. |

## Second pass: alert volume and module recovery

Read from a copy of `flight-recorder.db` (23,218 events in the last 24 hours;
about 18,000 are INFO telemetry).

| Source | Count / 24 h | Finding | Status |
| --- | --- | --- | --- |
| Counter-Agentic Detection (High) | 556 | Ollama's own sockets on port 11434. The Ollama executable has no digest-pinned operator approval, and the reviewed dedup key keeps full endpoints with a 60-second window. This is the T1071/T1059 repetition in the briefing. | Third pass, at the maintainer's direction: the bus alert for one process generation, peer host and role now repeats hourly; a new generation, peer host or role alerts immediately. The pinned endpoint keys are unchanged and `test_counter_agentic_socket_presentation.py` was updated for the new cadence. Approving the Ollama image in the process allowlist still removes the alert at its source. |
| Forensics Capture (Medium) | 639 | One "capture held" alert for every High observation that is not active evidence. | Identical reason/pid now reported at most every 15 minutes with a repeat count; health unchanged. |
| Memory Injection Scanner / SpywareGuard (Medium) | ~635 each | RWX regions in JIT hosts (Steam CEF, WebView2, Electron apps, PowerShell) re-reported on the 5-minute per-process cooldown and mirrored by SpywareGuard. | Third pass: a sweep that finds only regions already reported for the same process generation repeats hourly; any new region still reports on the 5-minute cadence. JIT hosts that keep allocating new regions will still repeat. |
| Packet Sniffer / Watchdog Monitor | 26 recoveries, 4 "manual attention" | Two defects. The 35-second worker deadline left 5 seconds for a cold interpreter to import Scapy before a 30-second capture (exit 124). The module's default 30-second first-cycle and work budgets expire before any 30-second capture can finish; the log shows recovery about 34 seconds after each start. | Worker deadline 80 s; module budgets 95 s. The second defect matches the log timing; the first is inferred and a hanging Npcap capture is not excluded. A capability contract can still override the class budget. |
| Persistence Sweep (Critical, Sept-Oct 8) | 100+ | Stock `\Microsoft\Windows\` rundll32 tasks. | Historical; the current classifier no longer rates these. |
| AV Telemetry Bridge (Critical) | 7 | Defender reported one script-trojan detection on a documentation file inside a globally installed npm package, and one ransomware-pattern detection six times on a developer tool's command line. Names are kept in the private host record. | Not investigated. Operator review needed. |
| Resilience Manager | each start | "Using the Python peer watchdog": the native Go parent in `frz/` is not built, signed or selected. | Open; needs the Go toolchain and a signing certificate. |

## SpywareGuard pass

Three standing findings were re-published every five-minute sweep (about 860
repeats a day): unquoted service paths for two services of one hardware
vendor's utility suite, and a startup entry for an uninstaller helper in a
randomly named folder under the user's temp directory (child of a wallpaper
utility, 13 anonymous RWX regions). The last one runs
from a temporary directory at every sign-in and has not been reviewed.
SpywareGuard sweeps every five minutes and auto-contain is enabled, but
containment is held with the rest of response authority in source mode.

## Changes

- `src/angerona/core/uiwatchdog.py`: optional `startup_stall_seconds`.
- `blackbox_recorder.py`: passes `startup_stall_seconds=45.0`.
- `src/angerona/modules/file_integrity.py`: `_user_folder()` for Documents/Downloads.
- `src/angerona/core/ollama_lifecycle.py`, `src/angerona/modules/ai_triage.py`: `configured_startup_timeout()`.
- `tools/Start-AngeronaOllama.ps1`, `Start-Angerona-With-Ollama.bat`: new, never executed.
- `tests/test_uiwatchdog_startup_budget.py`: new.
- `src/angerona/modules/forensics.py`: rate-limited hold alert.
- `src/angerona/modules/packet_sniffer.py`: worker startup allowance and module cycle budgets.
- `tests/test_alert_noise_bounds.py`: new, not run.
- `src/angerona/modules/counter_agentic.py`, `tests/test_counter_agentic_socket_presentation.py`: hourly per-generation repeat (an earlier key change was reverted first).
- `src/angerona/modules/mem_inject_scanner.py`: hourly repeat for unchanged region sets.
- `src/angerona/modules/spyware_guard.py`: six-hour repeat for identical exposure-only findings; no new test.
- `src/angerona/modules/kernel_posture_ledger.py`: six-hour repeat for an unchanged posture risk (was every 5 minutes, 61 High alerts a day for "HVCI not running"); no new test.
- `src/angerona/resilience/supervisor.py`: unexpected dead/suspended component reported at High (was Info); restart logic unchanged.
- `README.md` reordered; `CHANGELOG.md` and `llms.txt` carry a "not yet validated" entry. `tools/validate_documentation_drift.py` passes.

## Not started

Watchdog and anti-shutdown hardening, SpywareGuard review, act-first on the
installed package, Red Team gap fixes, documentation updates (`llms.txt`,
master manual, weakness review, README), publication, suite map and UI polish.
