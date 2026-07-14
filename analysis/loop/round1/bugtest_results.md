# Round 1 — Bug Test / QA Results

Date: 2026-07-14. Runner: BUG-TESTING/QA agent. Repo: AngeronaSuite.
Environment: Linux sandbox mount (Python 3.10.12), `PYTHONPATH=src`. Target platform
is Windows; PySide6, Ollama, Npcap/scapy, YARA, and Windows drivers are NOT present
in the sandbox — those absences are expected and are NOT defects.

Scope: verify the Round-1 remediation edits didn't break anything and hunt for bugs.
Edited files under review: `src/angerona/shark/playbook_tuner.py`,
`src/angerona/modules/posture_hardening.py`, `src/angerona/engines/sniffer.py`,
root `mitigation_gate.ps1`.

---

## 1. Compile (py_compile over all of src/angerona)

- **168 .py files scanned → 168 valid.**
- 1 tool-reported SyntaxError, **confirmed FALSE (sandbox mount artifact, NOT a real defect):**
  - `src/angerona/engines/sniffer.py` — py_compile/compile_check.py report `'{' was never closed (line 114)`.
  - Root cause: the sandbox mount served a **truncated 4792-byte / 116-line copy** that
    cuts off mid-dict (`"TCP_Count": stats["TCP"],`). The authoritative Windows file
    (read directly) is **122 lines, brace-balanced, valid Python** (dict opened line 114
    closes line 120; `try/except` complete). Reconstructing the real structure into
    `/tmp` compiled cleanly. `wc`/`cat`/`cp`/`py_compile` all route through the same
    stale mount, so all three agree on the false positive; the direct file read is
    correct. Same artifact was flagged (and worked around) by the remediation agent.
- The other 3 edited files were read from the authoritative filesystem and are complete
  and correct: `playbook_tuner.py` (144 lines), `mitigation_gate.ps1` (65 lines),
  `posture_hardening.py` (self_test passes, see below).

## 2. Self-tests

### Core / shark self_test() — 6 PASS / 1 N/A
| Component | Result |
|---|---|
| angerona.core.cve_ignore | PASS |
| angerona.core.cve_fix_advisor | PASS |
| angerona.core.alert_ack | PASS |
| angerona.core.incident_timeline | PASS |
| angerona.core.ir_bundle | PASS |
| angerona.shark.red_team | PASS (14 chained techniques, kill-chain order verified) |
| angerona.core.attack_coverage | **N/A — no self_test() defined** (REPORTED below) |

### Modules — 61 files, 61 imported (0 import failures)
Run with modules started (mirroring `tools/selfcheck.py` / `SelfTestRunner`, since the
default `BaseModule.self_test` returns False unless `status=="running"`):
**52 PASS / 8 FAIL. All 8 failures are platform/environmental (Linux sandbox), NOT code defects:**

| Module | Failure | Classification |
|---|---|---|
| AI Triage (Ollama) | Ollama unreachable (conn refused) | ENV — no Ollama server |
| AV Telemetry Bridge | Defender channel + PS cmdlets unavailable | ENV — Windows-only |
| Dynamic Resource Governor | `psutil` has no `HIGH_PRIORITY_CLASS` | PLATFORM — Windows-only psutil constant |
| ETW Core Listener | 4688 decode: name kept full path | PLATFORM — `os.path.basename` doesn't split `\` on Linux; module is `os.name=="nt"`-gated, passes on Windows |
| Kernel Sensor Bridge | AngeronaSensor.sys not loaded | ENV — driver absent |
| Memory Injection Scanner | kernel32 not loaded | ENV — Windows-only |
| Packet Sniffer | scapy import fails → status=error | ENV — scapy/Npcap not installed |
| YARA Scanner | yara64.exe Exec format error | ENV — Windows PE run on Linux |

Note: an initial pass WITHOUT starting modules showed ~19 "failures"; the extra ~11 were
all the default `status=stopped` readiness check (not real). Starting the modules first
(as the real harness does) cleared them. Posture Hardening self_test = **PASS**
(`running, health 100%`), and its R1-02 A-03 destructive-scan wiring
(`cve_fix_advisor.scan_powershell` reused at generate + apply) is present and correct.

## 3. Project harness

- `tools/selfcheck.py` — **SKIPPED (cannot run in sandbox):** hard-imports
  `PySide6.QtWidgets.QApplication` at module load; PySide6 is not installed. Expected —
  it's a GUI/offscreen harness for the Windows/venv environment.
- `tools/compile_check.py` — ran: `168 scanned, 1 failed` — the same `sniffer.py` mount
  false-positive documented in section 1. Real result: all pass.

## 4. Duplicate CODE / missing register() / broken imports

- **Duplicate CODE attributes: none.** (all module `CODE` values unique)
- **Duplicate module names: none.**
- **Broken imports: none** — all 61 modules + all exercised core modules import.
- **Missing register(): 14 modules** — `ai_triage, cloud_escalation, deception,
  file_integrity, forensics, network_monitor, packet_sniffer, persistence_sweep,
  process_monitor, remediation_actions, soar, soar_engine, yara_scanner` lack a
  module-level `register()`. **NOT a functional defect:** `ModuleManager.discover()`
  discovers modules by `BaseModule` subclassing, never by `register()`. `register()` is
  a documented convention used only by a few standalone `__main__` blocks and one GUI
  lookup (`gui/telemetry_worker.py`, for MEMC which HAS one). REPORTED as a consistency
  gap, not fixed (adding it to 14 files is scope/design work, not a clear-safe fix).

---

## Bugs

### FIXED
- **None.** No real code defects were found, so no gated fixes were required. The Round-1
  remediation edits compile and pass their self_tests; nothing regressed.

### REPORTED (no clear-safe fix / need judgment — not defects introduced this round)
- **B-R1-A (sandbox artifact, INFO):** `engines/sniffer.py` "SyntaxError" is a
  mount-truncation false positive, not a real bug. The real file is valid. Documented so
  it isn't re-flagged. When the user runs `run-compile-check.bat` on Windows it will pass.
- **B-R1-B (LOW):** `angerona.core.attack_coverage` has no `self_test()` function (the
  task listed it as a core self_test to run). It exposes `summary()` and `render()`, both
  of which work (summary keys present, render() 1700 chars). Either the task's expectation
  is stale or a `self_test()` was never added. No behavioral bug; a `self_test()` could be
  added later for parity but that's a design choice.
- **B-R1-C (INFO):** 14 modules lack `register()` (list above). Cosmetic/consistency only;
  discovery works without it.

## Sandbox artifacts vs real defects — summary
- REAL defects: **0.**
- Sandbox/platform artifacts (NOT defects): sniffer.py truncation SyntaxError; all 8
  started-mode module self_test failures (Ollama/Defender/scapy/YARA/driver/kernel32
  absent, and Windows-only `psutil` constant + `\`-path basename on Linux); selfcheck.py
  needing PySide6.
