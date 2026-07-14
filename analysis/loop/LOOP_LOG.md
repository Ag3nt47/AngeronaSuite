# Angerona Improvement Loop — Log

Started 2026-07-13. 3 rounds. Web research (innovation) in round 1 only; docs +
README update at end of round 3. All code changes are gated (compile + self_test,
behavior-preserving, no weakening of security controls).

---

## Round 1 — Red Team
- R1-01 (MEDIUM): shark/playbook_tuner.py stages raw Ollama-generated PowerShell into the auto-executed root mitigation_gate.ps1 with no destructive denylist / review gate (the control A-03 added for cve_fix_advisor is missing here).
- R1-02 (MEDIUM): posture_hardening.execute_remediation runs AI-generated PowerShell (elevated, -ExecutionPolicy Bypass) with only a hash+authorized gate, no A-03 destructive-content scan; AAR bulk _apply executes all staged scripts without per-script confirmation.
- R1-03 (LOW): repo-root mitigation_gate.ps1 + playbooks/ dir are dot-sourced/executed elevated; if the install dir grants Users:Write this is a writable-script local privilege escalation (distinct from A-04's Python drop-in dir).
- R1-04 (INFO): dead engines/sniffer.py leaks observed remote IPs to http://ip-api.com over plaintext HTTP and starts a DPI thread on import; currently unimported.
- Prior findings: A-01, A-02, A-03, A-05 verified STILL RESOLVED. A-04, A-06, A-07 remain OPEN (pre-existing, by-design/cosmetic). No prior mitigation regressed.

## Round 1 — Innovation
Web research (favor last 12–18 mo) → 10 buildable, defensive-only proposals in `analysis/loop/innovation_ideas.md`, ranked by impact÷effort. Verified none duplicate shipping code (no RunMRU/ClickFix, browser-cred, JA4, ETW-TI, OCSF, or callstack detection today).
- I1 (S, TOP): ClickFix/RunMRU clipboard-exec detector — new `clickfix_detector` module correlating RunMRU writes + LOLBIN spawn (T1204.004). Cited: MS Security, Sekoia. (#1 loader chain of 2025 per Huntress.)
- I2 (M): Indirect prompt-injection tripwire for Angerona's own AI-in-the-loop — harden `ai_guardrail`/`counter_agentic`, gate AI-derived remediations (OWASP LLM01). Cited: OWASP, MSRC, IPIGuard.
- I3 (M): Infostealer/browser-credential-store guard — new `infostealer_guard`, Sysmon EID10 on Login Data/cookies/Local State, DPAPI (T1555.003). Cited: DeepStrike, Detection Chokepoints.
- I4 (M): BYOVD behavioral EDR-kill detector — new `byovd_guard`, driver-load + security-proc-kill correlation (T1562.001). Cited: THN (54 EDR killers), Security.com.
- I5 (S–M): OCSF-normalized export — enhance `siem_forwarder` w/ OCSF findings + ATT&CK mapping. Cited: AWS OSS blog, ocsf.io (v1.8, Mar-2026).
- I6 (S): D3FEND countermeasure overlay on the ATT&CK heatmap — `attack_coverage`+GUI. Cited: AWS OSS blog.
- I7 (L): Callstack/unbacked-memory execution detection — enhance `mem_inject_scanner` w/ StackWalk (T1055). Cited: Elastic Security Labs.
- I8 (M): JA4/JA4+ TLS-client fingerprinting for C2 — enhance `packet_sniffer`/NDRD (T1071.001). Cited: FoxIO, Team Cymru.
- I9 (M): Sticky-canary ransomware trap + entropy-rate — enhance `deception`/`ransomware_heuristics` (~12s, T1486). Cited: Elastic Security Labs, MDPI.
- I10 (L, GATED): ETW-TI sensor — HIGH value but consumer requires PPL/AntimalwareLight cert Angerona lacks; buildable deliverable = ETW-TI tamper/disable watch. Limitation noted, no workaround. Cited: Praetorian, fluxsec.
- All web searches (WebSearch) succeeded; no domains blocked.

## Round 1 — Remediation
Fixed R1-01..R1-04, all behind gates, reusing the existing A-03 denylist
(`cve_fix_advisor.scan_powershell`) rather than inventing a new one. No control
weakened. Full write-up in `round1/remediation_summary.md`.
- **R1-01 (MEDIUM) FIXED** — `shark/playbook_tuner.py`: `tune_containment` now scans
  the Ollama-generated block with `scan_powershell` before staging it into a
  dot-sourced playbook; destructive output (or an unavailable scanner) falls back
  to the deterministic network-only block. Return dict reports `used_fallback` /
  `blocked_destructive`. Compile PASS. Verified: `Remove-Item` → fallback; clean
  `New-NetFirewallRule` → passes.
- **R1-02 (MEDIUM) FIXED** — `modules/posture_hardening.py`: `_generate_remediation`
  refuses to stamp destructive model output (writes a refusal placeholder instead);
  `execute_remediation` scans the exact SHA-verified bytes and refuses destructive
  scripts before the elevated run. The bulk AAR `_apply` funnels through
  `execute_remediation`, so every bulk-applied script is now scanned per-script.
  Compile PASS; `self_test` PASS (weaknesses=1, health=40 — verified in isolation
  because the sandbox mount served a truncated copy missing `self_test`).
- **R1-03 (LOW) FIXED** — `mitigation_gate.ps1`: added `Test-AngeronaUserWritable` +
  a fail-closed guard that aborts (`exit 1`) before dot-sourcing dynamic playbooks
  if the gate script or `playbooks\` dir grants write to an unprivileged SID
  (Everyone/AuthUsers/Users/INTERACTIVE). Behavior-preserving for correctly-ACL'd
  and normal per-user installs; blocks only the LPE-vulnerable writable case.
- **R1-04 (INFO) FIXED** — `engines/sniffer.py` (confirmed dead: no importers,
  package not auto-loaded): removed the import-time DPI worker thread (now opt-in
  `start_dpi_worker()`) and deleted the cleartext `http://ip-api.com` IP-geolocation
  egress from `get_geo_location` (now a local no-op). Compile PASS (isolated).
- Gate caveat: the sandbox mount intermittently served truncated reads of the two
  large edited files, causing FALSE `SyntaxError`s / a FALSE `self_test` miss;
  re-verified against the real filesystem and in `/tmp` harnesses per the runbook.

## Round 1 — Bug Test
QA sweep after remediation. Full write-up in `round1/bugtest_results.md`. **No real
defects found; nothing regressed. 0 bugs fixed, 3 items reported (none defects).**
- **Compile:** 168/168 .py files valid. The lone `engines/sniffer.py` "SyntaxError
  (line 114, '{' never closed)" is a CONFIRMED sandbox mount-truncation artifact — the
  mount serves a truncated 116-line/4792-byte copy; the real file is 122 lines and
  brace-balanced (verified via direct filesystem read + `/tmp` recompile). Same false
  positive from `tools/compile_check.py`.
- **Self-tests — core (6/7):** cve_ignore, cve_fix_advisor, alert_ack, incident_timeline,
  ir_bundle, shark.red_team all PASS. `core.attack_coverage` has NO `self_test()`
  (REPORTED B-R1-B) — its `summary()`/`render()` work fine.
- **Self-tests — modules:** 61 files, 61 import OK. Started-mode: **52 PASS / 8 FAIL**,
  all 8 platform/environmental (Ollama, Defender, scapy, yara64.exe, kernel driver,
  kernel32 absent; Windows-only `psutil.HIGH_PRIORITY_CLASS`; `os.path.basename` not
  splitting `\` on Linux for the Windows-gated ETW listener). Zero code defects.
  Posture Hardening self_test PASS; its R1-02 `scan_powershell` wiring confirmed present.
- **Duplicates/imports:** no duplicate CODE, no duplicate names, no broken imports.
  14 modules lack `register()` (REPORTED B-R1-C) — non-defect: discovery uses BaseModule
  subclassing, not `register()`.
- **selfcheck.py:** SKIPPED — hard-requires PySide6 (not installed in sandbox; GUI harness).
- Confirms Round-1 remediation (R1-01..R1-04) compiles and passes self_tests intact.

## Round 1 — Performance
Behaviour-preserving speed/memory work, gated (compile + behaviour proof, no
detection path throttled). Full write-up: `round1/performance_summary.md`.
- **P1 (APPLIED)** — `modules/flight_cache.py`: `FlightCache.put()` ran a
  `SELECT COUNT(*)` on **every** insert (hot path — MEMC subscribes to every bus
  event, ~140 ev/s) to size the eviction. Replaced with an exact in-process row
  counter (`put()` is the sole mutator). Micro-bench (20 000 inserts @ cap 5000):
  46.2 → 29.5 µs/insert, **1.57× faster**, ~16.7 µs/event saved, and removes an
  O(n) term that grows with the cache. Gate: `py_compile` PASS; isolated harness
  confirms self_test assertions hold and `count()` == real `COUNT(*)` across a
  500-insert eviction stress test. Same rows/eviction/reads.
- **P2 (APPLIED)** — `gui/main_window.py` `_update_threat_intel_pulse()`: was
  calling `threat_intel_btn.setStyleSheet()` every 1 s tick even when the style
  string was the unchanged constant `""` (idle case), forcing a redundant Qt
  style re-polish/repaint each second. Added a last-applied-string guard. Idle:
  10 ticks → 1 call (90% cut); pulsing: 10 ticks → 10 calls (animation
  preserved). Gate: `py_compile` PASS (isolated method — full-file compile hit
  the documented mount-truncation FALSE error at line ~1263; real file verified
  intact via host FS); fake-button harness confirms behaviour.
- **P3 (PROPOSED)** — `gui/attack_heatmap.py` `_refresh_coverage()`: rebuilds the
  **static** Coverage table (≈N×6 cells) every 5 s while open, though
  `attack_coverage.COVERAGE` + `_valid_action_keys()` are constant for the
  session. Propose build-once/change-detect. GUI render path — can't prove
  identical render without Qt → PROPOSE.
- **P4 (PROPOSED)** — `modules/beacon_detector.py` + `modules/counter_agentic.py`
  call `psutil.net_connections()` **directly**, bypassing the existing 1.5 s
  shared snapshot cache in `telemetry/sensors.list_connections()` built to
  collapse exactly these duplicate full scans (the priciest sensor call on
  Windows). Propose rewiring through the cache. These are live detection modules
  and the cache returns a different data shape (dict vs psutil object, no
  status/SYN_SENT semantics); equivalence not statically provable → PROPOSE per
  the RUNBOOK "when in doubt on a control, propose".
- Verified already-optimal (no change): `core/storage.py` (write-counter prune +
  `max_ts()` pre-check), `core/alert_ack.py` (mtime cache — the reference
  pattern), `main_window._refresh_body` (change-detected, tick-modulo staggered),
  `gui/telemetry_worker.py` (off-thread batching + backpressure), EventBus
  INFO-drop backpressure, and the `telemetry/sensors.py` shared scan cache.
