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

## Interstitial — Runtime slowdown fixes (user-reported)
Two GUI widget-leak/churn bugs causing progressive slowdown, both the same class
(setRowCount/removeRow does NOT free setCellWidget widgets):
- **AlertsPanel** (`gui/pages.py`): rebuilt all 120 rows + 360 Allow/Block/Analyze
  buttons every ~2 s on any new event, leaking the buttons. Fixed → incremental
  insert of only new rows, 120-row cap, explicit cell-widget freeing. Sim: alive
  widgets constant at 360 (was unbounded); ~40× fewer allocations.
- **ResolveCenter** (`gui/resolve_center.py`) — the "critical → near-unusable"
  cause: rebuilt N rows × 2 buttons every 2 s over a 24 h window AND ran a SHA-1
  signature over every HIGH+ event each tick (O(all alerts) when critical), leaking
  the buttons. Fixed → change-detection skip, per-refresh cap (scan 500 / show 200),
  explicit cell-widget freeing.
- **_notify_critical** (`gui/main_window.py`): batched the per-critical Black Box
  file writes into one write (was open/append/close per critical event per tick).
All behavior-preserving; py-compile verified (host files intact; mount truncation
gave false read errors, re-verified via Read tool + /tmp).

---
o (v1.8, Mar-2026).
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

## Round 2 — Red Team
- R2-01 (HIGH): SOAR alert enrichment interpolates telemetry-controlled file paths into an elevated `powershell -Command` Authenticode check, allowing quote/semicolon injection when an analyst invokes AI review.
- R2-02 (MEDIUM): Remote Bridge proves only sender possession of the shared key; the receiver is unauthenticated and event JSON has neither encryption nor a message MAC, enabling LAN disclosure and on-path modification.
- R2-03 (MEDIUM): EventBus HMAC excludes `details`, is not persisted by FlightRecorder, and is never verified on read, so the advertised tamper-evident ledger accepts modified forensic rows silently.
- R2-04 (LOW): MCP uses single-threaded `HTTPServer` while SSE handlers block indefinitely; one connection monopolizes the service, and POST bodies are unbounded.
- Prior findings: A-04 verified RESOLVED (external drop-ins explicit opt-in); A-07 verified RESOLVED (SHA-256). A-01/A-02/A-03/A-05 and R1-01..R1-04 remain resolved. A-06 remains the sole known open prior item. Totals: 10 resolved, 1 still open.

## Round 2 — Remediation

Applied three minimal, gated fixes; one protocol redesign was conservatively
deferred. Full evidence is in `round2/remediation_summary.md`.

- **R2-01 (HIGH) FIXED:** Authenticode enrichment now binds the telemetry path
  as child-process data and runs constant PowerShell with `-LiteralPath`; quotes,
  semicolons, spaces, and Unicode cannot become source. Compile and hostile-path
  regression PASS.
- **R2-02 (MEDIUM) DEFERRED:** Mutual authentication + AEAD/mTLS requires a
  versioned migration. An in-place wire change would break existing nodes and a
  dual-stack fallback could permit downgrade, so no unsafe compatibility hack
  was applied.
- **R2-03 (MEDIUM) FIXED:** Event HMAC now covers `details`; SQLite is migrated
  to persist signatures, DLQ entries retain them, all recorder reads verify
  them, invalid rows surface as CRITICAL integrity failures, and legacy rows are
  explicitly marked unsigned. GUI and headless buses are armed at startup.
  Compile plus migration/sign/tamper/legacy regression PASS.
- **R2-04 (LOW) FIXED:** MCP now serves requests concurrently and bounds active
  sessions, response queues, request bodies, backlog, and socket reads. Live
  SSE+POST concurrency and 413 body-cap regression PASS.

## Round 2 — Bug Test

Post-remediation Windows/venv QA completed. Full evidence is in
`round2/bugtest_results.md`. **No new production defect was found; 0 bugs fixed,
0 new bugs reported.** R2-02 remains the intentionally deferred, versioned
Remote Bridge protocol redesign.

- **Compile:** direct `py_compile` and `tools/compile_check.py` both PASS —
  **168/168** files, zero syntax errors.
- **Imports/discovery:** **61/61** module files import; **60** modules discovered;
  no discovery errors, duplicate CODEs, or duplicate discovered names. The 13
  files without optional module-level `register()` remain a non-functional
  consistency item because discovery uses `BaseModule` subclasses.
- **Self-tests:** core/Shark **6 PASS / 0 FAIL**. Module runner exercised the
  event pipeline plus every discovered module: pipeline PASS, **45 module PASS,
  15 expected stopped/idle/Ollama skips, 0 genuine failures**.
- **Targeted Round 2 regressions:** R2-01 hostile-path data binding PASS; R2-03
  migration/signature persistence/details-tamper/legacy/live-bus verification
  PASS; R2-04 live held-SSE + concurrent POST and 256 KiB/413 cap PASS.
- **Full project harness:** `tools/selfcheck.py` **26 PASS / 0 FAIL**, exit 0.

## Round 2 — Performance

Three measured, behavior-preserving optimizations were applied; full evidence is
in `round2/performance_summary.md`.

- **P3 APPLIED:** the static ATT&CK Coverage table now builds once. Fifty
  redundant offscreen refreshes fell from 38.175 ms to 0.0425 ms; displayed text
  and all 108 item identities were unchanged.
- **P5 APPLIED:** production GUI/headless buses use `FlightRecorder.record_bus()`
  to reuse the HMAC already produced by their shared authority. Public direct
  `record()` still independently signs exactly as before. Event preparation
  saves 13.61 us/event; integrity and compatibility regressions PASS.
- **P6 APPLIED:** shared process/connection cache misses are serialized with
  independent locks. Twelve concurrent callers now cause one OS enumeration,
  not twelve, while returning identical snapshots.
- **P4 PROPOSED:** BEAC/CAGT direct connection scans remain unchanged because
  cached data shape/freshness could alter live detection.
- **P7 NOT APPLIED:** SQLite commit batching would alter durability/visibility.
- **P8 PROPOSED:** a global MCP request-worker cap needs overload/protocol tests;
  Round 2's session, queue, body, backlog, and timeout caps remain intact.
- Gates: changed files compile; storage integrity/compatibility, offscreen Qt,
  and deterministic sensor-concurrency tests all PASS. YARA runtime output was
  not touched.

## Round 2 — Visionary

Researched current NIST, MITRE, and Microsoft primary sources and compared five
cross-module defensive concepts against Angerona's existing incident, SOAR,
provenance, canary, ledger, and Round 1 work. Shipped one bounded MVP:
**Evidence Lattice Fusion (ELAT)**.

- ELAT promotes MEDIUM evidence only when three modules across two sensor
  domains report the same structured PID, path/hash, or IP inside 90 seconds.
- State and dedup are bounded; the output is an explainable HIGH alert. There is
  no polling, egress, AI, persistence, privilege, containment, or host change.
- Compile, 61-module discovery (0 errors), deterministic fusion and
  false-positive controls, and full selfcheck all pass: **26/26, exit 0**.
- Four concepts remain proposals: telemetry expectation contracts, an isolated
  counterfactual twin, keyed causal-ledger checkpoints, and local novelty
  sketches. Full evidence: `round2/visionary_summary.md`.
- `rules/_active_combined.yar` was not touched.

## Round 3 — Red Team

- R3-01 (HIGH): Elevated startup still trusts user-writable code roots; the actual project ACL grants Authenticated Users FullControl, while the per-user `.env` can enable and populate the external-module directory before elevated `exec_module`, so A-04's opt-in is not an authorization boundary.
- R3-02 (MEDIUM): R2 ledger HMAC verification stores plaintext `bus.key` beside the SQLite DB under the same per-user FullControl ACL, allowing a ledger writer to forge valid rows or invalidate history by replacing the key.
- R3-03 (MEDIUM): The shared A-03/R1 PowerShell substring scanner accepts all five generated playbooks even though they contain WMI `Terminate()`/`SetState(0)` calls, including actions against `explorer.exe` and `svchost.exe`.
- R3-04 (MEDIUM): Evolution activates model-generated YARA without compiling it; the current `auto_generated.yar` is confirmed syntax-invalid, reload would still swap it active, and the scan loop ignores non-zero YARA exits while reporting healthy.
- Prior controls: 8 prior IDs remain verified resolved; 7 are open, deferred, or have an incomplete shared control. A-06 and R2-02 were not re-filed merely because they remain open. ELAT produced no new finding. `rules/_active_combined.yar` was not touched.

## Round 3 — Remediation

- **R3-01 (HIGH) DEFERRED:** a correct fix requires a packaged,
  Administrator/SYSTEM-owned runtime and privileged plug-in trust boundary.
  Angerona did not mutate host ACLs or make the FullControl development checkout
  silently unlaunchable.
- **R3-02 (MEDIUM) DEFERRED:** existing malformed/unreadable signing keys now
  fail closed and first-run creation is atomic/race-safe, but same-user key
  custody cannot be separated with user-scoped DPAPI. A privileged signer or
  packaged admin-only key boundary is still required.
- **R3-03 (MEDIUM) FIXED:** generated containment now passes a strict firewall
  command/parameter allow-list before atomic staging and a PowerShell AST gate
  immediately before execution. WMI/CIM, member calls, pipelines, aliases,
  dynamic invocation, and the five historical unsafe playbooks fail closed.
- **R3-04 (MEDIUM) FIXED:** generated YARA is compiled with the actual bundled
  engine before atomic activation; invalid candidates preserve last-known-good
  state, scan failures degrade health, and technique IDs/self-test are gated.
- Gates: all changed Python files compile; focused key/PowerShell checks PASS;
  the PowerShell gate parses; actual `yara64.exe` valid-activation,
  invalid-rejection, last-known-good, and live self-test regression PASS.
- `rules/_active_combined.yar` was not touched.

## Round 3 — Bug Test

Post-remediation Windows/venv QA completed. Full evidence is in
`round3/bugtest_results.md`.

- **Compile/import/discovery:** 169/169 Python files compile; 62/62 module files
  import; 61 modules discover with zero errors or duplicate codes. No partial or
  conflict-marked Round 3 edit was found. `mitigation_gate.ps1` parses cleanly.
- **Self-tests:** core/Shark 6 PASS / 0 FAIL; module runner pipeline PASS with
  46 module PASS, 15 expected stopped/idle/Ollama skips, and 0 genuine failures.
  ELAT fusion and false-positive controls PASS.
- **R3 gates:** key first-run/reload/malformed fail-closed PASS; all 5 historical
  WMI playbooks rejected while the firewall fallback passes; actual bundled
  YARA proves valid atomic activation, invalid rejection, last-known-good
  preservation, and live EICAR PASS. Focused R3 total: 12/12 PASS.
- **R2 regressions:** hostile Authenticode binding, ledger details integrity/HMAC
  reuse, live MCP SSE+POST/413 limits, and build-once coverage refresh PASS.
- **Full selfcheck:** 26/26 PASS, exit 0.
- **Reported:** R3-QA-01 (LOW performance) — a valid empty process/connection
  snapshot is not cached because cache validity depends on list truthiness, so
  concurrent empty results can repeat the OS enumeration. No production fix was
  made in the final QA stop; 0 bugs fixed, 1 low edge reported.
- `rules/_active_combined.yar` was not modified.

## Round 3 — Performance

- **P9 APPLIED:** valid empty process and connection snapshots are now cached by
  initialized timestamp + TTL instead of list truthiness. Deterministic
  eight-thread gates reduced both empty-result paths from 8 OS enumerations to
  1 (87.5% removed); non-empty behavior, the 1.5-second default TTL, and
  `max_age=0` forced refresh are unchanged.
- Gate: changed file `py_compile` PASS; process/connection × empty/non-empty
  concurrency regression **4/4 PASS**, with identical caller results and one
  enumeration per shared miss.
- **P4/P8 remain PROPOSED:** cached detector connections could change detection
  freshness/data shape; globally bounding MCP request workers changes overload
  protocol behavior and needs load tests.
- **P10 PROPOSED:** Evolution's rare bypass path reads the complete attack feed;
  a bounded reverse/indexed lookup should be gated for UTF-8 boundaries and
  newest-match equivalence before implementation.
- Evidence Lattice remains bounded/event-driven and generated YARA compilation
  remains bypass-driven; no second proven steady-state optimization was applied.
- Full evidence: `round3/performance_summary.md`. The active combined YARA
  runtime output was not touched.

## Round 3 — Visionary

Researched current MITRE, NIST, and OpenTelemetry primary/authoritative sources
and excluded Round 2 ELAT, incident correlation, provenance, SOAR, ledger, and
the existing hard-coded canary before selecting one bounded architectural MVP:
**Telemetry Expectation Contracts (TECT)**.

- TECT is a pure, bounded, thread-safe deadline state machine for the invariant
  “opaque probe X must produce exact named echoes A/B before D.” It has no host
  inspection, egress, model call, persistence, response callback, or privilege.
- DRILL now uses TECT and accepts its canary only from an ETWG-compatible EID
  4688 event. This fixes a demonstrated false-health path where DRILL accepted
  its own tagged `canary fired` announcement as the sensor echo.
- A real satisfied contract resets the consecutive-miss streak; firing a later
  probe no longer erases a current miss, so the existing two-miss escalation can
  operate as designed. Stop/start also reuses one bus subscription.
- `py_compile` and project `compileall` PASS; TECT and DRILL deterministic tests
  PASS; discovery finds 61 modules with 0 errors; full selfcheck is **26/26 PASS,
  exit 0** (47 module passes, 15 expected skips, 0 genuine failures).
- Four larger concepts remain proposals: isolated counterfactual replay, offline
  telemetry failure mutation, keyed causal-ledger checkpoints, and local novelty
  sketches. Full evidence: `round3/visionary_summary.md`.
- `rules/_active_combined.yar` was not touched.

## Round 3 — Visionary (legendary upgrades)
Built 7 additive, read-only, gated MVP engines (core/ + self_test each; NOT wired
into app startup → zero behavior/detection risk). Full vision: analysis/loop/
visionary/legendary_upgrades.md. All self_tests PASS.
- **core/cortex.py** ★ — unified correlation brain: entity graph + decay-weighted
  per-entity malice with convergence fusion. self_test: fused proc:42=65.5 > lone
  HIGH 16.8 > lone MEDIUM 8.4 (the 1+1=3).
- **core/angerona_score.py** — one 0-100 safety score + single next-best-action
  (quiet→88/SECURE, attack→0/CRITICAL→Contain).
- **core/sigma_engine.py** — Sigma-subset matcher (selections/modifiers/condition/
  and-not); import the public rule library.
- **core/ocsf_export.py** — events → OCSF Detection Finding (class 2004) for SIEM/XDR.
- **core/d3fend_map.py** — ATT&CK→D3FEND countermeasure map (19 techniques, 88% impl).
- **core/purple_loop.py** — coverage-gap finder + review-gated candidate detections
  (proposals only; nothing installed/executed).
- **core/copilot.py** — local NL query over Cortex/events ("why is it critical?").
Recommended production order: wire Cortex → Score on header → Sigma module →
Copilot pane → OCSF/D3FEND/purple-loop panels.

---

## Documentation / Loop Complete — 14 July 2026

- Three rounds complete. Twelve new security findings were confirmed: nine fixed and three deferred behind explicit protocol/deployment boundaries.
- Shipped visionary work: Evidence Lattice Fusion (ELAT), bringing discovery to 61 modules, and Telemetry Expectation Contracts (TECT), integrated into DRILL with strict trusted ETW/EID 4688 echo matching.
- Final gates: 177/177 Python files compile in the combined Claude/Codex tree; 62/62 module files import; 61 modules discover with zero errors or duplicate codes; focused Round 3 regressions pass 12/12; full self-check passes 26/26 with exit 0.
- Documentation updated to v1.7.5: Capability Doc, Master Manual, Vulnerabilities Assessment/Remediation, System Flow, Security Assessment loop addendum, README.md, and canonical llms.txt.
- Remaining deferred work is R2-02 Remote Bridge mutual authentication/encryption, R3-01 packaged administrator-owned trust roots, R3-02 privileged ledger-key custody, and the previously open A-06 centralized PowerShell execution boundary.
- Remaining visionary/performance proposals are recorded as proposed, not shipped. Visual DOCX render QA was unavailable because LibreOffice is absent; all five packages passed CRC, XML/package, python-docx reopen, content, metadata, and table-shape validation.
