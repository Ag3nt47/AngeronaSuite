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
- **P11 APPLIED:** process allowlist and drill resolution now expose immutable,
  reusable snapshots and cache their default data directories. Threat posture,
  Resolve Center, Memory Injection Scanner, both SOAR tiers, Posture Hardening,
  and Red Team AAR matching load once per evaluation batch instead of once per
  event/process/verdict. Existing direct-call APIs and mtime invalidation remain.
- P11 gates: nine touched files compile; exact name/path and old/new resolution
  behavior, immutability, next-batch write invalidation, and zero hidden reloads
  PASS. A 50-event threat batch used 1 policy + 1 resolution snapshot; a
  three-PID memory batch and both eight-event SOAR batches used one policy
  snapshot each. Response actions were stubbed, so no host state changed.
- **P4/P8 remain PROPOSED:** cached detector connections could change detection
  freshness/data shape; globally bounding MCP request workers changes overload
  protocol behavior and needs load tests.
- **P10 PROPOSED:** Evolution's rare bypass path reads the complete attack feed;
  a bounded reverse/indexed lookup should be gated for UTF-8 boundaries and
  newest-match equivalence before implementation.
- Evidence Lattice remains bounded/event-driven and generated YARA compilation
  remains bypass-driven; no further proven win was found in those two paths.
- Full evidence: `round3/performance_summary.md`. The active combined YARA
  runtime output was not touched.

### 2026-08-22 Chill live-path addendum

- **P12 APPLIED:** Evolution's EventBus-driven worker now parks on its stop token
  instead of waking every five seconds to do no work (**17,280 idle wakeups/day
  removed**).
- **P13 APPLIED:** Active Deception retains its five-second canary cadence but
  mtime/file-identity caches the attack feed, reducing an unchanged resident
  feed from up to **17,280 opens/day to one plus actual changes**.
- **P14 APPLIED:** quiet Chill applies reversible 6–8x floors only to AAR/patch
  staging, in-memory health accounting, and storage hygiene. This removes about
  **57,684 auxiliary cycle wakeups/day**. Network Monitor, C2 Beacon, WFP,
  ETW/Sysmon, Defender/AMSI, USB, watchdog, and SOAR stay live and unthrottled.
- Gates: compile and Ruff PASS; focused idle/Chill tests **10/10**; wider
  lifecycle/Evolution/performance regressions **47/47**; edited module
  self-tests PASS. Behavioral-learning transaction batching and a longer
  connection snapshot TTL remain proposed because equivalence is not proven.

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

---

## Round 1 — Innovation

### 2026-07-29 enterprise visionary refresh

Researched current Microsoft, NIST, OCSF, and Windows platform guidance and
reviewed the present 64-module architecture, enterprise backlog, existing
Evidence Lattice/TECT/Cortex/receipt capabilities, and the optional custom
kernel bridge. Six defensive-only designs are ranked in
`analysis/loop/innovation_ideas.md`.

- **M / first:** Windows Kernel-Boundary Posture Ledger — user-mode Code
  Integrity, HVCI/VBS, vulnerable-driver-control, driver-load, and source-health
  evidence; the custom driver remains lab-only behind separate assurance gates.
- **M / first:** Transactional WFP Containment — exact scope, PID/start-time/hash
  revalidation, recovery exclusions, expiry, OS-side verification, and rollback
  receipts.
- **M / first:** Telemetry Loss Accounting — ETW/Event Log loss, cursor,
  freshness, queue, and quality epochs attached to derived detections.
- **M / next:** Deterministic Investigation Broker — short-lived read-only
  capability leases; model text cannot authorize tools or response.
- **M / next:** Evidence Reference Resolver — mechanically resolvable citations
  and transformation provenance for incident, AI, response, and compliance
  claims.
- **S-M / after containment:** Pktmon Counter Flight Recorder — consent-gated,
  counters-only network-path/drop evidence with no payload retention.

Each proposal includes exact integration files, abuse cases, resource budgets,
acceptance tests, limitations, and explicit defensive-only safety boundaries.

Research/design refresh completed 2026-07-19. Eight defensive-only proposals were
checked against the current code so existing behavioral baselining, trusted paths,
telemetry contracts, ARIA voice, OCSF/D3FEND, and action-policy foundations were not
re-proposed. Full architecture, implementation slices, limitations, safety gates,
and primary-source citations are in `analysis/loop/innovation_ideas.md`.

- **I1 (M, implement first): Proof-Carrying Purple Remediation.** The present
  simulated-finding "resolve" path marks a database row patched but does not prove a
  detector changed. Replace it with `OPEN -> CANDIDATE_READY -> VERIFIED`; a finding
  closes only after an opaque-token micro-probe produces exact sensor, detector, and
  signed-ledger echoes. This directly targets the reported 0% After-Action score.
- **I2 (M, suitable now): Trust Passports.** Locally bind process trust to canonical
  path, hash, Authenticode publisher, parent/update lineage, and network boundary.
  Learning creates review candidates, not automatic trust; trust can reduce noise but
  can never suppress memory, credential, tamper, or corroborated HIGH/CRITICAL signals.
- **I3 (M, suitable now): Push-to-Talk ARIA + deterministic Settings Pilot.** Add a
  visible press/hold mic, bounded memory-only capture, local transcript preview, and a
  small typed/confirmed settings grammar. Voice alone cannot authorize a write.
- **I4 (M-L, incremental): Settings Capability Cockpit.** One typed schema and atomic
  transaction path for GUI, Setup, console, and voice, with search, dependencies,
  privacy/CPU impact, live test, diff, restart status, and rollback.
- **I5 (S-M, audit now): Driver Shield Audit.** Read-only HVCI, vulnerable-driver
  blocklist, ASR, and Code Integrity posture with audit-first guidance; never silently
  deploy boot-critical WDAC policy.
- **I6 (L, phase): Privacy Receipt Broker + Remote Bridge v2.** Central fail-closed
  egress consent/receipts, immediate bridge bind/hostname containment, then versioned
  TLS 1.3 mutual authentication with no plaintext downgrade.
- **I7 (L, phase): Attested One-Click Installer.** Pin and lock the release, verify
  bundled binary provenance, publish SBOM/build attestation, install elevated code to
  an administrator-owned directory, and keep runtime data on the selected drive.
- **I8 (M, after typed settings): Evidence-Taint Firewall.** Preserve provenance of
  email/web/telemetry/model/speech context and allow only deterministic code to form
  action names, typed arguments, and canonical confirmation dialogs.

Recommended pass order: I1 verified drill closure; I4 foundation + I3 mic; I2 trust
passports; immediate I6 bridge containment and I7 release provenance; I5 audit card
if time remains. Sources include 2025 NIST SP 800-53 updates and Privacy Framework,
MITRE CTID continuous emulation, Microsoft App Control/driver/privacy guidance,
GitHub artifact attestations, TLS 1.3, and OWASP LLM01/LLM06.

## Cycle 3 / Round 1 — Performance

Six behavior-preserving fixes were applied after reviewing the current crash and
not-responding evidence. Full measurements and gates are in
`cycle3/round1/performance_summary.md`.

- EventBus subscriptions are idempotent across module restarts, and bounded
  `recent(20)` reads are 4.04x faster.
- Dashboard SQLite reads now use a zero-wait read-only connection; the existing
  writer-busy skip behavior remains, eliminating the captured multi-second COUNT
  wait without changing stored or displayed event meaning.
- Memory Time-Machine connection collection uses one attributed system snapshot
  instead of one scan per PID (60.97x faster in the measured 238-process case),
  with fail-safe fallback to the original per-process path.
- Speculative-triage cooldown state expires when it can no longer affect a
  decision; sequential Eco wake cancellation is race-free; Stop filters by
  process name before command-line reads (3.13x faster measured).
- Gates: 205/205 Python files compile; performance/lifecycle regressions 11/11
  PASS; MTM, SPEC, and Overdrive self-tests PASS. A concurrent remediation API
  change left one unrelated legacy drill-resolution assertion for that pass to
  reconcile. Alert-model virtualization and live cosmetic-governor consumption
  remain proposed pending Qt equivalence/load tests.

## Cycle 3 / Round 2 — Bug Test

- Final source compile **206/206 PASS**; module imports **64/64**, discovery
  **63/63**, with zero import/discovery errors and zero duplicate names/codes.
- Full project selfcheck **26/26 PASS**. Direct module self-tests returned 48
  truthy passes and 15 expected stopped/idle/optional-driver false states, with
  zero unexpected exceptions; module-level core/resilience/connector tests are
  **29/29 PASS**. Repository regressions are **32/32 PASS**.
- **Fixed:** Settings Save no longer crashes after the Mobile tab redirect;
  legacy Mobile values are preserved. The exact historical `_mob_chk` traceback
  was reproduced and the isolated save/persist/no-plaintext gate passes.
- **Fixed:** resilience manager/supervisor/ecosystem self-tests now use bounded
  observable readiness and a real throwaway restart instead of impossible fixed
  Windows startup/spawn-lock timing assumptions. All three re-pass.
- **Fixed:** the stale drill regression now enforces the proof-carrying two-run
  contract: candidate install stays VULNERABLE; a distinct caught rerun marks
  PATCHED.
- Focused secure-store, Remote Bridge, Purple Guard T1059, performance lifecycle,
  drill cancellation, shutdown ownership, scoped Ollama unload, YARA-X, and
  voice no-auto-download gates pass.
- **Reported:** Teams' nominally offline self-test contacts Microsoft JWKS when
  PyJWT is installed; Posture History SQLite is captured blocking the GUI; and
  the legacy AAR Remediation rate counts SOAR actions but not separately verified
  detector-fix closure. Full evidence: `cycle3/round2/bugtest_results.md`.

## Cycle 3 / Round 3 — Security, privacy, and performance convergence

- **Evidence-based remediation:** `purple_guard.py` now recognizes only exact,
  inert drill evidence in Angerona's dedicated sandbox (plus the exact tagged
  T1059 process contract). Installing a candidate cannot certify the run that
  produced the miss. A distinct caught rerun is required to change a tracked
  finding from VULNERABLE to PATCHED. The AAR separately reports correlated
  response success. This replaces the misleading same-run administrative closure
  behind the reported 0% behavior without inflating coverage.
- **Credential and cloud privacy:** optional credentials moved from a
  working-directory `.env` to a current-user Windows DPAPI store with restricted
  ACLs and explicit legacy migration. ARIA cloud fallback is default-off and, if
  enabled, receives only a bounded redacted question plus minimal posture—not
  live telemetry, runbooks, or raw host context.
- **Transport and scanner hardening:** Remote Bridge RBRG2 mutually authenticates
  peers and protects events with AES-GCM; Teams is loopback-default,
  allowlist-required, bounded, and fail-closed on JWT/service-host validation;
  SIEM forwarding defaults to verified TLS and redacts common identifiers; YARA
  scanning uses the in-process YARA-X engine and compile-gates rules rather than
  trusting an executable from the working directory or PATH.
- **Consent-gated incident bundles:** support/IR exports now require affirmative
  consent and enforce recursive secret/identity/path redaction, ephemeral network
  pseudonyms, symlink-safe allowlisting, archive/member budgets, stable hashes,
  and a privacy manifest. Raw command lines, executable paths, users/host names,
  credentials, DPAPI blobs, databases, keys, and arbitrary files are excluded.
  Focused privacy gates pass 9 tests with one unavailable Windows symlink-creation
  case skipped; the platform-independent symlink rejection equivalent passes.
- **Posture-history freeze fixed:** HUD reads now use a query-only zero-wait
  connection, a 150 ms progress budget, bounded caches, and indexed lightweight
  queries. On 100,000 points, the 32-column sparkline improved 393.088 → 82.785 ms
  (**4.75×**) and trend 713.001 → 47.795 ms (**14.92×**). Forced contention
  returns the cached value in 0.031 ms instead of reproducing the observed 5–8 s
  GUI wait. Full evidence: `cycle3/round3/performance_final.md`.
- **Settings, voice, and installer quality of life:** Settings gained search,
  privacy-default restoration, connector validation, and a fixed Save path after
  Mobile consolidation. The HUD has a direct **VOICE & MIC** setup button; model
  download is explicit or installer-driven and GUI construction performs no
  download. `Install-Angerona.bat` installs the constrained Windows/voice set and
  verified offline model; release builds pin Actions to commits and publish a
  checksum, SBOM, and build attestations.
- **Final gates:** module discovery **63/63**; repository suite **57 passed / 1
  platform skip**; headless `tools/selfcheck.py` **26/26 PASS**; ARIA self-tests
  **13/13 PASS**. The current dashboard/module documentation now uses 63.
- **Public-release blocker remains:** current-tree privacy cleanup does not erase
  earlier Git commits. Historical screenshots, local identity/path data, or
  removed artifacts may remain recoverable until the owner deliberately audits
  and rewrites/replaces history. No documentation claims that history is already
  scrubbed, and any credential ever exposed there must be rotated.
- **Proposed, not shipped:** full Trust Passports, Driver Shield audit, a central
  privacy-receipt broker, authoritative evidence-taint enforcement,
  posture-history retention/compaction, and virtualized burst-table rendering.

## Cycle 3 — Documentation complete (19 July 2026)

- `README.md`, root `llms.txt`, `analysis/README.md`, and `analysis/llms.txt` now
  distinguish shipped v1.9.3 behavior from the innovation backlog.
- Security/privacy language reflects DPAPI credentials, consent-gated incident
  export, authenticated/encrypted Remote Bridge, verified-TLS SIEM, bounded Teams
  authentication, sanitized opt-in cloud fallback, and in-process YARA-X.
- Verification totals are synchronized at 63 modules, 57 passed / 1 platform
  skip, 26/26 headless phases, and 13/13 ARIA checks.
- The protected one-click release install is the recommended route; the source
  bootstrap is explicitly contributor/developer mode. Neither path claims an
  Authenticode signature that does not exist.

## Cycle 3 — Final installer and public-tree gate (19 July 2026)

- The Windows installer now rejects Python below 3.10, avoids inherited
  PATH/current-directory executable resolution, constrains build dependencies,
  and fails instead of reporting success when the Angerona package is absent.
- Vosk remains wheel-only: a deterministic repository-owned compatibility wheel
  supplies its two used SRT APIs, followed by the audited Vosk wheel installed
  with `--no-deps`. The compatibility wheel was built, installed to an isolated
  target, metadata-checked as the Angerona-local `srt` compatibility distribution,
  imported, and exercised successfully.
- Frozen releases collect all dynamic Angerona modules and build both programs
  one-file. The Black Box is built first and its SHA-256 is embedded in the main
  executable; runtime launch requires an administrator-owned Program Files root,
  non-writable ACLs, no reparse points, and an exact digest match. The release
  installer re-verifies both files, installs them to `%ProgramFiles%\Angerona`,
  and keeps mutable state in protected `D:\AngeronaData` on fixed D: volumes,
  with protected ProgramData only as the no-D: fallback. Docs/playbooks and the
  verified offline voice model are bundled.
- Privileged native watchdogs require a valid Authenticode signature before
  launch. The source installer no longer compiles an inherited-PATH Go tool or
  creates an unelevated Black Box shortcut against administrator-only evidence.
- The current public tree uses a synthetic `DEMO DATA` dashboard and no longer
  contains the live dashboard captures, personal repository handle, local
  workstation/backup paths, bundled YARA executable, or shell shortcut.
- Twelve repository analysis DOCX files received a v1.9.3 appendix and path/
  identity scrub. Together with two root files and ten Desktop analysis copies,
  all 24 passed ZIP/XML, reopen, marker, body-text, and metadata privacy checks.
  Visual DOCX render QA remains unavailable because LibreOffice is not installed.
- The complete CPython 3.12 Windows release/tool dependency closure is pinned in
  `constraints-release.txt`. Source launch rejects an untrusted pre-existing venv
  and only accepts Authenticode-valid official Python/Ollama executables.
- Final revalidation: Python compile PASS; pytest **57 passed / 1 skipped**;
  application self-check **26/26**; ARIA **13/13**; tracked PowerShell syntax,
  14 public PowerShell files, 22 embedded batch PowerShell blocks, and 7
  release-workflow PowerShell blocks
  all parse successfully; the wheel-only dependency dry run resolves.
- Git history remains a release blocker: the audit confirms one personal author
  email and one commit containing removed sensitive screenshots. Rewriting or
  replacing history is intentionally deferred until the owner explicitly chooses
  that destructive publication step.

## Round 1 — Innovation

Cycle 4 research/design refresh completed 27 July 2026. Six defensive-only
proposals were checked against the 63-module tree and the prior innovation
backlog; no product code was changed. Full data flows, UI placement, safety
gates, tests, phases, limitations, and primary-source citations are in
`analysis/loop/innovation_ideas.md`.

- **1 / S–M — NTFS Journal Ransomware Pulse:** consume the native USN change
  stream for early, content-free burst detection; journal-only evidence can
  alert but can never invent a PID or trigger containment.
- **2 / S–M — NTLM Exit Radar:** build a pseudonymized local compatibility graph
  before Windows disables NTLM by default; hardening remains audit-first and
  review-gated.
- **3 / M — Stack-to-Image Provenance Fuse:** score the Sysmon call traces
  Angerona already captures and add targeted image/ETW enrichment, never
  always-on whole-host stack profiling.
- **4 / M–L — Local Model Airlock:** centralize model calls, then place a
  dedicated worker behind restricted-token/AppContainer filesystem, process,
  UI, and network boundaries.
- **5 / M — QUIC Sightline:** correlate MsQuic/SMB audit metadata, UDP ownership,
  DNS, and cadence without decrypting or retaining payloads.
- **6 / L — Split-Token Angerona:** keep UI/ARIA unelevated, isolate privileged
  read-only sensors, and use a short-lived typed action broker for approved host
  changes.

Research anchors include MITRE ATT&CK's May 2026 detection updates, Microsoft's
2026 NTLM and Administrator Protection direction, the June 2026 experimental
Windows sandbox API, Windows USN/Sysmon/MsQuic documentation, NIST AI 600-1, and
the HTTP/3 standard.

## Cycle 4 / Round 1 — Performance

- Inspected both diagnostics trees: 125 total recorded GUI stalls (root 101,
  runtime-data 24), including repeated table rebuild, SQLite, posture-history,
  allow-list, threat-intel, and heatmap stacks. Current runtime core status is
  340.8 MiB RSS / 38 threads; older stall dumps listed 80–87 mostly sleeping or
  queue-blocked threads. Native access-violation dumps remain non-attributable.
- **Applied:** ATT&CK technique event-ID retention now uses an O(1) bounded deque
  (**14.17×** saturated-hit micro-benchmark); Compliance Mapper's exact
  newest-2,000 history uses O(1) deque eviction (**3.90×**); HEAL skips unchanged
  crash-directory globs (**816×** at 2,000 filenames); StatusReporter reuses one
  consistent EventBus snapshot (**19%** lower snapshot time).
- **Proposed:** move Top Talkers connection/PTR work off Qt; retention/reuse-safe
  cleanup for network and forensics PID state; explicit Scapy sniffer stop/join;
  and a separately authorized fix for newest-first EventBus cursor consumers.
- Gates: changed-source `py_compile` PASS; focused performance tests **4/4**;
  combined performance regressions **26/26**; Compliance Mapper and HEAL module
  self-tests PASS. Full evidence:
  `analysis/loop/cycle4/round1/performance_summary.md`.

## Cycle 4 / Rounds 2–3 — Security, Purple proof, lifecycle, and recovery

- **Security/privacy:** live-alert cloud analysis now has its own default-off
  consent and a recursively redacted, bounded provider payload. Signed AAR
  verification and manual report resolution fail closed. Failed response events
  cannot inflate remediation, and temporary drill response is restricted to
  recognized drill artifacts/tagged drill processes inside the selected scope.
- **Blue/Purple:** Top Talkers OS/PTR and AI work plus Upgrade Console model
  discovery/checks run asynchronously with single-flight and stale-result
  guards. ARP capture uses generation-local shutdown. Purple candidates still
  require exact proof from a distinct later drill and a future miss reopens them.
- **Lifecycle/performance:** BaseModule restart is join-aware and monotonic.
  SPEC workers, AI recovery pingers, IPC acceptors/clients, and ARP helpers
  cannot overlap a new generation. Network socket/PID knowledge, Forensics
  capture memory, and HEAL filename state are pruned and bounded.
- **Watchdog/Core recovery:** the Watchdog window now has **Restart Angerona
  Core**. Target-specific authenticated command files prevent another supervisor
  from consuming the request. The watchdog clears SAFE_MODE, binds an adopted
  heartbeat PID to the configured executable and Angerona command identity,
  terminates that Core, and relaunches it. A failed identity-safe termination
  refuses the restart instead of spawning a duplicate. Dead/suspended Core
  respawn remains automatic.
- **Final integrated gates:** repository pytest **133 passed / 1 skipped / 0
  failed**; focused Cycle 4 regressions **49/49**; headless self-check **26/26**;
  ARIA **13/13**; compile and diff checks PASS; module discovery **63**; offscreen
  watchdog-window control smoke test PASS.
- **Public-release scan:** no tracked runtime database/log/settings/secret dump
  paths and no live operator screenshots were found in the current tree. Future
  commits use a GitHub noreply identity. Existing commit history still contains
  the prior personal author email and requires an intentional rewrite or a clean
  public repository. Current release bundles are not Authenticode publisher
  signed; checksums, SBOMs, and provenance do not replace that identity boundary.

## Cycle 4 / Enterprise foundation implementation

- **Manifest-gated extensions:** external Python modules are verified before
  import against a detached Capability Manifest v1. The signed record binds the
  exact source hash, compatibility, entrypoint, permissions, event/MITRE
  declarations, privacy/egress/retention, resource budgets, and publisher.
  Trusted Ed25519 keys are explicit; unsigned external modules fail closed unless
  the operator deliberately enables hash-pinned development mode.
- **Causal incident reasoning:** a pure read-side builder consumes bounded recent
  facts and produces bounded process/file/network/response/proof graphs. PID
  generations and TTL gaps prevent unrelated process reuse from merging.
  Structural and temporal edges are distinct, and each relationship includes
  its evidence basis and confidence. The graph neither subscribes to the hot bus
  nor authorizes containment.
- **Proof receipts:** remediation-log entries now carry privacy-minimized,
  HMAC-authenticated receipts chained to the predecessor. The receipt binds the
  canonical record digest and verification state; an applied action without a
  passed postcondition cannot validate as proof. Retention checkpoints preserve
  verification after bounded log pruning.
- **Operator/API surface:** Settings adds an Enterprise readiness tab plus
  bounded causal snapshot. Console `enterprise`/`readiness` and local MCP
  readiness/causal tools expose the same read-only evidence. Existing MCP alert,
  health, and incident outputs were corrected to use canonical model fields.
- **Enterprise limits kept explicit:** fleet enrollment/mTLS, organization RBAC
  and audit, signed central policy distribution, cross-endpoint search/storage,
  high availability, and analyst case management are not claimed as shipped.
  Manifest permission declarations are auditable contracts, not yet an OS
  sandbox; receipt authenticity does not defend against a fully compromised
  in-process authority.
- **Verification:** repository pytest **133 passed / 1 platform skip / 0
  failed**; self-check **26/26**; ARIA **13/13**; module discovery **63 / 0
  errors**; compile scan and diff check PASS. A synthetic 100,000-event graph
  run completed in **2.958 s** (**29.58 μs/input event**), retained 1,000 events,
  respected the 2,500-node cap, and added about **3.81 MiB RSS**.

## Cycle 5 / Round 1 — Performance

- **Applied:** the GUI telemetry reader now reuses one thread-owned read-only
  SQLite connection and advances through new events with an indexed rowid
  cursor, preserving the initial newest-200 snapshot, oldest-first batch order,
  200-row backpressure, and complete burst draining.
- **Corrected:** removed invalid `QThread.setDaemon(True)`, which prevented the
  telemetry worker from being constructed under PySide6.
- **Measured:** 1,000 idle polls over a 5,000-row database fell from
  **2,338.7 ms to 156.6 ms** (**14.9x faster; 93.3% reduction**).
- **Gates:** changed-source `py_compile` PASS; focused SQLite/PySide6 cursor test
  PASS (initial 200, subsequent 250 drained as 200 + 50, zero duplicates).
- **Proposed:** replace the remaining 20 Hz EventBus snapshot poll with a bounded
  subscription queue, and share immutable recent-event snapshots across GUI
  refresh consumers after lifecycle/API integration coverage is added.
- Full evidence:
  `analysis/loop/cycle5/round1/performance_summary.md`.

## Cycle 6 / Round 3 — Performance

- Post-change telemetry regression PASS: 1,000 idle SQLite cursor polls over
  5,000 rows completed in **216.4 ms (216.4 µs/poll)**.
- Resolve Center remains bounded to 25 rendered rows: unchanged refresh calls
  measured **115.7 µs/call**; forced 5,000-event refreshes measured
  **3.38 ms/call**.
- Kernel posture work runs off the GUI thread every 300 seconds with bounded
  registry enumeration, ledger retention, and command timeouts. WFP scans run
  off the GUI thread every 30 seconds with a five-second connection cache. No
  tight loop or new blocking UI path was found.
- Gates: focused tests **15/15 PASS**, changed-module compile PASS, full `src`
  compile scan PASS. No product-code correction was required.
- Full evidence:
  `analysis/loop/cycle6/round3/performance_summary.md`.

## Cycle 6 / Round 2 — Remediation

- Teams development authentication is now ephemeral and direct-loopback only;
  forwarded/tunnelled and non-local requests always require a valid JWT.
- Shutdown authority is separated from EventBus signing, invalid keys fail
  closed, and packaged/elevated-launcher key ACL establishment is mandatory.
- Elevated source launch now rejects redirected, incomplete, and non-fixed
  trust roots. Full equivalence to a signed admin-owned installation remains
  deferred because an editable source checkout is intentionally user-writable.
- Gates: changed-file compile PASS; Teams and shutdown self-tests PASS; focused
  security suites **12 passed / 1 platform skip / 0 failed**.

## Cycle 6 / Round 3 — Remediation

- Elevated startup now establishes the protected runtime parent before any key
  access. Unsafe pre-existing authorities are quarantined without consuming
  attacker-known bytes; new-key creation inherits the final protected boundary.
- The optimized GUI telemetry cursor now verifies every persisted Event HMAC.
  Forged/tampered rows become canonical Critical integrity alerts while the
  indexed cursor and bounded reads remain intact.
- Gates: changed-file compile and PowerShell parse PASS; relevant self-tests
  PASS; regression suites **39 passed / 1 platform skip / 0 failed**.
- Architectural limit: user-mode ACLs do not defend against a compromised
  Administrator/SYSTEM principal or a hostile handle opened before repair.

## Cycle 6 / Round 3 — Bug Test

- Compiled **233/233** package files; full pytest completed **223 passed / 2
  skipped / 0 failed**.
- Discovered **65** uniquely named modules with zero discovery errors; imported
  all **67** module files without error.
- Fixed the headless self-check's narrow cross-platform classification bug:
  the explicitly macOS-only observe sensor is now a skip on Windows, while any
  other sensor failure remains actionable. Final self-check: **26/26 PASS**.
- ARIA component harness: **13/13 PASS**. Module stress drill: **51 passed / 15
  expected environment or platform skips**.
- No fresh crash/freeze evidence exists after 2026-07-19. Historic GUI stalls
  predate the bounded-table, cursor, and refresh work and require production
  soak validation rather than another speculative code change.
- Full evidence:
  `analysis/loop/cycle6/round3/bugtest_results.md`.

## Cycle 6 — Documentation Reconciliation

- README and both llms mirrors now describe the Teams tunnel-bypass closure,
  protected and separated key custody, HMAC-verified telemetry cursor,
  kernel-boundary posture ledger, transactional WFP planning boundary, live
  telemetry coverage accounting, Resolve Center pagination, and measured
  telemetry performance.
- Enterprise backlog statuses moved only to PARTIAL where acceptance evidence
  exists: ENT-ING-004, ENT-NET-006, and ENT-PERF-009. Durable fleet
  deduplication, a privileged WFP enforcement broker, and a complete
  bound/eviction audit remain open.
- Public claims explicitly retain the user-mode, editable-source,
  privileged-broker, kernel-driver-lab, tamper-proof, and certification limits.
- Recorded Cycle 6 gate is **223 passed / 2 intentional platform skips**,
  compile **233/233**, discovery **65 / 0 errors**, self-check **26/26**. A later
  aggregate count must be accompanied by its matching test transcript.
- Package version remains **1.9.4**; Cycle 6 is documented as current
  development rather than an invented release.

## Round 4 - Performance

- Purple Guard now parses one coherent remediation-policy snapshot per active
  cycle instead of three, reducing policy reads by **66.7%** without changing
  signatures or cadence.
- EventBus exposes a process-local publish revision, allowing Purple Guard to
  skip an unchanged 500-event classify walk. The isolated unchanged-scan path
  measured **168.6x faster**, while new publishes and policy enablement always
  force a recheck.
- System Pulse now reuses one sleeping sampler worker rather than creating a
  native thread every two seconds, eliminating **1,800 thread creations/hour**
  while preserving off-GUI-thread sampling and shutdown behavior.
- Gates: changed-source compile and Ruff PASS; focused suites **53/53 PASS**;
  Purple Guard self-test PASS; diff check PASS.
- Full evidence: `analysis/loop/round4/performance_summary.md`.

## Round 4 — Bug Test

- Package compile completed **277/277** twice; all **67** module files imported,
  **65** modules discovered with no errors, all **53** exposed `register()`
  functions constructed, and no duplicate module `CODE` was found.
- Module self-tests recorded **51 passes / 15 expected environment, stopped, or
  platform skips**; all **18** runnable core self-tests passed.
- Fixed the non-admin selfcheck startup regression: the diagnostic now uses a
  per-process D: workspace sandbox instead of the ACL-protected production
  flight recorder. Final selfcheck: **26/26 PASS**.
- Focused enterprise regressions: **133/133 PASS**. Full serial suite: **705
  passed / 2 intentional platform skips / 0 failed**. A post-performance-agent
  regression added **34/34 PASS**.
- The two-second soak smoke profile passed, but remains plumbing-only evidence;
  it does not replace an 8-hour or 24-hour live-runtime soak.
- Full evidence: `analysis/loop/round4/bugtest_results.md`.

## Round 5 — Innovation

- Completed a research/design-only audit of current enterprise capabilities and
  2025–2026 primary sources; full report:
  `analysis/loop/round5/innovation_recommendations.md`.
- Ranked five offline-first, Windows user-mode additions: App Control Policy
  Evidence Ledger; Signed Local Model Admission + ML-BOM; ClickFix and LOLBin
  Behavior-Chain Pack; Detection Contract v2 (ATT&CK v19 + Sigma 2.1); and
  ZTDNS/ECH-Aware Name-to-Flow Evidence.
- Existing HMAC evidence transport, typed hunts/cases, detection-package
  signing, identity/NDR foundations, AI broker, kernel posture, and WFP planning
  are reused. Earlier NTFS Journal, NTLM Exit, call-stack, model-airlock, QUIC,
  and split-token proposals were not relabeled as new work.
- All proposals are passive or policy-gated, defensive-only, and explicitly
  exclude kernel additions, cloud dependencies, payload decryption, arbitrary
  executable rules, and automatic enforcement. No product code or host policy
  changed in this round.

## Round 4 - Red Team

- R4-01 HIGH - Privileged startup trusts inherited environment values before
  hardening, allowing trusted-tool resolution and watchdog/core command control
  to cross the UAC boundary.
- R4-02 HIGH - First fleet migration accepts an inherited legacy secret and
  deterministically turns it into the tenant-operator credential.
- R4-03 HIGH - The loopback URL policy validates localhost but the default
  urllib proxy handler can route plaintext local-model prompts off-host; DNS
  resolution is not pinned to the validated peer.
- R4-04 MEDIUM - DPAPI/Keychain-protected provider, mail, and connector secrets
  are republished into the global environment and inherited by unrelated
  sidecars and interactive shells.
- R4-05 MEDIUM - Generated fleet credentials have no fixed expiry, while the
  service-account expiry is recalculated on every restart and therefore rolls
  forward indefinitely.
- No fleet HTTP framing, replay, tenant-authorization, or tracked-public-tree
  secret bypass was confirmed. Full evidence and tests:
  `analysis/loop/round4/redteam_findings.md`.

## Round 1 — Innovation

2026-08-20 visionary/enterprise challenge completed. Seven defensive-only
proposals were researched against the current 65-module tree and canonical
enterprise backlog; prior USN, NTLM, call-stack, QUIC, split-token, App Control,
model-admission, ClickFix, ATT&CK/Sigma, and ZTDNS designs were deliberately not
recycled. Ranked proposals cover a privacy-minimized crash breadcrumb capsule,
RMM/remote-support session trust, read-only WinRE/QMR readiness, Windows
Hello-bound response approval, current MCP tool/data provenance, purpose/epoch
telemetry tokens, and browser-session-theft correlation. The recommended
low-risk cut is diagnostic-only crash breadcrumbs plus read-only QMR posture.
Full threat models, architecture slices, tests, performance budgets, safety
boundaries, and primary-source citations are in
`analysis/loop/innovation_ideas.md`; no product code or host policy changed.
## Round 1 — Red Team (Cycle 7, 2026-08-20)

- C7-R1-01 HIGH — Authenticated Remote Bridge telemetry can supply receiver-local PIDs and attacker-selected module identities that satisfy default SOAR active-defense corroboration and trigger local process containment.
- C7-R1-02 MEDIUM — Threat Intel says an AI fix ran successfully even though the hardened backend only stages an inert review file.
- C7-R1-03 MEDIUM — “No fix” or unavailable AI can bulk-ignore applicable CISA KEVs and remove them from threat scoring.
- C7-R1-04 MEDIUM — A hung in-process “isolated” self-test can keep all modules stopped and EventBus publishing muted indefinitely.
- C7-R1-05 MEDIUM — Release dependencies are version-pinned but not artifact-hash locked, so provenance can faithfully attest a compromised upstream build input.
- C7-R1-06 MEDIUM — The constant-AppId Inno installer has no downgrade gate and uses `ignoreversion`, allowing an older genuine release to overwrite a fixed build.
- Expanded known R4-01: inherited `ANGERONA_DATA` reaches an elevated recursive DACL reset without canonical-path confinement; not counted as a new finding.

## Round 1 — Bug Test (Cycle 7, 2026-08-20)

- Reproduced a fresh native `Qt6Core.dll 6.11.1 / 0xc0000409` abort during the
  aggregate suite and fixed a concrete early-destruction path: AnalysisWorker
  no longer shadows native `QThread.finished()` with a result payload signal,
  and workers are reaped only after native completion.
- Post-fix Qt lifecycle stress passed **30/30** fresh-process repetitions with
  no subsequent crash dump. Final compile: **279/279**; module discovery:
  **65 / 0 errors**; module self-tests: **51 pass / 15 expected skips**; core
  self-tests: **18/18**; selfcheck: **26/26**.
- Reported a real Windows Fleet API shutdown race: stalled handler interruption
  failed **2/20** isolated repetitions and could retain the replay-ledger file
  handle. Explicit host sleep/resume grace and legacy manual engine write paths
  also remain open validation/remediation work.
- The latest combined aggregate completed without a Qt abort at **731 passed /
  2 platform skips / 1 reported Fleet shutdown failure**. Full evidence:
  `analysis/loop/cycle7/round1/bugtest_results.md`.

## Round 2 — Performance (Cycle 7, 2026-08-20)

- Purple Guard now identity-caches unchanged remediation policy JSON. A 5,000
  call benchmark improved **2.26x** and removes up to **86,399 redundant file
  opens/parses per active day** while atomic/in-place updates invalidate on the
  next cycle.
- Expanded Console refresh now uses Qt document revisioning. The unchanged
  804-KiB transcript benchmark improved from **3.708455 s to 0.002480 s for 500
  ticks (1,495x)** while changed output still renders immediately.
- System Pulse details copy history and rebuild graph/table state only for a new
  two-second sample; 20 unchanged refreshes caused zero copies/rebuilds.
- Module-resource and Top-Talkers views skip unchanged Qt table reconstruction;
  20 unchanged-refresh regressions caused zero rebuilds and changed evidence
  invalidated immediately.
- Gates: owned compile and Ruff PASS; Purple Guard self-test PASS; focused suite
  **34/34 PASS**; wider owned/relevant suite **70/70 PASS**. Full evidence:
  `analysis/loop/cycle7/round2/performance_summary.md`.

## Round 1 — Remediation (Cycle 7, 2026-08-20)

- C7-R1-02 FIXED — Threat Intel now renders model-authored CVE PowerShell as an
  inert **staged — not executed** proposal and never claims an unverified fix ran.
- C7-R1-03 FIXED — removed AI/no-fix bulk suppression; only an expiring, evidenced,
  approved `not_applicable` record can leave KEV threat scoring. Legacy ignores
  fail safe and become active.
- C7-R1-04 FIXED — Sandbox opening no longer pauses sensors or mutes EventBus;
  self-tests run in a disposable child with sanitized integrations and a hard
  deadline. Three consecutive never-returning probes were terminated on time.
- C7-R1-06 FIXED — Setup rejects versions older than the protected highest
  installed version and persists the monotonic marker under HKLM64.
- Gates: Python compile PASS; focused suite **7 passed, 1 environment skip**;
  CVE advisor, CVE exclusion, and Intel Sync self-tests PASS; local ISCC was not
  installed, so real installer compilation remains a release-CI gate. Details:
  `analysis/loop/cycle7/round1/remediation_summary.md`.

## Round 3 — Adversarial Re-challenge (Cycle 7, 2026-08-20)

- C7-R3-01 MEDIUM — authenticated Remote Bridge telemetry is correctly
  observe-only for SOAR and has receiver-local PID/path keys stripped, but the
  Evolution Engine still trusts peer-controlled `verified=SUCCESS` + `technique`
  fields and can start local work and replace the active generated YARA rule.
- C7-R1 verification: **4 resolved / 2 partial or open**. Threat Intel truth,
  AI/no-fix suppression, hung sandbox blackout, downgrade protection for the
  first public release, inherited data-root overwrite, and AnalysisWorker native
  completion ordering passed re-challenge. Remote mutating-consumer coverage and
  the elevated source installer's unhashed pip path remain open.
- Gates: focused tests **18/18 PASS**; malicious remote SOAR challenge **8 events
  / 0 actions**; remote Evolution proof **1 unauthorized activation**; hung-test
  cleanup **5/5 with 0 surviving descendants**; additional fresh-process Qt
  lifecycle stress **15/15 PASS** and no post-fix crash event.
- Full evidence:
  `analysis/loop/cycle7/round3/adversarial_verification.md`.

## Round 2 — Bug Remediation Follow-up (Cycle 7, 2026-08-20)

- C7-BT-02 FIXED — Fleet shutdown now atomically rejects setup-racing sockets,
  interrupts registered readers through a service-owned event, drains handlers
  before closing the durable replay ledger, and returns a reliable saturation
  503 on Windows. Stalled shutdown passed **25/25** isolated repetitions;
  saturation passed **20/20**; new internal partial/setup races passed **15/15**
  and **10/10** respectively.
- C7-BT-04 FIXED — Unified Defense/EDR status, the legacy flight recorder, and
  Defense Monitor payload staging now use the canonical Angerona data/temp
  helpers. Relative database overrides can no longer escape into the working
  directory; explicit absolute operator overrides remain supported.
- Gates: compile and Ruff PASS; focused suite **25/25 PASS**; wider Fleet suite
  **78/78 PASS**. Full evidence:
  `analysis/loop/cycle7/round2/remediation_followup.md`.

## Round 3 — Adversarial Closure (Cycle 7, 2026-08-20)

- C7-R3-01 FIXED — Evolution Engine now rejects observe-only remote evidence
  before peer-controlled verification fields can trigger local YARA mutation;
  post-fix Remote Bridge security tests pass **4/4**.
- C7-R1-05 FIXED — packaged and elevated source dependency paths are SHA-256
  locked. The source bootstrap is explicitly CPython 3.12 x64 and contains no
  unhashed pip/requirements/Vosk fallback. Release/source trust gates pass
  **32/32**.
- The exact SHA-256-verified Inno Setup 6.7.1 compiler parsed and compiled the
  complete installer locally with placeholder payloads. Real release binaries,
  clean install, upgrade, and downgrade rejection remain CI/VM acceptance gates.

## Round 3 — Full Validation (Cycle 7, 2026-08-20)

- Final current-tree compile completed **279/279**; all **67** module files
  imported; all **53** registration factories constructed; discovery completed
  **65 modules / 0 errors**; **48** module codes had **0 duplicates**.
- Module self-tests recorded **51 passes / 15 expected environment, idle, or
  platform skips / 0 unexpected failures**. Runnable core self-tests completed
  **18/18**, and the final headless selfcheck completed **26/26**.
- The first aggregate reproduced the known Windows Fleet partial-request
  shutdown race at **732 passed / 2 skipped / 1 failed**. After remediation,
  the authoritative final aggregate completed **744 passed / 2 intentional
  platform skips / 0 failed**; the final crash/lifecycle/remediation/security/
  performance/release focus set completed **34/34**.
- Ruff, documentation drift, source-trust preflight, workflow policy, and diff
  checks passed. No new crash dump or Windows crash/hang event appeared after
  the 21:58 validation start; the newest Python dump remains the pre-fix 21:25
  Qt event.
- Bandit was unavailable in the venv. Physical sleep/resume, a long interactive
  live-sensor/Ollama soak, and clean-VM release acceptance remain explicit
  external gates. Full evidence:
  `analysis/loop/cycle7/round3/full_validation.md`.

## Round 19 — Bug Test

- Baseline: **283/283** package files compiled; **66 modules / 0 discovery
  errors**; module self-tests **51 pass / 16 expected skips / 0 unexpected
  failures**; core self-tests **18/18**; headless selfcheck **26/26**.
- **C19-BT-01 FIXED (High):** both SOAR response tiers now re-verify EventBus
  HMAC integrity at the final action sink; Active Response also rechecks its
  configured response scope. A post-signature PID/path mutation now causes zero
  process or file mutation. Post-fix security gates: **30/30 pass**.
- Flood challenge: **40,000** signed events, no loss in the authoritative
  recorder/DLQ path, bounded SQLite/read-model rows, clean worker drains, and no
  crash. **C19-BT-02/03 REPORTED:** synchronous overflow spilling limited the run
  to about **1,182 events/s**, and the unbounded DLQ grew to **7.23 MB** in one
  run; performance/remediation owns a bounded authenticated spool/replay design.
- Drill closure lifecycle passed: applied remains unverified, the source run
  cannot self-certify, and a separate exact Purple Guard proof changes the AAR
  from 0% to **1/1 (100%)** verified closure. Lifecycle challenge: **100**
  start/stop cycles, **0** leaks; crash probe quarantined after 3 attempts and
  wrote its diagnostic snapshot.
- Full evidence: `analysis/loop/cycle19/bugtest.md`.

## Cycle 19 — Final Convergence (2026-08-21)

- Full Setup now has one 16-step path across installer first-run, the GUI SETUP
  button, `--setup`, and `angerona-setup`; integration secrets and the Signal PIN
  use OS-protected storage.
- The Windows inherited-environment/UAC launcher chain is closed. Supervised
  children and operator shells receive allowlisted, secret-free environments.
  R4-04 child secret propagation is fixed; a just-in-time in-process credential
  broker remains architectural debt for legacy in-process consumers.
- C19-RT-01 is fixed. Linux x86-64 and macOS arm64 source/release paths verify
  exact filename, size, and SHA-256 for 75 wheels per target before offline
  installation. Intel macOS fails closed until a safe current wheel exists.
- The recorder flood path improved from 33.855 seconds to 2.080 seconds for
  40,000 events (16.3x) without losing authoritative evidence. Overflow now uses
  a bounded authenticated 64 MiB spool with replay receipts, quarantine,
  backpressure, bounded shutdown, and a fix for the final full-cap replay
  deadlock.
- SOAR re-verifies Event HMAC at action time; shutdown token future-skew/replay
  state and Signal sender identity fail closed. A software-HMAC visibility MVP
  reports healthy/degraded/blind/untrusted without raw telemetry or response
  authority; it is not hardware-backed attestation.
- Final red-team outcome: **0 Critical / 0 High / 1 Medium**, with the Medium
  supply finding fixed. The public-tree secret scan is clean; historical Git
  author email remains operator-owned history privacy debt and was not rewritten.
- Final gates: **839 passed / 3 intentional platform skips / 0 failed**;
  **66 modules / 0 discovery errors**; selfcheck **26/26**; focused final group
  **84/84** and performance/settings **18/18**. Ruff, compileall, source trust,
  workflow YAML/policy, diff checks, documentation drift, requirements audit
  (0 known vulnerabilities), and Bandit Medium/High (0 findings; warnings only)
  pass. No post-fix crash was observed.
- External gates remain explicit: native target-runner release execution,
  clean-machine lifecycle, publisher signing/notarization, physical sleep/resume,
  long elevated soak, independent assessment, production fleet identity/HA, and
  a hardware-backed visibility proof.
- Visionary proposals remain backlog except for the bounded software-HMAC
  visibility MVP. Full ranking and implementation gates are in
  `analysis/loop/cycle19/innovation.md`.

## Cycle 19 — Device Security Lab and Scan Center Addendum (2026-08-21)

- Device Security Lab adds an owner-authorized Red Team tab for passive, local
  USB, Ethernet, Wi-Fi, Bluetooth, and display/HDMI posture. File-based
  companion enrollment uses short-lived Ed25519 proof-of-possession; only the
  public key/fingerprint is retained by the controller. Evidence is signed,
  fresh, replay-protected, and redacted.
- The lab exposes no target address, listener, active scanner, exploit, packet,
  credential, or response action. Pinned mutual-TLS companion transport remains
  a future gate.
- Live Alerts now opens Scan Center: bounded
  symlink/reparse/UNC/remote-mount-safe YARA-X/metadata path scans, passive local
  listener audit, privacy-safe aggregate network posture, trusted `MpCmdRun`
  Defender orchestration, cancellation, progress, and export.
- Custom Defender scans disable remediation. Quick/full scans may apply only
  configured Windows Security actions. Angerona complements rather than
  replaces Defender's kernel, AMSI, cloud, and reputation stack.
- Updated authoritative evidence: **839 passed / 3 intentional platform skips /
  0 failed**; discovery **66 modules / 0 errors**; selfcheck **26/26**;
  compileall, Ruff, source-trust, workflow-policy, and diff checks pass.

## Round 6 — Bug Test

- Chill/threat/drill regression: **296/296 compiled**, **66 modules / 0 discovery errors**, module self-tests **51 pass / 16 expected skips / 0 unexpected failures**, selfcheck **26/26**, and full pytest **902 passed / 3 intentional skips**.
- Fixed revision-safe active-threat wake-up, Chill Ollama leases, cancelled sequential-wake state recovery, strict Windows autostart XML validation, and active-only Daily Briefing posture semantics.
- Headless Chill orchestration remains reported for a GUI-neutral controller. Full evidence: `analysis/loop/round6/bugtest_results.md`.

## Round 7 — Bug Test

- Release QA compiled **297/297** package files, imported **125/125** core
  modules, discovered **66 modules / 0 errors / 0 duplicate codes**, passed core
  self-tests **18/18**, module self-tests **51 pass / 16 expected skips / 0
  unexpected failures**, and selfcheck **26/26**.
- The final aggregate passed **1026 tests / 3 intentional platform skips / 0
  failures**. The added launcher/repair/autostart regressions pass, and the
  async lifecycle file passes **5/5** with its timing assertion robust to cold
  Qt initialization. Ruff, Bandit Medium/High, dependency audit, PowerShell parsing,
  privacy scan, launcher bootstrap, and repeated async Qt lifecycle gates pass.
- Fixed four release regressions: an existing unsupported Python 3.14 venv could
  bypass the reviewed 3.12 launch boundary; Full Setup omitted the deception
  privacy switch; a transport source guard mistook a dictionary lookup for an
  HTTP request; and the push helper could push after a failed commit. The new
  confirmed source repair preserves the old venv and installs only the
  Authenticode-verified 3.12/hash-locked environment.
- At the Round 7 checkpoint, protected autostart still targeted the unrepaired
  3.14 venv and was not trusted. The later Cycle 22 operational check completed
  repair and live-reconciled it to CPython 3.12 `pythonw -m angerona --chill`.
  Full Round 7 evidence:
  `analysis/loop/round7/bugtest_results.md`.
- Python 3.12 follow-up fixed an async-recorder overflow lock convoy. The
  bounded C-backed queue preserves lossless synchronous fallback. Because a
  fixed five-second cutoff still varied with the live host at 93% CPU, the
  unchanged 40,000-event challenge now gates exact losslessness/bounds plus
  at least 95% async routing and real batch aggregation instead of machine
  speed. Loaded challenge passed **3/3**, async/priority suite **10/10**, and
  Ruff passed.

## Cycle 22 — Final convergence and documentation (2026-08-22)

- The unattended runtime is now explicitly network-first: Chill/autostart parks
  high-I/O and AI-heavy work, runs sparse maintenance sequentially, unloads the
  local model while idle, and wakes the fuller path only for authenticated
  active-threat evidence. Practice, exposure, and health events remain visible
  but do not drive global Critical posture.
- Live Chill profiling found presentation—not sensor polling—as the dominant
  idle CPU source. Dashboard presentation now uses 5s active-Chill / 10s
  inactive / 15s hidden cadences with elapsed-time-equivalent panel periods;
  High/Critical evidence receives one coalesced immediate GUI wake. ARIA motion
  fully stops in Chill/inactive/hidden, and minimized Watchdog/Scanner UI uses a
  cached 10s refresh. Sensor and supervisor recovery cadence is unchanged.
- Live Alerts, SOAR, Scan Center, and USB trust now form one bounded operator
  workflow: direct queueing, authenticated review/execute controls, responsive
  cancellable scans with honest Defender liveness, and protected PIN approval
  bound to removable-volume identity.
- Windows source state and default deception stay under canonical D:-drive data
  helpers. Personal-folder deception is explicit opt-in. Migration and protected
  stores reject link/junction, overlap, special-file, and unsafe-root cases.
- Qt lifecycle guards and authenticated/replay-checked heartbeat v2 address the
  observed close/reopen and watchdog authority failures. Process control still
  requires verified process identity and existing restart budgets. FRZ now emits
  the authenticated 32-byte v2 record instead of its legacy 16-byte raw map.
- JARVIS remote-control authority is now SecureStore-only; inherited tokens are
  scrubbed before elevation/runtime, and Setup provides masked enrollment and
  regeneration. FRZ v2 uses a distinct binary identity and pinned Go module
  graph. Go was unavailable, so native compilation remains external evidence.
- Red-team closure is now exact and report-bound. A distinct Test Fix run must
  prove positive detection, negative-control quiet, persisted detector evidence,
  authenticated EventBus evidence, real SOAR response/cleanup, and signed
  receipt; expiry or a later miss reopens the gap. No blanket 100% claim is made.
- The enterprise comparison yielded a privacy-preserving case upgrade: typed
  human-reviewed observables and bounded similar-case results use a derived-key
  HMAC private index; sanitized exports contain only aggregates. Distributed
  enterprise tenancy, HA, identity, and infrastructure remain external gates.
- Release boundaries now reject an existing incompatible CPython 3.14
  environment, provide a typed and rollback-preserving verified 3.12 repair, and
  stop the Git push helper after staging/commit failures. Bootstrap pins the
  reviewed pip 26.2.1 wheel by verified SHA-256 before dependencies and refuses
  a version mismatch. Manual release branch names also map to deterministic,
  path-safe artifact names without changing tag names. That repair completed on
  this host, and protected
  autostart was live-reconciled to the CPython 3.12 Chill entry. The validator
  recognizes Task Scheduler's omitted `RunLevel` as the Limited default only for
  the expected `InteractiveToken` principal; fresh-logon, clean-machine, and
  sleep/resume acceptance remain external.
- The F: backup helper now validates its fixed destination and repository root,
  rejects reparses/junctions/path escapes, excludes secret/runtime/cache/model/
  build state, and cleans stale private state before and after mirroring. Its
  `--validate-only` mode is non-destructive; no real mirror ran during this gate.
- Authoritative evidence: **1026 passed / 3 intentional platform skips / 0
  failed**; **66 modules / 0 discovery errors / 0 duplicate codes**; selfcheck
  **26/26**; core self-tests **18/18**; Ruff, Bandit Medium/High, and `pip-audit`
  clean. The concise record is
  `analysis/loop/cycle22/three_loop_summary.md`; canonical documentation is
  README + both `llms.txt` copies + the consolidated Cycle 22 master manual.

## Round 8 — Host Adaption Red Team

- Five Medium weaknesses were confirmed in the first implementation: stale
  automation authority, missing effective-state postconditions, over-broad
  exceptions/feedback, weaker SSID precedence over Public context, and
  incomplete collector identity/coverage.
- The pass also required trusted absolute Windows tool paths, a sanitized child
  environment, more explicit recovery evidence, and honest reporting when a
  bounded collector is partial.
- No real firewall policy was changed. Full evidence:
  `analysis/loop/round8/redteam_findings.md`.

## Round 8 — Host Adaption Remediation

- All five findings were fixed with revision/CAS authorization, final
  pre-execution context checks, a single-flight apply/rollback transaction,
  effective ActiveStore postcondition verification, automatic verified recovery,
  exact anomaly fingerprints, three-distinct-review feedback gating, and
  strongest-posture context ordering with no automatic relaxation.
- Service, listener, firewall-profile, and bounded firewall-rule collectors now
  carry explicit quality metadata. Missing coverage is never scored as healthy.
  A final live read-only check also fixed profile collection to request
  `Get-NetFirewallProfile -PolicyStore ActiveStore` explicitly.
- Deferred: deep firewall program/service/address/port filter joins, service
  executable signer/content-hash attestation, crash-independent trial leases,
  and event-driven context wakeups. Full evidence:
  `analysis/loop/round8/remediation_summary.md`.

## Round 8 — Bug Test

- Host-adaptation QA compiled **304/304** package files, imported **129/129**
  core modules, passed core self-tests **19/19**, discovered **66 modules / 0
  errors / 0 duplicate codes**, and passed selfcheck **26/26** through both the
  Python harness and batch wrapper.
- The final aggregate after adversary/remediation convergence passed **1077
  tests / 3 intentional platform skips / 0 failures**; the final focused
  host-adaptation/UI/performance set passed **20/20**.
- Fixed context re-entry proposal de-duplication, conservative multi-network
  Public-category detection, and batch self-check exit-code propagation. Real
  elevated firewall mutation/rollback and physical mixed-network topology
  remain controlled external acceptance gates. Full evidence:
  `analysis/loop/round8/bugtest_results.md`.

## Round 8 — Visionary

### Host Adaptation visionary pass (2026-08-24)

- Reviewed the new Adaption core/workbench against current Microsoft, NIST, and
  CISA primary guidance. The shipped design already separates audit, preview,
  simulation, approval, snapshot, apply, rollback, context automation, feedback,
  and activity with a closed firewall profile catalog.
- Ranked **9 defensive, buildable proposals**. Safe immediate priorities are a
  collector-quality contract, restrictive context lattice with hysteresis,
  effective Firewall ActiveStore/GPO/MDM ownership checks, an authenticated
  single-flight action journal, versioned baseline promotion, and event-driven
  drift provenance.
- Longer-term gates are a health-verified trial lease with crash-independent
  Watchdog rollback, poisoning-resistant shadow feedback, and signed
  non-executable Windows posture packs.
- The pass explicitly rejects arbitrary commands, SSID-only trust, automatic
  GPO/MDM reversal, online self-training, new offensive capabilities, and a new
  kernel driver. Full sources, architecture fit, effort, limitations, and safety
  boundaries are in `analysis/loop/innovation_ideas.md`.
- During remediation, bounded versions of collector-quality contracts,
  restrictive context ordering, effective ActiveStore verification, and
  single-flight revision-bound action admission shipped. Versioned baseline
  lifecycle, drift provenance, trial leases, shadow feedback, and signed posture
  packs remain proposals. Concise disposition:
  `analysis/loop/round8/visionary_summary.md`.

## Round 8 — Performance

- Removed signed-state filesystem I/O from the 15-second Qt timer callback and
  eliminated its duplicate enabled-cycle state read (two reads to one); all
  collection and command work remains on the existing single-flight worker.
- Coalesced full-workbench signed-state reads from three to two while preserving
  the core breaker's time-window semantics.
- Added bounded row signatures and selective automatic-cycle refresh routing so
  unchanged activity, exception, trigger, and snapshot views retain their Qt
  items. A 500-row activity microbenchmark improved from **12.671 ms** forced
  rebuild to **0.869 ms** unchanged refresh (**14.6x**).
- Gates: changed-file compile **PASS**; host-adaptation core self-test **PASS**;
  focused GUI/core tests **12 passed**. Event-driven Windows network wakeups and
  an asynchronous first-load bundle remain proposed pending native lifecycle and
  missed-event testing. Full evidence:
  `analysis/loop/round8/performance_summary.md`.

## Round 1 — Bug Test (2026-08-25 expansion loop)

- Compiled **305/305** package files; imported **69/69** module files; discovered
  **67 classes** with 0 duplicate names; and constructed **55/55** compatibility
  `register()` hooks.
- Fixed one real self-test reporting defect: stopped Adversary Combat incorrectly
  described itself as `armed`, making the headless harness report an unexpected
  failure. The status detail is now lifecycle-accurate and regression-covered.
- Core self-tests passed **19/19**; direct and batch selfcheck passed **26/26**;
  focused Adversary Combat/ARIA/Ollama/setup/update/menu tests passed **47/47**;
  the full `CI=true` suite passed **1085 tests / 3 intentional platform skips / 0
  failures**; Ruff passed.
- Live host-wide firewall mutation was reserved for a dedicated single-owner
  elevated acceptance run so parallel research was not disconnected. Full evidence:
  `analysis/loop/round1/bugtest_results.md` (2026-08-25 addendum).

## Round 1 — Innovation

### Defensive ecosystem and ARIA supply-chain review (2026-08-25)

- Compared the current 66-module baseline with primary documentation from
  Wazuh, Velociraptor, osquery/Fleet, Falco, Suricata, Zeek, Security Onion,
  Sigma, YARA-X, OCSF, OASIS STIX/TAXII, Microsoft Windows telemetry, Ollama,
  SLSA, and OWASP GenAI.
- Ranked **12 concrete defensive proposals**. The highest impact-per-effort
  shortlist is Community-ID flow fusion, restart-safe broader Windows event
  continuity, evidence-grade BYOVD handling, ARIA untrusted-data separation and
  hostile-eval gating, and OCSF 1.8 conformance.
- The next delivery tier is a strict signed Sigma 2.1 correlation runtime,
  verified stateful containment leases, and a provenance/hash/resource/eval/
  rollback-gated Ollama model and non-executable ARIA pack manager.
- Performance and depth proposals add YARA-X rule-cost admission,
  journal-backed ransomware/deception attribution, a bounded STIX/TAXII
  intelligence lifecycle, and a separately reviewed signed Linux CO-RE sidecar.
- The review explicitly rejects offensive tooling, arbitrary response scripts,
  executable downloaded skills, insecure or unverified model pulls, bulk
  community-artifact trust, an unsigned Windows driver, and blanket
  100-percent-coverage claims.
- Full sources, codebase fit, limitations, safety boundaries, and acceptance
  tests are in analysis/loop/innovation_ideas.md.

## Round 1 — Performance (2026-08-25 expansion loop)

- ARIA's local runbook BM25 hot path now pre-indexes term frequencies and length
  normalizers. Exact-score tests pass; real-index scoring improved **25.5x**
  (6.299023 s to 0.246808 s across 5,000 passes).
- The real-time ETW PID/name cache is now a 4,096-entry LRU with live-process
  fallback. A 100,000-PID stress case reduced peak tracked allocation from
  15,447,292 to 1,210,939 bytes (**92.2%**) while retaining active-parent and PID-
  reuse semantics.
- Gates: changed-file compile PASS, Ruff PASS, focused/regression **19/19**, both
  module behaviour checks PASS, and full `CI=true` suite **1088 passed / 3
  intentional platform skips / 0 failed**.
- Event-driven wake-up for the two legacy SOAR pollers remains proposed pending
  security-timing/lifecycle proof. Adversary Combat itself is already bounded
  and event-driven. Full evidence: `analysis/loop/round1/performance_summary.md`
  (2026-08-25 addendum).

## Round 3 — Bug Test (2026-08-25 expansion loop)

- Compiled **307/307** package files; Ruff passed; imported **69/69** module
  files; and discovered **67 modules** with no import/discovery errors,
  duplicate names, or duplicate non-empty codes.
- The focused Combat/bridge/ARIA/model-pack/Ollama/Sysmon/Community-ID/OCSF/
  interoperability/performance set passed **93/93**. Final concurrently edited
  UI/credential tests passed **17/17**, and the explicit menu/catalog audit
  passed **5/5** across 7 sections and 31 topics.
- The complete `CI=true` suite passed **1140 tests / 3 intentional platform
  skips / 0 failures**. Core self-tests passed **19/19**; direct and batch
  selfcheck passed **26/26**, with the batch wrapper exiting 0.
- No production defect or flaky test remained, so QA changed no product code and
  weakened no tests. The root agent retains the single-owner elevated
  host-isolation acceptance run to avoid disconnecting concurrent agents.
- Full evidence: `analysis/loop/round3/bugtest_results.md` (2026-08-25
  expansion-loop addendum).

## Round 3 — Performance (2026-08-25 expansion loop)

- Moved the Upgrade Console's periodic watchdog/core/heartbeat and scanner
  diagnostic file reads off the Qt thread while preserving Qt-owned rendering.
  Per-source single-flight backpressure prevents timer backlog: a 50 ms injected
  read returned control to Qt in **0.036 ms**, and 11 pending refresh requests
  coalesced to one job.
- Verified bounded model-pack catalogs/runbooks/state histories, stateless
  Community-ID and OCSF mappings, batch-level Sysmon cursor persistence, the
  4,096-entry ETW PID LRU, and pre-indexed ARIA BM25 scoring.
- Gates: changed-file compile PASS, Ruff PASS, and the governed-pack,
  Community-ID, OCSF, Sysmon, RAG, ETW, Upgrade Console, and shutdown regression
  set passed **45/45**.
- Constant-time first-run Sysmon tail seeking and asynchronous one-time ARIA
  manager/RAG startup remain proposed pending Windows-native cursor-race and
  startup lifecycle gates. Full evidence:
  `analysis/loop/round3/performance_summary.md` (2026-08-25 expansion addendum).

## Round 5 — Performance (2026-08-25 final hardening audit)

- Cached Sysmon's successfully derived cursor HMAC key while preserving missing-
  authority retry, signed cursor verification, atomic replacement, and per-batch
  durability. Repeated derivation improved from **282.11 us** to **0.095 us**
  (**2,969x**).
- Reduced Windows SourceSandbox handle-pinned component validation from quadratic
  ancestor re-walks to one pre/post validation per pinned component. An eight-
  level path improved from **6.862 ms** to **1.742 ms** (**3.94x**) with every
  reparse/TOCTOU gate retained.
- Eliminated the embedded Upgrade Console's duplicate post-lifecycle RAG build
  (**50% less indexing**) and batched catalog admission through one coherent
  resource snapshot (**44.22x / 97.7% faster** at the 128-pack bound). Actual
  install admission remains freshly probed immediately before mutation.
- Gates: changed-file compile and Ruff **PASS**; broad affected suite **62 passed**;
  Windows confinement set and live Sysmon self-test **PASS**.
- Full-history authenticated Combat journal append cost is superlinear (50/100/200
  records: **0.8551/1.9286/4.9859 s**). Signed segmentation remains **PROPOSED**;
  unsafe tail/stat caching and model-blob metadata caching were rejected because
  they could weaken mutation or local-model integrity. Full evidence:
  `analysis/loop/round5/performance_summary.md`.

## Round 5 — Bug Test (2026-08-25 final hardening audit)

- Compiled **307/307** package files; Ruff and patch-integrity gates passed;
  imported **69/69** module files; and discovered **67 modules** with no errors,
  duplicate names, or duplicate non-empty codes.
- Fixed two concrete regressions: an older Purple Guard test now verifies the
  required exact-target response contract, and FIM's accidentally stranded
  benign-drill provenance block is restored with an exact-registered-artifact
  versus filename-lookalike regression.
- Core/Shark self-tests passed **20/20**. Direct and batch selfcheck passed
  **26/26**; the module harness had **46 genuine passes / 13 expected inactive /
  8 disabled-platform skips / 0 genuine failures**. ARIA passed **15/15**.
- The final focused Combat/Sandbox/ARIA/model/Sysmon/producer set passed
  **96/96**; the complete `CI=true` suite passed **1181 / 3 intentional platform
  skips / 0 failures** after the final performance edits.
- Reported one design-level residual: Maximum Combat's 0.75/1.0-second network/
  process polling can reuse the default 1.5-second shared telemetry snapshot.
  Choosing a fast-mode cache age remains a detection-latency/performance policy
  decision; it was not silently changed in QA.
- Full evidence: `analysis/loop/round5/bugtest_results.md`.

## Round 5 — Red Team (2026-08-25 final release audit)

- **R5-01 HIGH:** default-on Maximum Combat grants raw FIM/network/process/Sysmon observations direct quarantine, firewall, process, honeypot, and host-isolation authority; ordinary or induced benign activity can create an elevated outage.
- **R5-02 HIGH:** Combat quarantine and undo validate string paths before later `shutil.move` calls without pinned parent handles, leaving a junction/TOCTOU privileged file-move or file-plant boundary.
- **R5-03 HIGH:** legacy SOAR tiers bypass exact response contracts and durable receipts; PID-only corroboration/state permits reuse mistakes, while armed Active Response can kill/unlink an event target without protected binding.
- **R5-04 HIGH:** authenticated mobile KILL/SUSPEND/LOCKDOWN directives have no consumer but report issuance; ROLLBACK instead restores every cached Shadow Shield file without an exact target.
- **R5-05 MEDIUM:** privileged bootstrap removes `ANGERONA_ENFORCE_KEY_ACL` before source data-root custody checks, so direct elevated source startup bypasses the intended fail-closed assertion.
- **R5-06 MEDIUM:** model manifests/blobs are verified, but inference trusts any process that owns unauthenticated loopback Ollama port 11434.
- **R5-07 LOW:** the SOAR stale/preflight-refusal GUI path calls `.discard()` on a dictionary and throws after correctly refusing the host action.
- Verdict: **release blocked**. Focused read-only boundary suites passed **160/160**, but do not cover these negative/race/consumer cases. Full evidence: `analysis/loop/round5/redteam_results.md`.

## Round 6 — Red Team (2026-08-25 exact-target response audit)

- **R6-01 HIGH (RESOLVED):** host escalation is explicit; weak Office/RWX/cadence/lattice signals have no host authority; LSASS/VSS gates now require role-aware argv plus exact trusted image semantics, while ambiguous PowerShell stays alert-only.
- **R6-02 HIGH (RESOLVED):** rename rates and recent entropy are now correlated within the same normalized directory; cross-directory evidence cannot mint host isolation, and uncorroborated churn can activate deception only.
- **R6-03 MEDIUM:** `isolate_program` is not contract-bound to executable identity, and Combat performs slow firewall work after its last PID birth-time check but before suspend/kill.
- **R6-04 MEDIUM:** handle-based Windows quarantine has no cross-volume path; the audited source layout stores quarantine on D: while default user watch roots are on C:.
- **R6-05 MEDIUM (RESOLVED):** commit/compensation failure now exposes an authenticated recovery-required orphan, opens the mutation circuit, and blocks later same-event/future actions; non-reversible commit loss also disarms Combat.
- Verified closed during this audit: filename-only real-driver response, unregistered BYOVD drill lookalikes, unpaired file-churn isolation, cross-PID beacon aggregation, and Evidence Lattice live-PID rebinding.
- Re-audit verdict: **both R6 High findings resolved; no release blocker remains in these exact semantic surfaces**. The semantic contract file passed **20/20** after strict LSASS/VSS negative controls; R6-05's journal/Undo circuit is now closed. R5-02 and R6-02 are resolved; R5-01 is materially narrowed. Full evidence: `analysis/loop/round6/redteam_findings.md`.

## Round 7 — Performance (2026-08-25 final release candidate)

- Removed redundant resolver calls for already-numeric loopback identities while
  retaining hostname resolution/pinning and call-time Ollama listener,
  process-birth, executable/signature, route, redirect, proxy, and size gates.
  Literal pinning improved **2.16x / 53.7%**.
- Memoized normalized directory identities within each ransomware correlation
  cycle. A ten-pass, 100,000-record flood benchmark improved **6.91x / 85.5%**
  without changing same-directory entropy authority or response output.
- Pruned only expired Network Monitor novelty identities instead of rebuilding
  two unchanged 10,000-entry maps every Maximum-mode poll, improving the measured
  state cycle **1.88x / 46.9%** without changing cadence or freshness.
- Compile and Ruff passed; the broad affected set passed **52/52**, and the final
  performance-boundary file passed **4/4**. Signed Combat journal segmentation
  and OS-native listener-bound attestation remain proposals because naive caches
  would weaken tamper or process-owner guarantees. Full evidence:
  `analysis/loop/round7/performance_summary.md`.

## Round 6 — Red Team (2026-08-25 broad current-tree closure)

- **R6-01 HIGH RESOLVED:** LSASS/VSS host escalation now requires exact trusted executable and role-aware destructive argv semantics.
- **R6-02 HIGH RESOLVED:** ransomware rename/entropy authority is directory-bound; unrelated roots cannot compose host isolation.
- **R6-03 MEDIUM OPEN:** process response still lacks a retained OS handle and persistent program rules lack a bounded executable-file lease.
- **R6-04 MEDIUM RESOLVED:** pinned, verified cross-volume copy/delete and undo now cover C:-to-D: quarantine.
- **R6-05 MEDIUM RESOLVED:** failed compensation exposes the authenticated orphan, trips a mutation circuit, blocks later actions, and supports exact manual recovery; irreversible commit loss also disarms Combat.
- **R6-06 HIGH RESOLVED:** local-model posture output is inert advisory text and cannot execute even with the old authorization flag.
- **R6-07 MEDIUM RESOLVED:** Red Team cleanup deletes exact run-owned artifacts only; filename-prefix lookalikes survive.
- **R6-08 MEDIUM RESOLVED:** SOAR delegates to Combat's journal; SUBMITTED is terminal, verified receipts reconcile exact queue IDs, and queue-admission failure releases dedup plus emits a signed failure receipt.
- **R6-09 MEDIUM RESOLVED:** Top Talkers binds PID birth/executable/peer and delegates typed containment to Combat instead of stale-PID termination.
- **R6-10 MEDIUM RESOLVED:** deployment mirror rejects broad/protected/overlapping/unowned destinations, previews `/MIR`, and requires exact typed authorization.
- **R6-11 MEDIUM RESOLVED:** GUI and helper shutdown require exact approved Angerona launch grammar plus PID creation-time revalidation; venv pytest/Jupyter and substring lookalikes are excluded.
- Verdict: **no Critical, High, or Medium release blocker remains**. R6-03 stays open only as defense-in-depth process-handle/program-file lease hardening. Full evidence: `analysis/loop/round6/redteam_findings.md`.

## Round 7 — Bug Test (2026-08-25 frozen v1.10.2 release candidate)

- Compiled **308/308** package files; Ruff, recursive imports, module discovery,
  and duplicate-name/code checks passed with zero errors.
- Collected **1,258 tests across 197 files**. The complete Windows contention-
  controlled run finished **1,255 passed / 3 intentional skips / 0 failed**.
- Module self-tests produced **46 genuine passes / 0 genuine failures**, plus 13
  expected inactive-environment results and 8 platform/operator skips. Core and
  Shark self-tests passed **20/20**; ARIA passed **15/15**.
- Direct and batch selfcheck entry points both passed **26/26**, including the
  Combat, Ollama, ARIA, SOAR, GUI/menu, and host-action surfaces.
- Fixed six low-risk regressions/harness gaps: exact Combat contract fixtures,
  Combat Undo empty-state controls, Posture advisory-path persistence, Red Team
  rapid-rerun cleanup ordering, SOAR signed receipt reconciliation coverage,
  and stale selfcheck expectations for now-inert model advice.
- `pip-audit --local` found no known vulnerabilities. No reproducible
  release-blocking QA defect remains. Full evidence:
  `analysis/loop/round7/bugtest_results.md`.

## Final documentation closure (2026-08-25 — v1.10.2)

- Consolidated the operator and engineering reference into the root
  `Angerona_Master_Manual.docx`; history now lives there instead of in parallel
  master/capability Word documents.
- Recast `ANGERONA_CAPABILITIES.md` as a short current-state capability and use-
  case sheet with no development history; refreshed `README.md` and `llms.txt`
  to point at the canonical current documents.
- Updated the security and feature-versus-defect assessments with the frozen
  release evidence and the explicit non-blocking R6-03 defense-in-depth item.
- Final Word QA: master 22 pages, security assessment 17 pages, and
  vulnerability/remediation assessment 13 pages. Every page was visually
  inspected after its final render; all three documents reopened successfully,
  required text was present, and the master's 23 tables fit the 9,360-DXA usable
  width. Accessibility audit reported zero high findings in all documents and
  zero medium findings in both assessments; the master retains seven intentional
  no-header layout-table notices (six one-cell callouts plus its footer).

## Cycle 23 Round 1 — Red Team (2026-08-26)

- **R1-01 MEDIUM:** missing event-log checkpoints baseline at newest and can silently skip an already-retained clear event.
- **R1-02 LOW:** a clear/refill after the post-query anchor check can bridge old rows to a replacement-generation terminal checkpoint, but physical WEVT timing/record-ID recreation was not demonstrated.
- **R1-03 MEDIUM:** SSH baseline coverage excludes included configuration bytes, configured custom key/CA/principals sources, and verified Windows ACL custody.
- **R1-04 MEDIUM:** default Windows OpenSSH event-channel evidence, non-service `sshd.exe`, and client-side tunnel processes are outside current runtime/log coverage.
- **R1-05 MEDIUM:** zero-trust network drift state uses an ephemeral key/in-memory baseline, while incomplete first collection can still report healthy.
- **R1-06 MEDIUM:** gateway attestation labels an interface when the enrolled gateway is merely one route; competing metrics and Windows IPv6 egress are not bound.
- **R1-07 LOW:** live activity public messages can retain MAC/SSID/user text and fragments of Windows paths containing spaces.
- **R1-08 INFO:** non-Windows discovery skips the network monitor because it lacks the required module-level literal platform declaration.
- **R1-09 LOW:** Defense Memory follows and fully reads its asset before enforcing the 64-KiB cap, allowing resource pressure before digest rejection.
- New findings: **9 open — 0 Critical, 0 High, 5 Medium, 3 Low, 1 Info**. Prior items explicitly rechecked: **1 resolved, 3 still open/architectural**. Focused regressions: **104 passed, 1 skipped**. Full evidence: `analysis/loop/cycle23/round1/redteam_findings.md`.

## Cycle 23 Round 1 — Remediation (2026-08-26)

- **R1-01/R1-02 FIXED:** event-log coverage now has a separate authenticated
  enrollment epoch, monotonic CAS cursor, stable non-reparse I/O, oldest-retained
  bounded replay, staged evidence, and pre/post-commit generation validation.
- **R1-03/R1-04 FIXED:** SSH coverage now aggregate-hashes bounded Include and
  configured key-authority sources, verifies Windows ACL custody, reads fixed
  OpenSSH event channels, and observes non-service server/client process,
  forwarding and socket evidence with explicit completeness. Authenticode stays
  explicitly unavailable rather than being falsely asserted.
- **R1-05/R1-06 FIXED:** network drift uses stable purpose keys and an
  authenticated provisional/trusted baseline; incomplete collection cannot
  enroll or advance it. Gateway labels require complete IPv4/IPv6 evidence,
  one selected route per family, matching interface index/epoch, no competitor,
  and unchanged pre/post-exchange context.
- **R1-07/R1-08/R1-09 FIXED:** public dashboard messages redact local identity
  and spaced paths, cross-platform AST discovery sees the network monitor, and
  Defense Memory uses bounded root-confined stable non-reparse admission.
- Gates: compile PASS; Ruff PASS; **134 passed, 2 skipped, 0 failed**; Audit Log,
  Network Trust, SSH Surface and ARP Watchdog self-tests PASS. Full evidence:
  `analysis/loop/cycle23/round1/remediation_summary.md`.

## Cycle 23 Round 1 — Bug Test (2026-08-26)

- Compiled **320/320** package files; imported **73/73** module files; discovered
  **71/71** module classes with zero errors or duplicate names/codes; all
  **57/57** optional registration hooks and **22/22** core/Shark self-tests
  passed.
- Direct and batch selfcheck each passed **26/26**. The module harness had
  **50 genuine passes / 13 inactive-or-optional skips / 5 operator-disabled
  skips / 3 platform skips / 0 genuine failures**, plus a passing EventBus
  pipeline.
- The focused Cycle 23 set passed **126 / 2 host-capability skips / 0 failures**;
  the complete serial suite collected 1,436 tests and passed **1,431 / 5
  intentional skips / 0 failures** across 207 files. Ruff also passed.
- **QA-R1-01 MEDIUM — REPORTED:** both event-log and network continuity stores
  reject a missing or tampered member, but a previously valid matching
  cursor/enrollment pair can be replayed after a newer revision and is accepted
  as current. Correct repair needs an independent monotonic/append-only witness
  plus migration and recovery policy; no unsafe local patch was applied.
- Bugs fixed: **0**. Bugs reported: **1**. Full evidence:
  `analysis/loop/cycle23/round1/bugtest_results.md`.

## Cycle 23 Round 1 — Performance (2026-08-26)

- Quiescent audit polls now re-read and authenticate both continuity documents
  without replacing/`fsync`ing identical state. Median checkpoint work improved
  from **42.189 ms to 1.001 ms (97.6%)**, avoiding up to **43,200** idle durable
  replacements per day at the unchanged four-second cadence.
- SSH runtime inventory now requests command lines only for admitted SSH client
  processes. The measured process-enumeration phase improved from **41.050 ms
  to 3.726 ms (90.9%)** while preserving process/socket evidence and forwarding
  findings.
- The network monitor still scans every collector-supplied link/route, but no
  longer rebuilds an already-untrusted immutable snapshot. The declared-bound
  benchmark improved from **1,319.25 us to 88.70 us (93.3%)**; forged positive
  attestation flags are still stripped.
- Compile and Ruff passed; focused gates passed **112 tests / 2 intentional
  host-capability skips / 0 failures**, and all three affected module self-tests
  passed. Windows inventory-process coalescing, a narrow post-attestation route
  observer, and event-driven WEVT delivery remain proposals pending dedicated
  completeness/race proofs. Full evidence:
  `analysis/loop/cycle23/round1/performance_summary.md`.

## Cycle 23 Round 2 — Red Team (2026-08-26)

- **R2-01 MEDIUM:** replaying both members of an older valid event/network state pair is accepted after a newer revision because neither store has independent high-water custody.
- **R2-02 MEDIUM:** relative per-user SSH key/principals sources resolve against the config directory, and file-only Windows ACL checks omit parent replacement custody.
- **R2-03 LOW:** the unreported 64-interface cap can omit a standby route while route/interface completeness remains asserted, allowing a positive gateway context the full view rejects.
- **R2-04 LOW:** one transient Windows OpenSSH source-open failure is never retried until module reconstruction, although the unavailable state remains fail visible.
- **R2-05 LOW:** SSH option normalization misses split `-o RemoteForward` forms and substring-matches unrelated long options into false High forwarding alerts.
- **R2-06 LOW:** audit classification does not bind provider/XML channel and preserves attacker-shaped field names or allowlisted values in EventBus details.
- New findings: **6 open — 0 Critical, 0 High, 2 Medium, 4 Low, 0 Info**. Round 1 exact red-team behaviors: **9 resolved, 0 reopened**; QA-R1-01: **1 still open**; older architectural residuals: **3 still open**. Focused regression gate: **5 passed**. Full evidence: `analysis/loop/cycle23/round2/redteam_findings.md`.

## Cycle 23 Round 2 — Remediation (2026-08-26)

- **R2-01 DEFERRED:** both authenticated stores now support a strictly injected,
  separate-domain monotonic high-water contract and reject witnessed
  behind/fork/clone state. Offline, migration, witness-loss, and external-first
  crash cases are fail-visible and non-advancing. No server/TPM authority is
  implemented or claimed; the existing Personal Sentinel compact receipt is
  not promoted to anti-rollback authority without server-enforced monotonic CAS.
- **R2-02/R2-04/R2-05 FIXED:** per-user SSH sources use bounded home/token
  semantics and explicit incomplete states; Windows custody covers the full
  parent replacement chain; event sources use capped reopen backoff with honest
  history bounds; forwarding classification uses a strict consuming grammar
  and normalized completeness labels only.
- **R2-03 FIXED:** omitted interfaces, rejected/overflow route rows, and
  incomplete address evidence clear authenticated completeness tokens, so both
  pre- and post-exchange Personal Sentinel labeling fail closed.
- **R2-06 FIXED:** audit events require authoritative channel/provider/event
  identity, publish fixed privacy-safe keys, and advance rejected parseable
  record IDs with bounded Angerona-owned rejection reasons.
- Gates: compile PASS; Ruff PASS; **135 passed, 2 existing host-capability
  skips, 0 failed**; network core plus Audit Log, Network Trust, and SSH Surface
  self-tests PASS. Full evidence:
  `analysis/loop/cycle23/round2/remediation_summary.md`.

## Cycle 23 Round 2 — Bug Test (2026-08-26)

- Compiled **321/321** package files; imported **73/73** module files; native
  discovery created **71/71** module classes with zero errors or duplicate
  names/non-empty codes. All **58/58** zero-argument compatibility hooks and
  **22/22** standalone core/Shark self-tests passed.
- Direct and batch selfcheck each passed **26/26**. The internal harness had
  **50 module passes / 0 failures / 21 expected skips**, plus one passing
  EventBus pipeline.
- The focused Round 2 set passed **135 / 2 host-capability skips / 0 failures**.
  Ruff passed, and the complete serial suite collected 1,460 tests across 208
  files and finished **1,455 passed / 5 intentional skips / 0 failed**.
- **QA-R2-01 FIXED:** added the omitted optional `register()` and `__all__`
  compatibility exports for the new SSH Surface guard; changed-file compile,
  Ruff, SSH tests, registration discovery, and the full suite all passed.
- **R2-01 remains REPORTED/DEFERRED:** the injected audit/network high-water
  contract rejects behind/fork/clone state and makes outage, migration, and
  external-first crashes fail visible, but no separately administered server
  or TPM authority is bundled. Without one, matching older local HMAC pairs
  remain locally authentic and explicitly not independently fresh.
- Bugs fixed: **1**. Bugs reported: **1 retained architectural residual**.
  Full evidence: `analysis/loop/cycle23/round2/bugtest_results.md`.

## Cycle 23 Round 2 — Performance (2026-08-26)

- Per-user SSH `%h`/`%u`/`%U`/`%%` source expansion now uses an exact
  no-token fast path and one-pass bounded token scanning instead of repeated
  cumulative-length rescans. Maximum-size `%%` input improved from **213.317
  ms to 1.335 ms (99.4%)**; a mixed over-limit fail-closed input improved from
  **70.783 ms to 0.827 ms (98.8%)**.
- Token grammar, ProgramData substitution, account/UID requirements,
  relative-home containment, privacy output, and the 4,096-character cap are
  unchanged. A randomized **2,000-case** differential corpus matched, then
  compile, Ruff, the module self-test, and the focused SSH suite passed.
- Final gates: changed-file compile PASS; Ruff PASS; SSH Surface Guard
  `self_test()` PASS; **33 passed / 1 expected host-capability skip / 0
  failed**.
- Exact audit sanitizer translation, fixed XPath precomputation, ASCII byte-cap
  admission, direct EventData iteration, and malformed-marker early rejection
  remain measured proposals. No high-water/anchor/route/completeness/freshness
  check or polling/retry cadence was changed. Full evidence:
  `analysis/loop/cycle23/round2/performance_summary.md`.

## Cycle 23 Round 2 — Visionary (2026-08-26)

- Reviewed five actor-neutral candidates and selected **no MVP**. No product,
  test, configuration, asset, README, manual, or `llms.txt` file changed.
- A separately administered Personal Sentinel monotonic witness remains
  **PROPOSED/DEFERRED**. It must enforce per-installation/per-domain CAS on a
  separate device/service under independent administration; an on-host file,
  receipt, database, or test fixture is not anti-rollback custody.
- Local semantic-correlation and ambient-telemetry variants were deprioritized:
  Evidence Lattice, incidents, Telemetry Expectations, Canary Drill silence
  checks, and module health already cover their useful local mechanics. A new
  wrapper would need a proven non-overlap and typed recovery semantics.
- Resource-scoped gateway assurance leases and SSH key-to-session provenance
  remain proposals pending policy/enforcement and authoritative event-schema
  design. Full scorecard and trust boundary:
  `analysis/loop/cycle23/round2/visionary_summary.md`.

## Round 3 — Red Team (Cycle 23, 2026-08-26)

- **R3-01 MEDIUM:** a newly observed physical network path updates only the
  in-memory trusted baseline; the authenticated pair remains stale, and a
  restart reloads the old path set without a drift finding. Recommended repair:
  emit interface-set drift and require gated reconciliation/persistence.
- Prior accounting: 14 Cycle 23 findings remain verified fixed; R2-01 remains
  honestly deferred to a separately administered monotonic authority. The
  stale A-07 entry is verified resolved (SHA-256); A-04/A-06/R6-03 are unchanged
  older architectural residuals, not new Cycle 23 findings.

## Round 3 — Remediation (Cycle 23, 2026-08-26)

- **R3-01 FIXED:** established baselines now produce an explicit bounded,
  tokenized `network.path_added` finding for a newly observed physical path.
- Complete addition-only candidates enter the authenticated cursor/epoch pair
  as provisional through the existing revision/freshness gate and independent
  high-water CAS when configured. A persisted tokenized pending set requires
  each added path to remain active and unchanged before promotion. Other drift,
  freshness loss, a failed transition, absence, or bounded-history eviction
  freezes the last authenticated comparison state.
- Restart regressions verify changed new-path evidence survives, stable
  reconciliation does not rewrite again, and removed paths retain their prior
  epoch semantics. Endpoint trust and response authority remain false.
- Gates: compile PASS; Ruff PASS; focused network/high-water/Personal Sentinel
  suite **92 passed, 0 skipped, 0 failed**; **2/2** network self-tests PASS.
  Full evidence: `analysis/loop/cycle23/round3/remediation_summary.md`.

## Cycle 23 Round 3 — Bug Test (2026-08-26)

- Compiled **321/321** product Python files; imported **73/73** module files;
  native discovery created **71/71** modules with zero errors or duplicate
  names/non-empty codes. All **58/58** compatibility hooks and **22/22**
  standalone core/Shark self-tests passed.
- Direct and batch selfcheck each passed **26/26**. The internal harness had
  **50 module passes / 0 failures / 21 expected skips**, plus one passing
  EventBus pipeline.
- The focused Cycle 23/R3 security and integration gate passed **155 tests / 2
  expected host skips / 0 failures**. It independently confirms provisional
  path-add persistence, add-path restart drift, absent-pending non-promotion,
  stable active promotion without repeated writes, the 64-link history bound,
  and conservative provisional schema-v1 pending-token migration.
- With no external authority, both audit and network state explicitly report
  `local-authenticity-only` and `independent_freshness_verified=False`.
  Dashboard, Defense Memory, cloud-egress, observe-only, and privacy boundaries
  remained green; no Personal Sentinel receipt or local fixture is represented
  as independent anti-rollback custody.
- Ruff passed. The complete serial suite collected **1,465 tests across 208
  files** and finished **1,460 passed / 5 intentional host-capability skips / 0
  failed**. Documentation counts remain intentionally stale for the final docs
  agent.
- Bugs fixed: **0**. Newly reported bugs: **0**. One separately administered
  monotonic high-water dependency remains honestly deferred. Full evidence:
  `analysis/loop/cycle23/round3/bugtest_results.md`.

## Cycle 23 Round 3 — Performance (2026-08-26)

- **No production or test change applied.** The Round 3 pending-token and
  finding-classification work is bounded to 64 paths and introduced no material
  hot path. Direct state predicates were retained so path-addition, promotion,
  completeness, history, privacy, freshness/CAS, and observe-only gates remain
  easy to audit.
- A 64-path baseline construction measured **23.256 us** with one pending path
  and **131.025 us** at the artificial 64-pending bound. Set reuse saved only
  **45.978 us** at that bound and regressed the normal one-pending validation
  kernel by **15.5%**, so it remains proposal-only.
- On an evaluator-produced 443-finding stress state, a one-pass drift/addition
  accumulator regressed from **53.817 us to 56.166 us (4.4%)**. The current
  short-circuit predicates were retained.
- End-to-end pure evaluation measured **3.113 ms** for a stable complete
  64-path state and **2.817 ms** for a complete 63-to-64 path addition. The
  unchanged 30-second cadence and inventory I/O dominate these bounded costs.
- Compile and Ruff passed; focused network tests passed **36 / 0 skipped / 0
  failed**; both affected self-tests passed. Full evidence:
  `analysis/loop/cycle23/round3/performance_summary.md`.

## Cycle 23 Round 3 — Visionary (2026-08-26)

- Final convergence selected **no MVP** and changed no product, test,
  configuration, asset, README, manual, or `llms.txt` file.
- R3-01's authenticated provisional pending-path flow closes the local
  topology-reconciliation gap; another local path reconciler is no longer a
  novel candidate.
- The separately administered monotonic witness remains the highest-value
  **PROPOSED/DEFERRED** design. Its CAS namespace must live on a separate
  device/service under independent administration; same-host files, receipts,
  databases, loopback services, and fixtures are not independent custody.
- Resource-scoped gateway leases and SSH key-to-session provenance remain
  proposals. Hardware-rooted Personal Sentinel firmware attestation remains a
  separate deferred release project. Local correlation/ambient-health wrappers
  remain deprioritized because existing Evidence Lattice, incidents, Telemetry
  Expectations, Canary Drill, module health, and the new typed path-addition
  flow already cover their local mechanics.
- Full scorecard and trust boundaries:
  `analysis/loop/cycle23/round3/visionary_summary.md`.

## Cycle 23 — Final text documentation (2026-08-26, v1.10.3)

- Consolidated the three-round record in
  `analysis/loop/cycle23/summary.md`: **16 findings / 15 fixed / 1 deferred
  external dependency**, with actor-neutral language, exact shipped/proposed
  boundaries, performance measurements, final validation, and primary sources.
- Reordered the public README so purpose, capability map, use cases, platform,
  installation, validation, and honest limits precede the detailed v1.10.3
  update notes. Added SSH, audit continuity, physical-network zero trust,
  Personal Sentinel client topology, Live Defense Activity, and ARIA Defense
  Memory without claiming an appliance/server, firmware attestation, endpoint
  trust, independent freshness, live code, or hidden reasoning.
- Updated `ANGERONA_CAPABILITIES.md`, root and analysis `llms.txt`, and
  `analysis/README.md` to the final evidence: **1,460 passed / 5 expected skips /
  0 failed from 1,465 tests across 208 files; 321/321 compile; 73/73 module files;
  71/71 modules; 58/58 compatibility hooks; 22/22 core/Shark self-tests; 50
  module pass / 0 fail / 21 expected skips plus EventBus; selfcheck 26/26 direct
  and batch; Ruff clean**.
- Reconciled `PRIOR_FINDINGS.md`: A-07 is RESOLVED with SHA-256; A-04, A-06,
  and R6-03 remain architectural/defense-in-depth residuals; independent
  high-water custody is tracked as the Cycle 23 deferred external dependency.
- Product version remains **v1.10.3**. The canonical Word manual remains under
  the coordinator's separate artifact workflow and was not touched by this
  documentation agent.

## Cycle 24 Round 1 — Red Team (2026-08-26)

- **R1-01 HIGH:** Neither supported Windows installer makes externally anchored artifact authenticity a prerequisite to privileged installation; the optional verifier also reopens a mutable path.
- **R1-02 MEDIUM:** Both nominally independent release signer secrets and the generated trust root share one workflow runner/script failure domain.
- **R1-03 MEDIUM:** A consumed privileged response capability is accepted again by a restarted authority using the same secret.
- **R1-04 MEDIUM:** The production Personal Sentinel CLI uses symmetric HMAC receipt/state signing, so a monitored-host verifier also holds signing authority.
- **R1-05 MEDIUM:** Signed Sentinel state remains vulnerable to valid-snapshot rollback and process-local locking permits cross-process forks.
- **R1-06 MEDIUM:** TLS handshake work occurs in the Sentinel accept loop before the handler timeout and bounded worker semaphore, enabling private-LAN availability denial.
- **R1-07 LOW:** Trusted-time appraisal lacks current-challenge binding and a durable receipt sequence floor, allowing captured-receipt reuse after restart plus clock rollback.
- **R1-08 MEDIUM:** Recovery assurance can aggregate posture across unrelated revisions and accept future-dated evidence, producing a false healthy result.
- **R1-09 MEDIUM:** The driver collector selects the first 256 sorted running services and then reports the truncated inventory complete.
- **R1-10 LOW:** Temporal and identity analytics treat EventBus storage HMAC as producer provenance instead of consuming broker-assigned sensor identities.
- **R1-11 INFO:** Sensor provenance, capability-only privileged service, external Sentinel freshness, process-egress enforcement, and RAG index admission remain unwired deployment foundations.
- **Resolved during review (not open):** The peripheral Windows probe now resolves only the trusted absolute PowerShell path and has a regression proving no PATH fallback.

## Cycle 24 Round 1 — Performance (2026-08-26)

- Applied one behavior-preserving driver-collector optimization: push the
  running-state predicate into CIM and use bounded list appends instead of
  repeated PowerShell array copying. No scan interval or security control was
  changed.
- Alternating enumeration measurements were client **7.0873 s**, filtered
  **1.5406 s**, client **3.1479 s**, filtered **1.5663 s**; the warm enumeration
  phase was **50.7% faster**. Authenticode remained the dominant cost at
  **11.310 s** in component profiling.
- Cross-scan signature caching was rejected: unchanged bytes can receive a new
  trust, catalog, revocation, or policy decision. Every service image continues
  to be hashed and verified on every 15-minute scan.
- Gates passed: compile, Ruff, **9/9** focused driver tests, module self-test,
  and a live **194 rows / 193 hashes / 193 valid signatures** evidence check.
  Full evidence: `analysis/loop/cycle24/round1/performance_summary.md`.

## Round 1 — Innovation (Cycle 24, 2026-08-26)

- Reconciled current 2024–2026 Microsoft, CISA, NSA, NIST, MITRE, IETF,
  OpenSSH, and vendor primary research against the concurrent Cycle 24 tree.
  Research is actor-neutral and separates observed tradecraft, established
  attack classes, and theoretical/lab-only risks.
- Code-backed foundations now cover identity/session analytics, driver
  provenance, ordered temporal correlation, peripheral/DMA posture,
  measured-boot appraisal contracts, process-egress leases, sensor/RAG
  provenance, release authorization, and a prototype Personal Sentinel
  authority. Several remain supplied-evidence-only, observe-only, injected, or
  unwired and are not promoted to release claims.
- P0 completion work is authoritative identity/source wiring, privileged
  process-egress enforcement, and remediation of Round 1's Sentinel,
  capability, recovery, release, driver-completeness, and producer-provenance
  findings. The highest-value new detectors are ClickFix/user-intent chains,
  SSH key-to-session plus PQ posture, and loaded-DLL provenance.
- P1/P2 roadmap: Wi-Fi/IPv6 first-hop attestation v2, WSL/Hyper-V visibility,
  out-of-band peripheral context, ATT&CK v19 analytic conformance, and a
  strictly experimental selective call-stack sensor.
- No product code, public documentation, version, or configuration was changed
  by the innovation pass. Full ranked proposals, feasibility limits, false-
  positive constraints, safety boundaries, and authoritative URLs:
  `analysis/loop/cycle24/round1/innovation_ideas.md`.

## Round 1 — Bug Test (Cycle 24, 2026-08-26)

- QA: **343/343 compile**, selfcheck **26/0** with **60 pass / 0 fail / 21 expected skips**, discovery **80 Windows / 14 Linux / 13 macOS** with no import or duplicate-identity errors; full pytest diagnostic **1,602 passed / 5 failed / 5 skipped**, with four load/scheduling timing artifacts clearing or intermittent in isolation and one expected README count drift (`71 -> 80`) assigned to final docs; **0 product bugs fixed, 0 reproducible product bugs reported**. Full evidence: `analysis/loop/cycle24/round1/qa_summary.md`.

## Round 1 — Remediation (Cycle 24, 2026-08-26)

- Fixed R1-03 through R1-07, R1-09, and R1-10: durable epoch-bound response
  capabilities; asymmetric Personal Sentinel production roles; OS singleton
  and pluggable generation floors; bounded pre-auth TLS with mandatory mTLS;
  challenge/floor-bound trusted time; explicit driver overflow; and broker-
  provenanced analytic confidence.
- Gates: **76 focused tests passed**, all changed files compiled, Ruff passed,
  five applicable self-tests passed, and remediation-path diff checks passed.
- Full per-finding changes, gates, and external TPM/second-witness residuals:
  `analysis/loop/cycle24/round1/remediation_summary.md`.

## Cycle 24 Round 2 — Performance (2026-08-26)

- Applied two behavior-preserving optimizations: Personal Sentinel now reuses
  one exact canonical unsigned-state buffer for its optional generation-floor
  digest and state signature; identity/session analytics now uses an
  eviction-synchronized digest set for O(1) replay membership.
- Sentinel's bounded serialization/signing kernel improved **30.2–39.0%** at
  64–4,096 retained nonces. Identity duplicate membership improved from
  **410.488 us to 0.060 us** at the artificial 4,096-event bound. Final signed
  bytes, fsync/atomic replacement, ordered correlations, and eviction semantics
  remain unchanged.
- Temporal write batching, process-egress material reuse, Windows posture-query
  coalescing, and mtime-based evidence caches were not applied because their
  crash continuity, cryptographic binding, freshness, or stable-read
  equivalence was not proven.
- Gates passed: **27/27** focused tests, **2/2** standalone self-tests, Ruff,
  and `py_compile`. Full evidence:
  `analysis/loop/cycle24/round2/performance_summary.md`.

## Cycle 24 Round 2 — Red Team (2026-08-26)

- **R2-01 HIGH:** First-install publisher checking remains inside the candidate Setup; use an OS-enforced signed MSIX/App Installer or mandatory publisher policy as the external trust anchor.
- **R2-02 MEDIUM:** Separate signer jobs are present, but finalization accepts artifact-carried public keys instead of roots pinned in an independently administered finalizer domain.
- **R2-03 MEDIUM:** The protected portable updater authenticates exact bytes, publisher, catalog, and attestation but does not enforce the signed release sequence/version against a highest-installed floor.
- **R2-04 LOW:** SSH live EventBus ingestion selects caller labels without broker provenance and allows unprovenanced input to advance the trusted known-source baseline.
- **R2-05 LOW:** Production trusted-time composition advances the same receipt floor in the client and appraisal, so a valid receipt fails closed as a regression.
- **R2-06 MEDIUM:** A closed Personal Sentinel authority can still process state transactions after releasing its singleton lease.
- **R2-07 LOW:** Linux removable-device posture can report complete absence when some enumerated per-device flags are unreadable.
- Prior status: six Round 1 findings fully resolved, three partial/deployment-residual, two open; C23-R2-01, A-04, A-06, and R6-03 remain external/architectural residuals.

## Cycle 24 Round 2/3 — Remediation and release boundary (2026-08-27)

- Closed the in-repository Round 2 release, provenance, trusted-time,
  Sentinel-lifecycle, SSH-baseline, Linux completeness, recovery-cohort, and
  anti-rollback findings with regression coverage. No offensive payload,
  credential collection, log erasure/evasion, or destructive autonomous
  remediation was added.
- Public Windows first install is now constrained to an OS-validated signed
  x64 MSIX. Classic Setup is non-public and migration-only; portable ZIPs are
  upgrade-only and delegate mutation to the verified installed updater.
  Publisher/root custody, the pinned packaging toolchain, clean-machine
  validation, and privileged whole-host rollback resistance remain external
  deployment gates.
- Final serial validation collected **1,675 tests across 229 files: 1,670
  passed, 5 expected host-capability skips, and 0 failed**. Ruff passed;
  compilation passed for **611/611** Python files and **345/345** product files.
  Selfcheck passed **26/26**; the module harness passed **60/60** with 21
  expected inactive/platform skips plus EventBus; discovery reported **80
  Windows / 14 Linux / 13 macOS** modules without errors.
- Published four fresh v1.11.0 dashboard/feature screenshots. Two independent
  capture runs were byte-identical. Screenshot QA also found and fixed a Qt
  alpha-channel ordering defect, now protected by focused theme tests.
- Updated README, capabilities, governed ARIA memory guidance, launch post,
  and the 35-page Word manual. The manual was rebuilt from its pristine
  snapshot with minimal version/capability/install/addendum edits and passed
  rendered visual plus structural QA.
- Final evidence: `analysis/loop/cycle24/summary.md`,
  `analysis/loop/cycle24/round3/qa_summary.md`, and
  `analysis/loop/cycle24/round3/release_remediation_summary.md`.
