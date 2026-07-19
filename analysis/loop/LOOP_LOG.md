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
