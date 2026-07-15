# Cycle 2 / Round 1 — Red-Team Findings

Date: 2026-07-14. Scope: read-only review of the current combined tree after
the D-drive storage, drill-remediation, trusted-process, staged-wakeup,
report-retention, shutdown/Ollama, and ARIA additions. No source, rules,
configuration, runtime data, or host state was changed. In particular,
`rules/_active_combined.yar` was not touched.

Prior findings were checked first. A-04/A-06, R2-02, R3-01, and R3-02 remain
known/deferred and are not re-filed. Previously fixed findings were not observed
to have regressed.

## C2-R1-01 — Name-only process trust can suppress scanning, threat posture, and SOAR for a renamed executable

- **Severity:** MEDIUM
- **Components:** `src/angerona/core/process_allowlist.py:105-126,139-151`;
  `src/angerona/gui/pages.py:3320-3327,3360-3368,3371-3380,3418-3430`;
  `src/angerona/modules/mem_inject_scanner.py:193-213`;
  `src/angerona/core/threat.py:48-55`;
  `src/angerona/modules/soar.py:96-105`;
  `src/angerona/modules/soar_engine.py:87-99`.
- **Evidence:** The policy deliberately accepts an entry with only an executable
  basename. `is_allowed()` then matches that name when no trusted path exists,
  irrespective of where the observed executable is located. The Settings UI
  exposes a direct **Trust name** action and, when a running process path cannot
  be read, offers to trust its basename everywhere. Memory Injection Scanner
  checks this name-only policy before opening the process and skips the entire
  PID. The same policy removes matching events from the dashboard threat level
  and both SOAR paths.
- **Exploitability / impact:** After an operator creates one name-only trust
  entry, malware can run under that basename from an unrelated writable
  directory. It can bypass memory-injection inspection and cause process-tagged
  HIGH/CRITICAL events to be excluded from posture and automated containment.
  Exploitation requires a pre-existing operator-approved name-only entry, which
  is why this is MEDIUM rather than HIGH. The restored Proton entries are exact
  paths and are not themselves vulnerable to this basename collision.
- **Safe remediation direction:** Do not let name-only entries bypass a scanner
  or SOAR. Require an exact canonical path for suppression; preferably bind
  trust to path plus Authenticode publisher and/or file hash. If a path is
  temporarily unavailable, treat the name as a display-noise hint only and keep
  detection/response active. Migrate existing basename rows to review-required
  entries and add a regression using the same basename from two directories.

## C2-R1-02 — AAR fuzzy PID/path matching can credit unrelated detections and remediation to drill steps

- **Severity:** MEDIUM
- **Components:** `src/angerona/shark/aar_report.py:89-100,107-134,371-400`;
  `src/angerona/shark/shark_attack.py:661-732,736-745`;
  `src/angerona/shark/red_team.py` (step histories and tagged process spawns).
- **Evidence:** `_matches()` accepts any event containing a matching artifact
  basename or PID. Evaluation has only a lower time bound (`step start - 2s`),
  no step-end bound, no expected detector set, and no run/step identifier. The
  first matching non-SOAR event becomes the catch; any later SOAR event matching
  the same broad PID/path becomes remediation. Some stages record Angerona's own
  long-lived PID, and multiple tagged spawns/artifacts can coexist in a run.
- **Exploitability / impact:** Ordinary telemetry concerning the same PID, a
  repeated filename, or a later step can be credited to the wrong step. One
  response event can also satisfy more than one verdict. This can inflate both
  detection and remediation rates and hide the exact drill gaps the AAR is meant
  to expose; no malicious actor is required, though an in-process event producer
  could deliberately manufacture a false pass.
- **Safe remediation direction:** Give every run and step an opaque `run_id` and
  `step_id`, propagate them through benign markers/tagged spawns and SOAR
  rollback events, and correlate on those structured fields. Also cap each
  step's time window at the next step/end-of-run and require an expected detector
  family. Keep legacy PID/path matching only as an explicitly labelled
  low-confidence fallback that cannot produce a PASS by itself.

## C2-R1-03 — Newest-row-only retention lets telemetry volume evict critical audit evidence

- **Severity:** MEDIUM
- **Components:** `src/angerona/core/storage.py:61-65,155-181,211-226`;
  `src/angerona/shark/aar_report.py:371-379`.
- **Evidence:** Every event shares one 40,000-row table. Every 1,000 inserts,
  `_prune_locked()` deletes all IDs older than `MAX(id) - MAX_ROWS`, without
  considering severity, incident membership, acknowledgement state, drill run,
  or age. AAR subsequently treats that same bounded ledger as its source of
  truth. Vacuum/checkpoint controls reclaim bytes but do not preserve evidence.
- **Exploitability / impact:** A scanner/drill storm—or an adversary able to
  induce high-volume low-severity telemetry—can push earlier HIGH/CRITICAL
  evidence and SOAR actions out of the ledger. This damages incident forensics
  and can make a delayed/re-run AAR show misses. The cap solves disk growth, but
  row-count eviction alone creates an evidence-erasure pressure point.
- **Safe remediation direction:** Keep the hot 40,000-row view, but protect
  HIGH/CRITICAL and incident/AAR-linked rows with a longer time-based tier or a
  bounded signed archive. Prune INFO first, then LOW, while retaining a hard
  overall byte ceiling. Emit and persist a visible retention/checkpoint record
  whenever evidence is retired, and test an INFO flood surrounding a critical
  event.

## C2-R1-04 — Emergency shutdown terminates unrelated Python jobs and every Ollama model runner

- **Severity:** MEDIUM
- **Components:** `kill-all-angerona.bat:17-29`;
  `src/angerona/core/ollama_lifecycle.py:21-53`;
  `src/angerona/app.py:231-260`.
- **Evidence:** The emergency batch runs elevated image-wide kills for
  `pythonw.exe` and `python.exe`, not Angerona-owned PIDs. After model-specific
  `ollama stop` attempts, its fallback forcibly kills every
  `ollama_llama_server.exe`. The normal in-app shutdown is much safer and unloads
  only resident configured/llama3-family models, but the documented recovery
  path is not similarly scoped.
- **Exploitability / impact:** An operator using the recovery script can
  terminate unrelated Python applications, notebooks, automation, or unsaved
  work and can unload models being used by other local applications. This is a
  high-impact reliability failure gated by an explicit local operator action,
  hence MEDIUM.
- **Safe remediation direction:** Persist the core, sidecar, resilience, and
  model-runner PIDs under `runtime-data` with executable path/start-time tokens;
  validate ownership before termination. As a fallback, filter command lines to
  the canonical Angerona root rather than killing by image name. If model-
  specific Ollama unload fails, report it and require a separate explicit
  `--force-all-ollama` action instead of silently killing every runner.

## C2-R1-05 — ARIA's off switch is stored but not enforced by the assistant action gate

- **Severity:** LOW (dormant until ARIA tools are integrated)
- **Components:** `src/angerona/core/assistant.py:63-84,107-158,270-282`;
  `src/angerona/core/aria_dispatch.py:89-114`;
  `src/angerona/gui/aria_hud.py:159-232`.
- **Evidence:** `Assistant(enabled=False)` records the flag, but `invoke()` and
  `confirm()` never check it. A disabled/default singleton can therefore run
  READ tools and stage/confirm WRITE tools if callers register them. Dispatch
  correctly labels agent operations as WRITE, but it relies entirely on this
  assistant gate. The current combined app does not yet wire these components,
  which limits present exploitability.
- **Exploitability / impact:** Once tools are registered, UI/settings state that
  says ARIA is disabled would not prevent actions. A caller holding a valid
  confirmation token could execute a registered write despite the opt-out,
  violating the documented safety boundary and creating a dangerous future
  integration trap.
- **Safe remediation direction:** Fail closed at the first line of `invoke()`,
  `confirm()`, and proactive/voice entry points when disabled; clear pending
  tokens when disabling; and bind each token to an immutable tool identity,
  argument digest, and preview. Add a regression proving disabled READ, WRITE,
  confirm, voice, and dispatch paths perform zero callbacks.

## Convergence statement

**Not converged in Cycle 2 / Round 1:** four active MEDIUM findings and one
dormant LOW ARIA finding are new to the current findings set. No finding was
filed for the already-deferred elevated trust-root, event-ledger key custody,
Remote Bridge protocol, or broad PowerShell-execution work. ARIA Overdrive,
Runbook RAG, posture history, routines, voice, channel push, inbox triage,
research, and the HUD were reviewed; apart from C2-R1-05, no additional active
security defect was established because these additions are presently unwired
or opt-in.

## Files reviewed

- Loop baseline: `analysis/loop/RUNBOOK.md`, `analysis/loop/PRIOR_FINDINGS.md`,
  all prior `round1`–`round3` red-team findings and remediation summaries, and
  the prior performance/visionary summaries relevant to these surfaces.
- Storage/path/shutdown: `src/angerona/core/data_paths.py`, `config.py`,
  `storage.py`, `ollama_lifecycle.py`, `eventbus.py`, `module_base.py`,
  `src/angerona/__main__.py`, `src/angerona/app.py`,
  `src/angerona/modules/storage_hygiene.py`, `blackbox_recorder.py`,
  `start-angerona.bat`, `start-angerona-guarded.bat`, `run.bat`, and
  `kill-all-angerona.bat`.
- Drill/trust/performance: `src/angerona/core/eco_wakeup.py`, `threat.py`,
  `process_allowlist.py`, `drill_resolution.py`,
  `src/angerona/gui/main_window.py`, `pages.py`, `resolve_center.py`,
  `red_team_console.py`, `src/angerona/modules/mem_inject_scanner.py`,
  `soar.py`, `soar_engine.py`, `process_monitor.py`, `network_monitor.py`,
  `packet_sniffer.py`, `yara_scanner.py`, `ransomware_heuristics.py`,
  `persistence_sweep.py`, `wlan_monitor.py`, `arp_watchdog.py`,
  `hardware_crypto.py`, and `src/angerona/shark/aar_report.py`, `verify.py`,
  `red_team.py`, `shark_attack.py`.
- ARIA: `src/angerona/core/assistant.py`, `aria_dispatch.py`,
  `aria_routines.py`, `runbook_rag.py`, `posture_history.py`,
  `perf_governor.py`, `src/angerona/connectors/voice.py`, `channel_push.py`,
  `inbox_triage.py`, `research.py`, and `src/angerona/gui/aria_hud.py`.

