# Cycle 27 Round 2 — Red Team simulation gap analysis

Date: 2026-08-28
Scope: inert, local-only simulation and read-only code analysis. No exploit,
network attack, host persistence, response mutation, or publication was run.

## Outcome

The reported “about 90% missed” result is reproducible. A one-cycle chained
campaign contains 15 steps: 13 detection-eligible probes, one explicitly
unmonitored Discovery step, and one negative-control Noise step. With the
13-entry validation policy present but `Purple Remediation Guard` not running,
the AAR credited only 1/13 eligible probes (7.7%) and missed 12/13 (92.3%). The
one credit was an INFO-level raw `Process Monitor` event, not an analytic
detector verdict.

This state is possible in the GUI because “13/13 technique contracts armed”
means only that policy JSON entries exist. The launch path does not prove that
Purple Guard is enabled, running, healthy, bound to the correct data root and
target, or through its first cycle. It also couples policy activation to the
Auto-contain response toggle.

Two controls passed under the same safe, isolated campaign:

| Variant | Eligible caught | Evidence |
|---|---:|---|
| Policy present; Purple Guard stopped; Process Monitor running | 1/13 (7.7%) | T1059 raw INFO only |
| Native FIM + Process Monitor, bounded 1-second FIM cadence | 13/13 | 12 generic FIM file-create MEDIUM events + T1059 raw INFO |
| Purple Guard + Process Monitor | 13/13 | 12 Purple HIGH verdicts + T1059 raw INFO and Purple verification |

These controls show that marker production and correlation work when the
required consumers are live. They do **not** prove real-world technique
coverage: twelve of the thirteen standard probes are filenames on inert text
files, and Purple Guard intentionally recognizes those simulation names.

## Exact failed-probe matrix

The table below is the `policy_active=13`, Purple-stopped reproduction. “Actual”
lists evidence observed before AAR scoring.

| Stage | ATT&CK-like probe | Expected simulation detector | Actual | Result | Root cause |
|---|---|---|---|---|---|
| Initial Access | T1566.001 invoice marker | Purple Guard; native FIM observation | none | MISSED | Policy exists but no required live detector |
| Discovery | read-only process enumeration | none by declared design | none | N/A | Correctly excluded from denominator |
| Credential Access | T1003 lsass-named marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Privilege Escalation | T1548.002 UAC-named marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Defense Evasion | T1070 AMSI/log-clear-named marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Registry Run Key | T1547.001 marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Scheduled Task | T1053.005 marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| WMI Persistence | T1546.003 marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Lateral Movement | T1021.002 PsExec/SMB-named marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Command & Control | T1071 beacon-config marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Exfil Staging | T1074 staging marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Ransomware Impact | T1486 ransom-note marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Data Destruction | T1485 wiper-named marker | Purple Guard; native FIM observation | none | MISSED | Same lifecycle/readiness gap |
| Benign Execution | T1059 nonce-tagged idle processes | Purple Guard analytic verification; Process/ETW observation | Process Monitor INFO, ~1.17 s | CAUGHT by current AAR | AAR treats observation as analytic detection |
| Noise Injection | benign note | no alert | none | PASS | Correct negative control |

## Pipeline map

1. `RedTeamConsole._launch()` builds the options and calls
   `MainWindow._run_simulation()`.
2. The main window optionally wakes Chill-paused modules, registers an FIM
   watch and Purple target, optionally writes the 13-entry validation policy,
   then starts `RedTeamEngine`.
3. `RedTeamEngine` writes twelve inert text markers, performs one read-only
   Discovery step, creates bounded nonce-tagged idle Python processes, and may
   add benign Noise/custom markers. Narration travels through a Qt callback;
   the engine does not currently publish narration to EventBus.
4. FIM and/or Purple Guard observe files; Process Monitor/ETW observes process
   creation; Purple Guard promotes matching process telemetry to a HIGH
   simulation verdict.
5. EventBus and FlightRecorder retain events. After completion the GUI waits
   45 seconds, then `aar_report.evaluate()` correlates paths/PIDs/tokens.
6. The AAR currently calls the earliest matching non-successful-remediation
   event a detection, regardless of severity or evidence type, and separately
   remembers a Purple Guard event as verification evidence.

## Findings and remediation matrix

| ID | Severity | Finding | Evidence | Required correction | Acceptance gate |
|---|---|---|---|---|---|
| RTS-01 | Critical | Policy presence is presented as detector readiness. | `main_window.py:1788-1796`; `purple_guard.py:179-210`; reproduced 13 policies + stopped detector = 1/13. | Add an atomic simulation coverage lease. Require module instance, enabled/running state, health, correct data root, registered target, EventBus/recorder binding, and fresh first-cycle receipt for every requested probe before creating marker 1. Temporarily start required detectors only under explicit launch authorization and restore prior state afterward; otherwise refuse with exact reasons. | Disabled/stopped/wrong-root/unhealthy/first-cycle-timeout negatives all refuse; ready case begins and records a signed preflight receipt. |
| RTS-02 | High | Detection coverage is coupled to Auto-contain response. | `main_window.py:1788`; policy activation occurs only when `_sim_auto_remediate`. | Always prepare observation/detection contracts for Red Team runs. Use Auto-contain only to authorize response actions. | Auto-contain OFF still produces full observation/analytic coverage while response remains 0 and no mutation occurs. |
| RTS-03 | Critical | AAR has no positive detector-evidence contract and permits self-credit. | `aar_report.py:271`; synthetic exact-path INFO events from `Red Team Attack Engine` and `Shark Attack Engine` were credited; only `Console` was rejected. A failed `Active Response SOAR` event was also credited. | Require authenticated `evidence_type`, `detector_verdict`, producer capability ID, run/step/target binding, and detector receipt. Explicitly reject simulator, console, narration, ground-truth, orchestration, and response-only sources. Do not rely only on a module-name denylist. | Simulator/Console/failed-response/raw-INFO negative controls never increase analytic coverage; valid signed detector receipts do. |
| RTS-04 | High | AAR conflates observation, analytic verdict, simulation validation, and native efficacy. | Native control scored T1059 from Process Monitor INFO; Purple is simulator-specific. | Report four separate rates: sensor observation, native analytic verdict, simulation-contract verification, and successful response/postcondition. Preserve the current value only as a clearly labelled compatibility field. | Each evidence class has independent numerator/denominator and provenance; Purple-only success cannot claim native behavioral coverage. |
| RTS-05 | High | Engine-start refusal is ignored, permitting stale AAR flow. | `main_window.py:1807-1811`; `RedTeamEngine.start()` returns bool but caller ignores it. Target registration failures are swallowed at `1777-1787`. | Treat target/watch registration and engine start as preflight gates. On false/exception, cancel pending AAR count, release evidence lease, restore environment, and show exact refusal. Bind AAR to the newly issued run ID and history digest. | Invalid target and rejected preflight produce no AAR from a prior run and leave no pending state/lease. |
| RTS-06 | High | Custom probes have no explicit expected-evidence contract. | `aar_report.py:259` defaults unknown stages to `detection`; ordinary custom marker has no Purple rule. `_redteam_custom_lsass_dump_*` collides with substring classification at `purple_guard.py:249-255`. | Require custom probe declaration: unique ID, expected producer/evidence type, category, safe matcher, timeout. Default undeclared custom probes to `informational`, never silently to detection. Match standard markers by exact grammar, not token-anywhere. | Ordinary custom probe is N/A until a detector contract is selected; token-collision custom names cannot impersonate T1003. |
| RTS-07 | Medium | T1059 promotion can lose busy-bus evidence. | `purple_guard.py:397` scans only `recent(500)` raw events. | Use an enrolled EventBus revision cursor with overflow detection, bounded batches, and explicit incomplete-coverage state. Prefer priority/assurance receipts for the process probe. | >500-event burst before scan still yields T1059 or a truthful `coverage_incomplete` result, never silent miss. |
| RTS-08 | Medium | Explicit AAR data roots can read a different ledger. | `aar_report.py:700,715`: `Config.load()` and `FlightRecorder(cfg.db_path)` ignore the supplied data root for DB selection. | Accept an explicit recorder/db path or derive it from the supplied root; validate it is the same run root. | Two-root negative test proves AAR reads only the requested run's recorder. |
| RTS-09 | Medium | A finite marker-name suite is presented too close to attack efficacy. | Twelve standard probes are inert text-file names; Purple signatures are intentionally simulation-only. | Add probe tiers: pipeline canary, native telemetry, analytic behavioral replay, and response exercise. Label coverage by tier and add inert event fixtures for ETW/AMSI/registry/task/WMI/network semantics without performing those actions. | UI/report never equates marker coverage with real-world or state-actor coverage; every tier has independent provenance and limitations. |

## Self-credit result

Observed live runs emitted **zero** simulator-origin EventBus records: current
`RedTeamEngine._narrate()` uses only its Qt callback (`red_team.py:131-134`).
Therefore the three measured live runs did not self-credit.

The scoring boundary is still unsafe. With one exact artifact path:

| Injected source | Severity | Current AAR credit |
|---|---:|---:|
| Console | INFO | rejected |
| Red Team Attack Engine | INFO | **credited** |
| Shark Attack Engine | INFO | **credited** |
| Process Monitor raw telemetry | INFO | **credited** |
| Active Response SOAR with `mitigated=False` | INFO | **credited** |

The fix must be a positive authenticated detector-evidence schema plus source
separation, not just adding two more names to the `Console` exception.

## Reliable safe reproduction

Run from repository root with `PYTHONPATH=src`. The reproduction is the same
bounded campaign used above: create a temporary data root, call
`ensure_redteam_validation_pack(root)`, start only `ProcessMonitorModule`, run
`RedTeamEngine.start(jitter_range=(0, 0), noise_chance=1, complexity=1,
campaign=True)`, wait three seconds, and call `evaluate()` over
`EventBus.recent(5000)` with `REDTEAM_STAGE_CATEGORY`. It deterministically
returns `policy_active=13`, `detection_steps=13`, `caught=1`, `missed=12`, and
`coverage_pct=7.7` on the verified Windows host. The complete output and exact
configuration are preserved in the adjacent JSON artifact.

Focused existing safety/contract gates:

```powershell
$env:PYTHONPATH = 'src'
.\venv\Scripts\python.exe -m pytest -q tests/test_redteam_runtime_targets.py tests/test_red_team_live_kill_chain.py tests/test_cycle5_shark_enterprise_contract.py
```

Do **not** use `tools/validate_adversary_combat.py` for this diagnostic: that
harness intentionally exercises reversible response actions, while this audit
was required to remain observation-only.

## Remediation order

1. RTS-01/02/05: fail-closed launch and coverage lease.
2. RTS-03/04: evidence taxonomy and anti-self-credit AAR contract.
3. RTS-06/07/08: custom, cursor, and root-binding correctness.
4. RTS-09: expand safe semantic replay tiers and make limitations explicit.

No product code was changed by this analysis.
