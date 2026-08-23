# Round 6 Bug Test — Chill / Threat / Drill Regression

## Gates run

- `py_compile`: 296/296 package files compiled.
- Discovery: 66 modules, 0 import errors, 0 duplicate non-empty CODEs, 0 missing self-tests.
- Module self-tests: 51 passed, 16 expected environment/disabled skips, 0 unexpected failures.
- `tools/selfcheck.py`: 26/26 passed.
- Focused Chill/threat/drill/startup/Ollama tests: 55/55, then 72/72 on the integrated tree.
- Full pytest: 902 passed, 3 intentional platform skips, 0 failed.
- Final local gates: Chill/race/performance/Ollama 17/17; autostart 5/5; briefing 9/9; daily-briefing self-test passed.
- `git diff --check`: clean (line-ending notices only).

## Findings

- **R6-BT-01 FIXED:** the UI consumed only 20 recent events by timestamp, so an INFO burst could hide an active threat from Chill auto-wake. It now consumes the EventBus revision delta atomically.
- **R6-BT-02 FIXED:** direct Ollama callers could retain llama for 30 minutes in Chill. Effective keep-alive now forces immediate release in Chill; idle AI modules are policy-paused.
- **R6-BT-03 FIXED:** a rapid Full -> Chill transition could cancel the sequential worker and strand stopped/restarting queued sensors. Entering Chill now reclaims every enabled deep module; the cancellation regression passes.
- **R6-BT-04 FIXED:** Windows autostart accepted any task with the expected name, including stale `python.exe`/old-path definitions. It now validates task XML for exact executable, arguments, working directory, one enabled logon trigger, enabled task state, and highest privilege. The installed task is currently valid; its previous run returned `-1`, with no matching Task Scheduler operational-history event available.
- **R6-BT-05 FIXED:** Daily Briefing used raw drill/exposure CRITICAL counts to claim `UNDER ATTACK`. Raw evidence counts are preserved, while posture, emission severity, and wording now use active-threat counts only.
- **R6-BT-06 REPORTED:** headless startup still needs a GUI-neutral Chill controller; simply deferring scanners would leave no active-threat wake/cooldown path. Assigned to the integration owner.

