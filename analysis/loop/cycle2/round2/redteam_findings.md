# Cycle 2 / Round 2 — Red-Team Findings

Date: 2026-07-14. Scope: read-only audit of the current combined tree after
Cycle 2 Round 1 remediation, QA, and performance work. Round 1 reports and the
prior findings ledger were reviewed first. Source, tests, runtime data, rules,
configuration, secrets, and host state were not modified; in particular,
`rules/_active_combined.yar` was not touched.

## C2-R2-01 — “Stop & clean” does not stop either running drill

- **Severity:** MEDIUM (active reliability/safety defect)
- **Components:** `src/angerona/gui/red_team_console.py:375-381`;
  `src/angerona/shark/shark_attack.py:239-247,329-378`;
  `src/angerona/shark/red_team.py:120-124,215-217,232-272`.
- **Evidence:** The console calls `stop_and_clean()` on both engines and tells
  the operator that a stop was requested. `SharkAttackEngine.stop_and_clean()`
  only deletes artifacts already recorded; it does not clear a run flag at all.
  `RedTeamEngine.stop_and_clean()` clears `_running`, but `_jitter()` uses an
  unconditional `time.sleep()` and neither the phase loop nor the step loop
  consults `_running`. Both playbooks therefore continue invoking later stages.
- **Exploitability / impact:** No attacker is required. During a high/extreme or
  multi-phase drill, an operator can press Stop & clean and see existing markers
  disappear, while the background thread continues sleeping, writing new inert
  markers, opening the Shark test connection, or spawning tagged benign
  processes. Cleanup can race those later writes, leaving artifacts behind and
  prolonging the exact CPU/UI load the operator tried to stop. Closing the
  console does not change the engine threads.
- **Exact remediation:** Give each engine a dedicated cancellation event. Make
  jitter and held waits interruptible with `event.wait(timeout)`, check
  cancellation before and after every stage and phase, and stop starting new
  stages once set. `stop_and_clean()` should signal cancellation, wait a short
  bounded interval for the worker to exit (never block the GUI), then perform a
  final scoped cleanup. Add a regression that stops during jitter and proves no
  later stage, process spawn, network call, completion callback, or marker write
  occurs.

## C2-R2-02 — Emergency shutdown ownership matching still reaches unrelated Python processes

- **Severity:** MEDIUM (active, operator-triggered scope defect)
- **Components:** `kill-all-angerona.bat:17-19`.
- **Evidence:** The Round 1 change removed image-wide Python termination, but
  the replacement uses `ExecutablePath.StartsWith($root)` without a directory
  boundary and accepts any command line containing the root substring. Thus a
  Python executable under a sibling such as `AngeronaSuite-copy` or
  `AngeronaSuiteEvil` passes the prefix check. An unrelated Python interpreter
  outside the suite also passes if one argument merely names a file below the
  Angerona repository.
- **Exploitability / impact:** The elevated recovery batch can still terminate
  an unrelated notebook, automation job, or tool that happens to use an
  Angerona file as input, and a sibling installation with the same prefix. This
  reopens the ownership portion of C2-R1-04 with narrower but concrete evidence;
  the image-wide Ollama fallback remains correctly removed.
- **Exact remediation:** Prefer persisted PID plus process-start-time and
  executable identity. For the current fallback, require the interpreter path
  to be exactly the suite virtual-environment interpreter or parse the command
  line and require the launched module/script entry point to resolve beneath
  the canonical root using a boundary-aware relative-path check. Do not treat an
  arbitrary argument containing the root as ownership. Add pure predicate tests
  for a valid suite process, sibling-prefix path, unrelated interpreter reading
  a repo file, mixed case, quoting, and PID reuse.

## C2-R2-03 — ARIA confirmation can execute a different callback than the operator previewed

- **Severity:** LOW (dormant/opt-in; becomes MEDIUM when third-party or dynamic
  tools are wired)
- **Components:** `src/angerona/core/assistant.py:97-100,136-164`.
- **Evidence:** A pending confirmation stores only `(tool name, args, kwargs,
  timestamp)`. On confirmation, ARIA resolves that name again from the mutable
  tool registry and executes the callback currently registered there. The
  staged record does not bind the original callback/tool identity, `ToolKind`,
  preview, or an immutable argument digest. `register()` can replace an entry
  under the same name between preview and confirmation.
- **Exploitability / impact:** A component with access to the shared Assistant
  can stage a benign-looking WRITE preview, replace the registry entry under the
  same name, and have the existing token invoke the replacement callback with
  the staged arguments. Mutable argument objects can also change after preview.
  ARIA is currently opt-in/unwired, limiting present exposure, but the defect
  violates its advertised confirm-the-exact-action boundary and is a dangerous
  integration trap for dispatch/connectors.
- **Exact remediation:** Store an immutable staged-action object containing the
  original callable identity (or stable registered tool version), required
  `ToolKind.WRITE`, deep-frozen/canonically serialized arguments, preview text,
  and a digest covering tool/version/arguments/expiry. On confirm, reject any
  registry/version mismatch and execute only the bound WRITE action. Clear
  pending tokens on register/unregister of the same name. Test callback
  replacement, WRITE-to-READ reclassification, mutable nested arguments,
  expiry, replay, and disable/reenable.

## C2-R2-04 — ARIA’s default research “READ” performs browser/egress side effects without confirmation

- **Severity:** LOW (dormant/opt-in integration defect)
- **Components:** `src/angerona/connectors/research_fetchers.py:44-59,87-104`;
  `src/angerona/connectors/research.py:73-96`.
- **Evidence:** `register_research_tool()` defaults `open_in_browser=True` and
  registers the tool as `ToolKind.READ`. A normal `aria.invoke("research", …)`
  therefore immediately calls `webbrowser.open()` for every source. Although
  hosts are allow-listed and the app does not issue the GET itself, opening the
  URLs changes host/UI state and the browser sends the queried hash, IP, domain,
  URL, or CVE to external sites. No ARIA confirmation or separate egress consent
  is required at invocation time.
- **Exploitability / impact:** Once wired, a prompt, voice transcript, or caller
  can cause multiple browser tabs and disclose an internal indicator to third
  parties through URL paths/query strings under a class documented as an
  immediate, observation-only READ. The allow-list limits destinations but not
  the privacy leak or denial-of-attention effect.
- **Exact remediation:** Split local URL construction from external opening.
  Keep a pure READ tool that only returns a preview/list; register “open research
  sources” as a WRITE/EGRESS action behind confirmation, with a source count,
  destination list, and redacted indicator preview. Default browser opening to
  false and require explicit per-invocation consent (or a narrowly scoped,
  visible operator policy). Add a regression proving READ causes zero opener or
  network calls.

## Convergence decision

**Not converged in Cycle 2 / Round 2.** Two active MEDIUM defects remain in
drill cancellation and emergency-shutdown ownership, plus two LOW dormant
ARIA/connector boundary defects that should be closed before those opt-in
surfaces are integrated. Round 1’s exact-path process trust, deterministic AAR
path/PID-token correlation, bounded severity-aware SQLite retention, disabled
ARIA gate, D-drive runtime setup, SOAR queue cache, and stat-card suppression
showed no new regression in this static pass. Previously deferred trust-root,
ledger-key/cold-archive, Remote Bridge, broad PowerShell, certificate/hash trust,
and PID/start-token architecture work was not re-filed except where C2-R2-02
demonstrates the current shutdown fallback still crosses an ownership boundary.

## Areas reviewed

- All Cycle 2 Round 1 findings, remediation, bug-test, performance, innovation,
  and loop-log evidence.
- Process allowlist consumers, memory scanner, threat posture, SOAR paths, AAR
  matching/windowing, red-team resolution state, Posture Hardening, retention,
  report history, and D-drive path setup.
- Red Team/Shark engines and console lifecycle, normal shutdown, emergency
  batch shutdown, Ollama lifecycle, Eco staged wake-up, dashboard refresh/cache,
  and current crash/watchdog evidence.
- ARIA Assistant, dispatch, routines, Runbook RAG, governor/history, HUD, voice,
  channel push, inbox triage, research, research fetchers, and their opt-in/
  disabled gates.
