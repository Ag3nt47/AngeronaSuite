# Chill efficiency and local AI lock

Date: 2026-10-18. Maintenance version remains 1.13.0. Baseline:
`706a819247af882fcc953f26290b0507ea854ca8`.

This follow-up makes Chill deliberately quieter and keeps local AI disabled
until the operator manually switches Chill off. Instructions are in the
[operator guide](../../docs/hardware-and-selfcheck.md#chill-mode).

## Operator intent and threat escalation

| Selection | Security sensors | Optional activity | Local AI |
| --- | --- | --- | --- |
| Quiet Chill | Existing live sentinels continue; deep scanners deferred | Slower budgets and refresh; selected cosmetics suspended | Blocked |
| Chill: Alert | Verified threat wakes eligible security modules sequentially | Existing alert/resource policy | Still blocked |
| Manual Chill OFF / Full | Configured modules resume | Full presentation and adaptive pressure policy | Permitted subject to existing trust/approval checks |

`runtime_chill_ai_blocked` and `ANGERONA_CHILL_AI_BLOCKED` preserve operator
intent separately from the temporary quiet-pacing flag. Both desktop and
headless engine transitions set it before startup. Incident escalation,
cooldown and drills do not clear it. AI Triage is excluded from automatic
incident wakes; pending HEAL AI diagnosis remains on disk until manual Full.
Automatic core recovery selects Chill, including Python and native Go watchdogs
that previously captured a Full-mode command. Engine services always begin in
runtime Chill, covering OS restarts from older unflagged service definitions.
Manual desktop/headless launches follow the saved startup preference unless
`--chill` is explicit. That flag also selects runtime Chill when an engine
console attaches to an existing engine. These runtime overrides do not save a
new preference. Go supervisors require rebuilding and redeployment; older
running executables retain their old launch policy. Native validation builds
are unsigned test artifacts, and live supervisor recovery/SCM installation was
not exercised.

Local service preparation, asynchronous startup, inference, streaming,
embeddings and model-management requests cannot override the lock. The final
shared URL boundary also checks direct callers and generic local-service
policies that target Ollama routes, before DNS/attestation and again before
opening the connection. Shared client calls return the explicit manual-off
instruction without preparing prompts or running inference. An in-flight
client's returned result is discarded if Chill was enabled during the call.

Only narrowly shaped resident-model release traffic is allowed in the release
helper's context: resident inventory followed by an empty generate request
with zero keep-alive for a reported model. An identical raw empty request
outside this custody is blocked, so the exception cannot cold-load a missing
model. Resident release precedes service shutdown. Angerona stops only service
handles it launched and retains them if exit is not observed, including failed
startups and multiple retries. A failed stop also blocks a replacement spawn until the retained
child's exit is proved, preventing repeated readiness checks from creating
additional daemons. It never discovers and kills an unrelated
Ollama process by name or PID. A separately launched/shared daemon remains
outside this ownership boundary.

The release shape follows [Ollama's upstream unload handler](https://github.com/ollama/ollama/blob/main/server/routes.go),
which expires a runner for an empty prompt and zero keep-alive before runner
scheduling. This source review does not establish native GPU release on the
operator's installed service.

Self-check records locked AI as an expected skip. The single-module inspector
also displays SKIP, and the engine result exposes `skipped`; none of these paths
starts the daemon or claims an active AI readiness pass. The status panel
shows the blocked reason and disables service retry until Full is selected.

## Reducing optional work

The shared controller has an explicit quiet-Chill lease, independent of the
adaptive pressure opt-out. Routine cooperative checkpoints request bounded
pauses of up to 50 ms and use their existing elapsed-work budgets. This retains
every item and makes slow hosts yield before a large count boundary. Live
inventory interval policy, event admission, response and watchdog cadence do
not inherit the optional interval floor. Indivisible native operations cannot
be preempted, and this is not a process CPU quota.

Explicit optional intervals request eightfold timing, capped at 300 seconds
added; inactive presentation windows can double that display interval further.
TUNE's quiet learning poll becomes 64 seconds instead of 8. Its known-good
query path remains available.

Dashboard presentation changes from 5/10/15 seconds to 15/30/60 seconds in
foreground/background/hidden Chill. Panel periods become 30/60/120 seconds;
posture becomes 60/60/120 seconds; optional flow-file updates become five
minutes. Full-mode periods remain unchanged. Flow timing is independent of
the panel modulus, so hidden Chill's five-tick flow period is five minutes.

System Pulse uses 30/60-second quiet samples, sleeping when its containing
window is hidden/minimized. A hidden card can share its sample with a visible
footer. Manual detail opening requests a fresh sample. Shared investigation
views have 15-second foreground and 30-second background floors; first-read
single shots and manual controls retain their separate response path.

The 30 Hz footer responsiveness sampler stops in quiet Chill. Nine selected
cosmetic timer sites, including ribbon motion and the floating orb, stop their
native timers. There are now 24 PresentationTimer construction sites; this
static count includes helpers, not 24 independent running windows. Mode changes
immediately synchronize existing timers; explicit stop/single-shot intent stays
respected. The orb's service clicks still work while its phase is frozen.

HIGH/CRITICAL evidence retains the coalesced immediate classification path.
USB approval, decision and removal notifications also wake that path, so sparse
painting does not postpone a PIN gate. The watchdog keeps its one-second
cadence. Event-driven security work remains distinct from stale presentation.

Recorder lanes wait five seconds on empty queues in quiet Chill instead of
100 ms; queue arrival wakes them immediately. Full empty waits are one second.
The first real item still starts its original 100 ms batch flush. Quiet
dead-letter replay probes are 30 seconds instead of two; forced replay remains
available. Queue sentinels wake shutdown, and peer completion preserves final
drain without periodic empty polling or persisting sentinel objects as events.

## Reproducible evidence

The broad regression also exposed an existing Windows archive-rename defect:
the filename buffer lacked an explicit trailing UTF-16 NUL. Certain path
alignments supplied no zero padding, allowing characters beyond the declared
filename to appear in the archive name. A [disposable canary](rename-proof.json) on the unchanged
Git baseline reproduced a `.logCANARY` suffix while retaining the file's bytes
and identity. Reserving and zero-initializing one extra WCHAR fixes the native
boundary without changing FileNameLength, held-handle custody or retention
permissions. Alignment/Unicode regressions exercise this repair. The failing
probe was interrupted to apply the fix before the final complete validation.

[Scheduling fixtures](scheduling.json) execute actual Git-baseline and current
controller/timing code with virtual clocks and four indivisible item costs.
Every 64-item workload completes in order; Full results match the baseline;
quiet Chill adds cooperative rest even on a healthy host; disabling adaptive
feedback does not remove that rest; manual Full restores the optional budget.
These fixtures measure requested policy, not physical CPU/RAM use or throughput.

[Recorder measurements](recorder.json) run actual AST-isolated queue/worker code
in disposable children with a private memory sink. In three matched roughly
350 ms idle samples, combined queue get calls fell **8 to 2** each time;
additional empty wait repetitions fell **6 to 0**. All six trials delivered
14 ordered, HMAC-verified events and left no unfinished workers. First delivery
was about 102.5–123.6 ms before and 105.4–119.4 ms after, consistent with
retaining the default 100 ms batch flush. This small fixture is not a general
latency bound, disk benchmark or whole-host CPU claim.

A separate inert Qt callback sample, after 200 ms warm-up, counted 20 footer
heartbeat callbacks and 14 cosmetic callbacks during 650 ms in Full, followed by zero of each in
650 ms of Chill; both native timers were inactive. This checks callbacks, not
process CPU. Targeted GUI tests also prove mode restoration, manual controls,
hidden/minimized ownership, the floating orb, and Ollama's blocked display.

Reproduce using the repository environment:

```text
venv/Scripts/python.exe tools/benchmark_chill_efficiency.py
venv/Scripts/python.exe tools/benchmark_chill_recorder.py
venv/Scripts/python.exe -m pytest -q
venv/Scripts/python.exe tools/selfcheck.py
venv/Scripts/python.exe tools/compile_check.py src tests tools
venv/Scripts/python.exe -m ruff check src tests tools
venv/Scripts/python.exe tools/validate_documentation_drift.py
```

[Validation results](validation.json) distinguish the complete regression,
self-check, source fingerprints and subsequent focused gates. Focused
selections overlap and must not be summed into another suite total.

The complete 5,078-case run reported **5,050 passed, 25 skipped and 3 failed**.
Its 993 Python source files matched the frozen fingerprint before and after
the run. One existing fixture crossed a five-minute alert-identity epoch;
[timestamp evidence](dedup-clock-proof.json) explains the two legitimate alerts.
Fixing only that fixture's module-local clock preserved every custody and
budget assertion. Its whole-file follow-up passed **24 cases with 1 skip**,
including the independent 5,000-epoch expiry/hard-cap case.

The other failures were an incomplete comprehensive containment receipt set
at its 100-second verification deadline and a disposable child exceeding its
10-second output deadline. A fresh sequential [13-case follow-up](timeout-followup.json)
passed on the unchanged sources and original deadlines. It verified all 36
quarantine and 3 process receipts, an empty response queue and the sandbox
descendant postcondition. Neither failure's physical cause is established;
staged builds/tests ran during part of the earlier full suite, which supplies
context without proving causality.

The [October 21 investigation](../timeout-rootcause-2026-10-21/README.md)
continues this work with controlled scheduling reproduction, measured
containment checkpoint stages and a fresh complete-suite record. The counts
above remain the historical October 18 outcome.

The later [entrypoint follow-up](entrypoint-followup.json) closes ignored
`--chill` flags in headless/console dispatch and stale Full-mode service/native
recovery commands. Its six Python production files, existing Python test file,
two Go launchers and two Go test files have separate source hashes and focused
validation. The final fingerprint also includes the clock-fixture correction;
the complete-run fingerprint remains the earlier frozen state. The applied
entrypoint changes passed **90 tests** in the real repository. Native checks
cover 5 top-level Go tests with 17 subtests, including 3 harmless child launches;
both launchers also compile for Windows amd64 and 386 with PE architecture
verification.

The final [offline self-check](selfcheck.json) passed **28 phases**. Its 84
module rows reconcile to 66 PASS and 18 expected SKIP results, with 559
subchecks and 9 independent verifier checks. The constrained-worker fixture
completed 32 inert modules with a measured peak of 2/2 workers and no unfinished
calls. Compilation of all 993 Python files, Ruff and documentation drift checks
also passed.

## Limits

Offline tests prove scheduling, transport denial, result accounting, process
handle custody and inert event delivery. They do not prove physical old-machine
CPU/RAM savings, native Ollama runner/GPU exit, live sensor efficacy, every
platform's native integration or a prolonged all-module soak. Native cleanup is
best effort when the local API/OS fails, while the local request lock remains
in force. Another application can independently start or use an unowned daemon.
An already admitted native call cannot be retroactively prevented by a mode
toggle. Slower presentation and queued replay can display older data.

The Word master manual retains its dated chapters. The linked Markdown guide
contains the current Chill instructions; no Word/manual rendering update is
claimed for this follow-up.
