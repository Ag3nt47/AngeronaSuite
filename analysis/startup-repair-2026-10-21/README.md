# Verified automatic source startup repair — October 21, 2026

`start-angerona.bat` now delegates source startup to a fixed Windows PowerShell
supervisor. A recognized runtime, dependency or GUI-runtime failure can invoke
the existing Angerona repair tool once. The supervisor releases its launch
lease only after the helper exits, waits for repair verification, then repeats
the complete original checks. A second failure stops. Generic errors, source
or package trust failures, busy environments, cancellation, low persistent
storage and dashboard readiness timeout cannot initiate replacement.

The repair entry points use the shared implementation in
`tools/startup_repair_common.ps1` and `Repair-Angerona-Python.ps1`:

- Verify fixed nonredirected local paths and unelevated source authority.
- Acquire checkout and canonical helper byte-range locks before mutation.
- Find independently installed PSF-signed CPython 3.12 x64, or use the existing
  Microsoft-signed winget route and independently check the resulting Python.
- Resolve exact hash-locked wheels, using verified local artifacts first.
  Installs and final-path refresh use the verified wheelhouse offline.
- Build and verify a separate candidate before preserving the old environment
  and promoting the candidate. Refresh activation scripts and executable
  entry points at their final path; reject references to staging.
- Independently check ABI, exact distributions, dependency consistency, Tk and
  offscreen native Qt before accepting the replacement.

No failure text becomes a shell command. Repair does not load Ollama, use
Llama/HEAL, change the Chill lock, reset configuration or response authority,
or discard journals, evidence or quarantine. The retry explicitly starts in
Chill. The manual repair entry point retains confirmation; the automatic
supervisor owns the single authorized attempt. Packaged installation repair
continues to require its signed installer boundary.

## Interruption and process custody

Review exposed two gaps in the first candidate: direct helper startup could
overlap replacement, and an abrupt exit during promotion lacked durable
recovery intent. Both are addressed before acceptance. Repair retains the
canonical `startup-helper.lock` as well as its checkout lock. The Python API,
check-only CLI and pre-Tk path take canonical custody before probes or GUI
runtime loading. The UI and worker retain references to the actual OS lease
until both finish.

Before either rename, repair flushes private intent, a matching witness and
candidate marker containing fixed paths and native directory identities.
Phase updates are flushed and atomically replaced. The source supervisor
detects pending work before executing any venv process. Under both locks,
repair restores the exactly identified previous environment for a consistent
interrupted transaction. Missing, corrupt, redirected, changed or ambiguous
evidence refuses automatic reconciliation and preserves files for review.
Verified completion or proven rollback records its resolution.

Review also reproduced pip configuration leakage with uppercase `NUL`: pip's
null-device comparison expects lowercase `nul`, so machine/site configuration
could otherwise redirect an install despite `--isolated`. The child environment
now uses the exact value. An actual pip configuration-loader fixture challenges
synthetic global/site `install.target` settings and verifies their exclusion;
it performs no installation.

Disposable repair commands enter a private kill-on-close Windows Job at
process creation, before their suspended main thread resumes. An explicit
inherited-handle list excludes unrelated handles. Each command has a finite
limit within the remaining 900-second overall command budget. Closing the
repair job retires its owned descendants. The live dashboard is outside that
job; startup cancellation or the original 120-second readiness timeout leaves
it running and cannot launch another copy.

## Storage and validation scope

Canonical persistent data must independently retain at least 128 MB free.
Private scratch can fall back to the checked installation drive; this does
not move or substitute for persistent settings/evidence storage. A fresh
exclusively created file is flushed and read back before the location is used.
Only child process TEMP/TMP values change, without registry or parent changes.

Regression fixtures exercise the actual PowerShell transaction functions on
temporary fake environments: candidate failure, final refresh failure,
independent verification failure, promotion, rollback and abrupt exits around
both renames. Other fixtures challenge corrupt/tampered/missing intent,
concurrent direct startup, lease lifetime, signatures, artifact hashes,
environment filtering, command deadlines and owned descendant cleanup.
Native readonly probes and disposable process/scaffold checks are distinct
from an actual operator repair. No real runtime replacement, installer or
network download is run by these regression fixtures.
Process termination fixtures do not simulate sudden power loss or establish
hardware durability. Malformed or ambiguous recovery evidence intentionally
requires review instead of guessing which environment to trust.

The operator instructions are in [Safe Startup](../../docs/safe-startup.md).

An initial full attempt exposed a stale inline-launcher assertion and an inert
pytest observer child timing out before test execution. Review found a second
stale launcher assertion. The failed attempt was deliberately interrupted;
its unchanged source snapshot is retained, and its termination is excluded
from acceptance. The dependent self-check correctly refused to run.

The launcher contracts now follow the fixed supervisor through the actual
hash-locked installer, retaining authority, offline installation, ordering,
logging and deadline assertions. The observer's inert children now fix their
pytest root and configuration boundary to their own temporary directory.
Pytest had enumerated unrelated ancestor scratch entries even for an explicit
probe file. A separate control rejects the old traversal with native/pytest
status 2 and zero collected tests; the corrected helper visits only its owned
directory and passes one test with native/pytest zero. Both complete
unconfigure and atexit, and retain the original 30-second child deadline.
Exact filesystem latency at the original timeout was not captured; the
collection fanout mechanism and the corrective boundary were independently
exercised. These component profiles are not whole-product speed benchmarks.

## First frozen local validation

The complete local Python 3.12 suite passed **5,228 tests / 25 skipped / 5,253
collected**, with zero failures/errors, in 2,543.25 seconds of pytest time.
Native process, session and SystemExit statuses were zero; unconfigure completed,
both atexit markers were present and stderr was empty. All **1,018 source/lock
inputs**, including **1,002 Python files**, matched before and after under
CRLF/CR-to-LF normalization. The supervisor's 2,615.594 seconds includes postrun
source readback. This is validation time, not an application speed benchmark.

Both actual GUI drills passed the original requirement for 37 verified positive
closures and independent pre/post OS witnesses. Each settled with zero pending
work, no timeout and no queue drops. These local passes do not establish the
cause of the earlier hosted Python 3.11 zero-action assertion.

The **Chill operator AI lock** profile passed **28/28 selfcheck phases** in
39.5 seconds. Its 84 module rows contain **66 PASS / 18 SKIP**; **558 module
subchecks** contain **528 PASS / 30 SKIP**. All **nine independent verifier
challenges** passed, including failure, timeout, malformed-result and corrupt
accounting canaries plus saved-report reconciliation. AI is skipped before
endpoint probing under the persistent Chill lock, including CHILL: ALERT.

A separate **Full capability diagnostic** with the AI lock cleared correctly
failed endpoint attestation for an existing Ollama wildcard listener. It recorded
27 passing phases and one failed phase; 84 modules contain 66 PASS, one FAIL and
17 SKIP, with 559 subchecks (530 PASS, one FAIL, 28 SKIP). All nine verifier
challenges still passed: the checker correctly retained the unhealthy verdict.
The signed Ollama tray/daemon chain predates these checks, but its launch
ownership could not be established. No stop, unload, rebind or reconfiguration
was performed. This host finding is preserved separately from the Chill pass;
there is no evidence connecting it to the earlier hosted GUI failure.

[Structured verification](verification.json) records both selfcheck profiles,
the full regression, focused gates, collection-boundary controls and private
evidence hashes. Selfcheck's existing harness verdict uses its established
`os._exit` policy; the full regression supplies separate normal-shutdown proof.

## Hosted follow-up at `3ed14db`

The [first published repair run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39697993480)
passed all eight non-Python CI jobs, and its
[three security jobs](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39697993504)
passed. All four Python versions failed the same **23 new startup-repair
cases**, each reporting **5,218 passed / 12 skipped / 23 failed / 5,253
collected**. Native/session/SystemExit were one; unconfigure and both atexit
markers completed. The failure lists contain neither the earlier GUI witness
assertion nor a native shutdown crash; that absence is not a separate per-case
GUI pass receipt.

Ordinary file creation relied on the token's default owner, which can be
Administrators on an elevated Windows runner despite an explicitly user-owned
parent. Hosted logs identify custody refusal without recording the original
owner SIDs; the wrong-owner challenge models that metadata at the query seam.
Fresh helper locks and
durable JSON now supply current-user ownership and a protected closed DACL
atomically at creation, then independently verify custody. Opening an existing
file preserves its original owner, ACL and contents; verification cannot repair
unsafe evidence into a passing result. Fixture candidate directories and Python
witness/resolution files now establish explicit private custody too. Each
malformed-resolution fixture proves file custody before testing its contents.

The old descendant fixture recorded a three-second deadline expiry followed by
a missing PID witness. Its inner log was not captured, so its exact phase before
expiry is unobserved. The replacement compiles a small native parent/child before
the measured command, avoiding nested interpreter setup. A negative control
proves its descendant survives a normal uncontained parent exit; the actual
Angerona Job must retire the witnessed descendant on the unchanged three-second
deadline. No deadline, admission predicate or ownership check is relaxed.

Focused corrective gates passed **54 startup-flow cases in 23.39 seconds**,
**33 repair-tool cases in 148.55 seconds**, and the three targeted transaction,
private-file and native Job cases in 12.27 seconds. Python lint/compilation and
all four launcher/repair PowerShell parser checks passed. Read-only delta review
found no security blocker. A real foreign-writer ACL remains rejected and
unchanged; wrong-owner coverage uses a qualified metadata-query model while
preserving the real descriptor and bytes. It is not an elevated OS reproduction.

The corrected frozen full regression passed **5,230 tests / 25 skipped / 5,255
collected** in **2,119.10 seconds** of pytest time. Native/session/SystemExit
were zero, unconfigure completed, both atexit markers were present and stderr
was empty. All **1,018 source/lock inputs**, including **1,002 Python files**,
matched before and after under newline normalization. Supervisor time was
2,123.094 seconds including postrun source readback. Different run durations do
not establish a product performance improvement.

The same run passed all 54 startup-flow and 33 repair-tool cases, 128 Chill
regressions, 98 performance regressions and 27 selfcheck-policy/cleanup cases.
These named component groups are subsets of the full suite. The actual dashboard
double-drill call passed in 123.640 seconds; both signed reports verified their
37 required positive closures and independent pre/post OS witnesses. Both drills
settled with zero pending work, no timeout and no queue drops.

The dependent **Chill-locked selfcheck** then passed **28/28 phases** in
30.718 seconds: **84 modules (66 PASS / 18 SKIP)**, **558 subchecks (528 PASS /
30 SKIP)**, the separate pipeline check and all **nine independent verifiers**,
including saved-report reconciliation. Its existing native harness verdict is
distinct from the full suite's independent normal-shutdown proof.

[Corrective verification](hosted-followup.json) preserves the four failed hosted
jobs and their exit diagnostics separately from this passing frozen rerun. The
earlier Full-mode wildcard-listener refusal remains in the first verification
record; no unowned/shared daemon was stopped or reconfigured. The historical
`ee61f3c` GUI zero-action cause remains unproved. GitHub acceptance of the next
published revision is checked separately from these offline results.
