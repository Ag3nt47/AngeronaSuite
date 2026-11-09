# Watchdog and Core mutual recovery hardening

Date: 8 November 2026. Version: 1.15.0 source maintenance.

The update strengthens Python peer identity, actual supervision progress and
source continuity, and extends native Safe Startup repair to the mutual
supervision chain. It does not create kernel protection or a new privilege
authority. Existing operator preferences and host security policy are preserved.

## Implementation

- Real authenticated heartbeat readers now require the expected invocation,
  image and process generation. Windows observations use query-only native
  leases and revalidate identity. A new generation must advance its counter;
  repeated authenticated timestamps cannot replace counter progress. Identity
  uncertainty holds replacement and termination.
- Core and Python Watchdog heartbeat loops require supervision work within
  180 seconds during startup and 60 seconds after a completed pass. Failed
  passes cannot refresh this progress. Existing heartbeat-staleness and bounded
  recovery policies remain separate deadlines.
- A bounded, immutable session seal covers selected execution file types in
  the package and fixed bootstrap/recovery files. Its inherited digest can
  inhibit a peer with different source. Background reviews run at 60-second
  intervals plus observation/scheduling time; actual launches recheck source.
  Failed checks stay held rather than adopting changed bytes automatically.
- Source-check status uses memory publications. Disk observation is outside
  Qt and the Watchdog heartbeat loop. Backoff does not repeatedly rehash source
  before a recovery is due. A held launch adds no new crash debt or permission
  to kill a live process. Manual relaunch reporting follows the actual result.
- Self-Integrity Monitor fingerprints the new gates and selected control-flow
  dependencies. This is another detector inside the same Python trust domain.
- A later review identified implicit working-directory/script-directory import
  shadows outside the sealed package. Canonical source peers and the exact
  Black Box script now use isolated Python startup. The initial source Core
  command also uses isolation while retaining its fresh-cache options. Other interpreters,
  unrelated commands and frozen executables are not rewritten. The existing
  editable installation resolves canonical source in isolation. Site packages
  and editable-install hooks retain their separate bootstrap trust boundary.
- The native recovery scope expands from 39 to 48 operational files. Exact
  canonical GitHub blobs remain bound to local pins, original preservation,
  custody checks and bounded repair. Runtime source checks perform no download
  or file overwrite. Older 39-file update capsules require an explicit reviewed
  transition; their unknown-profile refusal remains effective.

## Review and validation record

Independent review identified and corrected blocking source scans in the
Watchdog heartbeat loop, repeated scans during backoff, inaccurate success
reporting after refused manual relaunch, and importable plugin-named package
directories omitted from the seal. The new gates are also in the existing
in-memory fingerprint scope.

An initial combined 23-file gate produced 511 passes, seven failures and two
skips. Four failures reported a changed shared temporary ancestor during
source-update storage custody. Directory metadata included volatile content
timestamps, sizes and link counts. The correction retains exact named/native
directory identity and attributes while reserving full content-change checks
for the actual inventoried scope. Regular-file checks remain complete. Three
failures came from a Chill launch-command test double missing the new
supervision API; the fixture now isolates its declared launch-intent scope.
No verification barrier, deadline or alert original was cleared to obtain a
passing result. Some source edits also occurred during that initial gate, so
it is not final-revision acceptance.

The isolated manager lifecycle test observed scanner telemetry, no duplicate
launch and exactly one controlled scanner respawn, with its owned cleanup.
This uses a private diagnostic profile with Watchdog/Black Box disabled for
that fixture. It does not establish a full live host protection session or
independent proof of every component's retirement history.

The subsequent broad storage/recovery/lifecycle gate predates the final import
isolation follow-up. Its results, the separate import/peer gate and publication
are recorded below after their checks complete. Overlapping cohorts are not
added to a fictitious final total. The inert import test uses an explicit
allowlist seam for a nonexistent probe module and real owned child launch,
wait and cleanup; production's exact module allowlist is checked separately.

- The 25-file storage/recovery/lifecycle cohort completed with **602 passed,
  3 skipped**, in 1,611.44 seconds. The skipped link/reparse fixtures remain
  coverage limits for the current Windows token. This run began before the
  final import follow-up and dead-peer scan optimization.
- The eight-file import, peer-identity, STOP, source-policy integration and
  recovery cohort completed with **155 passed**, in 18.44 seconds.
- Documentation/export validation completed with **35 passed**, in 11.03
  seconds. The online manual links the maintained companion addendum; the
  dated Word/PDF revision is not relabeled as this source update.

The first final manager lifecycle repeat collected telemetry and avoided a
duplicate, but missed its existing 12-second controlled-respawn observation.
A private timed diagnostic reproduced the delay without source changes: full
source checks ran at admission, at the due-dead retry and immediately again at
dispatch. The redundant due-dead check took 2.891 seconds. Exactly one
replacement was observed after 12.344 seconds of the respawn observation.
The correction removes only that redundant due-dead check: dispatch still
performs fresh source verification, while suspended/manual recovery retains
both pre-termination and pre-dispatch checks. Existing deadlines are unchanged.
Fresh native recovery and final targeted results follow after verification.

The corrected timed diagnostic observed exactly one replacement after 7.828
seconds within the unchanged 12-second observation. It required the admission
scan and fresh dispatch scan. Replacement heartbeat readiness was verified.
Four query-only native process leases captured actual Job members across both
scanner generations before kill/STOP; all four waits signaled and handles
closed. The churn worker retired. Initial diagnostic cleanup had attempted to
query an already closed owner; its timing did not establish cleanup custody.
The corrected run used retained process handles instead. No operator Core,
Watchdog or Black Box was launched or selected for termination.

Final focused results are separate from the earlier broad run:

- Optimized supervisor/peer regression gate: **103 passed** in 17.52 seconds.
- Initial source import isolation, Safe Startup and stale-bytecode regression:
  **112 passed, 1 existing symlink-fixture skip** in 46.41 seconds. Inert child
  imports checked the real launch prefix without executing Core or sensors.
- Original isolated manager lifecycle self-test on final source: **passed** in
  22.02 seconds, with telemetry, duplicate prevention and exactly one scanner
  respawn. Its original 45-second outer budget and 12-second respawn observation
  remain unchanged.
- Ruff, compilation, documentation drift, manifest generation consistency and
  bootstrap-pin consistency are required final publication checks. Default
  Self-Integrity registration observed 49 callable fingerprints with no drift
  in the final read-only check; this is not independent initial code attestation.

Publication must be proven separately by the guarded publisher against the
exact reviewed commit, canonical origin, clean worktree, public default branch
and README assets. Hosted CI is independent evidence and is not predeclared
successful by these local results. No complete-suite, kernel-immunity or live
host protection claim is inferred by adding the overlapping counts above.

### Hosted integrity-contract follow-up

The first published revision, `0db2c83`, completed each of Python 3.10, 3.11,
3.12 and 3.13 with 15,025 passes, 44 skips and one identical failure. A retained
regression still required the old exact
31-target Self-Integrity closure. The implementation intentionally expanded
that closure to 49 targets. The follow-up preserves the exact 49-target
requirement, explicitly requires all 18 added peer targets/dependencies, and
tests reassignment of four new gates. Its five-file focused cohort passed
87 cases in 12.26 seconds; Ruff passed. No production check, deadline, ACL
condition or missing-target refusal was weakened. This is a test-contract
correction; production recovery pins and the previously verified GitHub blobs
are unchanged. Subsequent hosted results remain a separate exact-commit check.

### Final detector-cycle settlement follow-up

The next hosted Python 3.13 run at `3aaa06a` completed with 15,029 passes,
44 skips and one separate GUI containment-witness failure. The signed report
truthfully remained partial: 26 of 36 inert file markers were still present.
All 13 admitted response requests had completed, with no recorded proof hold,
journal fault, queue drop or remaining task. `AUTHORITY HELD` is the expected
Source Observe host-authority state in this fixture; the diagnostic previously
projected it to `other`. It is now represented explicitly.

The peer Watchdog/source-seal paths do not run in that fixture. The new four
Self-Integrity tests also start no workers and restore their callable changes
through function-scoped monkeypatches. No direct causal link to peer hardening
was established. A pre-change isolated GUI replay passed in 125.51 seconds;
its cleanup passed and the exact pytest generation exited. Missing hosted
private trace files prevent proving the exact scheduling of that failure.

Source inspection found a real independent race: Combat can have no pending
tasks while PurpleGuard is still enumerating files or preparing the next
synchronous event. Queue emptiness alone therefore cannot establish final
producer completion. A controlled regression parks an actual detector scan
after its file snapshot, then creates a later inert marker. It verifies that
the old empty-queue predicate is true while the marker remains unprocessed.

The correction requests a cycle from the exact admitted detector object,
lease, run and lifecycle generation. A request arriving during an older scan
can only be acknowledged by a later full cycle. Only after that acknowledgment
does settlement read the real response queue again. A pre-ack queue snapshot
cannot be reused. The response object and its lifecycle generation are also
revalidated around queue reads. Completion checks read the issuer's mutable
artifact/handoff state under its existing lock, released before acquiring the
detector lifecycle lock. Transient full-scope observation failure retries the same
bounded scheduling token on the existing worker cadence; it grants no receipt
or policy authority. Producer replacement, generation changes and failed work
cannot acknowledge completion. Producer work and response retirement share
the original run and settlement deadline without extension.

The deterministic regression requires actual sandbox quarantine and signed
postcondition evidence. Scheduling-only budget fixtures explicitly stub the
producer-observation seam; their original unfinished-task, expiry, cancellation,
warning and evidence-age assertions remain unchanged. The GUI witness retains
the original 36-file/three-process expectations and now records the bounded
producer observation state. A partial or unavailable result is not relabeled
as verified containment.

### Owned-process observation deadline precision

The same hosted revision completed Python 3.10 and 3.11 with 15,030 passes
and 44 skips each. Python 3.12 completed with 15,028 passes, 44 skips and two
owned-process composition failures. A valid one-second budget became
`1.0000000000000568` after internal floating-point deadline arithmetic, and the
strict nested owned-AI scope validator correctly rejected it. The binary-boundary
case is reproducible with a constant monotonic clock; host load is unnecessary.

The correction caps internal remaining waits at their original validated
caller budget after the existing finite, regression and expiry checks. Strict
public input limits stay unchanged, including rejection of an explicitly
over-budget input by one representable float. The affected App, companion,
native child, process-inventory and AI ownership handoffs use that rule;
observation expiry and identity custody are not renewed by an internal retry.
The first owned-AI focused gate passed 32 cases, including both hosted failure
identifiers. Final chain validation and changed-revision native GUI validation
are separate acceptance gates.

After the operator's normal STOP/Quit, the known startup lease holder was no
longer present. The previously held two manager edits and one child-job edit
then applied normally, without a file replacement, ACL change or process signal.
The full App/companion/AI gate passed **105 tests** in 9.03 seconds. The native
child/inventory gate passed **150 distinct tests** across its new and existing
files, including **32 new boundary cases**, with native fixture retirement and
handle-close verification. Counts overlap earlier focused checks and are not
added into a fictitious full-suite total.

The operational profile remains 48 files. Its regenerated manifest SHA256 is
`3f946cd9530050c0480467bb4d717b07579b54849868ebd13d8b0c7a9f8043d8`
and Git blob is `3d2821352371d1114219aa69bf7aa5d75a3bb292`. The native verifier
is unchanged. Bootstrap pins were regenerated from the reviewed current files.

The final 16-file GUI/lifecycle/recovery cohort passed **218 tests** in 482.32
seconds on the changed source. This includes the unchanged two accepted GUI
launches with authenticated AARs, original 36-file/three-process OS witness
requirements, producer and response-worker generation refusals, queued
reobservation, native containment, lifecycle and bootstrap contracts. Its
cleanup assertions passed, the pytest command exited successfully, and the
exact unique invocation was absent afterward. Earlier and later GUI timings
are not a controlled performance comparison. The operator's own open session
was preserved until their reported normal STOP/Quit; no operator process was
selected for termination.

The original isolated `ResilienceManager.self_test()` also passed on final
source in **19.89 seconds**, retaining its **45-second outer limit and
12-second respawn observation**. It observed initial scanner telemetry,
duplicate avoidance and exactly one respawn. Both actual scanner Jobs were
empty before close; all four retained query-only scanner-generation leases
and the isolated runner proved exit and closed. No observation errors were
recorded. Source and recovery-pin hashes matched before and after. Private
native receipts remain retained; no Core, Watchdog, Black Box or operator
application was launched or controlled by this scanner-only check.

## Remaining attack surface

The initial source seal inherits launcher trust. The inhibit-only environment
digest is not enrollment, a signing key or permission to resume STOP. A writable
same-user launcher remains inside the same compromise boundary. Loaded code,
ordinary bytecode caches, external dependencies, interpreter compromise and
check-to-execution races remain outside the seal. A kernel attacker can falsify
OS observations or disable both peers. Simultaneous suspension of all peers
cannot be solved by those peers alone.
An older matching source/launcher pair can also replay local trust across a
restart. This update does not add an independent hardware or remote freshness
floor, or authenticate the running OS through GitHub.

Changes to covered operational files require a coherent approved source
manifest and launcher pins. Intentional developer work belongs in the existing
sandbox/approval flow; neither a detected edit nor a GitHub response silently
approves it. Signed service/PPL/ELAM deployment, OS code-integrity policy and
independent boot/attestation controls remain separate acceptance work.

See [mutual recovery](../docs/resilience-recovery.md) and
[Safe Startup migration](../docs/safe-startup-recovery.md#recovery-profile-migration).
