# Startup recovery and storage maintenance review

This maintenance change bounds recovery storage, makes startup failures
diagnosable, and retains an independent recovery interface. It also publishes
the security boundaries and code owners for defensive review. The product
remains v1.14.0; source Observe and signed installed Protect retain separate
authority and acceptance requirements.

## Reproduced failures

Shadow Shield previously lacked an aggregate cache budget. Recovery copies
and interrupted read-only staging files could accumulate. The earlier scoped
storage fix introduced a 2 GiB default cache ceiling, a 2 GiB free-space reserve,
bounded inventory and maintenance, explicit Block/Delete/Change controls and
VSS requests off by default. A maintainer-approved cleanup removed recovery
copies only; original files, settings, keys and evidence were preserved.

The subsequent startup failure reproduced before the security engine or
Shadow Shield loaded: installed `certifi` metadata reported `2026.10.23`, while
the reviewed constraint required `2026.10.19`. Dependency consistency alone
did not identify this exact-pin mismatch. The startup assistant does not read
Shadow Shield's cache. This evidence does not support attributing the launch
failure to deletion of that cache.

The supervisor also mixed native repair output with its exit status. A verbose
successful helper could therefore look like an unsuccessful array result.
Owned output capture now returns one native integer and retains command logs
separately.

A real candidate rebuild reached the original 180-second offline-install
deadline before promotion. Its candidate was retired and the original runtime
was preserved. The failed attempt remains private diagnostic evidence.
Install commands now request `--no-compile` and allow 300 seconds for the locked
wheel operation within the unchanged 900-second transaction budget. Pip
documents that this flag disables bytecode compilation during installation.
That is a reduction in unnecessary install writes, not a measured attribution
of the earlier delay. [Pip install options](https://pip.pypa.io/en/stable/cli/pip_install/#cmdoption-no-compile).

The revised candidate completed installation and its runtime/Tk/Qt checks, then
failed dependency consistency before promotion: the external lock omitted
`typing-extensions`, required on Python 3.12 by `referencing` and
`cyclonedx-python-lib`. The pre-existing environment contained that unlisted
dependency, hiding the incomplete fresh-install closure. The lock generator
previously hashed listed constraints without validating wheel dependency
metadata for the target platform. Target marker, version, metadata and closure
validation now accompany generation; local compatibility wheels are explicit
inputs rather than ambient installed dependencies. Repair pip commands also
disable the shared pip cache explicitly, keeping new download/install work in
the owned transaction instead of silently growing a separate user cache.

A later fully verified candidate encountered a Windows sharing conflict at the
first runtime-directory move. Reconciliation proved the original directory
identity and rolled the transaction back. A controlled fixture reproduced the
failure under the verifier's retained parent-directory lease policy, even with
no runtime process. The ancestor policy therefore needed its own correction;
retired command handles alone do not prove that a directory is movable.
Runtime moves also retry short native access/sharing conflicts, for at most
twelve attempts separated by 250 ms. Each attempt rechecks the original
directory identity, vacant destination, active-runtime exclusion and transaction
deadline. Renames atomically refuse an existing destination, including one
created after the precheck. Already-proven reconciliation retains its separate
bounded move attempts when the forward-work budget has expired. Changed state
holds the operation. Failure records include the native
error, script location and bounded stack instead of a message alone.

Directory ancestors now retain traverse/read-attribute handles with read/write
sharing and no delete sharing; pinned regular files retain their read-only
sharing policy. Controlled tests prove that this permits child-runtime moves
while holding ancestor rename and junction retargeting. The actual rename binds
the expected source identity to a retained native delete handle, keeps validated
parent namespaces held, and uses the absolute-target Win32 form with overwrite
disabled. A native test caught error 87 in the initial relative-target form;
the corrected form passed real rename, conflict and rollback cases before use.

Process admission uses retained native query/synchronization handles to
distinguish a retired discovery row from a live process. A live unknown identity
still holds repair. Its compiler scratch is private and bounded independently
of whether transaction staging has been admitted.

The normal launch then exposed a separate PowerShell/.NET boundary bug that
check-only setup did not exercise: command-produced environment strings remained
`PSObject` values inside an untyped dictionary, and the strict capture helper
rejected them before starting the application. The boundary now unwraps only
string bases into a fresh typed string dictionary; invalid values remain held
without disclosing their contents. Capture and source-supervisor tests now cover
the real environment builder rather than only literal fixture strings.

That pre-application exception initially selected application-source recovery.
The preservation mechanism retained the exact original source archive before
trying canonical candidates. The maintainer restored its original source digest
under exclusive leases. Launcher/probe/capture exceptions now use a separate
infrastructure hold and cannot select application rollback or runtime reinstall.
Genuine returned application failures retain scoped source recovery. Ten capture
cases and fourteen classification/status-preservation cases passed after this
correction; the changed Python tests also passed Ruff using the retained previous
development environment, without installing extra packages into the fresh runtime.

## Implemented boundaries

- The readable batch anchor pins a manifest and verifier. Seventeen operational
  files include startup helpers, dependency locks and the local wheel builder.
  Exact canonical GitHub blobs are checked by byte count, SHA-256 and Git blob
  identity before execution. Native file and ancestor leases prevent replacing
  the verified generation between verification and execution.
- Automatic recovery and GitHub retrieval default on; explicit off settings
  are preserved. Malformed, duplicate, oversized or non-UTF-8 consent is off.
  Source coherence is required even in check-only mode or without diagnostics.
- Runtime, dependency and GUI failures have separate bounded repair budgets.
  Software rendering and a non-Tk startup path retain all readiness checks.
  Repeated identical failures require an operator Retry rather than an endless
  unattended download/write loop.
- A standard-library recovery interface and an OS Windows Forms fallback do
  not import the application. Reports are untrusted display data. An open
  recovery view is not proof of an active engine.
- Scoped source recovery preserves failed edits before restoring a ready
  snapshot or exact canonical GitHub candidate. Interrupted or ambiguous
  transactions hold launch. Dashboard-ready snapshots are bound to a stable
  prelaunch source digest. Restore-edits decisions apply at the next startup.
- Source snapshots retain two ready slots and one failed-edit slot, each
  bounded to 64 MiB; unreviewed edits are not evicted automatically. Operational
  quarantine is bounded to 32 MiB. Startup scratch has a 256 MiB admission
  budget and bounded retained attempts. Space reserves can hold new work.
- Runtime repair requires 5 GiB available before staging: a 2 GiB reserve plus
  3 GiB capacity allowance. It admits at most one full previous-runtime backup
  and two retained transactions. These are admission limits, not a filesystem
  quota. Owned disposable commands monitor their working/log volume reserve.
- Packaged SafeStart is independent of Python and Qt. It pins the final helper,
  retains native identity, preserves possible live work on timeout and prevents
  a second attempt over an active helper. Package entry, autostart, approved
  upgrade launch and local build routes use the authenticated entry selection.
  A candidate native check runs only from reconstructed catalog-authenticated
  files after threshold authorization, preventing an unlisted adjacent CLR
  configuration from participating in staged execution.

## Validation and observation

The broad integration run passed 549 cases with three explicit skips and one
README wording failure. All scoped source hashes were unchanged during that
run; all 441 retained observed process handles proved native retirement.
The README check was corrected and passed in a subsequent 23-case focused gate,
which also covered strict UTF-8 consent and the full inert bootstrap.

Additional focused gates passed 189 package-route cases, 53 staged-execution
cases, and the install-argument/deadline case. These scopes overlap; they are
not a combined unique-test count. The tests use inert children and private
data, without real host containment, installation, task registration or UAC.

After the final locking correction, 16 native move/transaction/crash cases
passed with 48 retained observed process handles retired. A separate 78-case
verifier/bootstrap/source-strategy/process/install-argument gate passed with
181 retained observed handles retired. Both gates proved their scoped source
hashes unchanged. Storage admission's seven cases and the compiler/ancestor
policy's 16 cases also passed in focused runs. These are overlapping scopes,
not an aggregate suite total. Ruff and documentation drift checks passed.

The 74-page master manual was rendered with the canonical document renderer
and an official hash/signature-verified task-local LibreOffice extraction.
Every page was inspected. Unrelated original package parts were preserved;
renderer installers and extracted tools were removed after review. The
45-second GIF uses the actual Qt interface with fixed synthetic records,
persistent DEMO labeling and blocked network/process dispatch.

The real repair completed candidate and final-path runtime/Tk/Qt/dependency and
entry-point verification. Its complete source setup returned zero, retained one
previous runtime, and removed its owned transaction scratch. The additional
read-only repair observer hit a CIM timeout; its descendant-retirement coverage
is incomplete and is not presented as a complete process inventory.

Normal startup subsequently returned zero and recorded a genuine dashboard-ready
receipt plus a source snapshot. A temporary occupied-runtime result used the new
infrastructure hold without source rollback; an explicit Retry then completed.
A retained native core handle was observed for 76.218 seconds: all 15 visible
window samples responded, the core remained alive, and application source bytes
were unchanged during that interval. Early advisory status samples belonged to
an older generation; a fresh matching current-core sample appeared later. This
gap is retained rather than replacing the old status or claiming continuous
collector coverage. The source profile reported v1.14.0, Chill mode and no
administrative authority. A separate layout refinement and final observation
follow this startup proof.

## Dashboard and operator STOP

All dashboard boxes can minimize individually. Startup opens the status cards,
module and alert tables, console, Live Activity and System Pulse; Module health
and activity alone starts folded. Readable table columns and explicit Filters,
Columns and full-row details reduce crowding. Native Windows font previews at
normal and enlarged sizes retain complete timestamps, running percentages and
headers. Responsive inert-widget checks cover 1280×720, 1366×768 and 1920×1080.

Dashboard STOP and tray Quit persist signed operator intent before fencing new
AI work and supervised launches. AI/direct Black Box retirement precedes waits
on healer or supervisor lifecycle locks. Owned Windows jobs and retained native
process generations cover redirectors, runners and adopted helpers after a core
restart. A shared Ollama daemon and downloaded weights remain; configured model
residency is unloaded. Automatic recovery and modern sign-in cannot erase STOP.
An explicit source helper resumes once after preflight, then its child honors a
new stop during warmup. Failure to persist the primary stop holds exit visibly.

The final STOP gate passed 326 cases across 22 files; native Go source compiled
and its tests passed. Separate automatic-start admission tests passed 29 cases,
with three observed native generations retired. Startup/route/update checks
passed 276 cases with one platform skip; source strategies/autostart/native
entry checks passed 80. These gates overlap earlier runs and are not summed into
a suite-wide total. Final layout and table gates passed 43 and 58 cases. Changed
Python files passed Ruff; an in-memory syntax pass covered 1,238 Python files.

The final 45-second GIF contains nine actual Qt scenes with synthetic records:
dashboard, scrolling alerts, alert details, SpywareGuard, Settings, MITRE ATT&CK,
SOAR, scans and Help. All 90 decoded timed slots match their quantized source
frames. Network/process dispatch attempts remained zero. Capture and encoding
generations retired, and duplicate private captures were removed. Public media
contain no raw host captures.

Final normal source startup returned zero and retained a ready snapshot for the
reviewed source. The initial 111.704-second observation recorded a single
window-response timeout at elapsed zero; every later sample responded. Its
original receipt and ten stale-status samples remain private. A separate
settled 80.235-second observation had responsive windows throughout, two fresh
matching status generations, no stale-status samples and unchanged application
source. Manual rendering and demo encoding overlapped the observations; this
does not isolate a performance cause or establish complete collector coverage.

After that success, exact identity/hash-bound cleanup removed 299 generated
repair wheel payloads totaling 1,204,659,722 bytes, with no retained failures.
Another task-owned duplicate ready archive was retired only after every source
byte was proven present in the retained original failed capture. Task-local Go
SDK/archive/build-cache cleanup removed about 388 MiB; about 9 MiB of read-only
module-cache artifacts were preserved rather than forcing their attributes.
The previous verified runtime, original source archive, logs, settings, keys
and evidence remain. Cleanup byte counts are logical files, not a promise of
the same physical free-space increase on a concurrently used drive.

The actual dashboard STOP and its Yes confirmation were invoked through the
exact core's Windows accessibility controls, without force termination. The
persistent operator-stop HMAC verified; all 40 retained process generations,
including the core, retired, as did its separately retained venv redirector. A continuous
75.219-second post-exit descriptor watch found no new live core. Three candidate
descendants could not be retained, and polling cannot prove every short-lived
or escaped child. This Chill run exposed no watchdog or owned AI process; those
paths have the separate inert native test evidence above. A read-only local
Ollama check before STOP found zero resident models. The app was left stopped,
and its old descriptor remains a stale record of the retired core. Both private
observer generations retired; the observed product hashes stayed unchanged.

## Remaining limits

Angerona is a Ring 3 application. An editable source launcher is not an
immutable same-user, administrator or kernel trust anchor. Public source and
hashes support review; they do not establish an uncompromised host or replace
independent publisher authority. Readiness, source snapshots, diagnostics and
AI annotations do not authorize response or reset trust baselines.

The existing direct dashboard stdout log does not have a lifetime byte quota.
Runtime/native command logging and general evidence retention are not covered
by a universal drive quota. Storage pressure remains visible and the documented
scoped limits must not be advertised as control over every writer on a drive.
Native collector availability and installed response acceptance remain separate
from dashboard launch.

The release signing authority is unprovisioned. The new packaged entry and
build checks are source implementation, not a finalized signed release. Final
helper signing must precede SafeStart pin embedding, followed by SafeStart
signing, independent verification and regenerated final release evidence.

See the [security review map](../docs/security-flow.md),
[startup operator guide](../docs/safe-startup-recovery.md),
[storage scope](../docs/storage-management.md) and
[external signing contract](../docs/enterprise/RELEASE_SIGNING_BOUNDARY.md).
