# Startup recovery and storage maintenance review

This maintenance change bounds recovery storage, makes startup failures
diagnosable, and retains an independent recovery interface. It also publishes
the security boundaries and code owners for defensive review. The product
is now versioned v1.14.1 maintenance; source Observe and signed installed Protect retain separate
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

## Version, mobile manual and update verification

The application/package version is 1.14.1; Windows packaging derives 1.14.1.0.
An offline guard compares canonical package/source versions with current README,
capability, llms and changelog headers. Its 35 cases passed, all 34 observed native
generations retired, and no QApplication was created. Independent component
implementation versions retain their own meaning. Only the editable Angerona
metadata/entry points were refreshed offline; the interpreter and dependencies
were preserved. Selected installed metadata and imported app version agree.
The guard was subsequently extended to both native startup-window version labels;
34 checker cases passed with unchanged scoped sources and all five observed
generations retired. The offline repository documentation check also passed.

GitHub mobile displayed the Word container as code. The Word document was valid
and public-byte verified; the fix adds a complete online Markdown manual and a
rendered PDF, with Word offered as a download. The 74-page 1.14.1 manual was
reviewed again at original resolution, including corrected current evidence
attribution. Its readable export retains 1,199 text nodes, 1,206 paragraphs,
117 headings, 27 tables and all three figures. Current cover/footer dates are
28 October; historical evidence and dates remain scoped. Exact renderer cleanup
removed about 1.91 GiB of task-owned files; reviewed page/PDF receipts remain.

The final versioned 45-second demo retains 90 exact-verified timed frames and
shows the imported canonical 1.14.1 version in its DEMO banner. Public telemetry
remains synthetic; capture and encoding generations retired.

Updater verification passed 266 cases with one native availability skip and all
three retained generations retired. Actual shared-script transport read canonical
main successfully and treated a missing stable release as none, rather than
claiming an installed update was current. Preferences, source, state and payload
were unchanged by that live read-only check. GUI source preparation asks Yes/No
with default No; declining prevents the download. Source staging retains local
edits, additions, deletions and conflict sides; ignored files remain in the
original checkout. Source activation remains held and is not a full source
installation. Accepted signed updates require separate exact-candidate approval;
unsigned custom code cannot be silently merged into signed binaries.

The updater audit also found aggregate growth across individually bounded
source candidates. Admission now happens under the existing stage lease before
Git/download or a new identifier: two retained candidates, 2 GiB logical
aggregate data and a 2 GiB volume reserve. Resolution checks prospective writes;
validation can return an explicitly unpersisted review if capacity is unavailable.
Bounded no-follow accounting holds unknown or incomplete namespaces without
deleting user candidates. The focused seven-suite gate passed 141 cases with one
existing native availability skip, unchanged scoped files and all nine retained
process generations retired. These limits are separate from runtime repair,
Shadow Shield, evidence retention and source activation authority.

Review of an earlier failing practice test found a reproducible delayed-receipt
window. A controlled 3.5-second delay reproduced missing persistence/response
credit after the owned native action had already completed. The fix observes
only the exact issuer's authenticated journal-backed completion and refreshes
overflow-checked evidence before credit, without repeating the action. Its seven
suites passed 183 cases with one existing native availability skip; all nine
observed generations retired. The original delayed-receipt replay then passed,
with all six retained generations retired. An independent review found no
concrete blockers. Historical CI causation remains unproved without action timing
evidence; the controlled reproduction establishes this specific race.

## Later startup timeout and missing sidecars

A later launch exposed a different preflight failure. The fixed dependency
inventory passed all 74 pins, but it consumed most of a shared 30-second budget;
the following consistency check timed out. That helper failure returned the
generic application-failure code, so the supervisor selected source alternatives
even though the trace had not established a source defect. Broad shared-runtime
exclusion then held otherwise read-only Retry behind a separate diagnostic job.
That job was preserved. The eventual Retry opened a dashboard without restoring
source files. A later existing dashboard STOP record at 23:27:28 UTC passed
read-only authentication, consistent with the subsequent core exit; no key was
created or stop record cleared for that verification.

Required probes now have separate 30-second phase allowances within a 100-second
overall limit. A disposable Windows Job owns the redirector, interpreter and
descendants, with only its explicit input/output handles inherited. Cancellation
and timeout require exact tree retirement; they have closed outcomes distinct
from application failure. Read-only source inspection reports explicit pending
transaction kinds before exclusive mutation is requested. Its 53-case gate
passed with unchanged scoped files and all three observed generations retired.

The native startup shell paints before Python runtime work, reports verification
pending, and follows a run/supervisor-generation-bound status publication. Its
paint receipt grants no protection or response authority. A genuine dashboard
receipt closes it; a hold exposes diagnostics and Retry. Loaded application code
is never replaced merely because this independent window is visible.

The same launch's retained core status reported watchdog, scanner and Black Box
in safe mode; their independent observations were stale. Bounded diagnostic
review identified repeated spawn refusals for `APPDATA`: the supervisor supplied
the inherited environment as strict child overrides. This was an environment
adapter error, not evidence of a compromised recovery key. The strict environment
filter must remain; no key, baseline or durable failure record was cleared.

The new compact footer presents actual component heartbeat publications. Fresh
generation-bound observations animate; missing, expired, disabled or unavailable
observations flatline red. The Qt widget copies memory only, bounds displayed
components, expires freshness independently of publisher updates and exposes
plain-text details. Its 60-case UI/viewport gate passed, including pixel-level
pulse/flatline, expiry, supplier failure and keyboard checks.

The final native supervisor/retained-custody gate passed 76 cases, including an
injected failed retirement that preserved its native handles and coordination
leases and refused further backend commands. Exact native window/reader fixture
generations retired. The final manifest and embedded bootstrap then passed 37
cases with unchanged pinned scope and all 104 observed generations retired.
The independent helper/probe/STOP gate passed 153 cases with one existing native
availability skip; cancellation/timeout retired the exact redirector, interpreter
and descendants while unrelated sentinels survived until their fixture cleanup.

The [one-shot mutual recovery helper](../docs/resilience-recovery.md) and corrected
environment adapter passed 45 cases. An isolated existing supervisor consumed
target-specific authenticated restart requests and launched real fixture peers;
all eight retained peer/redirector generations retired. Hostile inherited wrapper
text cannot change its fixed arguments or execute, check-only suppresses bytecode
and mutation, disabled Black Box stays excluded, and a late STOP is carried into
the guarded source route through an inhibition-only marker. No real host peer
was killed or a competing manager attached by these fixtures.

The final security-flow/manual update has 76 pages. Pages 1–54 match the prior
reviewed rendering byte for byte; all 22 changed pages were inspected at original
resolution. Complete Word/online/PDF consistency checks passed. Twelve exact
renderer/extraction generations retired, followed by reviewed expected-identity
retirement of task-only tools: 19,531 files and 1,626 empty directories,
2,004,278,656 logical bytes, zero retained targets. Final documents, rendered QA
and provenance remain; this cleanup did not delete application or user data.

The earlier eight-suite CI fixture replay passed 79 cases and retained one live
collector availability failure; all 53 observed native generations retired.
Its first signed simulation completed 37/37 with independent OS evidence; the
second admission refused collection loss and did not execute a payload. A later
read-only diagnostic observed a complete snapshot followed by two
`NoSuchProcess` row losses in another snapshot. That explains this current
loss category, not the historical CI failure. No detector health, authority,
collector deadline or refusal policy was relaxed to obtain a green result.
The live GUI fixture now registers the same owned inventory lifecycle used by
the application before constructing readers/modules. It uses the fixed original
worker API and authenticated private protocol, with actual host rows. Its entry
is separate from the independently tested application privilege guard, which
remains unchanged. The first focused replay passed four cases and refused the
live case's initial preflight after three lost rows; all 18 observed generations
retired and scoped source stayed unchanged. This fidelity correction did not
establish collection availability on the busy host.

Separate cadence review found that `eco_mode=False` did not disable the
independent adaptive scan pacing preference. The fixture's real responsiveness
monitor could multiply a nominal one-second Process Monitor delay by eight
under host/UI pressure. It now explicitly selects the supported
`adaptive_scan_pacing_enabled=False` test profile before constructing the window.
This does not mock native rows, change product defaults, extend readiness
deadlines or authorize incomplete observations. It removes a discretionary
resource-control delay from a test of collection and response.
The fixture also uses the established Wi-Fi provider seam to avoid decorative
`netsh` subprocesses while retaining the real CPU/RAM/network sampler thread,
mailbox and shutdown. Native process rows, sensor health, approvals and response
remain real. The subsequent five-case replay passed both required signed
simulation runs and independent OS witnesses; all 36 observed generations
retired and scoped source stayed unchanged. Earlier failed receipts remain.
This scoped success does not establish that Wi-Fi polling caused every prior
lost row or certify collection on an arbitrary busy host.

## Final source launch and operator STOP

The revised normal source route painted the independent native startup window
before Python source/runtime work, passed the required probes and obtained a
genuine responding dashboard receipt on its first ordinary attempt. No source
files were restored and no runtime repair was selected. The two retained ready
snapshots remained at their documented capacity; a new snapshot was held without
preventing launch or deleting preserved originals.

The actual dashboard's accessibility view reported core, watchdog, scanner and
Black Box live. A separate read-only observer saw all four authenticated native
generations advance in 12 samples; existing authority metadata was unchanged.
The one-shot check reported live supervision with no actions and explicitly
kept protection unverified. Core/scanner status showed forwarded telemetry,
no reported ring drops and no crash-loop safe-mode components.

The first 77-second window observation retained its original one-second timeout
for an auxiliary window. The dashboard HWND responded in every sample; the
other window was subsequently identified as a removable-media approval dialog.
No media was approved or PIN enrolled. A separate subsequent 80.953-second
observation received responses from every visible owned Angerona window, two
fresh matching 1.14.1 status generations and unchanged source. This does not
establish the cause of the earlier delay or guarantee future responsiveness.

Dashboard STOP and its exact process-owned Yes confirmation then exited the
actual core without force termination. All ten retained core/peer/inventory
and console generations retired, and the separately retained core redirector
also signaled retirement. Authenticated operator intent verified, and a
continuous 75.047-second post-exit watch saw no new live descriptor-selected
core. Three discovery gaps remain recorded; the two specifically named candidate
PIDs were independently absent afterward. This is exact observed ownership
evidence rather than proof about every short-lived or escaped process. A final
read-only recovery check honored STOP and requested no action. The app was left
stopped.

The final 45-second, 90-frame public demo was recaptured with the complete
Module health caption and synthetic green EKG/red-flatline details. All nine
decoded chapters were visually approved and source/decoded frame comparisons
passed. Capture, redirector and encoder generations retired; checksum-bound
duplicate captures were removed. Public media still performs no host response.

Final offline checks passed Ruff across the changed Python files, in-memory
syntax compilation for 1,247 tracked/unignored Python files without bytecode,
documentation/version drift, the regenerated recovery manifest/embedded
bootstrap, master-manual chapter/inventory/diagrams and complete readable
export identity. The source launcher also clears ambient `ERRORLEVEL`; its
read-only bootstrap self-test passed with hostile inherited exit-status text
and no injected command execution. GitHub publication and final-commit CI have
their separate receipts; historical failed or cancelled runs remain history.

## GitHub whole-suite follow-up

The first published 1.14.1 maintenance commit's
[Python 3.12 job](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/40795470838/job/123190783591)
completed with 9,947 passed, 26 skipped and 12 failures. Its original result is
retained. The initial CI follow-up corrected eight test files; application,
recovery and security-engine source were unchanged in that commit.

Hosted administrator tokens gave ordinary fixture files an Administrators
owner. Positive fixtures now explicitly establish the intended user's private
custody before invoking the unchanged owner/DACL checks. Inert supervision
children select their own user as default file owner; the parent token and
operator's files are untouched. The batch test builds its own pip-free venv
instead of assuming the checkout contains one. Native invocation checks bind
the actual CI entry module and retain wrong-role and native-generation negatives.

The real first-paint test now puts its receipt inside the unchanged native
reader's permitted installation/.tmp scope. Startup assertions cover the actual
30-second phase and 100-second overall bounds. Capability inventory checks
match each implementation's declared version rather than relabeling all modules
with the product version. The synthetic orb dispatcher test calls the unchanged
production methods with isolated Python state while retaining separate native
widget/deletion/minimize/GC tests. Its original intermittent Hide failure was
not reproduced locally; its cause remains unresolved.

Python 3.10, 3.11 and 3.13 each reported the same passed/skipped/failed counts, with
an additional process-admission fixture failure replacing the orb failure.
The original missing reader-identity publication remains unexplained. That
inert fixture now publishes complete identity atomically, requires an explicit
native-handle retention acknowledgement before Retry, and reports early child
exit or bounded publication failure. It still checks the actual reader's image,
birth and retirement before Retry returns. Fixed sleep is no longer the
ownership handshake; no production timeout was changed.

No blanket skips or production guard relaxations were introduced. Focused
validation retains native process-generation retirement receipts. The combined
eight-file replay through the actual CI entry passed 149 cases with one existing
file-symlink privilege skip; all 248 observed retained native generations retired
and the frozen test sources stayed unchanged. Ruff and documentation drift also
passed. Full GitHub
workflow results must still belong to the exact subsequently published commit.
Raw diagnostics and private fixtures are not included in this publication.

The subsequent `fe582597` whole-suite run retained two failures on Python 3.13
(9,958 passed, 26 skipped), and three on Python 3.11/3.12 (9,957 passed, 26
skipped). The remaining bootstrap archive creator uses the token's default
owner; its inert fixture simulates ordinary source startup under an otherwise
inadmissible hosted administrator token. The next fixture scope models only
that disposable child's ordinary-user default owner and restores it afterward;
production owner checks and elevation rejection remain unchanged.

The reader fixture now has defined redirected standard handles and immediate
stdin EOF, .NET-only bookkeeping, independent bounded phase/error records, and
share-compatible bounded live-log reads. Both parent launch identity and reader
identity publish atomically, and both must exist before native retention and
acknowledgement. A controlled early-reader failure proves that diagnostics do
not mask the original failure or manufacture readiness. The original hosted
failure's cause cannot be recovered from the masked historical log.

CI now checks the native bootstrap, reader-retirement and first-paint contracts
before the complete Python suite, preserving native failure exit codes and the
required full suite. This makes runner-specific failures visible earlier; it
does not substitute the focused checks for the remaining tests.

The first-paint failure exposed a separate observability defect: a caught native
window connection/reader/receipt exception appeared only inside the window,
leaving captured stderr empty. The recovery interface now emits advisory JSON
with the failed phase, run/process generations and a redacted error. ASCII JSON
escapes preserve characters across OEM console encodings; the complete record,
including its newline, is capped at 8 KiB. Overflow produces a complete omission
record. Logging failure cannot replace the original held state or grant a
receipt. Native reader, supervisor verification, receipt and poll ordering are
unchanged. A real wrong-supervisor-birth case keeps its receipt empty and
requires owned cancellation retirement while recording the reason.

The hosted first-paint timeout's historical cause remains unresolved; a blank
old log cannot establish that the window failed to paint. The fixture now
retains its exact native log path and reports bounded share-compatible log,
status, journal, receipt and process-generation evidence on failure. This adds
the missing evidence instead of skipping the UI check or raising its deadline.

After regeneration, the manifest/embedded-bootstrap checks, workflow policy,
Ruff and documentation drift passed. The bundle plus exact early-CI selections
passed 33 cases; all 113 observed retained native generations retired and scoped
sources stayed unchanged. The native logger's final complete-record boundary
checks passed with valid admission/fallback at 8 KiB including the newline.

A fresh ordinary source launch then reached the genuine dashboard-ready receipt
without selecting repair or restoring source. Snapshot recording remained held
at the existing capacity. The actual core stayed alive with unchanged Python
source and every sampled visible window responding for 80.64 seconds. Five
initial advisory status samples were rejected as another process generation;
two fresh matching 1.14.1 status generations followed. The read-only heartbeat
observer saw core, watchdog, scanner and Black Box all live in 12 samples,
matching the actual core descriptor; authority-file metadata was unchanged.
The dashboard accessibility view agreed. These are liveness observations rather
than verified detector coverage or response acceptance.

Dashboard STOP and its exact process-owned confirmation completed without force.
All ten retained core/peer/inventory/console generations retired, as did the
separately retained core redirector. Authenticated operator intent verified;
75.14 seconds of continuous post-exit observation saw no new live core, with
scoped source unchanged. Two transient descendant candidates could not be
retained; their discovery gaps remain in the original private receipt. The
final read-only helper honored STOP and requested no actions. Angerona was left
stopped. This supplements the earlier observation rather than replacing it.

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
