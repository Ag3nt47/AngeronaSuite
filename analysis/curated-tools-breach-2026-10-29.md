# Curated tools, priority scans and breach review — 29 October 2026

This map records the source maintenance work for Angerona 1.14.2. It does not
attest a signed release, an uncompromised endpoint, or a real breach. Public
screenshots and the GIF use production widgets with synthetic records and no
host scan, response, cloud service or actual network isolation.

## Curated toolkit boundary

The GitHub Tools workspace and SpywareGuard share a single asynchronous tool
controller. Zero-Breach Toolkit v0.1.10 is bundled at reviewed upstream commit
`81bd556ba604685dbd1c0ecb48138c10f43cccf8`, with exact byte pins, provenance,
licenses and credits. Its engine SHA256 is
`075b2a0ac20f285fa4385d6b6c5cda2cedd410364c4f4686db3c1b8b033265d3`.
Upstream code runs only in a separate owned child with fresh private temporary
paths. It is never imported into the dashboard or security engine. Arbitrary
repositories and imported reports do not gain response authority.

The integrated basic workflow uses fixed arguments and reviewed code. Advanced
upstream menus, dependency installation and unpinned updates remain held and
link to the independent toolkit. Elevated toolkit execution is held until an
ordinary-user broker exists. Windows job ownership and resource limits have
native inert-child tests; POSIX limits are per process and do not establish an
aggregate CPU, scheduling or mandatory file-lock boundary. Temporary native
writers are monitored, not protected by a universal filesystem quota.

Independent review found two cleanup/availability defects before publication.
Report deletion previously released verified custody before removal. It now
retains the same Windows read/DELETE handle through hashing and deletion;
concurrent writers and replacement are denied during that interval. Failed
prelaunch attempts previously consumed report slots. Created identities now
allow retirement of proven never-started attempts without deleting unknown or
edited entries. Uncertain native retirement retains files and custody and is
never labeled retired. The final backend gate passed 34 cases in 69.07 seconds;
all ten observed native fixture generations retired. Targeted independent
re-review verified both corrections and found no new blocker in those changes.
Root's subsequent review found a result-schema defect: the report-deletion loop
reused its retained-report counter name for a file handle. The counter now stays
an integer, with an explicit complete/zero-retained/JSON-round-trip regression.
The complete 34-case backend replay passed in 65.37 seconds; all thirteen
observed native generations retired. Independent integration review confirmed
this correction and the entry, settings, shutdown and GUI boundaries.

## Priority and shutdown

SpywareScan coordinates native SpywareGuard and selected curated scans, with
live copied resource observations and separate settings. It requests bounded
priority and routine-module pacing, while preserving event intake, heartbeats
and shutdown. High is the OS priority ceiling; REALTIME is not requested. Pacing
is not a guaranteed CPU share. Priority leases expire and restore previous
settings; the caller cannot elevate imported tool findings into detections.

Configuration validation passed 41 focused settings cases. Entry and lifecycle
validation passed 56 cases before the final optional-worker drain was added.
STOP fences the shared scanner and breach review before AI/watchdog teardown.
Final shutdown waits for worker retirement before closing evidence stores;
unresolved retirement keeps those stores open until process teardown.
The subsequent lifecycle gate passed 70 cases in 14.48 seconds, including real
thread retirement, optional failure and evidence-store preservation; all fourteen
observed native generations retired. An earlier run passed 69 cases and found
one inert STOP fixture missing the newly added GitHub window-close method; the
fixture was updated and the complete gate replayed. A combined configuration,
backend, GUI, priority, bundle and setup gate passed 137 cases in 94.99 seconds,
with all twelve observed native generations retired. Later breach-presentation
changes require their own fresh checks rather than borrowing this result.

## Breach response review

Only fresh, explicitly qualified, current-manager native evidence with the
required response contract can establish the breach review state. Critical
severity, an authenticated archive, exposure, scanner leads or an imported
report alone do not qualify. The red/orange badge and border are presentation
of the typed controller snapshot, not an independent compromise detector.

Independent review identified two authority/enforcement defects and an absence
parser weakness before publication. The correction reads effective ActiveStore
policy for Domain, Private and Public profiles plus the COM local-modify state.
Each profile must explicitly allow local and inbound rules, be enabled and have
no excluded interfaces. Unknown or NotConfigured results stay held. The proof
is checked before rule installation, before success and during recovered-case
projection; it is not packet-drop, GPO-immunity or kernel attestation.

Legacy and new process, network, quarantine and Undo boundaries now require
installed Protect authority. Policy and STOP are checked again after durable
intent. Process termination invokes the same guard after its final native
identity validation and before dispatch. The original event/contract/generation
and target remain bound. Netsh mutation/query use the fixed System32 executable
and working directory; no classifier rejection selects a weaker host route.
Rule absence requires the complete known provider response, so a description
cannot spoof absence. Independent re-review verified all three runtime hashes
and the targeted corrections without finding a new blocker.

The final affected-suite gate passed 307 cases in 89.73 seconds, with one
non-Windows-adapter skip and two native owned-child cases deliberately deselected
for that inert-only gate. All three observed generations retired and all
seventeen selected source/test files stayed unchanged. Earlier wider results
(313 passes, 60 failures, one skip) exposed legacy fixtures that assumed Source
could mutate; explicit inert installed-authority providers replaced that
assumption. Further focused runs corrected four narrow provider fixtures rather
than weakening the product guards. The later broad local run below includes
native owned-child cases. A separate audit found three negative tests whose
early Source guard hid their intended inner fault. Explicit local inert authority
and fault-entry assertions restored that coverage; its 49-case replay passed.

The breach display keeps the threat tile and footer Compromised while a case
remains latched, including after Lift. Normal engine scores and measured alert
counts stay intact; resolution restores the latest normal view and requests a
fresh read. The final GUI/credit gate passed 34 cases, after 74 broader cases;
all observed native generations retired. Maintained credit links and exact-host
spoof holds are covered without opening a browser. The public demo has thirteen
chapters, 130 frames and 65 seconds; its 8,920,592-byte GIF was decoded and
pixel-checked, with an identical DEMO banner throughout and zero host actions.

## Update and version checks

Project, source, startup UI and local editable metadata agree on 1.14.2;
Windows package metadata derives 1.14.2.0. Combat and SpywareGuard independently
report component 1.14.1. Recovery manifest/bootstrap checks pass after the
version change. No accepted signed release was created.

The update/preservation regression gate passed 295 cases with one skip and one
setup-inventory fixture failure. The new controller-owned lifted-case history
belongs with other internal fields rather than editable setup options. After
that fixture correction, all four setup cases passed; all five and three
observed native generations respectively retired. Tests cover prompted source
discovery, candidate preparation, configuration preservation, local additions,
bounded resources and signed-update authority separately. They do not establish
an accepted installed release or silently activate a prepared source candidate.

## Hosted startup checks

At `ea8ec3cb`, all fifteen GitHub jobs completed: eleven passed and all four
Python jobs failed the early native startup gate. Full Python suites did not
run. Bounded diagnostics established zero log admission due to a transient
non-flat entry, without establishing that entry's creator or the first-paint
delay's cause. Commit `bee6019` separates owner-helper compiler TEMP from the
flat critical log workspace. Its focused nineteen-case gate passed; the wider
gate passed 42 cases with one fixture-root-context failure, followed by a
passing focused replay. All observed native generations retired. Subsequent
hosted results retain their own commit-specific scope below.
The next reviewed correction, `cb459f8`, uses a system-only module search path
inside the initialized UI shell and .NET path construction before first paint.
Its 128-case local replay passed with all 283 observed generations retired.
Guarded publication verified canonical branch/default-main refs and nine images.
All four hosted Python versions then passed their early native startup gate
and reached full suites. At `6aff939f`, fourteen of fifteen hosted checks passed;
Python 3.10's four remaining failures were duplicate `PSMODULEPATH`/`PSModulePath`
fixture entries. The reviewed `dd17908` correction uses one owned module-path
override without changing production environment validation. The earlier runner
delay's historical cause is not inferred from subsequent success.

## Combined local review

The broad local run completed 10,102 passes, 74 failures, 58 skips and one setup
error in 3,950 seconds. Its private supervisor exceeded its 3,600-second budget;
the original pytest was then retained by exact native process generation and
allowed to finish naturally. All 27 generations observed by the recovery reader
retired. Processes that exited before that reader attached remain an explicit
coverage gap; the original supervisor did not emit its source-freeze receipt.
This is a failed validation run, not a passing complete-suite claim.

The run exposed a missing pinned optional BLAKE3 test extra, an AI transport
fixture that inherited a scheme-less Ollama CLI host, and legacy inert effect
fixtures that no longer crossed the strengthened Source Observe guard. The
already-declared BLAKE3 1.0.11 Windows wheel was acquired from official PyPI,
checked against its published SHA-256 and installed without replacing other
runtime packages. After the narrowly owned AI fixture correction, the combined
AI/UGCAP/enclave replay passed 135 cases with three skips in 125.28 seconds;
all seven observed native generations retired and selected sources stayed fixed.
The heartbeat self-witness failure came from that private run's `python -c`
development-library bootstrap rather than the expected module entry. Replaying
the unchanged witness through the normal module entry, together with the final
capture, native-output and GUI startup-role cases, passed all fourteen cases in
44.19 seconds. All 52 observed generations retired and selected sources stayed
unchanged; the invocation validator was not relaxed.

Other failures distinguish real missing local Process Monitor coverage from
response regressions. Incomplete host enumeration remains unavailable evidence;
no collector baseline, event history or coverage condition is reset to pass a
test. The response guard also held valid built-in lease-owned canaries, requiring
a separate narrow correction and fresh independent review. Ordinary Source
Observe host response must remain held. Focused replays below are separate from
complete hosted acceptance, which must be checked against the published commit.
Six additional legacy Combat test modules now request a local, non-autouse inert
installed-authority fixture only for their effect tests. They assert that the
specific intended effect, terminal fault and final dispatch guard were reached.
A saved-policy regression also owns its environment override, so earlier config
tests cannot keep its deliberately disabled policy enabled. The complete focused
gate passed 120 cases in 84.72 seconds while explicitly inheriting the enabled
override; all three observed native generations retired. This fixture correction
does not relax the product's authority checks.
Five authority/FIM/artifact test modules explicitly supply typed inventory input
to their lease setup, rather than depending on complete enumeration of an
unrelated developer host. The real Process Monitor worker, fresh request and
acknowledgement, generation/health checks, recorder, owned-child observations and
native FIM scans remain in use. Assertions prove that the fresh request consumed
the fixture input. All 41 cases passed in 31.25 seconds, with 23 observed native
generations retired and fifteen selected test/runtime dependency hashes fixed.
These results do not claim complete real-host process visibility.
The practice readiness view separately labels canary eligibility while ordinary
Source host response stays held. Its 53-case UI regression gate passed, including
eligibility revocation, general-status restoration and detection-only behavior;
all five observed helper generations retired. The local environment's isolated,
cache-disabled pip dependency check also passed, and source/editable metadata
both report 1.14.2.

The response correction admits only a live issuer-enrolled marker or tagged
child through the original signed event, exact action/target, current manager,
bus, recorder, producer, generation, lease and policy. It carries that private
proof through intent persistence and the final native dispatch. Only immediate
rollback of that same moved marker can use it to restore the exact pinned
original into its still-absent leased destination. No journal record, public
Undo or later restart can reconstruct the permission. Expiry, STOP or a raced
replacement preserves the object and recovery hold. Network, suspension and
ordinary Source process/file response remain held.

The worker observes installed authority before publishing initialized readiness.
Source status remains AUTHORITY HELD with general ready=False. A separate copied
canary eligibility value supports the advisory CANARYONLY practice assessment;
each actual action still requires fresh exact proof. Settings now reports this
known hold immediately instead of timing out. Its 57-case UI replay passed,
including supersession/disarm, unchanged saved bytes and zero policy writes;
all five observed native generations retired.

Final review also identified a direct quarantine admission path that checked
overall enablement without requiring the quarantine-specific flag. Admission,
post-intent and final move checks now enforce that effective setting. Canary
termination separately requires current termination policy outside contain mode.
The final six-case native gate passed in 196.46 seconds: five new policy cases
plus both full real GUI campaigns with signed AAR and witness checks. All 38
observed generations retired. The earlier 97-case replay had 96 passes and one
old GUI expectation of general Source readiness; the UI now reports the correct
held state. Independent final review passed unchanged Combat SHA-256
45464cdaa4e64d7495255b0d88e08123f2f363c7b503ab53300f86c2131b89cd and
drill-readiness 4f3286d1f506375b8869c7ab1522c401d7952ecd02fd4b2bac9302ad8b2cd745.
The final in-memory compile covered 1,266 Python files without writing bytecode;
Ruff, workflow policy, documentation drift and recovery-pin checks passed.

The final expanded replay of the original failures plus seventeen complete
affected suites passed 472 cases with one outdated positive transaction mock
in 514.65 seconds. All 86 observed native generations retired and all selected
source/test hashes stayed fixed. The mock rejected the new explicit canary
keyword before entering its intended native ordering check; after correction,
the complete 29-case process-priority suite passed in 3.03 seconds with all three
observed generations retired. A bounded audit found one additional positive
quarantine mock needing the same explicit journal/commit arguments and found no
negative test silently bypassing its intended fault through those keywords.
The fixture now proves both inner entries and continued pinned-object custody.
Its complete three-module replay passed all 40 cases in 45.04 seconds with all
five observed generations retired and selected hashes unchanged. Product code
did not change during these fixture corrections. Together with the separate
real GUI campaign replay, these checks cover all 75 original failed/error
selectors; they do not turn the earlier failed broad run into an all-suite pass.

The revised manual has 85 reviewed Word/PDF pages and a complete online export.
Five security-flow diagrams include the new toolkit and breach paths. Only
manifested, owned renderer extraction/install scratch was removed after its
processes retired: 2,003,759,726 bytes reclaimed; review and provenance artifacts
were retained. The LinkedIn material is a draft with a labeled synthetic
screenshot, not a published social post.

## Runtime maintenance observation

The previously running 1.14.1 source Core was identified by its retained native
PID, creation time and image, separately from the venv redirector and helpers.
The diagnostic client's first accessibility confirmation request remained
pending when that client exited, so its initial zero exit did not establish
STOP delivery. A fresh exact owned confirmation/question/button proof and
native client click then used the supported application STOP path. The private
client conservatively reported a process-image query hold while Core was
exiting; subsequent retained native waits proved Core and all nine observed
descendants retired. The original application invocation exited zero, the
authenticated operator stop remained active, and the following sixty-second
canonical lease observation recorded no replacement Core. This concerns the old
running revision; it cannot replace a fresh observation bound to the new
revision's actual Core PID, birth, image and source hashes.

## Published-revision follow-up

Guarded publication of `5b258ab3baae7d299c02e9451e67e6b900ec54bf` verified clean
canonical branch/default-main refs and sixteen byte-identical README images.
An additional twelve public downloads (six assets at the exact commit and main)
matched the reviewed GIF, Word/PDF/online manuals and settings/credits pictures.
All fifteen hosted checks completed: eleven passed and four Python jobs failed.
Each Python version passed 10,233 cases with 28 skips and the same fourteen
private-toolkit custody failures. Earlier module-path casing failures were absent.

Native private-file creation now supplies the established current-user owner and
protected DACL at CREATE_NEW, before writing or publication. Generic atomic
writes retain their default behavior, and POSIX mkstemp remains mode 0600. The
stdout/stderr pumps use the existing exclusive private-file creator, close exact
descriptors on failure and continue bounded pipe draining. The strict ownership
and ACL reader is unchanged; no existing file is adopted or repaired to pass.
The ordinary-user execution guard remains held for elevated toolkit execution.

An elevated hosted token selecting an Administrators default owner is consistent
with the old NULL-security-attributes creation path, but the old failure logs do
not expose its owner/ACL and cannot establish that historical cause. The native
regressions instead verify the required explicit owner, protected three-ACE ACL,
empty file before writing, non-inheritance, publication order and refusal paths
on actual retained temporary handles. The final 62-case gate passed in 97.64
seconds with all 36 observed generations naturally retired and hashes fixed.
Independent review passed curated-tools SHA-256
2bd36fb4648f4b39f0b0d01909fce18e71288ca3a121a25dcbd3af4df08fbbb9 and
source-sandbox f427b320c8b3371e62abe23291f109e1eb724f2435a0362a170bd3ee89561f6f.

The real 1.14.2 normal Safe Startup painted its independent interface before
runtime checks, then verified dashboard readiness and exited zero. An 80.406
second observation proved unchanged source, responsive visible owned windows,
two fresh matching status generations and no status gaps. Twelve samples had
all four real component heartbeats advancing; shutdown-key metadata stayed fixed.
The main window was visible and not minimized. Native PMv2 measurements then
exposed a remaining layout defect: its bottom exceeded the 125%-scaled monitor's
work area by 81 physical pixels. Responsive content tests had not proved outer
frame fit.

The frame helper now subtracts measured decorations from Qt's device-independent
work area and retains a small rounding inset. Initial placement and settled
reflow clamp the frame, preserve disclosure states and use the existing scroll
viewport. Small screens can lower the drag floor and larger screens restore it;
hidden, minimized, maximized and full-screen states remain alone. All 61 layout
regressions passed at actual offscreen DPR 1.25, including the observed 880-DIP
frame model, negative desktop origins, all-open scroll reachability and floor
restoration. All three observed native generations retired. Independent review
passed main-window SHA-256
627d41418e9c11374a7845963345d8c6d48cda6c308f1b76871be95b981bf6a1.
The synthetic media harness keeps its explicit export viewport; normal application
windows retain automatic fitting. Reviewed public media bytes remain unchanged.

The optional new source snapshot was held by the existing two-ready-copy limit.
There was no pending source decision, new source mutation or settings loss; the
inspection echoed an older saved repair summary. Both older copies remain
retained, and the current revision was not added as a ready fallback. No copy,
security baseline or trust decision was removed to clear that warning. Diagnostics
now put the current hold reason before long saved history, explicitly label
inspection read-only, and explain that the dashboard is already ready. Independent
review confirmed diagnostic-only behavior and unchanged admission/exit policy.

All 162 startup regressions passed with 293 native generations retired; its broad
freeze check correctly reported the concurrent curated-tools edit, while all
selected startup inputs stayed fixed. A subsequent frozen five-case replay of
the new diagnostic cases, native first paint and pinned bootstrap restoration
passed in 33.04 seconds with all 33 observed generations retired. The normal
application was then stopped through its supported STOP confirmation. Core and
all nine observed descendants retired; the 120-second lease observation saw no
replacement and the authenticated stop remained active. Device approval was
left untouched. Fresh frame-fit observation and hosted acceptance belong to
the follow-up commit rather than the earlier published revision.

## Scan presentation and final layout follow-up

The next normal source launch confirmed the main dashboard's visible DWM frame
inside the actual scaled work area. Invisible native resize borders were
measured separately. Its SpywareGuard dialog still exceeded that work area,
which motivated a dialog-owned fitter and scrollable workspace. During the
141.75-second observation, owned visible windows remained responsive, source
hashes stayed fixed, and two fresh matching status generations arrived. Sixteen
initial samples lacked a fresh status generation; they remain a coverage gap.
Nine samples showed all four component heartbeats live. The subsequent signed
operator-stop record identifies dashboard STOP; the diagnostic did not retain
all child handles for that user action and does not claim exact child retirement.

Hosted validation of `d0d376cc0287fe978ca9e18d1933244a3326502d` completed with
eleven successful checks and four failed Python jobs. Each Python job passed
10,265 cases with 28 skips and reported the same single narrow-header overlap.
The earlier fourteen private-file failures were absent. Header widths had been
calculated before the final screen clamp, leaving a wider SpywareGuard button
on the previous allocation until a delayed resize pass. Initial screen fitting
now precedes header allocation; the final fit and exact frame-helper body are
retained. The fix does not add a longer arbitrary test delay.

SpywareScan now separates scope, included checks, progress, stage explanation
and resource details. The primary scan button is red. Entire PC selects the
supported full toolkit checks; it does not promise every-file or privileged
coverage, and native live checks retain their supported system scope. Scope
changes require explicit selection. Wheel gestures scroll rather than changing
scan modes or resource choices. Refreshes preserve selections and expanded
details. Dialog fitting preserves the current tab, inputs and non-normal window
states; longer content remains reachable through scrolling.

Only first-party request-bound workflow counters advance the percentage ring.
External report text, elapsed time and resource samples cannot supply progress.
Indeterminate stages remain explicit. Rotation follows active visible work and
honors reduced-motion preferences. Stage explanations distinguish supported
collection, waiting, report assembly and cancellation. Resource labels identify
the toolkit process and its latest available sample, including whether process
liveness is running, stopped or unavailable.

Review also corrected aggregate completion: selected native work must finish
successfully and selected toolkit work must have a recognized completed result.
Held, preview, error, unknown and unscanned outcomes retain incomplete coverage,
with explicit text rather than color alone. Finished workflow stages do not
establish a clean host or response authority. No backend collection or authority
policy was expanded.

The 125%-DPI aggregate/UI gate passed 114 cases. The final 73-case replay included
the exact hosted failure, dashboard frame fitting, actual SpywareGuard and tools
dialog layouts, preserved settings, progress and controller behavior. All five
observed native job generations retired, sources stayed fixed and the job was
empty. A separate seven-case surface baseline passed at default DPR, including
the existing ATT&CK fixture whose fixed minimum exceeds the artificial small
125%-DPI offscreen screen. The original failing attempt remains private.
Independent review passed the final scan presentation and MainWindow reorder;
the frame helper's function text and AST matched the prior reviewed version.

The complete Word/PDF/online manual explains the controls and progress limits.
The 85-page fresh render carried forward 83 byte-identical reviewed PNGs; both
changed pages were visually reviewed at original 182-DPI resolution. Only the
Word document body changed. All renderer generations retired before cleanup of
its exact temporary tool roots. Final public assets and hosted checks must be
verified against the resulting published commit; parent results do not prove it.

## Detailed scan progress and actual engine execution

The published `5d037193a44a8f72caa26709b22a4897d57db3ae` subsequently passed all
fifteen GitHub checks. Its fresh normal startup and 76.406-second observation
showed responsive visible windows, unchanged source, two fresh matching status
generations and no status gaps. Native visible frames for both the dashboard
and SpywareGuard fit the actual 125%-scaled work area. Twelve samples showed
all four component heartbeats live. The shared read-only update transport
recognized the same canonical source revision and reported no stable release.
The user then used dashboard STOP; its authenticated record was present and the
Core and known role processes were absent before further source edits. The
diagnostic had not retained every child handle for that user action, so it does
not claim exact retirement of unobserved children.

The user's real priority scan reached its configured five-minute deadline
during browser checking. Its saved outcome was cancelled/incomplete; the GUI
discarded progress and hid that specific reason behind a generic unavailable
label. This was not an installation failure. Review separately found that the
controller always constructed a default 300-second operation, preventing a
longer configured budget from taking effect. The observed run itself had a
300-second budget; it does not establish that a longer saved setting caused
that historical timeout.

Per-run budgets now reach the actual operation owner without saving preferences.
The display retains exact errors, partial rows, current task/file, elapsed time,
per-check fractions and separate item/query progress. Native bounded hash-file
bytes contribute their measured fraction to that step. SQLite progress observes
the result list the pinned reader already fetched, with no extra SQL or host
enumeration. Current-query completion does not become whole-browser completion.
ETA is measured only where a denominator/rate exists; remaining whole-reader or
full-scan work can remain Calculating. Percentages describe the requested
workflow, not every file or proof of a clean host.

The continual native sensor worker remains alive after a priority request.
Admission waits for the same request and positive lifecycle generation plus
both collector-finished and request-finished flags, after collection and priority
restoration return. Missing flags, stale generations and renewal errors cannot
drop ownership. Tool retirement is separately tied to the exact native job.
Cancelled work remains Stopping while it drains; future rows become Not run
after their own scanner ends. Counters and partial percentages are retained.

Actual pinned-engine positive/negative execution exposed another adapter defect:
the write-budget guard rejected the standard-library NamedTemporaryFile opener
used to create reports. Metadata-only checks had not exercised report output.
The narrow repair accepts only the expected standard-library code/globals and
private report naming pattern, checks a fresh descriptor generation and current
native identity before adoption or close, and retains path/link/quota checks.
Foreign or replaced descriptors remain untouched. The upstream engine and
license bytes are unchanged.

Progress uses a parent-created private file with bound native identity and
job/nonce/process/sequence checks. The isolated standard-library worker briefly
opens that existing object for bounded latest-snapshot writes. It does not add
growing per-file logs or dependencies to the shared environment. Malformed,
oversized, stale or deeply nested advisory telemetry stays a progress gap and
does not abort an otherwise valid scan/report. Paths and activity text remain
untrusted literal display data and grant no response authority.

The native gate passed 152 cases, the final GUI/controller gate passed 121, and
the backend gate passed 52. Backend checks include actual pinned-engine positive
and negative reports, a private Chromium History query, controlled deadline
retirement and malformed progress that cannot prevent a valid real report.
All 24 observed backend native generations retired naturally with fixed sources
and no observation gaps. The browser fixture uses a controlled observation
delay: it proves counters, report integrity and retirement, not production speed.
Ordinary-user engine cases skip elevated hosted runners rather than bypassing
the execution guard. Failed intermediate attempts and their receipts remain
private. Independent review passed the reported frozen production hashes.

Concurrent advisory snapshot publications can arrive out of order. The parent
rejects stale sequence numbers and later samples recover; the sampler is joined
before the final forced publication, preserving terminal status and verdicts.
The complete manual now has 86 rendered pages: 74 exact previous PNGs carry the
prior review and all twelve changed/new pages were reviewed at original 182 DPI.
Its exact renderer tool roots were cleaned only after proven process retirement.
Final integration, public media and hosted acceptance must still bind to the
new resulting publication, independently of the successful parent revision.

The final controlled end-to-end replay additionally passed through the actual
Qt controller and controls, real CuratedToolService and unchanged pinned engine,
plus the real native module with inert providers and an owned non-executable
file. Qt observed genuine partial-file progress and the expected positive
report. The same native request/generation finished with both completion flags
while its continual sensor worker remained alive. Actual ModuleManager focus
and background preferences restored, no network attempt occurred, and both tool
process generations were proven retired. All five owned test-job generations
retired naturally with fixed production hashes. The initial smaller fixture
did not span a read chunk and could not prove intermediate progress; that test
failure was retained and the owned file was enlarged before the successful
7.02-second final replay. This is controlled execution evidence, not a full-PC
scan or detection-efficacy benchmark.

## Automatic scan completion review follow-up

The shared scanner controller now opens one nonmodal after-action report after
an admitted scan reaches a terminal result and its actual controller worker has
exited. The existing native request/generation completion and separate toolkit
custody gates still precede that result. Failed, timed-out, cancelled and partial
outcomes retain their original reasons, counters and coverage gaps. Shared Hub
and SpywareGuard views reuse one dialog; dismissing it does not repeat the scan.
Shutdown fences queued completion, and a preempted scan contributes at most one
bounded previous-attempt record. The report stays an unconfirmed review with no
response grants, even when its MainWindow parent independently displays an
authorized breach warning.

Current-run findings, report references, request identities and native custody
fields are scoped separately from saved historical reports. Resource snapshots
reset before a new scan and carry its operation/job identity, preventing old
CPU, RAM or process observations from becoming evidence for an early failure.

A coherent 133-case Qt/controller gate passed with five captured native
generations retired naturally and fixed source hashes. The actual pinned-engine
and native-module integration now additionally proves no early report while the
native collector is held, one visible report after both scanners settle, strict
completion flags, disabled mutation actions and no reopening after dismissal.
Independent source and custody review passed. The backend gate passed 52 cases;
its one new failure was an incorrect test-only expectation that disabled
preflight could not create an empty private control directory. The corrected
case checks that no scan job is created. That case and both real-engine positive
and negative executions then passed together, with all seven captured native
generations retired and final sources fixed. The failed intermediate receipt
remains private rather than being represented as a successful complete gate.

Full-mode browser profiles, caches and selected user-writable system roots can
exceed a finite per-run budget. These controlled checks do not prove that every
host finishes within 900 seconds or that an incomplete full scan is a clean
verdict. Real host evidence remains private, and no source or response authority
is expanded by automatic report presentation.
