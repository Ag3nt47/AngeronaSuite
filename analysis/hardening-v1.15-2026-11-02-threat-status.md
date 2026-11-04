# Visible threat-assessment availability

2 November 2026. Angerona 1.15.0 source-development follow-up.

The dashboard could retain a green Secure result and a zero critical count after
an asynchronous assessment failed. Only its tooltip reported unavailability.
Clearing a retained breach case could also paint an old normal snapshot as if it
were fresh. Neither behavior proved that current assessment was available.

The normal card now says **Active HIGH/CRITICAL (10m)**. A completed empty result
displays **None detected**; the threat detail window uses the same scope. The
engine's existing classifications remain unchanged. These values concern recent,
unresolved active detections, not recovery exposures, collection health, complete
coverage or proof that a host is safe. The separate posture score is still an
advisory metric.

On an initial or previously clear read failure, the card displays amber
**Unavailable** and the critical count becomes unknown. A retained High or
Critical result keeps its warning color with a visible **stale** suffix and
last-known count. Retrying or receiving a status callback cannot make retained
data fresh; successful snapshot delivery is required. Previous data stays in
memory for review.

A typed confirmed case continues to display Compromised through normal updates
and failures. Resolving that case renders the actual retained assessment state;
it cannot revive a failed green result. Case status and the recent critical
count remain distinct. These are presentation changes: no alert, baseline,
policy, response permission or signed evidence is cleared or altered.

## Focused verification

The eight-file Qt/core cohort passed 78 cases with no failures, errors or skips
in 10.12 seconds. It includes twelve new cases covering real asynchronous
failure, blocked retry and successful delivery; breach/failure/resolution
interleaving; visible stale warnings; compact minimized cards; and GUI-only
wording. Existing classification tests retain the engine's raw Secure label.
The fixture forbids host command and network dispatch. Its owned reader threads
are released and joined before widget disposal.

The bounded native test owner exited normally with its Job empty, proven handle
cleanup and unchanged source, inputs and selected saved preferences. These tests
do not establish live detector efficacy, whole-suite acceptance or resolution of
the historical native crash. Final static checks, startup observation and hosted
checks retain their own revision and scope.

The separate compact-window follow-up passed 36 cases in 12.94 seconds, with
zero failures, errors or skips. It checks modeless Settings, native work-window
controls, fullscreen lifecycle and heatmap reachability with long headings.
The heatmap previously required 760 logical pixels on a 640-pixel scaled work
area. It now uses the existing work-area fitter and wrapping summaries, with
filters, actions and matrix scrolling preserved. Native button hints are added
by the content-window owner before showing; constructing a bare Settings dialog
is a different stage from that supported opening path.

## Hosted predecessor results and controlled YARA follow-up

All fifteen checks for published `e600020` are terminal: eleven succeeded and
four Python suites failed. Every Python version from 3.10 through 3.13 completed
with the same seven failures, 13,090 passes and 39 skips. The suites finished in
about 33–37 minutes, with retained pytest summaries, wrapper exit/atexit markers
and native process exit one. These were completed failing suites, not another
one-hour timeout. Security, installers and platform checks succeeded. These
results do not validate later local changes.

One failure retained the old modal-Settings expectation. Two red-team scoring
cases constructed managers without normal startup's companion ownership
supplier. The guard correctly refused process mutation. Their repair shares the
existing real Core and complete inventory context, including unavailable-state
and retirement checks; original containment assertions and deadlines stay intact.
The two scoring cases passed in 56.97 seconds. A separate 104-case ownership,
lifecycle and signed after-action cohort passed in 149.39 seconds, with no
failures, errors or skips and proven native diagnostic retirement. These counts
overlap other cohorts and are not additive.

The published predecessor had four YARA cases that expected bare registered
practice artifacts to authorize containment. The controlled response required
issuer-owned proof tied to the original YARA event for report attribution.
The Windows Python 3.12 hosted job resolved YARA-X 1.22.1 under the dependency
range used at the time. The seven failures also covered Settings and companion
ownership cases.

A six-case prerequisite probe of YARA-X 1.19.0 passed four cases and failed two
in 2.58 seconds. Zero- and one-byte serialization sinks rejected writes within
their caps, but native serialization returned normally without propagating the
writer error. The test stopped at that assertion. A successful return alone
could not establish complete rule serialization.

The replacement prerequisite tested an input hash over the exact immutable
UTF-8 compilation input, with fixed compiler and scanner options and a pinned
native version. Six native API cases passed in 1.17 seconds. They covered native
types, positive and negative scans, changed input, UTF-8 comments, a compile
failure followed by fresh successful compilation, and owner-thread traceback
cleanup. The owner exited normally with its Job empty, handle cleanup proven
and unchanged input and preference fences. Those probes covered prerequisites.

The [YARA scanner](../src/angerona/modules/yara_scanner.py) now implements that
input and version binding on its worker. The controlled response requires a
current issuer-owned claim and the original YARA detection proof. Application
dependencies and CI pin YARA-X 1.19.0, matching the release locks and the
controlled scanner profile.

A local Windows run with 1.19.0, before the dependency declarations were pinned,
passed 45 tests across three files with zero failures, errors or skips. This
included the seven previously failing hosted cases. Exact-commit hosted checks
and Linux results remain separate from that focused run.

## Supplementary observations from the published predecessor

A separate ordinary startup of published `e600020` reached Full mode with 75
running modules. Its monitor retained 60 samples over 131.70 seconds, including
the mode transition and finite live follow. All four component counters increased
with recorded authentication and exact native identity bindings. Watchdog,
Scanner and Black Box each had one unavailable initial sample; all four had
advancing observations together from sample three onward. The first earlier
capture's separately retained archive also provides four increasing series.
The original three-file review had omitted that archive.

These supplementary reviews check retained counter, age and identity consistency.
The monitor performed authentication/native checks during capture; the saved
projections omit raw records and proofs and cannot independently repeat those
checks. Component activity does not establish detector coverage or kernel health.

The predecessor's retained critical recovery-assurance record remained an
exposure without response authorization, with eleven omitted details. The stream
reported an initial retention gap of 4,615 and omitted 5,303 detail fields across
707 events. Spyware exposure heuristics did not establish a confirmed breach.
Missing evidence precludes a clean-host conclusion. Strict observation acceptance
stays false for an inventory bound and recorded sampling gaps.

Fourteen distinct cached metric publications report trailing 15-second rolling
maxima, not individual GUI delays. Their recorded lag indicator had a 329 ms
median and 562 ms maximum. The Core averaged 116.56% of one logical processor
across the monitor span. Main-window response checks completed within 500 ms,
while sampled queue-drop counters stayed zero. These measure different things
and include startup/transition work. Per-stage GUI or module CPU timings were
not captured. They neither identify a CPU cause nor establish a performance
improvement or continuous UI responsiveness.

Normal STOP exited that exact Core zero; all fourteen retained waits across ten
unique native generations signaled, with no canonical replacement observed for
five seconds. No forced retirement occurred. Strict acceptance remains false
for its inventory bound and unavailable short-phase role samples. Source and
selected preference fences belong to this prepatch run.

Identity totals include the Core and deduplicate role-query handles. The first
CI-response STOP had eighteen waits across fourteen unique identities: thirteen
child rows plus the Core. Earlier prose had used only the child-list length.
Original receipts, their false acceptance values, authenticated evidence and
private review files remain unchanged; this is a separate accounting correction.
