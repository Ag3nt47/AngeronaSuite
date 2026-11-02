# Angerona 1.15 workspace and scan review

2 November 2026. Source-development update; publication and final-revision
runtime acceptance remain separate from the implementation described here.

## Findings and changes

The completed combined SpywareGuard and Zero-Breach scan exposed an after-action
presentation defect: the view sliced serialized JSON at a character limit and
could lose its beginning under the text document's block limit. The scanner had
settled, but the displayed payload was not complete valid JSON. The view now
constructs a valid bounded preview with explicit omissions and an overview of
the supplied workflow outcomes. Copy complete JSON uses the retained payload
within 2 MiB; atomic Export complete JSON permits 64 MiB with node/depth bounds.
Unsupported keys or exceeded limits produce a refusal and preserve the prior
clipboard or file. A report remains untrusted evidence, not response authority.

Progress distinguishes workflow stages, current checks and task/file work.
Unknown denominators show observed counts instead of invented percentages. A
successful browser database snapshot restores the main database task label after
sidecar work. Native checks that finish while the toolkit continues are shown as
finished checks awaiting aggregation. A budget remaining is a deadline, not an
estimated completion time; unavailable collectors remain coverage gaps.

The dedicated scan now has a persistent 3,600-second default budget, adjustable
from 30 to 14,400 seconds. The next-run panel starts from that dedicated value;
per-run overrides neither save preferences nor extend an active scan. Standalone
Run scan retains its existing 300-second default and 30–900-second saved range.
Legacy files missing the new field use its default without rewriting saved
settings. The longer default addresses the observed full scan's duration; it
does not guarantee every future scan completes or remove deadline coverage gaps.

Supported content workspaces are modeless and expose native Minimize/Maximize
controls plus F11/Esc fullscreen handling. Actual worker generations remain
owned until retirement. Deferred close uses a generation token so an old queued
callback cannot close a reopened or newly active view. Destruction fallback
removes invalid retained dialog wrappers. Closing a workspace does not cancel
its worker or approve a pending security choice.

Auto Adapt reflows its controls and presents each planned before/after change,
its reason, recovery requirement and verification state. Preset adjustments
invalidate the old preview and approval. The immutable plan expires after ten
minutes and retains exact-state, authority, recovery and journal checks.
Activity shows its latest 500 events and retained transaction details. Recovery
restores and verifies a complete captured Windows Firewall policy; it does not
restore the OS or demonstrate packet-level enforcement. The
[operator map](../docs/security-flow.md#11-auto-adapt-changes-and-rollback)
includes the review sequence and visual flow.

A separate Settings-save failure path copied and replaced the whole process
environment. A failed startup-registration change could therefore undo unrelated
background updates or reintroduce plaintext credential variables removed by the
secure store. Compensating rollback now restores only the 21 nonsecret runtime
values owned by the integration and UI/AI save path, preserving absence versus
empty values. It attempts each independently and reports failures while
continuing later restorations. Protected credential rollback retains its
existing protected-store API and scrubber. The process environment remains
shared mutable state; writers to those same 21 values are not made atomic.

Other maintained boundaries in this update include original-producer proof for
native-hash response, retained process/program custody, installed-only explicit
administrator sign-in enrollment and bounded crash capture. Source Observe does
not gain privileged response rights from a preference, report, review annotation
or enabled enrollment control. See the
[response and deployment boundaries](../docs/security-flow.md#5-response-authority-and-execution)
and [capacity policy](../docs/security-flow.md#6-persistence-and-capacity).

## Focused validation

The final 22-file cohort passed **450 tests with no failures, errors or skips
in 114.68 seconds**. All 507 source files, scoped test/tool inputs and selected
saved preferences stayed unchanged during its bounded native run, which retired
naturally with exit zero and an empty process job. This is focused validation.

The preceding broader run passed 446 of 448 cases and exposed a real narrow-view
layout error: the administrator-startup grid omitted its group-box frame margins
when choosing columns. Its corrected budget and a real-widget boundary regression
preserve full viewport fit without hiding overflow or starting backend work.
The other failure was a fixture race: accelerated news rotation legitimately
switched to a short headline and stopped its marquee. The test now restores the
normal cadence before showing the window, with separate short-headline coverage;
the product's correct timer behavior was preserved.

| Scope | Recorded result | Limit |
| --- | --- | --- |
| Final tree checks | Ruff passed `src`, `tests` and `tools`; all 1,378 Python files compiled. | Offline static checks, separate from the 450-case execution and detector efficacy. |
| Progress, AAR and workspace cohort | 280 passed, 0 failed, 0 skipped; 98.93 seconds | Twelve focused files, including 18 worker/thread cases and Qt report checks; predates the later Settings environment change. |
| Settings rollback and Config atomicity | 10 passed, 0 failed, 0 skipped; 4.63 seconds | Inert startup/store adapters, real credential-scrubbing path and synthetic environment values; no host startup registration or credential mutation. |
| Dedicated scan-budget behavior | 53 passed, 0 failed, 0 errors, 0 skipped; 11.38 seconds | Config defaults/ranges/legacy load, real ToolOperation budget propagation with inert work, no-persist overrides, UI/settings and Full Setup schema; not a fresh live full scan. |
| Final startup dependency preflight | Passed on the changed source; native exit zero, retained child/job retirement and unchanged 507-file source and selected-preference fences. | Check-only execution; no Core or sensors started and no live protection claim. |
| Lint | Ruff passed 507 source files; later `src`, `tests` and `tools` passed after the Settings rollback fix. | Separate checked revisions and source fences; not a complete-suite result. |
| Public baseline | Commit `9820aaf` completed all 15 hosted checks successfully. | Historical published baseline only; not validation of these unpublished changes. |

Each focused native test owner retained its bounded process job, checked
retirement and source/selected-preference fences. These overlapping cohorts must
not be added into a single independent test total. Initial failed or held runs
remain preserved privately with their original scope; corrected results do not
erase them. The final 105-page manual and 15-page security report were rendered
and visually reviewed in full; generated text/table/figure export checks passed.
Exact-commit publication and hosted checks are verified separately after the
reviewed commit is created.

## Actual scan and shutdown scope

The changed-source Full60 observation reached 75 running modules with Chill off.
Its bounded fresh window contained 246 events and no critical event or confirmed
breach. Port-only HIGH leads retained observation disposition and false response
authorization; other review items included exposures, collection health and
unresolved AI admission notices. All four Core, Watch, Scan and Black Box roles
advanced authenticated, generation-bound heartbeats during the capture. These
are liveness facts, not detector or kernel-integrity proof.

Original live acceptance remains held: two process-inventory bounds prevent
complete process history, and the transport retained a 4,826-record initial gap.
Unavailable native canaries and AI admission limits remain explicit. Independent
adapter verification confirmed unchanged source and selected preferences; the
original launch's success-only fields are absent and were not fabricated.
Competing document-rendering load prevents a controlled performance comparison.

The subsequent supported STOP confirmed the exact existing notice once. Core
exited zero naturally; all 17 observed wait rows across 13 unique generations
signaled, with no canonical replacement observed for five seconds. Source,
selected preferences and proof inputs were unchanged. Original strict acceptance
remains false for one process-inventory bound, separately from the proved exit
and retained-wait facts. Shared services were not independently killed. This
result does not close historical native P0 or prove complete process history.

The preceding combined scan finished after approximately 45 minutes. Its
retained after-action result contained one finding, two references and 24
coverage gaps. Native and toolkit work settled; the original terminal UI receipt
was not accepted because of the display defect described above. These counts
establish neither a confirmed spyware installation nor a clean host. This run
predates the newest presentation fixes.

The subsequent supported STOP exited the observed core with native exit zero;
all retained wait rows signaled and no canonical replacement was observed during
the bounded follow-up. A process-inventory bound prevents a complete process
history claim. The confirmation disclosed possible loss of volatile pending
telemetry. Preserved recordings and selected settings were not cleared to make
the observation pass.

## Residual exposure and acceptance

| Boundary | Remaining exposure or unproved acceptance |
| --- | --- |
| Same-user and privileged compromise | Source Observe remains in the interactive user's failure domain. A hostile same-user process, administrator/SYSTEM, compromised OS, kernel, firmware or hypervisor can tamper with or suppress evidence. No accepted PPL/ELAM or production kernel boundary is established. |
| Telemetry and coverage | Liveness and completed workflow stages do not prove usable kernel telemetry or absence of malware. Permission gaps, unavailable collectors, partial sources and loss remain visible. |
| Network enforcement | Path rules, retained executable custody and policy readback do not prove packet drops, PID-birth-bound socket admission or teardown of established/inherited flows. |
| Rollback freshness | Local integrity chains alone cannot defeat whole-root replay. Independent TPM/hardware freshness or witness enrollment needs separate accepted deployment. Firewall Undo is not OS rollback. |
| Storage and recovery | Admission samples and record bounds are not global quotas or cross-writer reservations. Incomplete capture, unknown custody or durability keeps recovery held. Protection cannot be guaranteed with compromised source, unavailable OS facilities or unusable storage. |
| Production deployment | Publisher/package pins, independent signing, installed administrator enrollment and actual native clean-machine acceptance remain external gates. Source tests do not establish a deployable privileged release. |
| Availability and causality | Historical native P0 and CPU/UI cost remain unresolved. This update does not attribute those failures to Optimus or treat a later normal exit as proof of their cause or closure. |

Raw host captures, paths, indicators and process identities remain private.
Public screenshots and demonstrations use synthetic data. The
[release notes](../docs/releases/v1.15.0.md) and
[operator security map](../docs/security-flow.md) describe the user-facing
controls without claiming that the remaining external gates are satisfied.
