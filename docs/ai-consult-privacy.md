# Review and send AI consultations

Development version: v1.14.0. The broader v1.15 integration remains incomplete.
This source-applied maintenance repairs the manual alert Research/SOAR consult
flow identified by SEC-15. SEC-16 tracks its effective resolution while retaining
the original finding unchanged. The repaired source passed the scoped 182-case
gate. A fresh 90.14-second passive 15-module observation completed with explicit
coverage gaps. See the evidence and limits below.

## Review before transmission

Within AIConsultDialog, opening, selecting Review original request, retrying or preparing
a follow-up creates a preview without starting a provider request. The dialog
shows the sanitized system/user JSON and eligible provider, model, endpoint and
fallback order. This previews content and destinations, not authorization headers
or every provider-specific transport byte. A separate explicit Send starts the reviewed request.

You can remove content from the JSON preview. Edits mark it dirty and disable
Send until Review edits rebuilds and sanitizes the preview. The JSON must contain
only the system and prompt text fields. Initial requests, retries and follow-ups
all require their own reviewed Send; a previous click does not authorize newly
constructed content. Model answers remain advisory and do not authorize host actions.

One Send permits only the displayed content and eligible fallback sequence.
Before submission and between fallbacks, the engine compares the current
sanitized content, destination/model configuration and process-local credential
binding to that review. A change holds the request for review again; no raw-data
fallback is substituted when preparation fails.

## Content preparation and destinations

Manual consult and the separate automatic alert-analysis path share the bounded
recursive sanitizer. Recognized sensitive fields, identifying paths/addresses
and token-like strings are removed or replaced; size/depth/node limits remain
explicit. Encoded or uncertain context may be omitted entirely. Attacker-supplied
redaction-marker text is not a trusted exemption from checking.

Redaction is best effort. Unlabelled, unusual or semantic secrets may remain.
Read and minimize the exact preview before Send; this does not promise perfect
privacy or make arbitrary imported text trustworthy. The original local evidence
is not rewritten by preparing a consultation.

Research/SOAR, CVE analysis and Sandbox Editor use the consultation dialog.
Direct consult_ai callers, including explicit CLI consultation and separately
configured ARIA fallback, are sanitized but do not universally require a GUI
preview; their existing policy and consent semantics remain distinct.

Configured manual cloud routes remain available after review and Send. Their
consent is separate from automatic fallback settings. This update introduces no
universal provider-egress deny, global computer-only setting or local-only toggle.
Ollama preview destinations admit localhost or numeric loopback through the
existing attested local transport; arbitrary local DNS aliases are held until
configured as localhost/loopback. Preview preparation performs no DNS/HTTP request.

Credential bindings are opaque process-local HMAC comparisons, not exported
credentials, durable revocation records or independent identity attestations.
They do not detect a change away and back entirely between observations or
protect against arbitrary code controlling the same process or a hostile kernel.

## Cancellation and remaining limits

A retained QThread runs the provider call. Closing requests cooperative
cancellation and keeps the worker owned until actual retirement. Cancellation is
checked before fallbacks; it is not atomic network admission. An in-flight
blocking call may finish or reach its timeout before retirement. Cancellation
does not prove that already submitted bytes were recalled.

Existing GUI-thread host/process context gathering remains a latency candidate.
The change does not implement broader process isolation, a universal AI gateway
or a privileged-response boundary. External coding/debug agents with filesystem,
shell or Git credentials operate outside Angerona's registered internal AI-tool
boundary; read-only Live Debug does not confine those grants. Multiple reviewers
sharing a host/account do not become independently administered trust anchors.
See [AI-aware defense](ai-aware-defense.md) for recommended operating controls.

## Evidence and publication

The first focused 12-suite cohort collected 182 cases: 180 passed, two failed,
zero skipped, native exit 1. Its preserved receipt is
63db99bc87db831f9db958d04c66ae23b6bf77de8ea78db9f170e9c23edc4da5.
Exact outer-two-generation retirement and frozen-input stability were retained;
a clean shutdown does not turn the failed test verdict into a pass.

Both failures were confirmed test fixtures. A long hexadecimal run was already
correctly redacted, so the 512-character benign-truncation fixture now uses
ordinary spaced prose and separately asserts hash-like redaction. The migration
fake now accepts strict=True and checks the exact strict-read/write/strict-read
sequence, verified persisted data and preservation of replaced plaintext.
The four production candidates are unchanged by those fixture corrections.

The corrected 12-suite/117-function cohort collected and passed 182 cases, including
all 75 new privacy cases, with zero failures/errors/skips; native exit 0. Its
current_validation_receipt_sha256 is
e2b0c5a6cf01be853ae5102bd5228a48137519fdc39c943e668f0cfddbd03b26.
JUnit recorded 11.607 s; the supervisor 15.5 s. Both exact outer generations retired
at the same birth/WAIT0/native 0, four retained handles closed, MainThread/no
QApplication remained, and source/HEAD/both indices/runtime39/helpers83 were stable.
This binds source 1872/f439ac7a9965ee111cd8d8a5adfee2c8160fad5557e1905c2bac10a413a3b83a;
it is not a current 29-phase selfcheck or all-module efficacy claim.

The fresh 90.14-second passive observation completed OBSERVED_WITH_GAPS:
15 eligible modules, 71 held, 17 gap strings across nine modules, and 65 events
(one critical, two high, 57 informational, three low and two medium). There were
zero recorded errors, crashes, capture/export/console loss or pending threads.
Its current_observation_receipt_sha256 is
98a191185b733fdf7a83b800a14d5d2b1d8943d30d0a56d2451e96ba1e651e4c.
The exact two outer generations and admitted core retired at their retained
process births with WAIT0/native 0 and closed handles; MainThread/no QApplication
and source/HEAD/both indices/runtime/helper stability were retained.

The filtered capture has 76 records: 65 events and 11 coverage controls. All
65 events carry original-integrity and live-receipt verification flags at export;
the redacted payload is not the complete authenticated original. Seven records
explicitly deny response authorization, 58 omit the field, and none explicitly
authorize response. The high/critical records describe an unavailable AegisPath
snapshot, unbound Fleet store and unmet Immutable Recovery requirements/exposure;
all three explicitly deny response authority. The three SpywareGuard rows also
deny response authority and mark spyware unconfirmed. Omitted evidence prevents
a host-compromise or false-positive verdict from this capture.

Optional memory, outbound research/cloud and response/quarantine/isolation/UGCAP/
beacon work remained off. This does not exercise real provider requests or the
consultation GUI, prove redaction complete, certify the host clean, or establish
speed improvement. Query-only primary-worker sampling completed 81 rounds with
16 handles opened/closed and no profiling gaps; it is not complete helper
attribution or independent process-retirement proof.

The historical [caf0 CI run](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/40047275752)
finished with eight successful jobs and four failed Python 3.10–3.13 jobs. Each
reported 8171 passes/one failure/22 skips from the same strict-migration fixture
mismatch; the Security workflow passed all three jobs. The failed hosted cohort
remains failed. The corrected local 182-case gate is separate evidence; it does
not establish a later hosted CI result.

The published caf0c568abbf60584ea7726fdc28def97daca397 checkpoint has its own
publication proof d592354c2c7a11b654cbdd16215cfeea31b34fd0fda0d0be2d0b0b90eedae2d0.
Its 786-test, 29-phase and 600-second results belong to that earlier source; they
do not validate this later privacy change. The [earlier scoped review](../analysis/live-debug-2026-10-22/key-and-memory-review.md)
retains those boundaries. Guarded GitHub publication is a separate mandatory gate;
tests and observation receipts alone do not prove publication.
