# UI responsiveness and alert calibration — 2026-09-05

## Observed problem

The operator reported slowdowns with 76 of 84 modules running and an unresponsive
Alert Detail window above Resolve Center. A local watchdog stack at 19:02:10
recorded a 37.4-second GUI stall inside Resolve Center's SQLite history fetch.
Another stack at 18:42:35 recorded a 5.2-second stall reaching process allowlist
filesystem inspection from a dashboard refresh. SQLite's nonblocking lock attempt
did not make query execution, row decoding or policy inspection asynchronous.

The screenshots also showed static MP3/PDF/XLSX entropy, anonymous RWX memory in
browser-based applications, regular Defender connections, executable names parsed
as DNS queries, Defender channel failures and an HVCI gap as HIGH active alerts.
These observations do not independently establish malicious activity. They do
not establish that the named programs or files are safe either.

## Changes

- Resolve Center uses one pending snapshot per dialog and at most two readers
  across dialogs. Database decoding, acknowledgements, policy evaluation and row
  preparation run outside Qt. Cached history is reclassified for expiry, live bus
  updates and policy changes; page changes read memory only. Selection follows
  event identity. Operator changes invalidate old results. Busy/error preserves
  prior rows, and closing never waits for an outstanding database call.
- Dashboard threat/posture and SOAR queue presentation use coalesced background
  snapshots. Security wake classification has a separate worker, retains the
  event revision until classification succeeds, and preserves priority events
  through ordinary telemetry bursts. GUI updates use completed snapshots;
  pending/failure does not substitute a fresh Secure result.
  Observation-only event sets also avoid unnecessary response-policy reads.
- Static entropy and ordinary authenticated file edits/deletions become INFO
  observations without response contracts. Sampling, authenticated receipts,
  changed-content evidence and canary protections remain. Rename correlation
  requires changed content in the actual old/new pairs inside the time window.
  An unrelated high-entropy file cannot promote a rename burst to containment.
- Anonymous RWX, connection cadence without threat intelligence, and lexical DNS
  anomalies become MEDIUM observations. No blanket exemption by executable name
  or file extension was introduced. Corroborated malicious-peer beacons retain
  exact process/peer response contracts. DNS consumes bounded typed query fields,
  rather than extracting apparent domains from arbitrary log prose.
- Evidence Lattice excludes these calibrated observations from elevation. They
  cannot manufacture actionable HIGH evidence through a count of sensor names;
  eligible independent detector signals retain their existing correlation path.
- Alert Detail explains the assessment separately from recorded severity.
  Observation containment controls are disabled, with original evidence retained.
- Defender telemetry continuity failures remain visible as health evidence, and
  kernel control gaps as hardening exposure. Narrow compatibility rules remove
  the old indicator records from active threat calculations without changing
  their original severity, details or signatures. Explicit exploitation and
  critical corroborated evidence still count as active.

## Validation

- Exact maintenance worktree: **3,153 tests passed, 17 platform skips**, in
  **410.70 seconds**. VMware work in progress was excluded from that tree.
- New checks deliberately block history, policy, KEV and SOAR reads while a Qt
  heartbeat continues. They verify one pending worker, coalesced refresh,
  retained state on failure, stale/closed result rejection, stable selection,
  cached pagination and security-event delivery through an INFO burst.
- Detector checks cover static compressed content, ordinary changes/deletions,
  unchanged or unrelated media during renames, precise changed-content pairing,
  typed DNS versus executable-name prose, RWX, cadence and later corroboration.
  Existing file identity, authenticated receipt, sampling and response-contract
  regression checks passed. Legacy event signatures remain verifiable.
- The headless self-check diagnostic rerun passed **26 phases**. Its module and
  pipeline runner reported **69 passed, 0 failed, 16 expected skips**. The first
  harness invocation exited 1 without a final phase report; it did not reproduce
  when an independent JSON capture recorded every phase before the original
  exit call. Assertions and product behavior were unchanged; the original
  incomplete run is not counted as passing.
- Whole-tree compilation, Ruff correctness checks, documentation drift and
  whitespace checks passed. The updated Alert Detail layout was rendered with
  synthetic evidence at 900 × 720 and inspected; observation text and actions
  remain visible. The disabled containment control was checked programmatically.

## Limits and deployment

The regression checks exercise blocked readers and synthetic detector inputs;
they are not a measurement of the operator's running 76-module workload. Existing
SQLite calls cannot be interrupted, but outstanding Resolve reads stay capped at
two and the GUI does not wait for them. This update does not change journal
recovery, approval requirements or the response authority boundary.

Restart the source-launched application to load the updated code. A running
process or previously built executable does not hot-reload these changes.
VMware Analysis Lab remains separate work in progress with live acceptance
pending; it is not included in this maintenance publication.
