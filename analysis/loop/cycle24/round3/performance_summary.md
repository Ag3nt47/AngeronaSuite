# Cycle 24 Round 3 — Performance and Reliability

Date: 2026-08-27

## Result

Six narrow reliability improvements were applied. Directory enumeration and
recovery-file reads now stop at explicit budgets, Personal Sentinel drains
admitted workers before releasing its authority lease, SSH consumer-schema
rejection can no longer consume broker continuity invisibly, and the public
gallery is byte-reproducible instead of depending on UI/storage scheduling.
Qt translucent theme colors now use the toolkit's documented alpha-byte order,
eliminating opaque alternate-row and hover colors.
No protection cadence, cryptographic check, evidence field, response boundary,
or fail-closed state was relaxed.

## Measurements

Measurements used deterministic in-memory or synthetic public-demo fixtures.
They did not contact a network service, execute a response, read host telemetry,
or alter a security policy.

- A 100,000-row synthetic directory benchmark measured the retained bounded
  iterator at **0.0242 ms** per call versus **3.3220 ms** for the prior
  materialize-then-check reference: **137.24x faster** at the over-budget case.
  More importantly, the retained path consumes exactly `limit + 1` rows rather
  than memory proportional to provider output.
- Over five runs of 5,000 authenticated events, unconstrained
  `SensorProvenanceBroker.ingest()` measured **68.502 us/event** median and the
  new label/type/schema-constrained admission measured **72.562 us/event**:
  **4.060 us/event** added for the fail-closed consumer boundary.
- Two complete four-image gallery runs produced byte-identical PNGs for every
  surface. Final hashes from the paired run were:
  - dashboard: `d5c8d1a05b36e0828ef64915abd4477460146ec0bdd125e776c282fd963ebacf`
  - SOAR review: `bc6f8cc5c7620d9dcbe582abe10ed5472d8839a65861e96a058f9d88817ae87d`
  - Scan Center: `2f0e46793082b1aebaee9361ecf815762f92af779bb785e57a6e2a6c5627431b`
  - ARIA local-first detail: `360ee07800cfa28f5b2c8be5d591c3d19592a75d66ca64945c9cf1dad80a78`

## Applied improvements

### Bounded peripheral enumeration

- **Component:** `src/angerona/core/peripheral_posture.py`
- **Problem:** `_bounded_entries()` converted all provider rows to a tuple and
  checked the 1,024-row limit afterward. A faulty or hostile evidence provider
  could therefore force unbounded traversal and allocation.
- **Change:** Consume at most `limit + 1` rows with `islice`; an over-budget
  source still fails to UNKNOWN exactly as before.
- **Proof:** A regression verifies that a 100-row generator yields only five
  rows when the injected limit is four.

### Complete Linux Thunderbolt security reduction

- **Component:** `src/angerona/core/peripheral_posture.py`
- **Problem:** the Linux collector stopped after the first readable Thunderbolt
  domain. Directory order could therefore let a secure domain mask a later
  controller whose security value was `none`.
- **Change:** read every domain's bounded `security` attribute through the
  existing identity-stable, no-follow, 64-byte reader and select the
  least-protective definite state. Any `none` domain remains a decisive open
  finding. Missing, unreadable, or invalid sibling evidence makes collection
  incomplete and yields UNKNOWN unless that open finding is already present.
- **Performance/security behavior:** work remains linear in the already-capped
  1,024-entry inventory, performs no writes or device changes, and adds no
  unbounded traversal. Multi-controller secure-plus-none, all-secure,
  mixed-unreadable, and open-plus-unreadable regressions cover the reduction.

### Bounded recovery directory and stable file reads

- **Component:** `src/angerona/core/recovery_assurance.py`
- **Problem:** non-recursive globbing could enumerate an unbounded evidence
  directory before applying the 64-file limit, and `read_bytes()` could
  materialize a file that grew after the initial path check.
- **Change:** scan at most 1,025 directory entries, stop immediately at the
  65th JSON evidence file, and read each evidence envelope through a no-follow,
  identity-stable descriptor capped at 64 KiB.
- **Security behavior:** excessive, unreadable, linked, replaced, or unstable
  evidence remains an explicit load error and can never contribute a healthy
  recovery result.

### Deterministic Personal Sentinel shutdown

- **Component:** `tools/personal_sentinel_server.py`
- **Problem:** daemon request workers and separately spawned pre-authentication
  threads were not guaranteed to finish before `authority.close()` released
  the singleton lease.
- **Change:** stop admission under a lock, track the bounded set of at most 16
  pre-authentication threads/sockets, close them, use one shared bounded drain
  deadline, and let `ThreadingMixIn` join non-daemon authenticated workers.
- **Security behavior:** no post-drain request can be dispatched, and the
  authority's irreversible closed-state checks remain the final backstop.

### Schema-constrained sensor continuity

- **Components:** `src/angerona/core/sensor_provenance.py` and
  `src/angerona/modules/ssh_surface_guard.py`
- **Problem:** an authenticated SSH producer could send sequence 1 under the
  wrong event type; the generic broker advanced its high-water mark before SSH
  rejected the body. A valid sequence 2 then appeared ready with no gap.
- **Change:** optional exact producer label, event type, and bounded consumer
  validator checks run after HMAC authentication but before any sequence/loss
  mutation. SSH supplies its complete fixed channel/provider/message schema.
- **Proof:** wrong-type sequence 1 leaves `last_sequence=0` and
  `accepted_events=0`; a subsequent valid sequence 2 produces
  `observed_gap_total=1`, remains degraded, and cannot seed trusted known-source
  state. The constraint adds 4.060 us/event in the deterministic benchmark.

### Reproducible public gallery capture

- **Component:** `tools/capture_public_dashboard.py`
- **Problem:** the main dashboard timer, nested ARIA orb/meter timers, persisted
  sparkline, and asynchronous alert reader could change pixels or leave Live
  Alerts empty depending on scheduling.
- **Change:** stop all relevant top-level and nested timers, freeze the orb
  phase and synthetic sparkline, and populate the real alert table
  synchronously from the fixed synthetic EventBus fixture. An exact 12-row gate
  fails capture instead of publishing an incomplete screenshot.
- **Proof:** two back-to-back complete gallery runs matched all four SHA-256
  hashes exactly.

### Correct Qt translucent-colour encoding

- **Component:** `src/angerona/gui/theme.py`
- **Problem:** Qt QSS reads eight-digit hexadecimal colours as `#AARRGGBB`,
  while the theme used CSS-style `#RRGGBBAA`. The intended low-opacity white
  alternate row therefore rendered as opaque yellow on the SOAR table.
- **Change:** store alternate-row colours in Qt ARGB order and generate every
  accent tint through one bounded helper that preserves the RGB bytes.
- **Proof:** focused regressions verify built-in and custom-accent QSS, and the
  final paired gallery run is visually clean and byte-identical on all four
  published surfaces.

## Static audit and deliberately deferred work

- Release authorization and portable-upgrade verification re-hash exact
  artifacts rather than caching them. Reusing digests across trust decisions
  was not applied because it would weaken change detection across a mutation
  or handoff boundary.
- Payload-manifest generation is capped at 4,096 admitted files and rejects
  reparse directories, but Python's controlled-CI `os.walk` can still
  materialize a very large single directory before the file-count check. If
  release staging ever accepts untrusted directory trees, add an independent
  directory-entry budget using a descriptor-based walker.
- Personal Sentinel state remains capped at 512 KiB and 4,096 nonces. Its
  fsync/atomic replace per accepted transaction is intentionally retained;
  batching would weaken crash continuity.
- Temporal persistence, RAG stable reads, recovery signature verification,
  release hashing, and Windows trust evaluation remain fresh and uncached.
  Their I/O is part of the evidence contract rather than cosmetic work.
- New module loops retain bounded queues and use module worker threads rather
  than the GUI thread. No unbounded process creation, recursive GUI refresh,
  or leaked capture worker was found in the audited Cycle 24 paths.

## Validation

- Focused pytest: **78 passed, 1 skipped** across sensor provenance, SSH
  surface, peripheral/DMA posture, recovery assurance, and Personal Sentinel
  server tests.
- Standalone self-tests: **3 passed** — SSH Surface Guard, Peripheral DMA Guard,
  and Immutable Recovery Guard.
- Ruff: PASS for all changed Python product/tool/test files.
- `py_compile`: PASS for all changed Python product/tool/test files.
- Gallery reproducibility: **8 successful captures**, with the final paired
  four-image run matching byte-for-byte.
- `git diff --check`: PASS; only repository line-ending notices were emitted.

## Files changed by this audit

- `src/angerona/core/peripheral_posture.py`
- `src/angerona/core/recovery_assurance.py`
- `src/angerona/core/sensor_provenance.py`
- `src/angerona/modules/ssh_surface_guard.py`
- `tools/personal_sentinel_server.py`
- `tools/capture_public_dashboard.py`
- `src/angerona/gui/theme.py`
- `tests/test_peripheral_dma_guard.py`
- `tests/test_recovery_assurance.py`
- `tests/test_sensor_provenance.py`
- `tests/test_ssh_surface_guard.py`
- `tests/test_personal_sentinel_server.py`
- `tests/test_theme.py`
- `analysis/loop/cycle24/round3/performance_summary.md`
