# Changelog

## 1.14.0 — model parser error normalization

- Normalize malformed manifest, inventory and approved-baseline parsing failures
  into the existing typed integrity error at three lower-level boundaries. Integer
  conversion limits, excessive JSON nesting and baseline timestamp overflow now
  follow the same refusal path. Hash, HMAC, approval and baseline-preservation
  checks remain in place; invalid evidence continues to block inference.
- Separate original/candidate comparison: 17 functions / 83 cases / 249 phases
  per mode; original 60 passed / 23 failed, corrected candidate 83 passed, with
  zero errors or skips. Preserve the rejected earlier run (candidate 74 passed /
  nine failed): its nine shared deep-fixture failures came from an assumed JSON
  depth and did not demonstrate a product recursion failure. A bounded real JSON
  probe established a failing depth of 4256 after three probes on this Python 3.12
  runtime without changing interpreter limits, mocking the parser or forcing skips.
- Fresh focused integration: 44 suites / 606 functions / 1263 cases, 1258 passed,
  zero failures/errors, five unchanged exact native availability skips and 3789
  phases. All 83 parser cases passed and all 13 configured product origins loaded.
  Default selfcheck passed all 29 phases: 68 module PASS, 18 module SKIP and one
  pipeline PASS; IPC was naturally unloaded, with no forced import credit.
- A real private AI Model Integrity Guard worker completed its first check during
  a 30.062-second observation with 119 observer heartbeats. An absent approved
  baseline produced approval-required state, health 25 and a verified signed
  MEDIUM availability event. Two expected health/interval gaps remain explicit:
  OBSERVED_WITH_GAPS is not healthy attestation. Normal cadence and default key
  handling were retained; no baseline was enrolled or host model/provider used.
- Preserve all 191 historical issue objects and old root values byte-for-byte;
  append only current_parser_normalization_review. The historical SEC-20 open
  record remains intact while the new descriptor resolves this scoped lower-level
  normalization gap. HOST-03/HOST-04 and older native/GUI causes remain open.
- The preceding published IPC revision passed all 15 Actions jobs, including
  8534 passes / 22 skips on each Python 3.10–3.13 job. That historical result
  neither certifies this parser revision nor explains the earlier GUI producer
  failure. This entry records scoped local validation; final-source offline checks,
  guarded publication and exact-head Actions are verified separately.

Exact scope: two code/test paths plus seven existing documents; no new module,
version bump or measured speedup. Product remains v1.14.0 maintenance; broader
v1.15 is incomplete. See [the current evidence and limits](analysis/live-debug-2026-10-22/README.md)
and [model integrity boundaries](docs/key-and-communication-integrity.md).

## 1.14.0 — IPC key custody and constructor recovery (historical checkpoint)

- Serialize cooperating scanner-ring key initialization through the existing
  public credential transaction. Permit two finite initialization rounds with
  bounded collision/custody reclassification; preserve an existing malformed or
  failed authority for explicit recovery instead of rotating it or deleting a
  potentially substituted winner. This reuses the lock namespace, not credential
  encryption or backend reads/writes.
- Admit at most 4096 key-file bytes; read the admitted size plus one through the
  retained descriptor and verify named/held identity before and after the read.
  Compare platform-compatible timestamps across APIs while keeping each API's
  raw change-time checks exact. Existing 32-byte keys, 64-hex representation,
  HMAC/AAD/frame/schema/layout and pressure/drop contracts remain unchanged.
- Close the constructor's owned file and mapping on failures after file-object
  acquisition. Real closed-state assertions run before fixture fallback cleanup;
  no persistent field leak or cleanup-error injection is claimed.
- Preserve baseline ten-case characterization and the rejected first candidate
  (26 passed / five failed). The corrected final 43-case comparison retained
  original eight passes / 35 failures versus candidate 43 passes, zero errors or
  skips, with 21 functions and 129 phases per mode. Short parameter labels keep
  the unchanged 4096-character ledger limit; values and assertions remain.
- A separate existing property passed once in native Windows namespace mode and
  once in a private Linux-namespace model: two cases / six passed phases. Both
  used actual Windows leases; this is not native POSIX, home-permission or ACL
  assurance, and is separate from the focused gate totals.
- Fresh focused gate: 43 suites / 589 functions / 1180 cases, 1175 passed,
  zero failures/errors and five exact native availability skips. All 13 configured
  origins loaded, including IPC; all 589 function counters and 3540 phases agree.
  Selfcheck: 29 phases passed, 68 module PASS plus pipeline PASS and 18 module
  SKIP. IPC was naturally unloaded in selfcheck; it adds no ring self-test credit.
- Fresh ordinary-user process-telemetry observation completed 30.172 s with
  31 scanner heartbeats, two raw sensor frames and 119 observer heartbeats;
  zero matrix errors/gap records/drops/pending threads. Original outer two
  generations and a separately held core retired. Its selected capture retains
  11 advisory coverage records and zero EventBus event records; that does not
  establish complete alert visibility, file scanning or a clean host. The
  unchanged offline summarizer grouped those 11 coverage notes into 11
  needs-review cases with zero parse omissions/overflow/identity conflicts;
  selected-input processing only, continuity unverified and no disposition or
  response-authority changes.
- Preserve all 188 historical raw issues and append IPC-01/IPC-02/IPC-03 with
  separate scoped review metadata. SEC-20 is unapplied; HOST-03/HOST-04 and
  historical native/GUI causes remain open. Published 89c708's Python 3.13 CI
  failure remains unresolved; the rerun request returned 403 with no new attempt.
- Current scope: three code/test paths and seven existing docs, one added test,
  no new module or document. Final-source offline checks, reviewed commit,
  unchanged guarded publication and current CI need separate fresh receipts.
  Product remains v1.14.0 maintenance; broader v1.15 remains incomplete.

See [key custody and recovery](docs/key-and-communication-integrity.md) and
[the current scoped review](analysis/live-debug-2026-10-22/README.md).

## 1.14.0 — SCN-06 ring self-test resource cleanup

- Nest the existing writer/reader contexts inside the self-test's outer cleanup
  so real mappings/files close before directory removal. Preserve the pressure
  getter, explicit synthetic key, layout, frame/drop semantics and assertions.
- Actual staged comparison: original zero passes / four failures / native exit 1;
  candidate four passes / native exit 0, both zero errors/skips. Three functions
  check normal return, genuine reader rejection before allocation and two body
  failures after genuine I/O. No internal post-acquisition constructor cleanup
  or historical field-residue/host-leak conclusion is claimed.
- Fresh gate: 42 suites / 568 functions / 1137 cases, 1132 passed, zero
  failures/errors and five exact native availability gaps. All four lifetime
  and 20 pressure cases passed; privacy 75 and nested seven are included subsets.
  Selfcheck: 29 phases / zero failures, 68 module PASS plus pipeline PASS and
  18 module SKIP. IPC was naturally unloaded in selfcheck; no import was forced.
- Independent process-creation telemetry ScannerHost 30 s completed 30.047 s with
  31 heartbeats and six raw sensor frames, zero matrix errors/gaps/drops/pending.
  Its selected capture retains 11 coverage records and zero EventBus event
  records. The selected 11 coverage records mapped to 11 needs-review groups, with zero parse omissions, overflow or identity conflicts. Processing is complete only for that input; continuity remains unverified, original statuses stay intact and no response authority is granted. No file scan, malware verdict, assumed 85%
  trigger, GUI, clean-host, field-efficacy or speed conclusion follows.
- Preserve all 187 historical issue objects/root values and append only SCN-06
  as issue 188 with a separate scoped review. Exact scope is eight paths: two
  code/test plus six existing docs, one added test and no new doc. Final-source
  offline checks, reviewed commit, unchanged canonical guarded publication and
  current CI each require their own fresh receipt; none is preclaimed here.
  Product v1.14.0 maintenance; broader v1.15 remains incomplete.
  [Current evidence and open findings](analysis/live-debug-2026-10-22/README.md).

## 1.14.0 — SCN-05 telemetry backpressure maintenance

- Re-evaluate live occupancy before the producer's shedding decision so a
  drained ring can resume without an otherwise impossible extra write. Keep
  producer-only pressure-flag updates, the 85% threshold, authenticated frame
  and sequence/layout checks, cadence and earlier shed/drop evidence. Malformed
  observed headers remain explicit errors; no atomic snapshot or race immunity.
- Separate staged comparison: original source 3 passed / 17 failed / native
  exit 1 versus candidate 20 passed / native exit 0, both zero errors/skips.
  Preserve baseline failures as negative controls. The actual ScannerHost.run
  fixture uses a private real ring and inert gated sensor; it is unit evidence.
- Fresh active-source gate: 41 suites / 565 functions / 1133 cases, 1128 passed,
  zero failures/errors and five exact native availability skips. All 20 new
  scanner cases passed; privacy 75 and seven named nested cases are included
  subsets. All 13 configured origins loaded, including IPC. Acceptance is
  complete; skipped native coverage and imported-byte limits remain.
- Fresh default selfcheck: 29 phases / zero failures, 68 module PASS plus
  pipeline PASS, 18 module SKIP; five required origins loaded, seven configured
  loaded / six unloaded. IPC was naturally unloaded: selfcheck adds no changed-
  IPC execution credit, and no import was forced to make it pass.
- Fresh process-creation ScannerHost observation: 30.031 s, 31 heartbeats and
  four raw sensor frames; zero matrix interval gaps, recorded errors/drops or
  pending threads. Original outer two generations and separately held core
  retired with their scoped native proofs. The selected 2751-byte capture
  separately retains 11 advisory coverage notes and zero EventBus event records;
  raw sensor frames are not alert-event records or complete alert visibility.
- The selected 11 coverage records mapped to 11 needs-review groups, with zero parse omissions, overflow or identity conflicts; processing is complete only for that input, while continuity remains unverified and original dispositions/response authority are unchanged.
- Preserve all 186 prior raw issues and old root/history/review values; append
  SCN-05 as issue 187. SCN-04 stays the unrelated Windows Run-view issue. SEC-20,
  HOST-03/HOST-04, earlier causes and all unadjudicated findings remain OPEN.
- Exact scope: two code/test paths plus six existing docs, one added test,
  1880 source / 1167 Python entries before final doc binding. Final-source
  offline checks, reviewed commit, canonical guarded publication and current CI
  need separate fresh receipts; no completion is attested here. Prior successful
  7b44dc3 CI is historical only. No file-malware verdict, passive 85% trigger,
  live-host efficacy, GUI/all-module coverage or speed gain is claimed.

See [the scoped review](analysis/live-debug-2026-10-22/README.md). Product remains
v1.14.0 maintenance; broader v1.15 remains incomplete.

## 1.14.0 — original-path model custody maintenance

- Check the original model-root leaf and each in-root component before canonical
  resolution; retain confinement and root/file identity snapshots. Trusted ambient
  ancestors retain their existing assumptions. No directory lease, atomic
  resolve/open, kernel resistance or previous SHA/HMAC bypass is claimed.
- Fresh 40-suite / 556-function / 1113-case gate: 1108 passed, zero failures/errors,
  five exact Windows availability skips. Three lexical native cases remain
  privilege gaps. Failed R2 acceptance remains preserved. All 29 selfcheck phases
  passed: 68 module PASS plus pipeline PASS, 18 module SKIP, five required origins.
- Fresh synthetic model-worker observation completed 30 s with one 117-byte read,
  two verified files and original-worker retirement. Separate SpywareGuard and
  independent process-creation telemetry ScannerHost observations completed
  30.172 s and 30.047 s. The ScannerHost case submits no file-scan request or
  file-malware verdict. The 15-module combined run completed 600.625 s with
  1723 heartbeats, 360 events and 18 retained interval gap strings across ten
  modules; it recorded zero errors, drops or pending threads.
- The selected combined capture mapped 371 records into 93 needs-review groups,
  with zero parse omissions, overflow or conflicts. Continuity is unverified;
  original dispositions and response authority are unchanged. Final-source
  offline validation and the unchanged canonical guarded publisher require
  separate receipts for the exact ten-path scope; this entry does not attest
  offline, commit, publication or CI completion.
- Preserve all 186 historical raw issue objects and the OPEN SEC-19 snapshot.
  Current scope is recorded separately; native, host and historical unknowns remain.

See [the model-integrity reference](analysis/live-debug-2026-10-22/model-integrity-review.md).
Product remains v1.14.0 maintenance; broader v1.15 remains incomplete.


## 1.14.0 — model-manifest reader maintenance

- PER-19: request an already-admitted manifest size plus one byte instead of the
  full 16 MiB cap plus one. Preserve growth/identity/length/cap, hashing, baseline
  and response checks. New reader parity/error controls and adjacent suites are
  included in the fresh 39-suite/544-function/1061-case gate: 1059 passed, zero
  failures/errors, two exact Windows availability skips; coverage is incomplete.
- SEC-19 remains OPEN: original lexical link aliases can be erased by canonical
  resolution before lower-level no-link checks. Full approved inventory rejects
  links and pinned digests still apply; no new lower-trust bypass is confirmed.
  SEC-20 remains OPEN: lower-level deep/malformed parser errors need consistent
  normalization. Outer callers hold on errors; no runtime fail-open/DoS reproduced.
- DBG-18: retain the first failed acceptance despite 1059 test passes/native zero;
  its private grader required the old 34-suite scope. The corrected grader was
  followed by a fresh accepted full run. Separate guarded observer controls are
  harness evidence, not product features or additions to the test count.
- Fresh 29-phase selfcheck passed with 68 module PASS, pipeline PASS and 18 module
  SKIP; five required origins loaded (seven configured loaded/five unloaded).
  Active model attestation was not part of that selfcheck.
- OBS-08: the 600.297-second default 15-module window recorded 463 events and zero
  errors/drops/pending threads, retaining 19 interval gaps (18 module strings
  across ten modules plus a 3.531-second heartbeat gap). The 3.2106547-second
  persistence stage already used durable=False without explicit fsync; its cause
  remains UNKNOWN. Final C2/Sysmon health 100 does not erase interval history.
- Separate 30-second actual model-worker observation used a synthetic baseline/key:
  one 117-byte reader return, two verified files, four ordered call/return records,
  120 snapshots and one event; original worker/two outer process generations
  retired. No real enrollment, key-custody, provider, GUI or speed proof follows.
- An 8192-byte synthetic fixture measured tracked Python allocation peaks of
  16,787,510 versus 18,873 bytes. This is not RSS/native/product performance.
  Preserve all 181 prior raw issue objects/order/status; append five IDs for 186.
  Product remains v1.14.0 maintenance; broader v1.15 is incomplete. Final offline
  validation and guarded publication remain separate mandatory proofs.

See [the model-integrity evidence reference](analysis/live-debug-2026-10-22/model-integrity-review.md).


## 1.14.0 — SpywareGuard evidence review and beacon lifecycle

The scoped R4 gate, fresh selfcheck and three serial observations are accepted
with explicit coverage gaps; final offline checks and publication remain gated.
This is 1.14 maintenance, not a 1.15 release or completed publication.

- SEC-18 (LOW): frozen IndicatorReviewIdentity binds literal/source/digest/times,
  CSPRNG store session/revision, and module session/lifecycle generation. Compare
  and assign under store → module lock order. No expiry revival, same-byte-refresh
  consent or duplicate-source substitution. Keep exact-receipt revocation/source
  removal, receipt-aware dedup and detached JSON/500-row snapshots. Runtime
  evidence is not a signature, actor attribution or permission from imported text.
- PER-17: skip only the pure LSASS matcher for an already-alerted existing key,
  after unchanged command/readability accounting. Preserve collection, identity
  gaps, health/counters, freshness, eviction, events and response scopes. Recheck
  negative commands. No native-query, benign-workload or wall-clock gain claimed.
- DBG-17: retain original beacon Popen/READY reader/cleanup worker/streams/primary
  handle through proved retirement; no snapshot wait/join, replacement overlap or
  production kill fallback. Continue after BrokenPipeError from stdin.close only
  if that same stream is closed, then require the unchanged wait/poll/reader/handle
  proofs and explicit closure of all streams. Generic/unclosed faults stay
  unresolved. Closed stdin does not prove authenticated stop-frame delivery.
  Intentional early detach remains; admitted graceful work cannot be unsent.
  Pipe I/O can block before finite waits, so total cleanup is NOT bounded; the
  startup READY five-second wait and heartbeat/instance locking remain.
- Test fixture: require live kernel-reported image admission, strict alias/PE/
  fingerprint checks and retained direct child handles. Terminal proof separately
  requires the same PID/raw FILETIME birth, WAIT0 and native exit agreement. A
  failed proof stays sticky after resource cleanup; cached Popen status cannot
  turn it into a pass. Test bootstrap explicitly supplies win32/win32/lib/Pythonwin
  and retains the pywin32_system32 DLL-directory handle. These are fixture-only
  changes; no unmodified production-launcher or unknown-descendant proof.
  The 12 private product controls and 38 fixture controls passed separately:
  a3738ecec2658723f5c0bc56296823f56c93e7bf95d7a5d6fe390c8b5cfdb740 / 3c26afc83e27b1e37f1bc136279e9175fe5ec8f48bcd8ee8f22d634534ee5e66.
- Actual R4: 34 suites, 491 function occurrences, 973 collected, 971 passed,
  zero failures/errors, two exact Windows availability skips; receipt
  78b36785802635147855f0cbc8ce1cba88cc35b483c0ebfb319547b97b773f29. Ledger 52fbfd2b117a64f8a87880a59eb2164f3aab3c4fab0e335add3be7c59d30ca1a; independent multiplicity counter
  3b1fb5396dc88316f56453600e351aefdf3cddf1d114bebf4debbe71c288ecde. All 75 privacy cases and seven named nested cases (including
  all five native beacon scenarios and their in-test retirement checks) passed.
  Exact independent outer attestation remains two generations: WAIT0/native0,
  four handles closed, MainThread/noQApp, source/HEAD/indices/runtime stable.
  This is not generalized independent attestation of every nested child.
- Only unavailable Windows 8.3 alias (Volume has no distinct short filename) and
  symlink creation (symlinks unavailable) skip. Acceptance is complete; coverage
  is not. Preserve precollection be111aa05ef19cc995ae0bbfe39b8b5892c47a766b02ef2ce8814dfb2225ddc1, R2 failed (944 passed / 1 failed / 4 setup errors / 2 skips)
  cf17c1f491117f540c0d73a2d8c3b60b96f4ba0d9c896628d8e19619529029c0, and R3 failed (944 passed / 1 failed / 4 setup errors / 2 skips) 38768982d0cd8d557b81c5c0636d831cd87086882931755ca1861e177d6a0b9e. R3 nested proof was absent,
  and its exact historical cleanup API cause stays UNKNOWN. A passing combined
  repair or isolated close mechanism cannot retroactively prove that cause.
- R4 tested pre-documentation inventory 87acb370d9e68a75244b29da3297c3496d3330dc22a3bc2dc2f68fc7b31d4f47; final
  documentation/source authority root-held final whole-source inventory after documentation review. New source cores are
  beacon 20c8dd1f / tests 22563b45 / fixture 47ea3f12; source 1876/Python 1164 and
  prospective 19 paths  = 11 code/test + 8 docs/two additions remain descriptors.
  Selfcheck ACCEPTED 29 phases / 0 failed, 18 module skips; ecd25a52f7731aeff24b071a2e68f1cbbbb5326ea9324586cfb6270fe65dc572; SpywareGuard 30 OBSERVED_WITH_GAPS 30.094s; 65a957fc5ff7d73e7ced9ae34b64b51f53ba6108b9b6d75fb4c72417c64fe58e; scanner 30-second
  OBSERVED 30.172s / 31 heartbeats; 840e5f87acecaec74b56ca8f8dfbcaa34f97953e3144f3c421906252f0b09fec; all-15 / 600-second OBSERVED_WITH_GAPS 600.312s / 1933 heartbeats / 369 events / 17 retained interval gap strings across nine modules; 42bc0a86bc8f3746c87aa82de109728e1a429c1294a7d7453da3bf22899c685f; offline REQUIRED after final documentation: fresh offline checks under root approval;
  publication REQUIRED after a reviewed completed commit: the unchanged canonical guarded publisher.
- PER-18 stays private-harness-only: 31 inert controls and one 8192-byte ABBA
  fixture, eight old requests 703.7053 ms/eight new 5.0245 ms. Root review
  8c3af5b0a8210e1be38ee58c734fc1c7e7a976ba1ea5668112062b0af97b388f. No product/whole-gate speed or earlier-failure cause.
- Registry 181 keeps all 176 prior raw issue objects/order/status and the original
  review_status unchanged under historical_review_status_before_spyware_lsass_beacon.
  New SEC-18/PER-17/DBG-17/PER-18/OBS-07 remain scoped; HOST-03/HOST-04, older
  failures, unknowns and gaps are not cleared. Broader 1.15 remains incomplete.


## 1.14.0 — AI broker authority and benchmark integrity

- SEC-17: refresh execution-enabled, finite-time and expiry checks after
  both broker waits, immediately before capability consumption and handler
  admission. Keep signed typed arguments, code custody and one-shot semantics.
  This LOW library/API finding has no current deployed broker consumer under src;
  it does not demonstrate a model-to-host response route. All 23 broker cases
  passed, including 14 new wait/race cases. Equality at expiry remains valid; no clock rollback,
  disable/re-enable epoch or atomic in-flight revocation guarantee is added.
- PER-16: repair the benchmark's stale list_processes fixture to supply the actual
  typed process_snapshot seam. Require complete reads/cohorts, latch guarded host
  access even when caught, and restore patched APIs/cache bindings/module entries.
  All seven functions/28 cases passed. This repairs measurement
  integrity, not production collectors; it proves no speed improvement. Use only
  a separate single-purpose interpreter. It is not a hostile-Python sandbox, and
  the optional CLI Git baseline retrieval remains outside the measured guard.
- Actual 15-suite/156-function gate: 254 collected, 253 passed, zero failures/errors
  and one exact Windows skip: Volume has no distinct short filename. Acceptance
  is complete, coverage is not. All 75 privacy cases remained passing; exact
  outer-two retirement and source/HEAD/both indices/runtime39 stability retained.
  A fresh 90.329 s passive 15-eligible/71-held observation completed with 17 gap
  strings across nine modules, 97 events and zero recorded errors/crashes/loss/
  pending threads. Exact outer/core retirement and frozen inputs were retained;
  this does not exercise real cloud/GUI privacy or prove host cleanliness/speed.
  Offline checks and guarded publication remain separate mandatory gates.
- Preserve all 174 earlier raw issue objects/order and prior review status; append
  SEC-17 and PER-16 for 176 unique IDs. Published 24ed22c privacy evidence
  (182 cases and 90.14 s) is historical and does not validate this later change.
  Development version remains v1.14.0; broader v1.15 remains incomplete.

## 1.14.0 — reviewed AI consultation privacy

- Prepare bounded sanitized system/user JSON before manual alert Research/SOAR
  consultation. Show provider/model/endpoints and eligible fallback order; require
  explicit Send for the initial request, retries and follow-ups. Editing invalidates
  the preview until re-sanitized. Bind submission/fallback to reviewed content,
  routes and exact credential binding; hold preparation/configuration failures.
- Reuse the shared sanitizer and retain cancellable provider workers through actual
  retirement. Redaction is best effort; GUI context gathering is still a latency
  candidate. No global computer-only setting, local-only toggle or universal AI deny.
- Preserve the actual first 182-case/180-pass/two-failure/zero-skip/native 1 cohort.
  Correct only the benign-text truncation fixture and strict migration fake; four
  production candidates remain unchanged. Repaired source passed 182 cases with
  zero failures/errors/skips across 12 suites, including 75 new cases and exact
  native retirement. A fresh 90.14 s passive 15-module observation retained 17
  coverage gaps across nine modules, 65 events and zero recorded errors/crashes/
  loss/pending threads. It does not test cloud/GUI requests or prove host cleanliness,
  redaction completeness or speed improvement.
- Add SEC-16 as effective resolution of SEC-15; all 173 prior raw issue objects/order
  and historical statuses remain unchanged. No real exfiltration, autonomous upload
  or authority bypass was demonstrated by the source finding.
- The published caf0 checkpoint and its 786/29/600 results remain historical.
  [Consultation privacy](docs/ai-consult-privacy.md) records scope and limitations.
  Version stays v1.14.0; broader v1.15 remains incomplete. Guarded publication is a
  separate mandatory gate, not a conclusion from test receipts.

## 1.14.0 — memory identity, private diagnostics and key integrity

- Bind executable-region metadata to the same retained Windows query handle.
  Partial, inconsistent or obsolete-owner evidence remains advisory; no memory
  contents, stronger VM rights or kernel inspection are added.
- Bound private Black Box exports in a retained cancellable worker, with redacted
  settings, explicit cap/cleanup gaps and create-only output. Preserve duplicate
  export and worker-retirement admission.
- Serialize protected-map updates and atomic first-key creation for seven
  consumers. Bridge migration fails closed, disabled mode avoids credential
  access, and the timestamp repair compares consistent path/descriptor clocks
  while retaining all custody/readback/cleanup holds. Explicit strong environment
  configuration remains supported.
- Linux first provisioning needs nonsecret absence proof and gdbus; native POSIX
  cases remain unavailable on Windows. SGX hints stay unverified, plain SQLite
  cannot report SQLCipher success, and helper/singleton key creation is locked.
- Current R5 passed 786 tests/zero failures with three exact POSIX skips across
  32 suites/451 functions. Acceptance is complete, coverage is not. Same-source
  selfcheck passed 29 phases: 68 module passes/18 explicit skips plus pipeline.
- Fresh SpywareGuard 30.203 s, scanner 30.079 s and 15-module 600.531 s observations
  completed. The combined run retained 17 coverage strings and 364 events, with
  zero recorded errors/crashes/loss/pending threads and exact outer/core retirement.
  It remains OBSERVED_WITH_GAPS; no host verdict, speed gain or all 86-sensor claim.
- Preserve all earlier failures, unknown R4 cause and open HOST-03/HOST-04.
  SEC-15 manual cloud-consult privacy remains open for a separate repair.
  See [scoped evidence](analysis/live-debug-2026-10-22/key-and-memory-review.md).
- Guarded GitHub publication is a separate mandatory gate; these receipts alone
  do not prove publication. The broader v1.15 integration remains incomplete.

## 1.14.0 — shared process inventory and measured worker CPU

- Enumerate public PIDs without unused cached iterator objects. Keep both fresh
  identity passes, parent-map bracket, collection bounds and 1.5-second freshness.
- Fourteen complete suites passed 452 tests with no failures, errors or skips.
  The default isolated self-check passed all 29 phases and reconciled 86 module
  rows: 68 passed and 18 explicitly skipped.
- A fresh 90.437-second run of 15 audited modules retired cleanly with 17 coverage
  gaps and no recorded errors or capture/export drops. Observed CPU was 55.59375
  seconds versus the earlier 52.46875; no speed gain is demonstrated.
- Add the sanitized worker CPU and interaction map. Preserve two optional
  profiler failures before scanning, all 162 earlier issue objects, open host
  findings and unknown historical causes. SpywareGuard’s guide now names its
  inclusion in v1.14.0. Current CI/publication require separate receipts.

## 1.14.0 — clearer live diagnostics

- Live Debug preserves the producer’s explicit `process_identity_complete` boolean
  in advisory views. Missing or malformed values stay unknown; original signed
  events and response authorization are unchanged.
- Publication staging failures expose bounded numeric `errno`/`winerror` codes
  without printing private filenames or raw OS error text. Copy/custody enforcement
  and the original private exception cause are retained.
- Twelve complete diagnostic/publication suites passed229 tests, with0 failures/errors and1 explicit Windows symlink skip (7a8884ab); both native interpreter generations retired cleanly. The initial 11 failures came from one new
  test fixture selecting the startup coverage row; that failed cohort is retained.
- The published e98ceaf snapshot completed a separate 90.282-second passive
  15-module run with no recorded crashes or dropped records and 17 coverage
  strings across nine modules. It remains OBSERVED_WITH_GAPS, not host assurance.
- One local publication staging failure was confirmed ENOSPC. Verified reversible
  cache offload provided limited headroom; disk health and older timeout causes
  remain open. HOST-03 and its native custody refusal remain unchanged.


## 1.14.0 — updater shared-deadline handoff

- Integrate the approved local5e4e5ba/remote14bc675 histories while retaining
  native inbox custody and HOST-03. UPD-06 clamps each transport handoff to the
  original scalar budget and rejects invalid worker budgets before child setup.
- The checksum and archive still share one absolute deadline; it is not reset
  per asset. Eleven deterministic cases cover rounding, elapsed/expired budget
  and malformed worker-budget rejection. Combined validation: 229 focused checks passed: 228 production cases and one actual native custody-refusal check, with no failures/errors/skips.
- The merged guide preserves remote historical CI/rerun claims and its unexplained
  staging-rename refusal. These are separate from the fresh combined-source gate.
  The earlier integration supervisor did not produce clean completion evidence;
  recovered exact source/index evidence is retained separately.
- HOST-03 remains open; the native validator and host ACL are unchanged. This
  does not bound metadata/filesystem/installer runtime, establish native install
  or restart health, close old timeout causes, or assert publication/CI success.

## 1.14.0 — verified updater integration and native custody

- Integrate the approved a156bdd/f848c01 histories and preserve both llms.txt
  additions. The local a156bdd checkpoint was not published independently.
- UPD-05 permits Windows servicing hardlinks only for canonical inbox PowerShell
  after native owner/DACL, ancestry and file-identity checks. Downloaded files,
  installed installer scripts and state retain strict single-link validation.
- Seven updater suites plus an actual read-only refusal check passed218 cases
  with exact process retirement. HOST-03 remains OPEN_NATIVE_OBSERVED: unsafe
  OS-volume-root permissions correctly hold installation. No host ACL changed.
- The detailed review retains the initial217/1 private expectation failure,
  diagnostic collection refusal, overlapping31-case capture, and a3 Python3.13
  timeout with cause UNKNOWN. Later archive/publication receipts have separate
  source scopes. No live UAC/install, source activation or restart health is claimed.

## 1.14.0 — Black Box admission and App Control observation

- Retain one firewall-detail dialog/query per Black Box tab, focus an existing
  dialog, hold replacement while its worker retires, and include detached
  retained workers during shutdown (SIDE-08). Four focused suites passed 41
  cases with actual Qt threads and inert providers; no PowerShell query or
  historical-watchdog cause is established.
- Admit only the reviewed normal App Control constructor in the isolated
  observation harness. Exact provider/key/checkpoint/correlator/cadence checks
  passed within 119 focused tests. Counts are 15 audited sensor paths, 71 held
  solos, 105 generated pairs and 123 eligible plan cases; plans are not observations.
- The single real App Control run completed 90.016 seconds as OBSERVED with 352
  samples, 44 scheduled module cycles and no events or recorded gaps/loss/crashes.
  Core and outer generations retired exactly. Policy presence and detection
  efficacy remain unknown; PER-07 whole-provider deadline/cancellation is OPEN.

The 41-case source snapshot is 1857/d68d; the 119-case gate and actual solo use
1857/0379. Their separate receipts retain exact scope and native retirement.
The preceding a3 checkpoint's unsigned archives retain the earlier 1857/60ee snapshot,
not current 0379 source; earlier 09c7 archives remain historical.
Published 36df CI ultimately passed 12/12 and Security 3/3, with 7757 passes/19 skips
on each Python version. At the prior 18:16:30 UTC snapshot, published a3 [CI](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39999282235)
currently retains a Python 3.13 failure:27 setup errors from one 45-second
preflight timeout, cause UNKNOWN. Python 3.10 passed 7795/19;3.11/3.12 were still
running in the 18:16:30 UTC snapshot on 23 October. Security 3/3 and eight non-Python jobs
passed. These hosted runs do not validate the later 0379 test snapshot.

Later terminal a3 proof records **11 of 12 CI jobs passed** and **Security 3/3**. Python 3.10/3.11/3.12 each passed 7795 tests with 19 skips; reported times were 1004.28/1437.24/1409.50 seconds. Python 3.13 retains 7768 passes,19 skips and 27 setup errors from the same single 45-second preflight; its cause remains UNKNOWN. This terminal proof supersedes the earlier partial status without rewriting that snapshot.

## 1.14.0 — prior focused maintenance review

- Replace Resolve Center's empty-list "Secure" claim with neutral wording that
  keeps exposures and protection readiness separate (GUI-19).
- Apply nonblocking Black Box detail-dialog shutdown while retaining a busy
  worker's owner and dialog result; six actual-QThread controls passed within
  the 148-test focused gate (SIDE-07). This does not identify the historical five-second UI-stall cause.
- Admit calendar-valid dated CISA alerts while retaining existing undated
  categories, URL restrictions, publication freshness and advisory-only output
  (NEWS-02). All 32 new offline cases passed within the focused gate; live CISA
  availability remains unproved.

Prior checkpoint [36dfadf](https://github.com/Ag3nt47/AngeronaSuite/commit/36dfadf1052e5a2e656afa52376b2f310a092446) is published on public main
with all seven README assets verified. Its unsigned archives describe the historical
09c7 source snapshot, not these changed-source files. Exact-head [CI](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39994972951)
and [Security](https://github.com/Ag3nt47/AngeronaSuite/actions/runs/39994972961) at 17:33 UTC on
23 October showed Security 3/3 and eight non-Python CI jobs passed; four Python
jobs were still running.

Validation: six full suites passed **148 tests**, no failures/errors/skips, with
exact interpreter retirement and MainThread/no QApplication/zero-widget shutdown.
The unchanged tested code snapshot is 1857/ae402; 09c7 packages are historical.
The held-thread queries are inert, CISA cases offline, and no PowerShell, network,
full regression, selfcheck, signed release or physical-protection proof is claimed.

A later lint scan flagged six F821 references in the new test callbacks. The
callbacks now use weak references; the six affected cases passed separately
with exact retirement. These cases overlap the 148-test cohort. Product code
is unchanged; the initial lint failure and original test receipt are retained.

## 1.14.0 — 2026-10-23 published maintenance

- Read shared HKCU Run/RunOnce keys once, retaining separate HKLM views and
  missing/denied coverage. Original R7 findings remain unadjudicated.
- Bind CVE analyses and cached proposals to exact current records and accepted
  request order. Preserve distinct duplicate rows and retain live or unknown
  workers through startup failure, close and asynchronous retirement.
- Reconcile source-conflict resolutions after process interruption only for the
  same explicit choice and verified owned bytes. Partial, changed, replaced or
  unowned candidates remain held. POSIX retry opens require nonblocking/no-follow
  flags and descriptor checks before stream construction; this does not prove
  power-loss recovery or a universal device-I/O deadline.
- Add bounded release-fixture operation tracing without changing checks or
  deadlines. The hosted 6ead Python 3.11 timeout cause remains UNKNOWN.
- Require lossless native receipt review; corrections are advisory artifacts
  separate from authenticated originals.

Validation: initial **214-test cohort**, final **54-test follow-up**, **1,152 AST
checks** and **29-phase default selfcheck** passed. The test cohorts overlap;
68 module rows passed and 18 were explicitly skipped. Exact retirement was
verified. A **90.140-second pair observation completed with coverage gaps** and
352 status/heartbeat samples; all four exported events had
response_authorized=false. This checkpoint was published as 36dfadf; the
publication proof is separate from the retained test and observation receipts.

The [issue review](analysis/live-debug-2026-10-22/README.md) and
[validation record](analysis/live-debug-2026-10-22/validation.json) retain earlier
results, failures and limits. See the [v1.14 feature notes](docs/releases/v1.14.0.md)
for the wider feature set. Source publication does not grant release trust,
installed enforcement or source-activation authority.
