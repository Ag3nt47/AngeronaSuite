# Cycle 37 / Round 1 — final security reattack

Date: 2026-09-30. This read-only pass inspected the in-progress Shark artifact
custody patch, authenticated GUI archive reader, YARA scanner ownership change,
and Flight Cache eviction change. All adversarial file work used a disposable
temporary directory; no production data or response action was used.

## Candidate-fix checks

- The focused, independent archive/Shark/YARA suite passed **17/17**. It covered
  unsigned/changed history text, changed signed metadata, oversized and
  hardlinked archive members, copied signed pairs, pre-existing Shark marker
  names, hardlink names, replacement-file cleanup, exact owned cleanup, and a
  two-thread YARA activation check. This test briefly overlapped the
  maintainer's all-worker performance soak and is therefore functional
  evidence only, not independent performance evidence.
- Code review confirms Shark now creates through exclusive no-follow handles
  and cleans only an identity checked against the file created by that run.
  The stale-marker survey has entry, match, and read limits and no longer
  grants deletion authority from a filename or marker string. These targeted
  checks support candidate closure of **R37-01**, **R37-02**, and Shark's half
  of **R37-04**. The current patch intentionally retains swapped or uncertain
  files for operator review.
- YARA's live scanner is local to its run thread; temporary activation probes
  are destroyed on their creator threads. A new scanner after reload is built
  and replaces the old one on the run thread. The two-thread restart test
  passed. An independent instrumented run/reload/stop probe constructed four
  thread-tracking scanner stand-ins; **4/4** were destroyed on their creator
  thread and the worker stopped cleanly. The stand-ins exercise Python
  ownership flow, not the native YARA engine under a long live scan.
- Flight Cache's direct-ID eviction tracks only successfully inserted rows.
  The old subquery is gone; the change does not add a new cross-process trust
  boundary. Whole-host responsiveness remains a separate measured question.
- Ransomware Heuristics now reuses a byte histogram only for a complete,
  aligned entropy window; partial reads still take the original accumulation
  path. The focused test compares both paths' proof records and hashes. The
  optimization changes no response authorization or file-custody decision.

## R37-FR-01 — A replacement at a registered drill path is still classified as practice

**Severity:** MEDIUM. **Status:** REMEDIATED IN REVIEWED PATCH; FINAL GATE REQUIRED. **Components:**
`src/angerona/shark/shark_attack.py:_create_artifact`,
`src/angerona/core/practice_scope.py:134-166,244-273`, and
`src/angerona/core/threat.py:88-103,252-273`.

Practice provenance is keyed to the resolved pathname without the created
object's identity. `_create_artifact()` registers that name before completing
its write, and the run retains the registration for detection attribution.
`event_disposition()` consults practice provenance before an event's explicit
`active_attack` field. In a disposable Windows proof, I created a Shark marker
through `_write_bytes_artifact()`, renamed that owned object, and wrote inert
unrelated bytes at the original name. A `File Integrity Monitor` event for the
replacement with `active_attack=True` was classified **`practice`**. The new
`stop_and_clean()` correctly preserved the unrelated replacement; after it
revoked the run's registration, the same event classified **`active`**. This
proves the path-provenance classification gap without creating malware or
claiming a live detector was evaded.

An attacker needs local write/rename access to an operator-selected drill
directory and must race a live registration or reuse its name before expiry.
The event remains stored at its original severity, but active posture and
practice-aware correlation can be suppressed during that window. Bind practice
registration to the file ID and an appropriate change/content token captured
from the creation handle; require those tokens to match when a file-backed
detector classifies an event. Where the object has already moved or vanished,
use an exact signed drill receipt rather than trusting a reused path. Revoke
registrations promptly when cleanup or name identity fails. Keep explicit
`active_attack` evidence ahead of a weak practice classification.

## Signed archive-listing reattack

The first candidate history verifier coupled a signed `generated` timestamp
to an archive filename stamped only *after* journal validation and fsync. Its
five-second tolerance could reject a genuine report on a busy host. The
revised listing verifies each candidate's HMAC metadata before showing it,
sorts and labels by signed generation time, and deduplicates identical signed
`(run_id, report_text_sha256)` pairs. A copied old signed pair with a 2099
filename remained one old row in an independent disposable-file probe. A
newer forged unsigned archive could not appear as a verified row. The focused
archive tests passed **6/6**, including delayed genuine archive stamping and
tampered-text GUI rejection. In a separate offscreen probe, closing a visible
dialog while its history worker slept disabled result delivery and the shared
pool drained cleanly. These results support candidate closure of
**R37-03** and the GUI portion of **R37-04**.

The metadata cap was raised from 64 KiB to the producer's 16 MiB report
maximum after inspection found a **107,224-byte current-schema report** from a
disposable full GUI drill. With that run's own key, its HMAC verified, the
revised listing returned one signed row, and the selected archive yielded
28,824 authenticated report characters. An independent 73,331-byte signed
synthetic pair also listed and loaded. The listing now has a 2,048-entry
directory scan, 256 metadata-candidate limit, and 32 MiB total metadata-read
budget; a limit condition is surfaced in the GUI. Selected text is fully
verified before at most 524,288 characters are rendered with an explicit
shortening notice.

A local writer can still crowd an archive directory with many newer-named
unsigned files so a bounded scan misses an older valid pair. With the
candidate cap lowered to three for a disposable proof, three forged names
hid one genuine row, but the result flagged `limited=True` and showed no
forged text. This is an availability limit with an explicit UI indication,
not a passing-score forgery. The normal archive writer prunes its own history;
an independently writable/flooded history directory remains a local trust
boundary.

## Coordinator's completed provenance remediation

The interrupted agent work was completed and retested by the coordinator.
Artifact registration now captures a held file ID and SHA-256 of completed
bytes; marker creation no longer pre-registers an empty pathname or re-registers
an arbitrary path from a later step record. File-backed practice classification
requires detector-observed identity and content digest. FIM derives them from
its exact scan custody even without a Red Team lease; YARA derives them from
its held scan descriptor. Every stated path must match the same live record.

The final focused tests reject a byte-identical replacement with a different
file ID, an in-place overwrite, and both temporal swap-back cases. Restoring
the original marker before classification cannot bless the earlier replacement
event. Path-only or mixed-resource claims fail closed before run-ID fallback.
An exact prior benign observation can remain practice after quarantine while
the registry remains live; a current pathname lookup is no longer treated as
proof of an earlier event. Defender-only file evidence and cleanup deletions
without observed identity remain active, a conservative false-positive tradeoff.

Windows registration hashes through the already-held readable creation
descriptor, avoiding a sharing violation on delete-capable marker handles.
FIM readers separately share deletion while preserving no-follow and stable
identity/hash checks. A bounded small-scan disappearance retry preserves the
existing signed receipt schema and incomplete-coverage refusal.

The provenance/Shark/producer/YARA set passed 57 tests with three platform
skips; the final FIM custody/cancellation/baseline/churn/native-receipt set
passed 22/22. The completed-patch FIM-enabled GUI/OS-witness probe passed 2/2,
with 37/37 verified containment in each run and 34/37 and 11/37 native
observations. These coordinator gates supplement the earlier independent
reattack; they do not represent an external penetration test or certify
all native opportunities. Exact-commit validation and publication are separate.

Prior baseline finding count verified from `PRIOR_FINDINGS.md`: **4 closed or
mitigated to a staged-only path, 4 retained open/mitigated boundaries** among
its eight core entries. The current pass did not reclassify those boundaries.
