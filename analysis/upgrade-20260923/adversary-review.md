# Adversarial review of the September 23 upgrade

Scope: shared process collection, YARA scanning and native receipts, Combat content binding,
alert retention, detached-engine IPC, and configured AI-agent file integrity. Review uses
inert fixtures only. It does not claim an exhaustive security assessment or long-duration
performance evidence. Findings below were sent to the implementing agents; their final
fixes require the release validation pass.

## Confirmed findings

1. **Known YARA detections discarded by archive errors (high detection impact).** A stored
   ZIP containing an inert matching signature and 128 additional empty members produced a
   positive result from the actual YARA-X engine, but `_scan_file` returned `failed` and
   published zero findings because the archive member limit was exceeded. Encryption,
   CRC errors, and incomplete archive inspection must not erase already verified outer-file
   or previously inspected member matches. Preserve positives while reporting incomplete
   coverage and withholding a clean scan-cache entry. Root reports this remediation landed.

2. **ZIP metadata allocated before the member cap (resource exhaustion).** `ZipFile`
   eagerly materializes its central directory before `len(infolist())` is checked. A
   1,720,022-byte inert archive with 20,000 empty entries allocated 11,128,012 traced bytes
   and took 1.915 seconds under tracemalloc before the 128-member cap could run. These are
   instrumented parser measurements, not whole-application performance results. Root added
   a bounded EOCD/central-directory preflight before constructing `ZipFile`; positive
   outer-file signature inspection remains separate from archive coverage.

3. **Retention repeatedly scanned only the same directory prefix (unbounded growth).**
   The original maintenance pass counted unrelated entries against `MAX_ENTRIES` and
   restarted at the beginning. In an isolated native fixture with the limit reduced to
   three, five unrelated files preceding one expired managed archive prevented deletion
   in three consecutive passes. Reports showed `incomplete`, but observed managed bytes
   remained zero. The production limit was 1024. The retention agent reports a bounded
   progress fix; regression must prove eventual consideration of later managed archives.

4. **Unicode event pages exceeded the IPC response limit (telemetry availability).**
   Two hundred valid events with 1000 non-BMP characters each produced 2,418,547 canonical
   JSON bytes, exceeding the 1,048,576-byte transport limit. Sending failed before the
   client received its next cursor; retries requested the same oversized page. Page by
   encoded bytes including the authenticated envelope, preserve revision order, and report
   truncation/loss explicitly. The protection graph itself continued independently.

5. **POSIX agent guards did not hold immutable approved bytes (authorization race).**
   The reused POSIX file helper only opens a read descriptor; the directory helper only
   validates paths before yielding. Neither prevents another process with write access
   to an enrolled agent file from replacing or modifying it after hashing while the
   integrated tool executes. Windows write/delete-sharing denial provides a stronger
   boundary. Configure tool enforcement to fail closed where that custody cannot be
   provided, or make the integrated consumer use an immutable approved snapshot. Checking
   after a mutating tool returns cannot undo an already executed action. This finding is
   based on the concrete POSIX helper implementations; no native Linux/macOS claim is made.

6. **Same-session signed baseline rollback accepted (approval replay).** Native inert
   test: approve generation 1, explicitly accept generation 2, restore the generation-1
   signed manifest and old file bytes, then call `verify()` on the *same* store object.
   It returned `approved`. No key knowledge, marker deletion, or Angerona code modification
   was required. Track the highest accepted generation and its canonical digest within
   each live store. Full process/state rollback still needs an independent authority;
   local HMAC alone cannot prove historical freshness.

7. **Windows 8.3 aliases bypassed runtime-authority exclusion (scope validation).** An
   inert file inside the forbidden Angerona runtime root was successfully enrolled through
   `GetShortPathName`, although its ordinary long path was forbidden. Path-derived target
   IDs also allowed aliases for one physical file. Canonicalize final long-path identity
   under no-follow custody or reject ambiguous spellings. Do not resolve and silently
   accept junctions or symbolic links.

8. **Windows path/descriptor ctime mismatch (availability regression, repaired).** Forty-
   three of 100 freshly written inert files had differing `Path.stat().st_ctime_ns` and
   `os.fstat().st_ctime_ns` while their device, inode, size, mtime, and link count agreed.
   This caused real scans to be rejected before inspection. Root replaced the cross-API
   ctime comparison with the native held-handle change token and added restored-mtime
   protection. The final targeted AAR/process regression batch passed 83 tests.

## Properties checked and remaining boundaries

- Shark native credit requires the exact currently registered built-in YARA producer,
  matching manager/bus/recorder graph, current lifecycle generation, and the producer's
  actual immutable event digest receipt. Signed fabricated native fields, replacement
  objects, instance verifier overrides, mutated/re-signed events, and old generations
  received no native credit in the new tests. Red Team retains its independent live lease.
- YARA receipts retain at most 4096 records. Expiry/eviction or restart means historical
  native proof may be unavailable; report refresh cannot manufacture replacement proof.
- Combat hashes the held single-link file before moving it and compares the detector's
  observed outer-file digest. Existing delegation copies the digest. The comparison is
  additive for legacy producers; it is not a claim that every old detector supplies it.
- Retention uses a narrow managed filename grammar, single-link checks, anchored parent
  custody, an authority lease, and Windows handle-based deletion. Pins and inaccessible
  files can keep usage above the target; this must remain visible rather than claiming a
  hard storage ceiling. Signed ledgers and response/recovery evidence are excluded.
- IPC uses bounded JSON, duplicate-key rejection, fresh challenges, directional HMACs,
  exact instances, PID birth checks, four exchange slots, and a closed operation catalog.
  It is an ordinary-user boundary, not protection against compromise of that same user's
  credential store. Unauthenticated local clients can still contend for bounded exchange
  slots; this does not grant control authority or stop independent protection workers.
- Shared process snapshots preserve explicit loss, immutable rich metadata, current PID
  birth checks, and force-refresh support. The incompatible lossy connection snapshot was
  not substituted into WFP ownership collection.
