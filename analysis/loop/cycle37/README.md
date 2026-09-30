# Cycle 37 — running-mode performance, drill custody, and truthful report history

Date: 2026-09-30. Maintenance follow-up to public baseline `795cc55` on
the v1.13.0 line. The 84-module catalog is unchanged.

## Applied changes

- Shark marker and ZIP creation is exclusive, no-follow, single-link, and
  bound to the object created by the run. Existing files are refused. Windows
  cleanup deletes through a verified held handle; ambiguous replacements are
  retained. Portable POSIX cleanup retains objects for review where an atomic
  exact-object deletion is unavailable. Old-marker surveys and scratch work
  have explicit entry, candidate, and byte bounds.
- Practice file provenance now binds the created file ID and completed-byte
  SHA-256. FIM and YARA attach the identity and digest actually observed by
  the detector. A same-name replacement, byte-identical copy with a different
  file ID, in-place content overwrite, or temporal swap-back cannot inherit
  practice classification. Every supplied file resource must match the same
  registration. Path-only evidence remains active even if it claims a run ID.
  An exact earlier benign observation remains attributable after quarantine;
  looking up the current pathname cannot prove an earlier event's identity.
- FIM's Windows read handles share read/write/delete with response custody,
  preserving no-follow and stable-identity/hash checks. This avoids denying
  native inspection merely because response retains a delete-capable handle.
  One small snapshot may retry after confirmed leaf disappearance: at most
  256 visited files and 16 MiB content, with a cancelable 50 ms wait. Permission,
  link, root, and other failures do not receive this retry. A partial first
  snapshot earns no complete-coverage credit; the signed receipt schema and
  native validation requirements are unchanged.
- YARA-X scanners remain local to their creator/run thread across activation,
  rules reload, stop, and restart. The real all-worker run had exposed an
  unsendable-scanner destruction error before this change.
- History listing verifies HMAC metadata, sorts by signed generation time,
  and deduplicates signed run/digest pairs. Selected text appears only after
  its digest verifies. Work runs off Qt with coalesced requests and visible
  pending, verified, failed, and scan-limit states. Limits are 2,048 directory
  entries, 256 metadata candidates, 32 MiB total metadata, and the producer's
  16 MiB per-member maximum. Rendering stops at 524,288 characters only after
  full verification, with an explicit notice. Legacy metadata lacking a signed
  text digest cannot authenticate the text and is excluded.
- Flight Cache evicts the known oldest successfully inserted ID directly.
  Its paired full-cache median improved from 61.5 to 28.0 microseconds/event.
  The module panel reuses one current usage-policy result per row; its
  84-row policy projection improved from 3.372 to 1.085 ms. Ransomware content
  sampling reuses the histogram of an exact full 64 KiB window; the paired
  1 MiB proof CPU median improved from 0.359 to 0.172 seconds with identical
  proof fields and digests. These are component benchmarks.

## Additional verification

The completed-patch FIM-enabled offscreen operator clickthrough passed both
launches and its negative OS-witness control: **2/2 tests** in 124.69 seconds.
Each launch completed **38/38 steps** with **37/37 signed verified simulation
containment responses**. Native analytic detections were **34/37** and
**11/37** overall; the plan provides 36 FIM file-marker opportunities plus
one process observation-only step. These counts are inert-drill observations,
not real-attack efficacy or a claim of complete native coverage.

A separate process checked all **36** source-marker removals and quarantine
SHA-256 matches in each launch, plus three tagged process exits with captured
birth identities. The independent negative control rejects an uncontained
marker. The two runs took 59.547 and 57.906 seconds; response latency remains
a concern even when final containment verifies.

Earlier FIM-enabled attempts failed the positive-native-observation assertion
with zero native credit while containment still verified. The traces exposed
incomplete scans during file churn. Intermediate patch checks also caught
Windows marker-hash handle sharing and a receipt-schema mismatch; both were
corrected before the completed-patch run. No scoring assertion, detector
completeness rule, or product deadline was relaxed.

The focused provenance/Shark/producer/YARA set passed **57 tests / 3 platform
skips** before the final FIM read-handle change. The FIM custody, cancellation,
approved-baseline, churn-retry, and exact native-receipt set then passed
**22/22**. History and module-panel checks passed **19/19**. The earlier
isolated package selfcheck passed 26/26 phases, with 67 module passes and 18
explicit platform/inactive skips. Concurrent all-worker selfchecks failed
existing deadlines and are retained in the [bug report](round1/bugtest_results.md).
These targeted checks do not replace the final whole-tree release gate.

## Whole-application performance

The production-recorder 66-worker instrumented baseline reproduced a
**7,761 ms** Full-mode Qt heartbeat slip and **18** gaps over one second.
The longest gap was outside the timed refresh callback. The initial-Chill
baseline also overlapped pytest and is not a clean performance comparison.
The post-change soak adds an independent minimal Qt heartbeat process to
distinguish host scheduling from Angerona's process. Its result is recorded
in the [performance analysis](round1/performance_summary.md).

The completed-code repeat measured maximum slips of **1480 / 527 / 1074 ms**
in Chill / Full / returned Chill, with **1 / 0 / 2** gaps over one second.
The separate Qt process peaked at **43 ms**. All **1079/1079** accepted events
persisted and drained. Full improved in this run, but Chill pauses and high
CPU remain unresolved; component optimizations do not establish a whole-app
CPU reduction or sustained stability.

The fixture scopes FIM/YARA and persistent data to disposable directories and
excludes USB registry enforcement, synthetic canary/deception workers, a
priority governor, and the evolution writer. It exercises 66 selected real
workers, not every host-mutating feature, physical-display operation, or an
all-day run. A clean short soak cannot certify those longer conditions.

## Release requirements

The first exact-commit gate passed **4400 tests, 23 skips**, bytecode, lint,
and documentation checks. Dependency auditing first encountered HTTP 503;
its retry found 15 reported vulnerabilities in PyJWT 2.13.0 and urllib3
2.7.0. The follow-up upgrades verified universal wheels to PyJWT 2.15.0 and
urllib3 2.8.0, raises source-install floors, and refreshes Windows/POSIX pins,
hashes and artifact manifests. Wheel bytes were checked against PyPI metadata.

The follow-up also bounds Storage Hygiene's recursive inspection to 2048
entries and a one-second traversal budget, avoiding whole-directory lists.
An exhausted budget reports unavailable coverage and health 30; it never
reports a clean tree or enables mutation. Individual OS metadata calls can
still block beyond the traversal deadline. Targeted storage/security checks
passed **35/35** after retaining the existing reparse inspection boundary.
This change has not yet been repeated in the 66-worker soak above and has no
claimed whole-application speedup. The combined tree requires a fresh gate.

The final reviewed commit must pass the fixed bytecode, dependency-audit,
documentation-drift, lint, and full pytest gate. GitHub completion is proved
by `tools/publish_github_update.py`, including canonical HTTPS origin,
fast-forward public main and working-branch equality, a clean worktree, and
byte-identical public README images. Targeted results in this record are
distinct from that exact-commit evidence and publication proof.

Detailed records: [bugs](round1/bugtest_results.md),
[performance](round1/performance_summary.md),
[original security findings](round1/redteam_findings.md), and
[security reattack](round1/security_final_reattack.md).
