# Cycle 5 — Shark/Red Team Enterprise Evidence Contract

## Decision

This pass adds a versioned, fail-closed safety and evidence contract around
Angerona's existing marker-only Shark and Red Team drills. It deliberately does
not add offensive execution. The upgrade makes a drill request bounded before
work begins, gives every run and step a durable identity, records the realized
ATT&CK-mapped campaign, fingerprints drill-owned artifacts, and prevents an
altered ground-truth file from being turned into a trusted After-Action Report.

The highest-value gap was not another simulated technique. It was provenance:
`shark_history.json` and `redteam_history.json` were mutable JSON inputs. An
altered history could be compared against telemetry and then authenticated only
at the derived AAR layer. That weakened remediation evidence and reproducibility.

## Why this closes an enterprise gap

- MITRE CALDERA exports operation reports and event logs containing per-step
  identity, timestamps, status, ATT&CK metadata, and operation metadata. This is
  the useful interoperability shape Angerona now approximates while remaining
  local and marker-only:
  [MITRE CALDERA — Operation Results](https://caldera.readthedocs.io/en/stable/Operation-Results.html).
- Invoke-AtomicRedTeam documents both execution logging and cleanup. Its
  continuous-testing guidance correlates executions by a test GUID and performs
  cleanup after each test. Angerona now binds steps to a run identifier and
  keeps its existing cleanup contract:
  [Continuous Atomic Testing](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Continuous-Atomic-Testing) and
  [Cleanup After Executing Atomic Tests](https://github.com/redcanaryco/invoke-atomicredteam/wiki/Cleanup-After-Executing-Atomic-Tests).
- ATT&CK v18 replaced technique-level detections with Detection Strategies and
  Analytics and extended its STIX model. Explicit technique identifiers and a
  versioned campaign manifest give Angerona a stable migration point for that
  newer defensive model:
  [MITRE ATT&CK v18 — October 2025 updates](https://attack.mitre.org/resources/updates/updates-october-2025/).

## Shipped controls

### Pre-execution safety gate

`run_manifest.preflight_run()` validates a request before a worker thread,
marker, process, or history file is created. It rejects:

- more than four cycles;
- invalid or over-60-second jitter;
- invalid noise probabilities;
- custom names over 128 characters;
- custom inert text over 16 KiB or invalid UTF-8; and
- filesystem roots, UNC/network shares, and Windows device paths as marker
  targets; and
- projected step, artifact, or process counts over fixed safety budgets.

The preflight record stores only the length and SHA-256 of custom marker text,
not its body. It likewise stores only the target folder name and a path digest,
not the full path. The engine retains the validated body only in memory long
enough to create the operator-requested inert marker.

### Versioned ground truth

Every completed or cancelled run now records:

- schema and safety-contract versions;
- run status and run-bound deterministic step IDs;
- ATT&CK technique IDs parsed from the existing benign technique labels;
- the requested campaign digest and realized plan digest;
- actual step/artifact/process usage against the safety budget; and
- bounded artifact receipts containing basename, size, status, and SHA-256.

Artifact content is never copied into the manifest. Files larger than 16 MiB,
symlinks, missing files, and unreadable files are described but not followed or
hashed.

### Tamper-evident evidence and fail-closed reporting

Step records and artifact receipts form a SHA-256 chain, and the complete
history is HMAC-SHA256-attested with Angerona's existing per-install bus key.
Writes use a same-directory temporary file followed by atomic replacement.

`aar_report.generate_aar()` now verifies schema, HMAC, run/step binding,
evidence chain, campaign consistency, and safety usage before it queries the
flight recorder. Invalid or unauthenticated ground truth produces a clear
integrity error and no AAR.

Older unsigned histories are rejected by default. A reviewed compatibility
workflow can temporarily set `ANGERONA_ALLOW_UNSIGNED_DRILL_HISTORY=1`; this
weakens provenance and must not be used for remediation evidence.

## Files

- `src/angerona/shark/run_manifest.py` — safety preflight, schema, evidence
  receipts, hash chain, HMAC attestation, bounded atomic I/O, and verification.
- `src/angerona/shark/shark_attack.py` — Shark preflight and trusted history.
- `src/angerona/shark/red_team.py` — Red Team preflight and trusted history.
- `src/angerona/shark/aar_report.py` — fail-closed ground-truth ingestion.
- `src/angerona/modules/evolution_engine.py` — verified-history-only fallback for
  detection-rule synthesis.
- `tests/test_cycle5_shark_enterprise_contract.py` — boundary, privacy,
  provenance, tamper, compatibility, no-side-effect rejection, and
  Evolution-poisoning tests.

## Safety and privacy properties

- Defensive-only: no exploit, credential access, persistence, bypass, destructive
  action, arbitrary command, or real-data exfiltration was added.
- Local-only: the evidence contract performs no network request.
- Reversible: existing drill cleanup remains responsible for drill-owned
  artifacts; this layer only observes and records them.
- Bounded: input, work projection, file hashing, history size, and history
  loading all have explicit limits.
- Private custom text is not retained in the ground-truth contract.

## Verification

- `python -m py_compile` passed for all four changed runtime modules and the new
  test file.
- New enterprise-contract tests: **9 passed**.
- Existing policy/drill-resolution, purple-remediation end-to-end, and Cycle 4
  purple tests: **12 passed**.

## Residual limits and next safe increments

- HMAC attestation is an application/process trust boundary, not TPM-backed or
  independently witnessed chain of custody. Code that can read the bus key can
  forge a history.
- If the bus key is unavailable, history is retained for diagnostics but is
  unsigned and therefore rejected by the AAR path.
- A detector or SOAR action may quarantine a marker before its receipt is
  collected; that becomes a truthful `missing` receipt rather than a false hash.
- This records the realized randomized plan, but it does not yet implement
  seeded deterministic replay.
- Evolution's drill-history fallback now calls `load_verified_history()`.
  Unsigned or altered ground truth is ignored and cannot influence generated
  detection rules.
- A later, reviewed upgrade can map current steps to ATT&CK v18 Detection
  Strategies/Analytics via versioned STIX data. That should remain a pure
  metadata/import feature and must not expand drill execution.
