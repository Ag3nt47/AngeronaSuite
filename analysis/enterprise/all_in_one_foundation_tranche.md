# All-in-One Local Security Platform — Foundation Tranche

## Outcome

This tranche implements three reusable, offline-first foundations without
overstating enterprise readiness:

1. normalized local evidence and bounded hunting;
2. detection-as-code package contracts; and
3. explainable exposure prioritization and recovery planning.

## Implemented

`src/angerona/core/evidence_store.py` provides a versioned SQLite schema,
deterministic Event normalization, retention and query bounds, and typed hunt
predicates. It exposes no arbitrary SQL interface. It is deliberately not
subscribed synchronously to EventBus: database work on producer threads could
recreate Angerona's long-running slowdown. Production integration requires a
bounded asynchronous ingest queue, backpressure metrics, batching, and shutdown
draining.

`src/angerona/core/detection_packages.py` and `detection-packages/` define
digest-verified JSON detection packages with ownership, versioning, telemetry
requirements, ATT&CK mapping, fixtures, expiry, rollback, severity/confidence,
and performance budgets. The loader rejects oversized or malformed content and
does not execute package-supplied code.

`src/angerona/core/exposure_recovery.py` provides deterministic exposure scoring
with auditable factors and typed recovery plans. Plans must define
prerequisites, verification, and rollback. The model is planning-only and
rejects execution authorization so it cannot silently make host changes.

## Verification

- Focused enterprise-foundation tests: 14 passed.
- Full repository suite: 237 passed, 2 intentional platform skips, 0 failed.
- Compile gate: 236 of 236 Python files.
- Cycle 6 discovery: 65 modules, 0 errors.
- Cycle 6 headless self-check: 26 of 26.

## Remaining enterprise gates

- bounded asynchronous evidence ingestion and a hunt/case UI;
- signed detection distribution, trust roots, revocation, and promotion rings;
- real asset, software, identity, and exposure collectors;
- fleet identity, tenant isolation, RBAC, and audit export;
- separately privileged, transactional WFP containment broker;
- recovery execution with approvals and independently tested rollback;
- signed installer/updater, SBOM, provenance, reproducible builds, and external
  compatibility/security validation.

These gates are the controls that separate a strong local suite from a
supportable enterprise security product.
