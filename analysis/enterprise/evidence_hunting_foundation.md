# Normalized Evidence and Hunting Foundation

Angerona now has a versioned `angerona.evidence/1.0` envelope and a separate
bounded SQLite read model for local investigation. The existing FlightRecorder
remains the authoritative HMAC-authenticated alert ledger; the evidence store
does not replace or weaken it.

Guarantees:

- Local-origin ingestion is the default and remote evidence is rejected.
- Event normalization is deterministic and retains source-integrity provenance.
- Duplicate event IDs are idempotent.
- Age, row, envelope-size, query-result, predicate-count, membership-list, and
  candidate-scan limits are enforced.
- Hunting accepts typed fields and operators only. It never accepts or evaluates
  caller-provided SQL.
- The schema is explicitly named and versioned so later migrations can coexist.

Scale and product gates still open:

- Wire selected high-value producers after field mappings and privacy review.
- Add schema migrations before changing the 1.0 envelope.
- Add at-rest encryption and administrator-owned ACLs for managed deployments.
- Add retention classes/legal holds and disk-budget governance.
- Replace bounded JSON residual filtering with indexed columns or a purpose-built
  local analytics engine only after representative fleet benchmarks.
- Define signed export/import and per-device trust before enabling fleet ingest.
