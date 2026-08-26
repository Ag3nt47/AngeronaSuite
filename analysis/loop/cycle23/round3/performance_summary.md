# Cycle 23 Round 3 — Performance Summary

Date: 2026-08-26  
Scope: only the Round 3 `network.path_added`, authenticated pending-token
schema/migration, active-and-unchanged promotion, and bounded history changes.

No production or test code changed in this phase. The new work is bounded by
`MAX_LINKS = 64`, runs after the existing network observation/evaluation path,
and did not introduce a material hot path. The direct security-state logic was
therefore retained for reviewability: no collection, completeness, privacy,
authenticated-state, independent-freshness/CAS, promotion, history, or
observe-only check was cached, coalesced, reordered, or skipped.

## Measurements and decisions

### Pending-token membership set reuse — PROPOSED / NOT APPLIED

- **Component:** `NetworkTrustBaseline.__post_init__()` in
  `src/angerona/core/network_trust.py`.
- **Problem considered:** schema v2 validates that every pending token belongs
  to the bounded baseline. Reusing the path-token set would replace bounded
  list membership with set membership.
- **Measured current cost:** constructing a 64-path baseline took **23.256 us**
  with one pending path and **131.025 us** with all 64 paths pending.
- **Measured candidate kernel:** with one pending token, the candidate regressed
  from **9.351 us to 10.804 us (15.5% slower)**. At the artificial 64-pending
  bound it improved from **67.438 us to 21.460 us (68.2%)**, but saved only
  **45.978 us absolute** in a rare transitional state.
- **Decision:** not applied. The normal one-addition case gets slower, the
  maximum absolute saving is immaterial at the unchanged 30-second monitor
  cadence, and the present validation reads directly like the schema rule.
- **Status:** **PROPOSED** only if future profiles show sustained large pending
  sets; no current change is justified.

### One-pass drift/addition classification — PROPOSED / NOT APPLIED

- **Component:** `NetworkTrustMonitorModule._tick()` in
  `src/angerona/modules/network_trust_monitor.py`.
- **Problem considered:** the bounded finding tuple is queried separately for
  historical drift, explicit path addition, other drift, and pending addition
  tokens.
- **Measured candidate:** on an evaluator-produced 443-finding stress result
  containing one real `network.path_added` plus bounded drift across the other
  paths, the current direct predicates took **53.817 us** and the proposed
  one-pass accumulator took **56.166 us (4.4% slower)**. A separate synthetic
  no-drift scan can favor one pass, but only by tens of microseconds and the
  candidate loses the existing `any()` short-circuit behavior.
- **Decision:** not applied. There is no stable improvement across states, and
  the separate predicates keep the security transitions auditable.
- **Status:** **PROPOSED** only for reconsideration with production profile
  evidence; rejected for this round.

### End-to-end bounded evaluator — RETAINED

- A complete stable 64-path evaluation measured **3.113 ms median**.
- A complete 63-to-64 path-addition evaluation measured **2.817 ms median** and
  emitted exactly one privacy-safe `network.path_added` finding.
- These are pure evaluator costs at the declared maximum, before considering
  that the monitor polls every 30 seconds and Windows inventory process launch
  and I/O dominate the real tick. No cadence or evidence collection was
  reduced.

## Security invariants retained

- Explicit `network.path_added` evidence and privacy tokenization are unchanged.
- The schema-v2 authenticated pending set and conservative schema-v1 migration
  remain unchanged.
- Every pending path must be active and unchanged before promotion.
- Provisional/trusted transitions still require the authenticated revision gate
  and truthful independent-freshness/CAS state when an authority is injected.
- Incomplete collection, other drift, absent paths, failed persistence, and
  `MAX_LINKS` history eviction continue to fail closed.
- Endpoint trust and `response_authorized` remain false.

## Focused gates

- Changed-scope `py_compile`: **PASS** for the network core, monitor, and focused
  regression file.
- Ruff: **PASS** for the same three files.
- Focused network regression suite: **36 passed, 0 skipped, 0 failed**.
- Network core and Zero-Trust Network Path Monitor `self_test()`: **2 passed,
  0 failed**.
- Product/test change gate: **not applicable — no product or test code changed**.

| Optimization | Component | Status | Expected/measured win |
|---|---|---|---|
| Reuse path-token set for pending membership | Network baseline schema validation | PROPOSED | 45.978 us saved only at 64 pending; 15.5% slower with one pending |
| One-pass drift/addition classification | Network monitor transition logic | PROPOSED | 4.4% slower on evaluator-produced 443-finding stress state |
| Retain direct bounded implementation | Network evaluator and monitor | RETAINED | Stable 64-path evaluation 3.113 ms; add-path evaluation 2.817 ms |
