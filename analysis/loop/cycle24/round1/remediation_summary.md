# Cycle 24 Round 1 — Remediation Summary

Scope: assigned findings R1-03 through R1-07, R1-09, and R1-10 only. No
release-installer, recovery-assurance, documentation, version, manual, or
screenshot work was performed by this remediation pass.

## R1-03 — FIXED

- `src/angerona/core/response_capability.py`: capability v2 binds tokens to an
  unpredictable per-process epoch; production readiness now requires an
  authenticated durable state file and OS-exclusive lease; issue and consume
  high-water values are persisted before a token/action can return. A separate
  authenticated enrollment anchor makes ordinary state deletion fail closed.
- `src/angerona/core/file_lease.py`: added the small non-blocking Windows/POSIX
  singleton lease shared by the security authorities.
- Regression coverage: consumed-token replay after restart, concurrent writer,
  and deleted-state restart.
- Gates: compile PASS; 17 focused capability/service tests PASS; Ruff PASS.
- Residual: same-host files and a freshly rotated epoch cannot authoritatively
  detect deletion of both state and anchor or a live-memory/whole-machine
  snapshot. TPM NV or a separately administered witness remains required for
  that threat model.

## R1-04 — FIXED

- `tools/personal_sentinel_server.py`: production provisioning now accepts only
  a client Ed25519 public request-verification key and an appliance-held
  Ed25519 private response/state key. The monitored host needs only the pinned
  authority public verifier. Symmetric HMAC is accepted only with the explicit
  loopback test switch and test-only environment gate.
- Regression coverage: PEM signer/verify-only separation and production/test
  argument boundaries.
- Gates: compile PASS; included in 26 Sentinel/server/time tests PASS; Ruff PASS.

## R1-05 — FIXED

- `src/angerona/core/personal_sentinel_authority.py`: every authority instance
  holds an OS-exclusive lifetime lease; state transactions remain under the
  process lock and cannot fork through a second process. State now carries a
  signed generation and supports an injected `SentinelGenerationFloor` atomic
  compare-and-advance contract for TPM, WORM, or a second witness.
- The public `rollback_assurance` value distinguishes
  `external-generation-floor` from `local-signed-state-only`; the production
  CLI prints the remaining full-appliance-snapshot limitation.
- Regression coverage: second live authority rejection and restoration of an
  older validly signed snapshot against an external floor.
- Gates: compile PASS; included in 26 Sentinel/server/time tests PASS; self-test
  PASS; Ruff PASS.
- Residual: without an injected hardware/independent floor, local signatures
  detect tampering but not restoration of the whole appliance snapshot. The
  code does not manufacture an external-custody claim.

## R1-06 — FIXED

- `tools/personal_sentinel_server.py`: the listening socket remains raw;
  handshakes execute in a separately bounded 16-slot pre-authentication thread
  pool with a three-second timeout before entering the bounded request-worker
  pool. One stalled ClientHello no longer blocks `accept()`.
- Production now requires mutual TLS and a client CA rather than treating mTLS
  as optional.
- Regression coverage: a stalled fake TLS peer while a second peer reaches
  authenticated dispatch within its deadline; mandatory client-CA parsing.
- Gates: compile PASS; included in 26 Sentinel/server/time tests PASS; Ruff PASS.

## R1-07 — FIXED

- `src/angerona/core/trusted_time.py`: independent freshness requires an exact
  caller-supplied unpredictable challenge plus a durable sequence/time floor;
  detached valid receipts are labelled `historical-witness`, not fresh.
- `src/angerona/core/personal_sentinel_authority.py`: production HTTPS clients
  fail closed without an injected durable `SentinelResponseFloor`; test-only
  in-process transport remains explicitly exempt and cannot claim TLS.
- Regression coverage: captured receipt, wrong challenge, sequence replay,
  production client without a floor, and valid floor advancement.
- Gates: compile PASS; included in 26 Sentinel/server/time tests PASS; trusted-
  time and Sentinel self-tests PASS; Ruff PASS.

## R1-09 — FIXED

- `src/angerona/modules/driver_provenance_guard.py`: the fixed PowerShell query
  reports exact total count separately from its 256 retained rows. Python
  validates count/truncation consistency, marks overflow incomplete, and emits
  reported/observed/omitted counts. The performance agent's server-side CIM
  filter and list construction are preserved.
- Regression coverage: 257 running drivers with the high-sorting final row
  omitted cannot produce complete coverage.
- Gates: compile PASS; included in 33 driver/temporal/identity tests PASS;
  driver self-test PASS; Ruff PASS.
- Residual: visible rows still appraise current on-disk files rather than a
  cryptographically bound kernel load identity; the result remains observe-only.

## R1-10 — FIXED

- `src/angerona/core/temporal_tradecraft.py` and
  `src/angerona/core/identity_session.py`: EventBus HMAC is no longer promoted
  to producer authentication. Grades are `broker-provenanced`,
  `schema-admitted-local`, or `unprovenanced`; non-broker findings are capped at
  Medium.
- `src/angerona/modules/temporal_tradecraft_correlator.py` and
  `src/angerona/modules/identity_session_guard.py`: fixed producer/schema maps
  reject arbitrary module labels. When present, `SensorProvenanceBroker`
  envelopes bind broker-assigned producer identity, event type, sequence, loss,
  and continuity before High/Critical confidence is retained.
- Regression coverage: arbitrary producer rejection, local confidence caps,
  and successful real broker-envelope chains for temporal and identity paths.
- Gates: compile PASS; included in 33 driver/temporal/identity tests PASS;
  temporal and identity self-tests PASS; Ruff PASS.
- Residual: the broker remains an in-memory privilege-separation primitive
  until the application injects protected producer credentials and lifecycle.

## Gate roll-up

- `py_compile`: PASS for every changed product/helper file.
- Ruff: PASS for every changed product/helper/test file.
- Focused tests: 17 + 26 + 33 = **76 passed**.
- Self-tests: Personal Sentinel, trusted time, driver provenance, temporal
  correlator, and identity/session guard: **5 passed**.
- `git diff --check` on the remediation-owned paths: PASS.

Focused pytest runs used `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1` after unrelated
parallel host/plugin startup contention; no test semantics, product controls,
or assertions were disabled.
