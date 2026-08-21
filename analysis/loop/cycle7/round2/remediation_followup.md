# Cycle 7 Round 2 — Bug Remediation Follow-up

Date: 2026-08-20

Scope: C7-BT-02 and C7-BT-04 from the Cycle 7 Round 1 bug-test report.
No unrelated product behavior was changed in this follow-up.

## C7-BT-02 — FIXED: Windows Fleet handler shutdown race

The loopback Fleet service now makes shutdown and handler registration one
atomic lifecycle decision. Once shutdown begins, newly accepted sockets cannot
enter handler setup; already registered handlers receive a service-owned stop
event. Request reads use a deadline-preserving, shutdown-aware socket reader,
so Windows no longer has to cancel a blocked `socket.makefile()` read from a
different thread. Handler accounting is idempotent, and the replay ledger is
closed only after the accept thread and every handler have drained.

The related saturation regression was also corrected. Before returning 503,
the server drains one bounded request header. This prevents Windows from
replacing the HTTP response with WinError 10053 when a socket is closed with
unread inbound request bytes.

Adversarial gates:

- original stalled partial-body shutdown: **25/25 isolated repetitions PASS**;
- bounded saturation rejection/recovery: **20/20 isolated repetitions PASS**;
- new partial-request drain plus replay-handle release: **15 internal
  repetitions PASS**;
- new deliberately paused handler-setup race: **10 internal repetitions PASS**;
- nonce replay survived a forced partial-request shutdown and service restart;
- the SQLite replay file was movable immediately after every successful stop,
  proving its Windows handle was released.

## C7-BT-04 — FIXED: legacy manual write paths

All four documented manually runnable legacy engine paths now default to the
canonical Angerona runtime root:

- Unified Defense Engine writes `edr_status.json` under `data_dir()`;
- the optional Unified EDR viewer reads that same canonical status file;
- the flight recorder writes `ude_telemetry.db` under `data_dir()`;
- Defense Monitor stages unique incident payloads under
  `runtime_temp_dir()` and removes each payload in `finally`.

An explicit absolute `EDR_FLIGHT_DB` operator override remains supported. A
relative override is contained beneath `data_dir()` instead of resolving from
the process working directory. The two formerly standard-library-only manual
entry points bootstrap the known source `src` root when executed directly from
a checkout, preserving their standalone workflow.

## Changed files

- `src/angerona/core/fleet_service.py`
- `src/angerona/engines/unified_defense_engine.py`
- `src/angerona/engines/unified_edr.py`
- `src/angerona/engines/persistence.py`
- `src/angerona/engines/defense_monitor.py`
- `tests/test_cycle7_round2_fleet_remediation.py`

## Verification

- Python compile: **PASS**
- Ruff on every owned product/test file: **PASS**
- focused Fleet, lifecycle, storage, and legacy-path suite: **25/25 PASS**
- wider Fleet authentication, batching, compression, tenancy, integrity,
  rate-limit, credential, and control-plane suite: **78/78 PASS**

