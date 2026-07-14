# Round 2 — Remediation Summary

Remediation used only `round2/redteam_findings.md` and `.json` as findings
input. Changes were applied highest severity first and kept targeted. The
runtime-generated `rules/_active_combined.yar` file was not touched.

## R2-01 — FIXED

- **Change:** `src/angerona/gui/pages.py` now passes the telemetry-controlled
  Authenticode target through a child-process environment variable to a
  constant PowerShell command and uses `-LiteralPath`. The path is never part
  of PowerShell source text.
- **Compile gate:** PASS (`py_compile`).
- **Relevant self-test:** No module `self_test()` exists. Targeted regression
  PASS: a path containing a quote, semicolon, spaces, and Unicode remained
  absent from argv/script text and arrived unchanged as data.

## R2-02 — DEFERRED

- **Reason:** A correct fix requires a versioned mutual-authentication and AEAD
  protocol (or mutual TLS), certificate/key lifecycle, replay state, and a
  compatibility migration for existing sender/receiver nodes. Replacing the
  deployed wire format in-place would break configured nodes, while accepting
  both formats could create a downgrade path. No safe migration can be proven
  within this targeted remediation round.
- **Gate:** N/A — no code changed.

## R2-03 — FIXED

- **Change:** `src/angerona/core/eventbus.py` signs canonical JSON covering
  module, severity, message, timestamp, and the complete details object.
  `src/angerona/core/storage.py` migrates the SQLite schema with `hmac_sig`,
  signs all recorded events, persists signatures in SQLite and the DLQ, and
  verifies every event-returning read/search path. Invalid records are replaced
  by explicit CRITICAL integrity-failure events; migrated unsigned rows are
  visibly marked `[UNSIGNED LEGACY]`. `src/angerona/app.py` and
  `src/angerona/core/headless.py` arm the live bus with the recorder authority.
- **Compile gate:** PASS (`py_compile` for all four files).
- **Relevant self-test:** No module `self_test()` exists. Targeted migration,
  signature persistence, details-tamper, legacy-row, and live-bus verification
  regression PASS.
- **Scope note:** A chained ledger/checkpoint scheme for deletion/reordering is
  a separate design enhancement; it was not required to close the confirmed
  field-tampering gap.

## R2-04 — FIXED

- **Change:** `src/angerona/engines/mcp_server.py` now uses a daemonized
  `ThreadingHTTPServer`, so the long-lived SSE handler cannot monopolize POST
  handling. It caps active sessions (16), per-session responses (128), JSON
  bodies (256 KiB), listen backlog (32), and socket reads (10 seconds), and
  synchronizes session access.
- **Compile gate:** PASS (`py_compile`).
- **Relevant self-test:** No module `self_test()` exists. Live loopback
  regression PASS: an initialize POST completed with an SSE stream held open,
  its response arrived on that stream, and an oversized request received 413.

## Gate Summary

| Finding | Status | Compile | Relevant verification |
|---|---|---|---|
| R2-01 | FIXED | PASS | PASS — hostile path binding |
| R2-02 | DEFERRED | N/A | N/A — protocol migration required |
| R2-03 | FIXED | PASS | PASS — migration/sign/tamper/legacy |
| R2-04 | FIXED | PASS | PASS — live SSE+POST/body cap |
