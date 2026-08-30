# Cycle 27 Round 1 — HIGH remediation, shard B

Scope was limited to `C27-R1-B07` and `C27-R1-B09`. All reproductions are
inert. No host security setting, account, network endpoint, repository history,
or publication state was changed.

## C27-R1-B07 — FIXED

Finding: a JIT-safe basename could opt a process out of Memory Injection
Scanner inspection, while native enumeration failures were compatible with
health 100.

Changes:

- `src/angerona/modules/mem_inject_scanner.py:125` adds a typed, immutable
  coverage receipt containing enumerated, opened, scanned, denied, failed,
  skipped, enumeration-complete, and enumeration-error fields. Health is
  derived from that receipt and cannot be 100 for incomplete enumeration or
  inaccessible targets.
- `src/angerona/modules/mem_inject_scanner.py:192` declares HANDLE-safe
  `CreateToolhelp32Snapshot`, `Process32FirstW`, `Process32NextW`,
  `CloseHandle`, `QueryFullProcessImageNameW`, and process-time prototypes.
  Snapshot handles close in `finally`; partial/failed enumeration remains
  explicit.
- `src/angerona/modules/mem_inject_scanner.py:314` sends every non-self PID to
  `_scan_pid`; `chrome.exe`, `python.exe`, and every other basename have no
  pre-open or pre-scan authority.
- `src/angerona/modules/mem_inject_scanner.py:393` returns a typed per-PID
  result and distinguishes access denied, open/query failure, and completed
  scanning. A failed mid-walk query cannot count as scanned.
- `src/angerona/modules/mem_inject_scanner.py:475` resolves path, process birth,
  and image digest through the exact still-open process object only after a
  suspicious region exists. `src/angerona/modules/mem_inject_scanner.py:600`
  permits the JIT false-positive damper only when an exact policy path and
  SHA-256 match that bound identity. It changes severity only; the event is
  still emitted.
- `tests/test_cycle27_round1_high_b.py:27` reproduces the old renamed/JIT
  basename bypass and proves all such PIDs are scanned. Additional cases prove
  honest coverage arithmetic and exact path+digest damping.

Gates:

- `py_compile`: PASS.
- Ruff: PASS.
- Dedicated and related regression tests: PASS (`53 passed`).
- Module `self_test()` with live `kernel32`/`VirtualQueryEx`: PASS
  (`VirtualQueryEx functional`).

## C27-R1-B09 — FIXED

Finding: a configured, replaceable `signal-cli` inherited parent credentials;
unbounded stdout was trusted without return-code, local transcript, executable,
or launch-custody proof.

Changes:

- `src/angerona/modules/mobile_bridge.py:188` validates Windows owner/DACL
  custody for the executable and every path component, rejecting any
  untrusted write/add/delete-child authority. Fixed-local volume, ordinary
  absolute `.exe`, no symlink/reparse point, and single-hard-link requirements
  are also fail-closed.
- `src/angerona/modules/mobile_bridge.py:345` verifies Authenticode with the
  WinAPI-derived inbox PowerShell path and a minimal environment. The exact
  certificate subject and SHA-256 must match
  `mobile_signal_cli_publisher` and `mobile_signal_cli_sha256`; a path alone is
  never execution authority.
- `src/angerona/modules/mobile_bridge.py:570` opens the pinned executable with
  read-only sharing, denying write/delete replacement, and retains that handle
  through launch. File identity, link count, digest, path custody, and ACL are
  revalidated after the child exits; any drift discards all output.
- `src/angerona/modules/mobile_bridge.py:679` streams at most 256 KiB with a hard
  deadline. `src/angerona/modules/mobile_bridge.py:738` starts the exact path
  suspended, assigns CPU/memory/process/kill-on-close job limits before resume,
  uses an exact cwd and minimal `source={}` environment, and never inherits
  either mobile PIN variable.
- `src/angerona/modules/mobile_bridge.py:786` authenticates purpose, fresh
  256-bit nonce, binary digest, return code, output length/digest, and terminal
  state with a process-local HMAC receipt. Nonzero exit, timeout, overflow,
  malformed/tampered receipt, changed output, or changed binary fails closed.
- `src/angerona/modules/mobile_bridge.py:930` and `:948` accept send/receive
  completion only through that sealed receipt. Per-purpose failure state is
  retained, so a later successful receive cannot overwrite a send failure.
- `src/angerona/modules/mobile_bridge.py:1578` keeps the enabled bridge inert at
  degraded health when pins/custody are unavailable. Health 100 requires a
  recent verified child round trip; `self_test()` performs the same sealed,
  job-limited `--version` receipt check when enabled.
- `tests/test_cycle27_round1_high_b.py:140` covers missing pins, nonce/return
  code/output tampering, nonzero exit, persistent failure health, secret-free
  child environment/job custody, and NTFS hard-link rejection without sending
  a message or changing the host.

Safe integration condition: the repository configuration/settings layer must
persist the two new non-secret pin fields before the opt-in bridge can become
healthy. Until then it remains deliberately proposal-only/inert rather than
falling back to pathname execution.

Gates:

- `py_compile`: PASS.
- Ruff: PASS.
- Dedicated and related regression tests: PASS (`53 passed`).
- Module `self_test()` in its default disabled state: PASS (`disabled
  (opt-in)`). Enabled mode is covered with an inert sealed-child harness; no
  external Signal command was issued.
- Shard JSON schema/load: PASS; only `C27-R1-B07` and `C27-R1-B09` changed to
  `FIXED`.

| Finding | Status | Gate result |
|---|---|---|
| C27-R1-B07 | FIXED | compile, Ruff, 53 tests, live module self-test PASS |
| C27-R1-B09 | FIXED | compile, Ruff, 53 tests, disabled self-test PASS |
