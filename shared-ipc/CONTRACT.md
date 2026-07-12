# Angerona Resilience — Shared IPC Wire Contract

Any language (Python, Go, Rust, C) that participates in the resilience ecosystem
MUST read/write these exact byte layouts. The reference implementation is the
verified Python package `angerona.resilience`; these constants are copied from it.
Everything is **little-endian**.

## Data directory

All shared files live under the data root:

```
ANGERONA_DATA   (env)   e.g.  F:\Users\<user>\AppData\Local\Angerona
  else  %LOCALAPPDATA%\Angerona   (Windows)   /   ~/Angerona   (POSIX)
```

Sub-paths:

```
<data>/heartbeats/<component>.hb     per-process heartbeat  (core, scanner, watchdog)
<data>/ipc/telemetry.ring            raw-telemetry ring buffer (scanner → core)
<data>/ipc/standdown.cmd             signed graceful stand-down command
<data>/ipc/scanner.ping              core→scanner self-test ping nonce (plain text)
<data>/bus.key                       32-byte per-install HMAC key, hex-encoded
```

## 1. Heartbeat — `AWDG`, 32 bytes

Struct format `"<IQIQII"` (Python `struct`):

| offset | type   | field   | meaning |
|--------|--------|---------|---------|
| 0      | u32    | magic   | `0x41574447` ("AWDG") |
| 4      | u64    | ts_ns   | `time.time_ns()` of the beat (wall clock) |
| 12     | u32    | pid     | writer PID |
| 16     | u64    | proof   | first 8 bytes of `SHA-256(token ‖ counter_le_u32)`, LE u64 (0 if no token) |
| 24     | u32    | counter | monotonically incrementing beat counter |
| 28     | u32    | flags   | 1 = running, 0 = cleanly stopped |

**Liveness / suspension rules (reader):**
- `flags == 0` → writer stopped cleanly (not a failure).
- `counter` advancing → **alive**.
- `counter` frozen ≥ `stale_after` seconds:
  - PID still alive → **suspended** (SIGSTOP / thread-blinding) → treat as compromised.
  - PID gone → **dead**.
- Missing file → **dead**.

`proof` lets a reader confirm the writer knows the shared per-launch token
(anti-impersonation). `token` is the raw bytes of `ANGERONA_WATCHDOG_TOKEN` (hex).

## 2. Telemetry ring — `ARNG`

Header struct `"<IIIIQQQI"` (44 bytes) padded to **64** bytes, then
`slot_count` fixed slots of `slot_size` bytes each.

| offset | type | field |
|--------|------|-------|
| 0  | u32 | magic `0x41524E47` ("ARNG") |
| 4  | u32 | version (1) |
| 8  | u32 | slot_count (default 4096) |
| 12 | u32 | slot_size (default 512) |
| 16 | u64 | write_seq |
| 24 | u64 | read_seq |
| 32 | u64 | drops |
| 40 | u32 | backpressure flag (0/1) |
| 44..63 | — | reserved (zero) |

**Slot** at `64 + (seq % slot_count) * slot_size`:
- `u32` record length `L`, then `L` bytes of record.
- Record = `"<HHI"` header `[schema_ver u16, sensor_id u16, seq u32]` + payload.

Producer (single) increments `write_seq`; on lap (`write_seq - read_seq >=
slot_count`) it advances `read_seq` (overwrite oldest) and bumps `drops`. Raises
the backpressure flag at ≥ 85% occupancy. Consumer (single) reads
`read_seq..write_seq`, fast-forwarding if it fell more than a full lap behind.

Sensor ids: `1 = process_creation`. Payloads are UTF-8 JSON in the reference
scanner (a compiled sensor may use any bytes; the core decodes by `sensor_id`).

## 3. Graceful stand-down token

`<data>/ipc/standdown.cmd` is JSON:

```json
{ "nonce": "<hex16>", "ts": <unix_float>, "reason": "<str>", "sig": "<hex>" }
```

`sig = HMAC_SHA256(key, payload)` where
`payload = nonce + "\x00" + str(int(ts)) + "\x00" + reason` (UTF-8) and `key` is
the raw bytes decoded from `<data>/bus.key` (hex). A command is honoured only if
the signature verifies AND `now - ts <= max_age` (default 3600 s). Any component
that sees a valid stand-down MUST stop respawning peers (maintenance mode).

Challenge/response (optional): `sign_challenge(nonce) = HMAC_SHA256(key, nonce)`.

## 4. Diagnostics (for the read-only BlackBox)

Components write atomically (temp + rename) under `<data>`-independent
`diagnostics/` (or `ANGERONA_DIAG_DIR`):

```
status_<component>.json   { component, state, pid, ts, rss_mb, cpu_pct, num_threads, ... }
status.json               most-recent component snapshot (compat)
thread_dump.json          { threads: [ {tid, name, stack[]} ] }
tracemalloc.json          { top: [ {traceback, size_kb, count} ] }
selftest_failures.json    [ { name, detail, component, ts } ]   (appended)
```

## Cross-monitoring matrix

```
                 ┌────────────────────────────┐
                 │  Watchdog (compiled binary) │  writes watchdog.hb
                 └──────────┬─────────┬────────┘
          reads core.hb ◄───┘         └──► reads scanner.hb, respawns each on dead/suspended
                 ▲                              ▲
   writes core.hb│                              │writes scanner.hb + telemetry.ring
        ┌────────┴────────┐            ┌─────────┴──────────┐
        │  Angerona core  │──supervises─►│ Telemetry Scanner │
        │  (Python)       │◄─drains ring─│  (standalone)     │
        └─────────────────┘            └────────────────────┘
                 │
                 └──► diagnostics/*.json ──► BlackBox (read-only)
```

Every component beats its own `*.hb`; each active healer reads its peers' `*.hb`
and respawns a dead/suspended peer (with backoff → SAFE_MODE). A valid
stand-down token halts all respawns. Executables use clear, honest names — no
process-ghosting / stealth renaming.
