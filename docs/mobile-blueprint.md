# Angerona — Remote Mobile Integration Blueprint

Engineering blueprint for monitoring and controlling Angerona from a phone. Two
parts: (1) a secure **web alert pipeline** on the host, and (2) a **cross-platform
mobile app**. Nothing here weakens the local-first model — the pipeline is
opt-in, end-to-end encrypted, and authenticated.

---

## Part 1 — Web-Based Alert Pipeline

### 1.1 Components

```
 Angerona host                          Relay (optional)            Phone
 ┌──────────────────────────┐           ┌──────────────┐           ┌───────────┐
 │ EventBus ─► BridgeModule │  WSS/TLS  │  Lightweight │  WSS/TLS  │ Angerona  │
 │            (FastAPI +     │◄─────────►│  fan-out hub │◄─────────►│ mobile app│
 │             WebSocket)    │           │ (push tokens)│           │           │
 └──────────────────────────┘           └──────────────┘           └───────────┘
```

- **BridgeModule** (new Angerona module): subscribes to the EventBus and serves a
  local FastAPI app exposing a WebSocket + REST endpoints. Binds to LAN or via the
  relay for off-network access.
- **Relay** (optional, for cellular/off-LAN): a tiny stateless hub the host dials
  out to (so no inbound port-forwarding). Forwards encrypted frames and triggers
  push notifications. The relay never sees plaintext (E2E encrypted payloads).

### 1.2 Transport & security

- **WSS (WebSocket over TLS)** for the live channel; **HTTPS** for REST.
- **Device pairing:** QR code shown in the desktop Settings encodes
  `{host_id, pairing_token, x25519_pubkey}`. Phone scans → ECDH key exchange →
  per-device symmetric key.
- **Auth:** each frame carries a short-lived JWT (signed with the device key).
  Commands additionally require a **per-command HMAC** and a nonce (replay-proof).
- **E2E encryption:** payloads encrypted with the paired key (libsodium /
  AES-256-GCM), so a relay only routes ciphertext.
- **Authorization tiers:** `read` (view alerts) vs `act` (send mitigations); `act`
  requires biometric confirmation on the phone.

### 1.3 WebSocket protocol

JSON frames, `type`-tagged. Server→client:

```jsonc
// live alert
{ "type": "alert", "id": "evt_8f3…", "ts": 1750000000.12, "module": "YARA Scanner",
  "severity": "CRITICAL", "message": "YARA match: Mimikatz…", "details": {"pid": 4821},
  "sha256": "ab12…" }

// status heartbeat (every 5s)
{ "type": "status", "threat": "SECURE", "modules": {"running": 9, "total": 10},
  "health": [{"name":"AI Triage","health":100,"state":"ok"}, …] }

// command result
{ "type": "ack", "cmd_id": "cmd_77", "ok": true, "detail": "Suspended pid 4821" }
```

Client→server:

```jsonc
// subscribe / filter
{ "type": "subscribe", "min_severity": "MEDIUM" }

// mitigation command (requires 'act' tier + HMAC + nonce)
{ "type": "command", "cmd_id": "cmd_77", "action": "suspend", "pid": 4821,
  "nonce": "…", "hmac": "…" }

// supported actions: suspend | resume | kill | isolate | restore_network |
//                    run_selftest | acknowledge_alert
```

### 1.4 REST endpoints (FastAPI)

```
GET  /api/health                 -> liveness + version
GET  /api/alerts?limit=100       -> recent alerts (paginated, auth required)
GET  /api/alerts/{id}            -> full record + sha256
GET  /api/modules                -> modules + health
POST /api/command                -> {action, args, nonce, hmac}  (act tier)
POST /api/pair                   -> finalize device pairing (QR flow)
```

### 1.5 Host implementation sketch

`modules/bridge.py` (new): a `BaseModule` that starts a `uvicorn` server in a
thread, subscribes to the bus, and pushes each event to connected sockets. Reuses
the existing `commands.CommandConsole` to execute mitigation actions, so the phone
and the desktop console share one audited action path.

---

## Part 2 — Cross-Platform Mobile App (iOS / Android)

### 2.1 Stack

- **React Native (Expo)** or **Flutter** — one codebase, both platforms.
- Secure storage: iOS Keychain / Android Keystore for the device key.
- Push: APNs / FCM via the relay for background alerts.
- Live data: a single WSS connection with auto-reconnect + offline cache.

### 2.2 Screens / wireframes

```
┌─ DASHBOARD ───────────────┐   ┌─ ALERT DETAIL ────────────┐   ┌─ ALERTS LIST ─────────────┐
│  ANGERONA            ● SEC │   │  ‹ Back        CRITICAL ▲ │   │  Filter: [All ▼] [≥MED ▼] │
│  Threat: SECURE           │   │  YARA Scanner             │   │  ───────────────────────  │
│  Modules  9/10  ▮▮▮▮▮▮▮▮▮▯ │   │  10:42:05                 │   │ ▲ CRIT  Mimikatz match    │
│                           │   │  "YARA match: Mimikatz…"  │   │ ● HIGH  Office→powershell │
│  ┌ Recent ─────────────┐  │   │                           │   │ ● HIGH  Susp. port 4444   │
│  │▲ CRIT Mimikatz match│  │   │  SHA-256: ab12cd34…       │   │ ◦ MED   Ollama offline    │
│  │● HIGH Office→psh    │  │   │  PID 4821  parent: word…  │   │ ◦ INFO  Self-test passed  │
│  └─────────────────────┘  │   │                           │   │                           │
│  [ PANIC: ISOLATE HOST ]  │   │  [Suspend][Kill][Forensic]│   │  (tap a row → detail)     │
└───────────────────────────┘   └───────────────────────────┘   └───────────────────────────┘
```

- **Dashboard:** threat banner, module health bars, recent alerts, a prominent
  **PANIC: Isolate Host** button (calls `isolate`; `restore` to undo).
- **Alerts list:** severity-sorted, filterable; tap → detail.
- **Alert detail:** full record + SHA-256 fingerprint + process context; action
  buttons (**Suspend / Kill / Forensic capture**) that send `command` frames.
- **Mitigation flow:** tapping an action → biometric prompt → signed `command` →
  `ack` toast with the host's result.
- **Settings:** pairing (scan QR from desktop), tier (read/act), notification
  thresholds, connection status.

### 2.3 Action → host mapping

| Mobile button | WS `action` | Host effect (via CommandConsole) |
|---------------|-------------|----------------------------------|
| Suspend | `suspend` | freeze the PID |
| Kill | `kill` | terminate the PID |
| Forensic | `run_forensic` | trigger Forensics Capture on the PID |
| Isolate Host | `isolate` | network panic button (loopback + pipeline only) |
| Restore | `restore_network` | lift isolation |
| Run self-test | `run_selftest` | run the stress drill |

### 2.4 Build order

1. Host `BridgeModule` (WSS + REST + pairing) — reuse `CommandConsole` for actions.
2. Pairing/QR + key exchange.
3. Mobile read-only MVP (dashboard + alerts + detail over WSS).
4. `act` tier (signed commands) + biometric gate.
5. Relay + push for off-LAN/background.
6. Panic-button + forensic action wiring.

> **Dependency:** the desktop **network isolation panic button** (roadmap item)
> should land first so the mobile `isolate` action has a host-side implementation.
