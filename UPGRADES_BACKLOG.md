# Project Angerona — Upgrades Backlog

Derived from `Upgrades For Angerona.docx` and the mobile artifact drops, reconciled
against what is actually implemented in the repo as of this pass.

**Status legend:** ✅ Done · 🟡 Partial · ⬜ Planned · ⛔ Out of scope (declined)

---

## 1. Storage hygiene (keep data off C:)

- ✅ **Detect + relocate stray C: data to the configured root** — implemented as
  `modules/storage_hygiene.py` (SHYG). Uses the suite's canonical `ANGERONA_DATA`
  resolver; migrates the default `LOCALAPPDATA\Angerona` spill to the configured
  root. Auto-migrate is opt-in (`ANGERONA_STORAGE_AUTOMIGRATE=1`); destructive
  purge is operator-gated (`purge_stray(confirm=True)`).
- 🟡 **Point data root at F:** — operational step: set `ANGERONA_DATA=F:\...`.
  Everything already resolves through the canonical helper; no code change needed.
- ⬜ **"Automatic removal" button in the GUI** — surface SHYG's purge behind a
  confirmed button in the console (currently API + event only).

## 2. Mobile integration

- ✅ **Settings + Test button + notification window** — `gui/upgrade_console.py`
  "Mobile Integration" tab: host/operator/PIN/notification-window fields persisted
  to `.env`; a real "Test Mobile Integration" send through the mobile bridge with
  pass/fail + reason + fix.
- 🟡 **Send a real test SMS/alert** — wired to whatever mobile bridge module is
  present (`mobile_bridge`); confirm the transport (ntfy/Pushover/Signal/SMS) is
  configured for true end-to-end delivery.
- ⬜ **Include data from BlackBox / sensors in alerts** — enrich outbound alerts
  with recent BlackBox + sensor context.

## 3. AI sandbox & model management

- ✅ **Implement Code button** — console appends AI-proposed code to a chosen
  sandbox file (operator picks file + confirms).
- ✅ **Custom AI provider / API-key settings** — console persists provider keys to
  `.env` (OpenAI/Anthropic/HuggingFace/Groq/Gemini); Ollama needs no key.
- ✅ **Check-for-updates / switch local model** — console queries the local Ollama
  API for installed models and shows the `ollama pull <model>` update path.

## 4. Detection & intel modules (installed this pass)

- ✅ **ETW real-time process sensor** — `modules/etw_realtime_sensor.py` (ETWR).
- ✅ **AI Model Integrity Guard** — `modules/ai_model_integrity.py` (AMIG).
- ✅ **Compliance Mapper (MITRE→NIST/STIG)** — `modules/compliance_mapper.py` (CMAP).
- ✅ **SIEM Forwarder (CEF/Syslog)** — `modules/siem_forwarder.py` (SIEM).
- ✅ **Threat-Intel Fusion (STIX/TAXII IOC cache)** — merged into `modules/intel_sync.py`.
- ✅ **Fix pre-existing `canary_drill` import bug** — rewired to the bound-bus API.

## 5. Counter-Agentic Protocol (CAGT)

- ✅ **Behavioral loop / latency fingerprinting** — `modules/counter_agentic.py`.
- ✅ **Discovery→action chain detection** — implemented.
- ✅ **Local inference-port (Ollama 11434) watch** — detection/alert only.
- ⛔ **Semantic tar-pits / weaponized prompt-injection payloads** — offensive; not built.
- ⛔ **EDoS recursive-junk endpoints (token-exhaustion DoS)** — offensive DoS; not built.
- ⛔ **Adversarial Unicode / VLM output corruption** — offensive evasion; not built.
- 🟡 **Intent-based tool gating via Ollama triage** — detection heuristic present;
  optional deeper ATRG semantic gating remains a future, detection-only extension.

> CAGT is deliberately scoped to defensive detection, consistent with the project's
> own "defensive detection only" note. Active mitigation stays with operator-gated SOAR.

## 6. Decoupled multi-process architecture (standalone Watchdog / Scanner / BlackBox)

Goal: Watchdog and Telemetry Scanner run as their own low-footprint processes that
mutually keep each other (and Angerona + BlackBox) alive, feeding raw data to the
core for analysis. **Existing scaffolding:** `frz/angerona_watchdog.go`,
`frz/frz_watchdog.go`, `kernel/AngeronaSensor/*.cpp`, `syscall_bridge/`,
`core/watchdog_link.py`, `engines/watchdog.py`; BlackBox (`blackbox_recorder.py`)
already decoupled and read-only.

**Phase 1 — Process decoupling**
- ⬜ Cluster sensors into standalone executables (`angerona-sensor-sys`,
  `angerona-sensor-net`) rather than one-process-per-module.
- ⬜ Detached process creation (no shared process tree) so a group kill can't take
  down both core and watchdog.

**Phase 2 — IPC**
- ✅ Data plane: shared-memory (mmap) ring buffer — `resilience/ipc_ring.py`
  (versioned framed records, backpressure/drop; verified cross-process).
- 🟡 Control plane: signed stand-down token done (`shutdown_token.py` + Go); full loopback
  RPC command channel still planned.
- 🟡 Versioned framed records `[schema_ver, sensor_id, seq]` implemented; swap to
  Protobuf/FlatBuffers later for cross-language zero-copy.

**Phase 3 — Mutual watchdogging (event-driven, ~0% idle CPU)**
- ✅ Cross-monitor: `frz/hypervisor/main.go` (Go) revives core+scanner on dead/suspended,
  byte-compatible with the Python contract (interop math verified). Compile on Windows.
- ✅ Anti-suspension: `resilience/heartbeat.py` — AWDG-compatible mmap tick;
  frozen-tick + live-pid ⇒ suspended (verified).
- 🟡 Go hypervisor uses a 500ms low-CPU loop (native ~0% idle); `RegisterWaitForSingleObject`
  upgrade optional.
- ✅ N-fail backoff → SAFE_MODE + CRITICAL to BlackBox — `resilience/supervisor.py` (verified).

**Phase 4 — Graceful stand-down**
- ✅ Nonce challenge-response shutdown token — `resilience/shutdown_token.py`
  (HMAC over the bus key; supervisor honours it; verified).

**Phase 5 — GUI hubs (same Angerona theme)**
- ✅ Watchdog Hub + Telemetry Scanner Hub in `gui/upgrade_console.py` now read the LIVE
  ecosystem heartbeats + `status_*.json` (scanner fwd/drops/backpressure, core frames,
  watchdog pid/rss), falling back to honest placeholders when standalone.

**Phase 6 — Diagnostics for BlackBox**
- ✅ Atomic diagnostics writers for BlackBox — `resilience/diagnostics.py` (verified).

**Phase 7 — Self-test**
- ✅ `resilience/selftest.py` — heartbeat liveness, core→scanner ping round-trip,
  resource budgets, dry-run resurrection; failures → `diagnostics/selftest_failures.json`.

**Wire contract:** `shared-ipc/CONTRACT.md` documents the exact AWDG heartbeat, ARNG
ring, and stand-down HMAC byte layouts so Go/Rust/C stay byte-compatible with Python.
**Language:** Go (matches `frz/*.go`); compile `frz/hypervisor/build.bat` on Windows.

> Note: the doc's "process ghosting / randomized stealth naming to blend into OS
> noise" is intentionally **not** planned — it is a defense-evasion technique and
> contradicts the doc's own later principle that an operator should see clearly-named
> executables in Task Manager. Executables use clear, honest names.

## 7. Deployment

- ✅ **`Install-Angerona.bat` bootstrapper** — idempotent one-shot: UAC elevation,
  winget Python 3.10, venv + deps, Ollama + `llama3:8b`, compiles the Go watchdog
  (`frz/hypervisor/build.bat`), Desktop shortcuts (reuses `create-blackbox-launcher.ps1`),
  color-coded output. (Sensor-service registration deferred until the clustered
  `angerona-sensor-*` executables exist; the core supervises the scanner via
  `ANGERONA_RESILIENCE=1` in the meantime.)

## 8. Housekeeping / docs

- ✅ Added `pywintrace` (Windows) to `requirements.txt` for ETWR.
- ⬜ Update `docs/*.docx` in the Analysis folder and `llms.txt`.
- ⬜ Back up the repo to F:.
