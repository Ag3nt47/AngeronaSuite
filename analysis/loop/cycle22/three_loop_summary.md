# Cycle 22 — Three-loop convergence summary

Date: 2026-08-22  
Product version: 1.10.0, Cycle 22 documentation addendum  
Scope: local defensive behavior, reliability, privacy, remediation proof, and release readiness

## Loop 1 — unattended defense and safety

- Implemented a shared GUI/headless network-first Chill controller. Network,
  endpoint-event, response, USB, and resilience sentinels stay available; deep
  scans and local-AI work are parked or placed on a sparse sequential cadence.
  Ollama/llama3 unloads while idle and an authenticated active-threat revision
  wakes the fuller defense path.
- Live profiling showed presentation—not sensor polling—as the idle CPU leader.
  Dashboard presentation now uses 5s active-Chill / 10s inactive / 15s hidden
  cadences with elapsed-time-equivalent panels and a coalesced immediate wake for
  High/Critical evidence. ARIA motion stops in Chill/inactive/hidden; minimized
  Watchdog/Scanner UI uses a cached 10s refresh. Sensor/supervisor recovery
  cadence is unchanged.
- Separated severity from disposition. Registered practice, exposure,
  vulnerability, health, Defender-state, and ordinary USB events cannot assert
  global Critical; only active-threat/active-attack evidence can do so.
- Consolidated source runtime writes under the D:-drive canonical data root and
  moved default deception there. Personal-folder deception requires opt-in.
- Hardened async Qt close/reopen lifecycle and changed watchdog heartbeat/recovery
  authority to component-bound HMAC, freshness, and replay validation. FRZ now
  emits the authenticated 32-byte heartbeat-v2 record instead of its legacy
  16-byte raw map.

## Loop 2 — response proof and enterprise-pattern comparison

- Completed direct Live Alerts → SOAR queueing and authenticated
  approve/dismiss/execute controls. Scan Center received responsive layout,
  cancellation/child cleanup, and truthful Defender activity reporting.
- Added protected USB PIN enrollment/lockout/reset and volume-identity-bound
  authorization. Reused mount letters do not inherit approval from another
  device, and selected-media scans revalidate before reading.
- Reworked simulated-gap closure around the exact report and action contract.
  Test Fix must prove production detector output, persisted evidence,
  authenticated EventBus evidence, real Active Response SOAR, cleanup, a quiet
  negative control, and a signed receipt from a distinct run. Later misses or
  expiry reopen closure.
- Applied the reviewed case pattern from TheHive-style observables/similar cases:
  bounded typed observables, human approval, HMAC-private similarity, tamper
  refusal, and aggregate-only sanitized export. This adds local investigation
  context; it is not a claim of distributed enterprise parity.

## Loop 3 — release and regression closure

- Enforced exact CPython 3.12 x64 for hardened Windows source launch even when a
  pre-existing 3.14 virtual environment exists. Added an explicit typed,
  signature-checked, hash-locked, rollback-preserving repair path.
- Pinned the bootstrap to the reviewed pip 26.2.1 wheel by verified SHA-256,
  installed it before dependencies, and rejected unexpected pip versions.
- Completed that repair on this host, live-reconciled protected autostart to the
  Chill entry, and validated Windows' omitted `RunLevel` as the Limited default
  only for the expected interactive principal.
- Hardened the Git publication helper so staging/commit failure aborts the push
  and commit messages do not pass through shell interpolation. Manual release
  branch names now map to deterministic path-safe artifacts without changing
  tag names.
- Restricted JARVIS authority to SecureStore, scrubbed inherited tokens before
  elevation/runtime, and added masked enrollment/regeneration. FRZ v2 now uses a
  distinct binary name and pinned Go module graph; the native binary was not
  built because Go was unavailable on the verification host.
- Hardened `backup_to_F.bat` with strict repository/F: destination validation,
  reparse and path-escape rejection, broader secret/runtime/cache/model/build
  exclusions, pre/post stale-private-state cleanup, and non-destructive
  `--validate-only`. No real mirror ran during verification.
- Regenerated the public dashboard from fixed synthetic-only values: 66 modules,
  posture 96 Secure, and 0 alerts.

## Final evidence

- Pytest: **1026 passed, 3 intentional platform skips, 0 failed**.
- Discovery: **66 modules, 0 errors, 0 duplicate codes**.
- Selfcheck: **26/26**. Core self-tests: **18/18**.
- Package compile: **297/297**. Core imports: **125/125**.
- Ruff, Bandit Medium/High, and `pip-audit`: clean.
- The async UI lifecycle file passes **5/5**, including a cold-Qt-tolerant timing
  assertion.

## Honest remaining gates

The Python repair completed on this host and protected autostart was
live-reconciled to the CPython 3.12 `pythonw -m angerona --chill` entry. Fresh
logon, clean-machine registration, physical sleep/resume, and extended
elevated-host soaks remain acceptance work. Publisher signing/notarization,
native privileged sensors, production Defender/ETW/AMSI/WFP validation,
multi-node HA, production mTLS/OIDC, hardware-backed custody, and independent
penetration/DR evidence remain external work. Cycle 22 does not establish
enterprise parity or certification.
