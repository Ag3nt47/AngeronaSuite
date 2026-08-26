# Round 9 Integrated Closure — 2026-08-25

## Outcome

Round 9 combined independent function/process, UI-surface, and current defensive
capability research. It added one new production sensor, closed defects exposed
by repeated adversarial review, and converted the UI inventory into durable
contract tests.

## Shipped

- **App Control Decision Evidence:** read-only parsing of Windows Code Integrity
  3004, 3033, 3034, 3076, 3077, 3089, and policy-health events. Audit and enforced
  decisions remain distinct; 3089 evidence is strictly correlated by ActivityID.
- **Continuity:** HMAC-authenticated atomic cursor and pending state, exact record
  anchors, retained-range accounting, restart-safe incomplete joins, hard bounds,
  clear/regression and record-reuse detection, staged reads, and replay after
  generation changes. Six review loops closed strict-cardinality, persistence,
  bounds, privacy, pre-poll replacement, mid-poll replacement, and checkpoint-
  write replacement defects.
- **Privacy/authority:** ordinary EventBus/UI/export details expose basenames and
  keyed path tokens rather than full local paths. Sensor evidence is explicitly
  observe-only and cannot change App Control policy or authorize response.
- **UI closure:** 46 construction paths, 46 tab sites, 244 button sites, 9 actions,
  3 menus, and 32 Info topics inventoried. All 10 functional Settings tabs open
  their exact isolated code sandbox. Info/sandbox and Red Team editor paths fail
  soft, the ATT&CK heatmap fits 800x600, shutdown timers are owned, and visible
  Adaptation spelling is consistent.
- **Selfcheck truthfulness:** timeout text cannot waive a hung module; stopped
  states use structured classification and an explicit expected-stop allowlist.

## Verification

- Pytest: **1,305 passed, 3 intentional platform skips, 0 failed** from 1,308
  collected tests.
- Compile check: **310/310** product Python files.
- Static discovery: **68 modules, 0 errors**.
- Module self-tests: **48 pass, 0 genuine failures, 21 classified skips**.
- UI-focused gate: **153/153**; App Control focused gate: **35/35**.
- Ruff and selfcheck **26/26** pass.
- Read-only live Code Integrity sample: 256/256 parsed, 107/107 complete
  correlations, zero missing decision paths and zero parser errors.

## Next ranked capability work

1. Digest-pinned ATT&CK v19.2 registry and migration.
2. PowerShell Operational/4104 sensor with protected-content handling.
3. EPSS v5 + KEV + SSVC host-applicability queue.
4. Event-driven Task Scheduler and BITS persistence evidence.
5. App Control policy inventory and audit-to-enforce lifecycle.

The complete designs and primary sources are in `innovation_research.md`.

## External acceptance gates

Physical Windows Event Log clear/rollover/restart/suspend-resume soak, long
elevated runtime soak, clean-machine release matrices, signing/notarization,
fleet-scale throughput, false-positive baselining, and independent efficacy
evaluation remain outside deterministic local validation. Passing simulations
and fixtures is strong regression evidence, not proof of complete real-world
threat coverage.
