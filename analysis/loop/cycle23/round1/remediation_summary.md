# Cycle 23 Round 1 — Remediation Summary

Date: 2026-08-26  
Scope: only R1-01 through R1-09 from this round's red-team findings.

All changes remain actor-neutral and observe-only. They do not mutate SSH,
Windows Event Log, routes, firewalls, network profiles, gateway configuration,
or credentials, and every EventBus response-authority field remains false.

## R1-01 — FIXED

- **Changed:** `src/angerona/core/event_log_integrity.py` now pairs the cursor
  with a separately purpose-signed enrollment epoch, monotonic revision and
  byte-exact compare-and-swap admission. Cursor/key reads are bounded,
  regular-file-only, stable-identity and link/reparse rejecting.
- **Changed:** `src/angerona/modules/audit_log_guard.py` replays fixed tamper
  event IDs from the oldest retained record in 128-row batches on genuine first
  enrollment, treats a post-enrollment missing cursor as untrusted, and emits
  provisional/start plus stable-terminal coverage events.
- **Regression:** `tests/test_event_log_integrity_guard.py` covers retained 1102
  evidence, cursor deletion after enrollment, stale-writer CAS rejection,
  tamper, and link/reparse-parent rejection (platform skip when links cannot be
  created).
- **Gates:** compile PASS; Ruff PASS; focused combined suite PASS; Audit Log
  Integrity Guard `self_test()` PASS.

## R1-02 — FIXED

- **Changed:** `src/angerona/modules/audit_log_guard.py` stages parsed records,
  validates admission and terminal anchors after query/parse, again immediately
  before authenticated commit, and once more before publication. A generation
  change discards staged rows and persists a fail-closed rollback cursor rather
  than bridging generations.
- **Regression:** deterministic pre-commit and post-commit clear/refill races
  both discard a staged clear record and emit explicit gap evidence.
- **Gates:** compile PASS; Ruff PASS; focused combined suite PASS; module
  `self_test()` PASS.

## R1-03 — FIXED

- **Changed:** `src/angerona/core/ssh_surface.py` and
  `src/angerona/modules/ssh_surface_guard.py` add a root-confined Include graph
  (32 files, depth 4, 2 MiB aggregate, bounded directory rows), stable
  non-reparse reads, aggregate identity/content digest, configured authorized
  key/CA/principals evidence, explicit unsupported command/dynamic-source
  states, and native Windows ACL custody for configuration, includes,
  authorized keys and host keys. The new evidence is in the authenticated
  schema-v2 baseline, with authenticated schema-v1 compatibility.
- **Regression:** Include escape/cycle/change, configured-source, ACL-custody,
  schema-migration and privacy boundaries are covered.
- **Gates:** compile PASS; Ruff PASS; SSH focused suite PASS; SSH Surface Guard
  `self_test()` PASS.

## R1-04 — FIXED

- **Changed:** the SSH core/module now read only fixed `OpenSSH/Operational` and
  `OpenSSH/Admin` providers/event IDs 1–4 with bounded strict XML admission;
  enumerate service and non-service `sshd.exe` plus `ssh.exe`; bind PID birth,
  executable tokens, normalized forwarding flags, listeners and established
  connections; and expose source-completeness drift without raw identities,
  command lines or endpoints.
- **Boundary retained honestly:** Authenticode is not asserted. The module emits
  `ssh.runtime.signature_verification_unavailable`, and Include semantics that
  require identity-specific OpenSSH evaluation remain explicitly ambiguous.
  Neither condition is represented as healthy or verified.
- **Gates:** compile PASS; Ruff PASS; SSH focused suite PASS; SSH Surface Guard
  `self_test()` PASS.

## R1-05 — FIXED

- **Changed:** `src/angerona/core/network_trust.py` adds purpose-derived stable
  privacy/baseline keys and a strict HMAC baseline with provisional/trusted
  states, a separate enrollment epoch, stable bounded file admission and
  missing-after-enrollment rejection. Incomplete evidence never advances the
  in-memory or persistent baseline.
- **Changed:** `src/angerona/modules/network_trust_monitor.py` adds explicit
  global/per-interface source completeness, interface-bound structured Windows
  DNS/DHCP/routes/profile collection, authenticated restart comparison, and an
  in-flight child pipe cap that kills/discards oversized or timed-out inventory
  output. Unsupported non-Windows sources remain incomplete rather than being
  declared healthy.
- **Regression:** restart/offline DNS drift, deleted baseline, incomplete first
  enrollment, and oversized child output all fail closed.
- **Gates:** compile PASS; Ruff PASS; network/gateway focused suite PASS; Zero-
  Trust Network Path Monitor `self_test()` PASS.

## R1-06 — FIXED

- **Changed:** `src/angerona/core/network_trust.py`,
  `src/angerona/modules/network_trust_monitor.py`, and
  `src/angerona/core/personal_sentinel_gateway.py` represent selection and
  attestation on each default route. Positive labeling requires complete IPv4
  and IPv6 inventories, exactly one default route per applicable family, the
  selected gateway on the enrolled interface, matching interface index and
  epoch, and an unchanged route context before/after the pinned HTTPS exchange.
  Competing, ambiguous, incomplete, dual-stack bypass, or changed routes remain
  untrusted.
- **Regression:** lower-metric competitor, standby competitor, IPv6 bypass and
  post-exchange metric drift are rejected without making or retaining a false
  positive path claim.
- **Gates:** compile PASS; Ruff PASS; network plus Personal Sentinel focused
  suites PASS; network module `self_test()` PASS.

## R1-07 — FIXED

- **Changed:** `src/angerona/gui/live_defense_activity.py` enforces the public
  message contract and redacts MAC/EUI, SSID, adapter/account labels, secrets,
  and quoted or unquoted Windows paths containing spaces. The card still never
  reads Event details or model-private reasoning.
- **Changed:** `src/angerona/modules/arp_watchdog.py` public messages are now
  identity-free; governed details retain the existing local evidence boundary.
- **Regression:** real ARP and other identifier-bearing producer messages plus
  spaced/quoted path fixtures are covered.
- **Gates:** compile PASS; Ruff PASS; live/ARP focused tests PASS; ARP Watchdog
  `self_test()` PASS.

## R1-08 — FIXED

- **Changed:** `src/angerona/modules/network_trust_monitor.py` declares the
  literal module-level `SUPPORTED_PLATFORMS = ("windows", "macos", "linux")`
  and the class references that tuple.
- **Regression:** AST preflight admits Linux/macOS while an undeclared legacy
  module remains conservatively Windows-only.
- **Gates:** compile PASS; Ruff PASS; AST discovery regression PASS; network
  module `self_test()` PASS.

## R1-09 — FIXED

- **Changed:** `src/angerona/core/defense_memory.py` requires a regular file
  contained by the bundled resource root; rejects link/reparse components;
  opens once with no-follow where supported; reads only `MAX_FILE_BYTES + 1`;
  and compares path/opened/before/after identity and metadata before retaining
  the existing canonical digest, duplicate-key, schema and governance checks.
- **Regression:** oversized, out-of-root, symlink/reparse, replacement-race and
  bounded-read cases are covered.
- **Gates:** compile PASS; Ruff PASS; Defense Memory focused tests PASS; no
  module `self_test()` exists.

## Aggregate gates

- `py_compile`: PASS for every changed production file in these findings.
- Ruff: PASS for all changed production files and focused tests.
- Focused cross-module pytest: **134 passed, 2 skipped, 0 failed**. The skips
  are environment-gated link/ACL cases; equivalent rejection logic is covered
  where the host permits the primitive.
- Module self-tests: Audit Log Integrity Guard, Zero-Trust Network Path
  Monitor, SSH Surface Guard and ARP Watchdog all PASS.

