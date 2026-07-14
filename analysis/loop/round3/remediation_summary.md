# Round 3 — Remediation Summary

Remediation was limited to the four Round 3 findings and applied highest
severity first. No host ACL was changed, the current developer checkout remains
launchable, and `rules/_active_combined.yar` was not modified.

## R3-01 — DEFERRED

**Elevated startup executes code from user-writable trust roots**

- No source or host-ACL change was applied. Correct closure requires a packaged,
  Administrator/SYSTEM-owned runtime plus a privileged plug-in trust service or
  signed/hash-allow-listed admin-owned plug-in directory.
- Making the current FullControl development checkout fail closed would silently
  make it unlaunchable; changing host ACLs is outside this gated remediation.
- The existing default-off external-module switch remains defense in depth, but
  is not treated as an authorization boundary.
- **Gate:** design/safety review PASS; compatible trust-root implementation not
  proven. **Status: DEFERRED.**

## R3-02 — DEFERRED (partial hardening applied)

**The event-ledger signing key shares the database's writable boundary**

- `src/angerona/core/eventbus.py`: malformed or unreadable existing keys now fail
  closed instead of silently rotating; first-run creation is create-only,
  fsynced, and race-safe.
- Key custody is still not separated from a same-user writer. User-scoped DPAPI
  would not create that separation, and host ACL mutation or a privileged
  non-exportable signing service was not introduced.
- **Gates:** `py_compile` PASS; isolated first-run/reload/malformed-key regression
  PASS. **Status: DEFERRED** pending a packaged privileged signer/key boundary.

## R3-03 — FIXED

**The shared PowerShell substring denylist accepts destructive WMI actions**

- `src/angerona/core/cve_fix_advisor.py`: added precise WMI/CIM and
  `Terminate()`/`SetState()` rejection, plus a strict generated-containment
  allow-list limited to bounded `New-NetFirewallRule` commands and parameters.
- `src/angerona/shark/playbook_tuner.py`: validates model output before staging,
  validates the exact staged bytes again, and atomically promotes only safe
  playbooks. Unsafe output falls back to the deterministic network-only block.
- `mitigation_gate.ps1`: parses and validates every dynamic playbook immediately
  before execution and aborts the entire gate before host changes if any artifact
  is unsafe. The five historical WMI playbooks are quarantined in place by this
  fail-closed check and are no longer statically dot-sourced.
- **Gates:** Python `py_compile` PASS; CVE/self-test and safe-fallback regression
  PASS; all five historical playbooks rejected; PowerShell AST parse PASS.
  **Status: FIXED.**

## R3-04 — FIXED

**Invalid model-generated YARA is activated without a compile gate**

- `src/angerona/modules/yara_scanner.py`: builds a temporary base-plus-generated
  candidate, compiles it with the bundled YARA engine, and atomically promotes it
  to `_active_runtime.yar` only on success. Failed candidates leave the active
  and persisted last-known-good rules untouched. Live scan non-zero exits now
  lower health and emit HIGH failures; self-test fails if the live rules do not
  compile.
- `src/angerona/modules/evolution_engine.py`: accepts only canonical ATT&CK
  technique IDs and deploys solely through the scanner's compile gate; rejected
  model output is recorded as rejected rather than verified.
- **Gates:** both Python files `py_compile` PASS; isolated regression using the
  actual bundled `yara64.exe` proved valid atomic activation, invalid-candidate
  rejection, last-known-good preservation, and live self-test PASS.
  **Status: FIXED.**

## Gate summary

| Finding | Status | Gate result |
|---|---|---|
| R3-01 | DEFERRED | Safety/design review PASS; packaged trust boundary required |
| R3-02 | DEFERRED | Compile + partial hardening regressions PASS; custody boundary required |
| R3-03 | FIXED | Compile, self-test, hostile-playbook rejection, PS parse PASS |
| R3-04 | FIXED | Compile + actual-engine atomic activation/rejection PASS |
