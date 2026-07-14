# Round 1 — Remediation Summary

Agent: `angerona-remediation`. Authority: apply behind gates. All fixes reuse the
existing A-03 denylist (`core.cve_fix_advisor.scan_powershell`) — no new denylist
was invented. No security control was weakened.

Gate note: the sandbox mount flakily served **truncated** reads of the two large
files (`engines/sniffer.py`, `modules/posture_hardening.py`), producing FALSE
`SyntaxError`s and a FALSE `self_test` miss (a truncated copy missing the
`self_test` method fell through to `BaseModule`'s default). Verified via the real
filesystem (Read tool, intact tails) and isolated `/tmp` harnesses, as the runbook
prescribes.

| ID | Severity | File(s) changed | One-line change | Compile | self_test | Status |
|----|----------|-----------------|-----------------|---------|-----------|--------|
| R1-01 | MEDIUM | `src/angerona/shark/playbook_tuner.py` | Scan Ollama-generated PowerShell with `scan_powershell` before staging; fall back to the deterministic network-only block if destructive (or scan unavailable) | PASS | n/a (no self_test) | FIXED |
| R1-02 | MEDIUM | `src/angerona/modules/posture_hardening.py` | Refuse to stamp destructive model output in `_generate_remediation`; scan the exact verified bytes in `execute_remediation` before elevated run (covers the bulk AAR `_apply`, which funnels through it) | PASS | PASS (isolated) | FIXED |
| R1-03 | LOW | `mitigation_gate.ps1` (repo root) | Fail-closed LPE guard: abort before dot-sourcing dynamic playbooks if the gate script or `playbooks\` dir is writable by a non-admin SID (Everyone/AuthUsers/Users/INTERACTIVE) | n/a (PowerShell) | n/a | FIXED |
| R1-04 | INFO | `src/angerona/engines/sniffer.py` | Remove import-time DPI worker thread (now opt-in `start_dpi_worker()`); delete the cleartext `http://ip-api.com` IP-geolocation egress from `get_geo_location` | PASS (isolated) | n/a | FIXED |

## Details

### R1-01 — LLM PowerShell into the auto-executed SOAR gate (FIXED)
`tune_containment` previously did `block = _ollama_block(...) or _fallback_block(...)`
and wrote the raw model text straight into `playbooks\dynamic_block_<tid>.ps1`,
which `_register_in_gate` dot-sources from the auto-executed `mitigation_gate.ps1`.
Now the model block is passed through `cve_fix_advisor.scan_powershell`; any
destructive construct (or an unavailable scanner) forces a fall back to the
deterministic, network-only `_fallback_block`. The return dict now reports
`used_fallback` and `blocked_destructive`. Verified: `Remove-Item ...` output →
`blocked_destructive=['remove-item']`, `used_fallback=True`; a clean
`New-NetFirewallRule` block → passes through.

### R1-02 — Elevated AI PowerShell without a destructive scan (FIXED)
Two gates added, both reusing `scan_powershell` (imported as `_scan_ps` with a
standalone fallback):
1. `_generate_remediation`: if the local-AI script contains destructive
   constructs it is NOT stamped/staged — a refusal placeholder is written and the
   attempt is logged/emitted instead.
2. `execute_remediation`: after the existing SHA-256 integrity check, the EXACT
   verified bytes are scanned; destructive content is refused (CRITICAL edr log +
   emit + `blocked_destructive` attempt log) before any elevated `-File` run.
Because the AAR-dialog bulk `_apply` (`gui/main_window.py:842`) calls
`execute_remediation(..., authorized=True)` per weakness, every bulk-applied script
now passes the same per-script destructive gate. `self_test` (unchanged path)
passes: `probe weaknesses=1, health=40, staged=1`.

### R1-03 — Writable SOAR gate / playbooks (FIXED, minimal fail-closed hardening)
Added `Test-AngeronaUserWritable` to `mitigation_gate.ps1` and a guard that runs
BEFORE the appended dynamic playbook includes. It inspects the ACLs of the gate
script and `playbooks\` dir; if any Allow ACE grants Write/Modify/FullControl to an
unprivileged SID (Everyone `S-1-1-0`, Authenticated Users `S-1-5-11`, BUILTIN\Users
`S-1-5-32-545`, INTERACTIVE `S-1-5-4`) it prints a red warning and `exit 1` — not
applying containment is safer than dot-sourcing attacker-plantable elevated code.
Behavior-preserving for correctly-ACL'd installs and for normal per-user checkouts
(the owning user has rights via its explicit SID, not via the `Users` group), so
the common case is unaffected; only the genuinely dangerous writable case is
blocked. Fail-closed, strengthens the control.

### R1-04 — Dead sniffer cleartext IP leak (FIXED)
Confirmed dead: no Python `import` of `engines.sniffer` anywhere (only docs /
analysis references); `engines/__init__.py` states the package is not auto-loaded
and has no import side effects. Neutralized in place rather than deleted (lower
risk, keeps the file importable):
- The import-time `threading.Thread(asynchronous_dpi_worker).start()` is removed;
  it is now an explicit, default-off `start_dpi_worker()`.
- The `http://ip-api.com/json/{ip}` cleartext egress in `get_geo_location` is
  deleted; the function is now a local no-op returning `[Unknown Region]`.
