# Round 3 — Red Team Findings

Scope: current post-Round-2 `src/angerona/**`, root launch/helper scripts,
`.gitignore`, generated defensive artifacts, and the actual Windows ACLs on the
project and Angerona data directories. This was a read-only source/runtime audit;
`src/` and `rules/_active_combined.yar` were not modified. Severity assumes the
documented single-host deployment in which the launcher elevates Angerona.

Bottom line: four newly confirmed weaknesses remain. Two expose incomplete prior
controls (A-04 and R2-03); two are demonstrated failures in autonomous defensive
generation. ELAT itself is bounded, local, response-free, and did not yield a new
security finding.

---

## R3-01 — Elevated startup executes code from user-writable trust roots

- **Severity:** HIGH
- **Component:** `start-angerona.bat:13-18,39-42`;
  `src/angerona/core/config.py:16-22,82-85,153-162`;
  `src/angerona/core/module_manager.py:69-88`;
  `src/angerona/app.py:21,49,188-201`.
- **Description:** The launcher obtains an Administrator token and then executes
  the project virtual environment/package in place. The current project ACL grants
  inherited `FullControl` to `Authenticated Users`. Independently, A-04's new
  external-module control is only an environment switch. `Config.load()` reads
  environment assignments from `<data>/.env`; `Config.external_modules_dir` is
  `<data>/modules`; and, when `ANGERONA_EXTERNAL_MODULES` is truthy,
  `ModuleManager._external_classes()` executes every non-underscore `.py` file's
  top-level code via `exec_module`. The actual `%LOCALAPPDATA%\Angerona` ACL grants
  the unelevated account `FullControl`. Consequently an unelevated process can
  write the opt-in flag and a Python drop-in before the next launch. The elevated
  discovery thread then executes it. In the current checkout an attacker can take
  the even simpler route of modifying the elevated launcher or package directly.
- **Impact:** Local privilege escalation and durable arbitrary code execution with
  Angerona's Administrator token on the next operator launch. This also defeats the
  intended A-04 default-off boundary.
- **Existing mitigations / exploitability:** A UAC-approved restart is required,
  external modules default off, and a properly packaged admin-only installation
  would remove the project-root route. Neither default-off nor UAC protects against
  pre-positioned code in a path the elevated process later trusts. The data-dir
  route remains even if source is installed under Program Files.
- **Recommendation:** Never import privileged plug-ins from a per-user writable
  directory or enable them from a per-user `.env`. Load only signed/allow-listed
  modules from an Administrator/SYSTEM-owned directory and verify owner/DACL plus
  signature/hash immediately before import. Install the elevated runtime under an
  admin-only ACL, fail closed before elevation if the launcher/interpreter/package
  is writable by non-admin principals, and preferably separate the privileged
  sensor service from the unelevated UI.

## R3-02 — The event-ledger signing key shares the database's writable boundary

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/eventbus.py:91-117`;
  `src/angerona/core/storage.py:72-81,276-300`;
  `src/angerona/core/config.py:16-22,73-75`.
- **Description:** Round 2 now persists and verifies event HMACs, but
  `BusAuthority` stores the plaintext hex key as `<data>/bus.key` while the signed
  ledger is `<data>/flight-recorder.db`. No restrictive DACL or protected key store
  is applied when the key is created. The actual data-directory ACL grants the
  normal user `FullControl`, so the same unelevated process that can edit the
  SQLite ledger can read `bus.key`, recompute valid HMACs over forged fields, and
  update the signature. It can also corrupt/delete the key; `load()` silently
  generates a replacement, making every existing signed row appear invalid.
- **Impact:** An unelevated same-user process can forge trusted forensic history or
  invalidate the entire ledger despite the R2-03 verification path. This affects
  stored evidence and analyst views, not the live in-memory response stream.
- **Existing mitigations / exploitability:** Signatures now cover all event fields,
  are persisted, and are verified on every recorder read. Those controls stop
  accidental corruption and a DB-only writer that cannot obtain the key, but the
  deployed ACL does not provide that separation.
- **Recommendation:** Keep signing material outside the ledger's writable boundary:
  use an Administrator/SYSTEM-only DACL and Windows protected key storage (or a
  service-held, non-exportable key), fail closed on malformed/missing existing key
  instead of silently rotating it, and add a regression that proves an unelevated
  process able to write the DB cannot read or replace the key. Plan key rotation and
  legacy-row migration explicitly.

## R3-03 — The shared PowerShell substring denylist accepts destructive WMI actions

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/cve_fix_advisor.py:109-137`;
  `src/angerona/shark/playbook_tuner.py:107-134`;
  `mitigation_gate.ps1:25-64`; `playbooks/dynamic_block_*.ps1`.
- **Description:** The A-03/R1 remediation uses a case-insensitive substring
  denylist as the safety decision for model-authored PowerShell. It does not reject
  WMI/CIM method calls such as `Win32_Process ... $_.Terminate()` or
  `$_.SetState(0)`, nor does it enforce the tuner prompt's claimed network-only
  command set. All five currently generated playbooks return an empty finding list
  from `scan_powershell()`. Those artifacts contain process-termination/state calls;
  several target `explorer.exe` or `svchost.exe`, and the gate dot-sources all five.
- **Impact:** A hallucinating or poisoned local model can stage host-destabilizing
  commands into a privileged containment gate while the UI/result reports that the
  destructive scan passed. Terminating `svchost.exe` can disrupt critical Windows
  services; other unenumerated PowerShell spellings/aliases remain equally viable.
- **Existing mitigations / exploitability:** The current project's non-admin-writable
  ACL makes the R1-03 gate abort before dot-sourcing, and gate execution is described
  as review-gated/manual. A securely ACL'd deployment would pass that guard and run
  the accepted playbooks. The model prompt asks for firewall containment but is not
  an enforcement boundary.
- **Recommendation:** Replace the blacklist decision with a strict AST/command
  allow-list for generated containment: permit only specifically parameter-validated
  `New-NetFirewallRule`/approved `netsh` forms, reject pipelines, member invocation,
  WMI/CIM, aliases, dynamic invocation, script blocks, and unknown commands. Parse
  and validate before writing and again immediately before execution. Quarantine the
  existing unsafe playbooks and add regression cases for `Terminate`, `SetState`,
  `Invoke-CimMethod`, aliases, concatenation, and encoded/dynamic invocation.

## R3-04 — Invalid model-generated YARA is activated without a compile gate

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/evolution_engine.py:168-181,211-220,236-265`;
  `src/angerona/modules/yara_scanner.py:55-75,144-176`;
  `rules/auto_generated.yar:1-14`.
- **Description:** `EvolutionEngine._ollama_yara()` accepts model text after only
  checking for the substrings `rule ` and `{`. `_deploy()` overwrites the sole
  auto-generated rule and calls `reload_rules()` without compiling the candidate or
  retaining a last-known-good copy. `reload_rules()` concatenates the candidate and
  immediately swaps `_active_rules`; the scan loop ignores YARA's non-zero return
  code/stderr and leaves module health at 100. This is not hypothetical: the current
  `rules/auto_generated.yar` is syntax-invalid, and a direct read-only
  `yara64.exe -w rules\auto_generated.yar README.md` check fails at line 7 with
  `syntax error, unexpected '{'`. The built-in self-test can still pass via a
  separate minimal rule and therefore masks an invalid active ruleset.
- **Impact:** A containment-bypass event followed by malformed model output can
  silently replace a working YARA configuration with one that matches nothing,
  creating a persistent signature-detection blind spot while the module reports
  healthy. Remote Bridge's known unauthenticated payload path can also manufacture
  the `verified=SUCCESS`/`technique` details that trigger this flow, but no network
  attacker is required for ordinary model syntax failure.
- **Existing mitigations / exploitability:** Evolution is bounded to three attempts,
  YARA content cannot execute general Python/PowerShell, and a CRITICAL alert is
  eventually emitted when verification fails. The invalid final candidate is not
  rolled back, so those controls do not preserve detection.
- **Recommendation:** Compile a temporary candidate plus the base rules with the
  actual YARA engine before any replacement; atomically promote only a successful
  candidate, retain/restore the last-known-good ruleset, validate technique IDs and
  escape metadata, and treat non-zero scan exits as a HIGH health failure. Make the
  self-test compile the live `_active_rules` and fail on any syntax error instead of
  passing solely through a fallback rule.

---

## Convergence and prior-control verification

| Prior IDs | Round 3 disposition |
|---|---|
| A-01, A-02, A-05, A-07, R1-03, R1-04, R2-01, R2-04 | **Still resolved** in current code. |
| A-06, R2-02 | **Still open/deferred, unchanged**; not re-filed merely for remaining open. |
| A-04 | **Incomplete/reopened by R3-01**: the opt-in and imported directory share a user-writable pre-elevation boundary. |
| R2-03 | **Incomplete/reopened by R3-02**: field verification works, but key custody does not separate a ledger writer from a signer. |
| A-03, R1-01, R1-02 | **Shared mitigation incomplete under R3-03**: the scanner is present at each gate, but demonstrated destructive semantics pass it. |

Prior finding IDs verified resolved: **8**. Prior IDs still open, deferred, or
backed by an incomplete shared control: **7**. New Round 3 findings: **4**.

No new finding was filed for the already-documented global MCP worker-cap proposal
(P8), Remote Bridge protocol weakness (R2-02), PowerShell centralization (A-06), or
ledger deletion/reordering enhancement. Evidence Lattice Fusion was manually
reviewed and remained bounded (512 entities, 16 signals/entity), structured-entity
only, deduplicated, response-free, and recursive-output guarded.
