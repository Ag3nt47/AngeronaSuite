# Round 2 — Red Team Findings

Scope: `src/angerona/**`, root `*.bat`/`*.ps1`, and `.gitignore`. This was a
read-only source audit against the post-stability/security-sweep tree. Deployment
model assumed: one Windows host with Angerona running elevated; severity is impact
times exploitability in that model, with default-off and user-interaction gates
credited.

Bottom line: four new weaknesses were confirmed. The highest-risk item is an
attacker-controlled file path interpolated into an elevated PowerShell command.
The two prior items specifically requested for re-check, A-04 and A-07, are now
resolved in current code and are not re-reported.

---

## R2-01 — Alert enrichment interpolates an attacker-controlled path into elevated PowerShell

- **Severity:** HIGH
- **Component:** `src/angerona/gui/pages.py:2361-2366,2397-2421`; invoked by the single-alert and bulk AI-review paths at `:2482` and `:2529`.
- **Description:** `_enrich()` obtains `path` from an event's `details.path`,
  `details.image`, or `details.exe` (or from the referenced process). These values
  originate in process/AV/ETW telemetry and can therefore name an executable or
  file created by an unprivileged attacker. If the path exists, Angerona builds
  `f"(Get-AuthenticodeSignature '{path}').Status"` and supplies that string to
  `powershell -Command`. Windows filenames may contain a single quote and
  semicolon. A path containing PowerShell syntax can therefore terminate the
  quoted literal and append commands. Using an argv list does not prevent
  injection because the unsafe interpolation occurs inside the `-Command`
  argument itself.
- **Impact:** When an analyst asks Angerona to review the planted alert, injected
  PowerShell executes with Angerona's elevated token, creating a local
  privilege-escalation route from a low-privilege process/file to Administrator.
- **Existing mitigations / exploitability:** The exact path must exist and the
  analyst must invoke AI review of that queued item. Those requirements reduce
  likelihood, but are realistic for an alert-generating executable and do not
  reduce the elevation impact.
- **Recommendation:** Do not interpolate the path into PowerShell source. Prefer
  a native Authenticode/WinVerifyTrust API. If PowerShell remains necessary, pass
  the path as a separately bound parameter to a constant script and use
  `Get-AuthenticodeSignature -LiteralPath`; add a regression case containing
  quotes, semicolons, spaces, and Unicode.

## R2-02 — Remote Bridge authenticates only the sender and leaves telemetry unauthenticated and unencrypted

- **Severity:** MEDIUM
- **Component:** `src/angerona/modules/remote_bridge.py:62-87,184-203,209-262`.
- **Description:** The receiver challenges the sender, which proves knowledge of
  the shared key. The sender never authenticates the receiver: it accepts any
  `CHALLENGE`, sends the HMAC response, accepts the literal string `OK`, and then
  transmits the event as plaintext JSON. The JSON body itself has no MAC or AEAD
  tag. Consequently, an active LAN attacker who can intercept/redirect the
  configured peer can impersonate the receiver and collect telemetry without the
  key; an on-path attacker can relay the handshake and alter fields such as
  `severity`, `message`, `details`, and `node_origin` before the real receiver
  republishes them. Passive observers can also read the event payload. A
  passphrase is reduced with one unsalted SHA-256 rather than a password KDF, so
  captured challenge/response pairs also permit efficient offline guessing of
  weak passphrases.
- **Impact:** Disclosure of high/critical host telemetry and falsification or
  suppression of cross-node security events, undermining central triage.
- **Existing mitigations / exploitability:** The module is disabled by default,
  requires explicit sender/receiver configuration and a shared key, and accepts
  at most 1 MB per event. Exploitation requires LAN/on-path positioning or peer
  redirection, so this is MEDIUM rather than HIGH.
- **Recommendation:** Replace the bespoke channel with TLS 1.3 and mutual
  authentication (pinned certificates/keys), or use a transcript-bound mutual
  challenge plus AEAD for every framed payload. Derive keys with HKDF from random
  key material; if human passphrases are supported, use a memory-hard KDF. Bind
  length, sequence number, and both peer identities into the authenticated data
  and reject replayed sequence numbers.

## R2-03 — The advertised tamper-evident event ledger neither persists nor verifies event HMACs

- **Severity:** MEDIUM
- **Component:** `src/angerona/core/eventbus.py:118-131,158-168`; `src/angerona/core/storage.py:79-94,113-124,181-230`.
- **Description:** `BusAuthority.sign()` covers module, severity, message, and
  timestamp, but omits the mutable `details` dictionary that carries PIDs, paths,
  network indicators, and response metadata. More importantly, the SQLite
  `events` schema has no `hmac_sig` column, `FlightRecorder.record()` discards the
  signature, and every read reconstructs an unsigned `Event`. Repository-wide
  review found no consumer that calls `bus.verify()`. The implementation therefore
  does not deliver its stated protection against an attacker modifying the
  SQLite ledger; modified rows and details are displayed and exported normally.
- **Impact:** A local attacker with write access to the recorder can alter or
  fabricate forensic history, incident evidence, and analyst-visible details
  without detection. This does not directly forge the live in-memory SOAR stream,
  so the finding is MEDIUM rather than HIGH.
- **Recommendation:** Canonically serialize and sign all security-relevant fields,
  including `details`; persist `hmac_sig` in SQLite and the DLQ; verify signatures
  on every read/import; and surface invalid or legacy-unsigned records as explicit
  integrity failures. Add a schema migration and tamper tests for each signed
  field. Consider a chained record hash or periodic signed checkpoints to detect
  deletion/reordering as well as field edits.

## R2-04 — A single MCP SSE connection monopolizes the single-threaded server

- **Severity:** LOW
- **Component:** `src/angerona/engines/mcp_server.py:108-170,499-540`.
- **Description:** The server is a standard single-threaded `HTTPServer`.
  `_handle_sse()` intentionally remains in an infinite keepalive loop, so the
  request handler never returns to accept the client's subsequent `POST
  /message`. The first SSE client therefore monopolizes the only server thread;
  a local process can hold that connection to deny MCP access, and even a normal
  MCP session cannot complete the advertised two-endpoint flow. `do_POST()` also
  trusts an unbounded `Content-Length` and reads that many bytes with no request
  timeout or body cap, providing a second local blocking/allocation primitive.
- **Impact:** Denial of the local AI/security-data integration while MCP is
  enabled. The main Angerona UI and sensors remain running.
- **Existing mitigations / exploitability:** MCP is disabled by default,
  loopback-bound, Host-checked, and optionally bearer-authenticated. Attackers
  need local access (or the configured token when one is required), hence LOW.
- **Recommendation:** Use `ThreadingHTTPServer` (or an async server) so SSE and
  POST requests can progress concurrently; cap active sessions and queue depth;
  enforce a small JSON body limit and socket/request timeouts; and add an
  end-to-end test that opens SSE and successfully posts a tool call while another
  idle connection is present.

---

## Prior finding verification

| Prior ID(s) | Round 2 status | Evidence |
|---|---|---|
| A-01 | **Resolved** | Self-evolution remains off by default and `hot_reload_capability` scans generated source before `exec_module`. |
| A-02 | **Resolved** | MCP remains loopback-only with Host validation, no wildcard CORS, and optional bearer authentication. R2-04 is an availability flaw, not a regression of the A-02 access-control fix. |
| A-03 | **Resolved** | `cve_fix_advisor` scans fix scripts during normalization and immediately before application, and scans revert scripts immediately before execution; the denylist now includes defense-weakening and persistence patterns. |
| A-04 | **Resolved** | `ModuleManager._external_classes()` returns without importing anything unless `ANGERONA_EXTERNAL_MODULES` is explicitly truthy (`core/module_manager.py:69-77`). Explicit opt-in still trusts those files, as documented by the code comment. |
| A-05 | **Resolved** | Forensics runs `netstat -ano` as an argv list and performs PID filtering in Python (`modules/forensics.py:114-125`). |
| A-06 | **Still open (known)** | Six `-ExecutionPolicy Bypass` sites remain across source, plus launcher/helper scripts; execution is not yet centralized/allowlisted/audited. Not re-filed as a new Round 2 item. |
| A-07 | **Resolved** | `ShadowShield._key()` now uses SHA-256 (`modules/shadow_shield.py:77-79`). |
| R1-01 / R1-02 | **Resolved** | Both AI-authored PowerShell paths reuse `scan_powershell`; Posture Hardening scans the exact hash-verified bytes before execution. |
| R1-03 | **Resolved** | `mitigation_gate.ps1` aborts before dot-sourcing when the gate or playbooks directory grants write access to unprivileged SIDs. |
| R1-04 | **Resolved** | The dead sniffer no longer starts a thread on import and its cleartext IP-geolocation request was removed. |

**Prior findings verified resolved: 10. Prior findings still open: 1 (A-06).**
