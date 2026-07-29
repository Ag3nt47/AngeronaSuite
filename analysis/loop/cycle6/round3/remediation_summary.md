# Cycle 6 / Round 3 — Remediation

## C6-R3-01 — Key precreation and custody

- **Status:** FIXED
- **Changed:** the elevated launcher creates the runtime parent with its final
  protected Administrator/SYSTEM ACL atomically, before creating runtime
  subdirectories or accessing keys. If an existing parent was not protected,
  its boundary is closed first and existing EventBus/shutdown authorities are
  quarantined. Python verifies the protected parent before key access and
  quarantines any unsafe pre-existing key before reading its bytes.
- **Attack regression:** an attacker-known pre-created `bus.key` is rejected,
  quarantined, and replaced; its known key cannot reproduce the active
  authority's signature.
- **Gates:** Python compilation PASS; PowerShell parser PASS; shutdown-token
  self-test PASS; focused regressions PASS.
- **Windows limit:** a user-mode ACL cannot defeat an already-compromised local
  Administrator/SYSTEM principal, nor revoke a hostile handle opened before
  the boundary is repaired. Signed installation into a protected program/data
  root and OS credential isolation remain the enterprise boundary.

## C6-R3-02 — Persisted telemetry HMAC bypass

- **Status:** FIXED
- **Changed:** the persistent GUI cursor now selects `hmac_sig`, reconstructs
  the canonical Event, and verifies it with `BusAuthority` before display.
  Missing, forged, malformed, or tampered rows are not rendered; a canonical
  Critical `Ledger Integrity` alert is emitted visibly in their place. The
  indexed rowid cursor and 200-row backpressure behavior are preserved.
- **Attack regression:** changing a signed row's message to a forged shutdown
  alert is rejected; attacker-controlled content never reaches the returned
  GUI batch. Valid signed rows remain accepted and incremental reads remain
  duplicate-free.
- **Gates:** Python compilation PASS; focused cursor/security regressions PASS.

## Combined verification

- New and adjacent remediation/UI suites: **19 passed / 1 platform skip**.
- Fresh security, performance, and state-bound suites: **20 passed**.
- Module self-tests: Teams and shutdown-token PASS.
