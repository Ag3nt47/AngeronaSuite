# Cycle 6 / Round 2 — Remediation

## C6-R2-01 — Teams development authentication bypass

- **Status:** FIXED
- **Changed:** `connectors/teams_bot.py`, `core/config.py`, and the Teams
  settings UI. The bypass now requires a process-local environment opt-in, a
  direct loopback peer, and no forwarding headers. It is never loaded from or
  written to `settings.json`.
- **Gates:** changed-file `py_compile` PASS; Teams self-test PASS; focused
  forwarded/non-local/persistence regressions PASS.

## C6-R2-02 — Shutdown and EventBus key custody

- **Status:** FIXED
- **Changed:** shutdown commands use a dedicated `shutdown.key`; malformed or
  unreadable material fails closed and is never silently rotated. Packaged
  releases and the elevated source launcher require Administrator/SYSTEM-only
  key ACL establishment for both signing authorities.
- **Gates:** changed-file `py_compile` PASS; shutdown-token self-test PASS;
  focused separation and malformed-key regressions PASS.

## C6-R2-03 — Elevated editable source trust

- **Status:** DEFERRED
- **Changed:** the source launcher now rejects redirected, incomplete, or
  non-fixed roots before elevated execution and performs a second Python
  containment preflight before GUI launch. These are meaningful fail-closed
  roadblocks, but an editable checkout owned by the interactive user is not
  equivalent to a signed, Administrator-owned installed release.
- **Remainder:** closing the boundary fully requires deployment through the
  signed release installer into an Administrator/SYSTEM-owned, non-writable
  program directory. Automatically removing write access from a live Git
  checkout would break source development and updates.
- **Gates:** launcher helper and focused tests `py_compile` PASS; structural
  preflight regression PASS (symlink case skips where Windows denies test
  symlink creation).

## Combined verification

`12 passed, 1 skipped, 0 failed` across the new remediation suite plus existing
remote-bridge and fresh-security regression suites. All changed Python files
compile. Teams and shutdown module self-tests pass.
