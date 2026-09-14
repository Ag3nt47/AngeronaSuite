# Module-table discovery stall

The supplied UI-watchdog snapshot at 2026-09-13 20:35:53 observed MainThread
unresponsive for approximately 5.7 seconds. Its active stack was
`MainWindow._refresh_body -> ModulesPanel.refresh -> ModulesPanel._build ->
QTableWidget.setCellWidget`. This identifies expensive GUI work during table
construction; a single stack sample does not prove a mutual-wait deadlock.

Module discovery adds entries while the dashboard is already visible. The
former module-count check rebuilt the entire table at each observed count
change: it deleted all rows, inserted them individually, and constructed a
checkbox widget, wrapper widget, and layout for every module. The build path
also left painting enabled while doing that work.

The panel now uses native checkable items without persistent cell widgets.
It removes only departed or filtered rows, allocates added rows in one batch,
and updates existing items in place. Existing selection and item identity
survive discovery additions. A cached presentation snapshot skips all table
writes when displayed values are unchanged. Same-count replacement, external
enable/disable changes, status colors, contract metadata, and mode filters are
reconciled on refresh.

Sorting, painting, and change signals are suspended around mutations and
restored even after a render failure. Incomplete rows can be rebuilt on the
next refresh. Checkbox changes still go through `ModuleManager.set_enabled`;
the panel then restores the manager's actual state after policy/platform
denials or exceptions. Programmatic refresh cannot enable or disable a module.
Inspectors continue resolving the module by its stable key after sorting.
The sort selector now controls the intended column; name sorting ignores
decorative category avatars and assurance sorting retains numeric values.

## Validation

- Twelve new offscreen tests cover 84/200-module discovery, item and selection
  preservation, forbidden per-row widget installation, authoritative toggles,
  rejection, filtering, replacements, numeric/name sorting, and render retry.
- The focused panel, page safety, assurance, dashboard snapshot, refresh-worker,
  and performance suite passes 41 tests, including in the clean publication
  checkout containing only this update.
- The isolated full offline selfcheck passes all 26 phases with zero failures;
  its module/event-pipeline checks report 69 passes and 16 expected skips.
  Package compilation covers 377 source files with zero failures. Changed
  Python Ruff, Git whitespace, and offline documentation checks pass.
- The broader health-evidence suite has a pre-existing failure in
  `test_all_builtin_snapshots_share_health_evidence_schema_and_parity`:
  `source_state` is `available` where it expects `untrusted-external`. The same
  six-file suite produces the identical result (38 passed, 1 failed) in an
  isolated checkout of unmodified published commit `f98e306`. No source-trust
  behavior or assertion was changed for this UI fix.
- A controlled offscreen probe with synthetic module/assurance data increased
  discovery through 21, 42, 63, and 84 modules. The final update measured
  88.56 ms before and 21.51 ms after; average unchanged refresh over 30 calls
  measured 2.40 ms before and 0.66 ms after. Persistent checkbox cell widgets
  fell from 84 to zero. These measurements isolate table overhead and do not
  reproduce or certify elimination of every host-dependent UI stall.

Restart Angerona to load this source update. No live module, process, key,
cursor, or diagnostic evidence is reset by the fix.
