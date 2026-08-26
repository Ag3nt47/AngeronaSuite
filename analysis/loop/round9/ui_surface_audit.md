# Round 9 GUI surface audit

Date: 2026-08-25
Scope: `src/angerona/gui`, the contextual Info/source-sandbox integration, and
the existing offscreen Qt regression suite.

## Result

The audited GUI has no statically declared dead `QPushButton` site and no blank
literal tab label. Three evidence-backed usability defects were corrected:

1. Contextual Info previously constructed its protected source sandbox during
   the parent window constructor. A permission or custody error could therefore
   prevent Settings, Operations, Attack Map, Red Team, or another tabbed surface
   from opening. Info now fails soft: descriptions and source locations remain
   visible, sandbox controls are disabled, and a plain-language reason is shown.
2. The Red Team console independently constructed its editor sandbox during
   startup and could fail for the same reason. The simulation Run, History, and
   Device Security Lab tabs now remain usable; only the unavailable editor and
   its three working-copy controls are disabled.
3. The ATT&CK heatmap forced a 1420-pixel minimum width and placed every toolbar
   control on one row. It now fits an 800x600 compact/offscreen desktop, retains
   its horizontal matrix scrollbar, uses a two-row toolbar, exposes maximize,
   and keeps all four tabs and three toolbar actions reachable.

Visible `Adaption` misspellings were also normalized to `Adaptation` across the
dashboard, workbench, tour, help text, dialog titles, warnings, and headings.
Internal compatibility identifiers such as topic keys, thread names, and log
tags were intentionally left unchanged.

## Source inventory

Static inventory of the current GUI source found:

- 35 reusable window classes: 32 `QDialog` descendants and 3 `QMainWindow`
  descendants.
- 11 additional inline/transient `QDialog` construction paths, for 46 total
  explicit window/dialog construction paths.
- 46 `addTab(...)` declaration sites.
- 244 direct `QPushButton(...)` declaration sites. Loops can create more than
  one runtime button from a single declaration site.
- 9 `QAction(...)` declaration sites: three use `triggered.connect`; six are a
  SOAR row context menu dispatched from the exact action returned by
  `QMenu.exec`.
- 3 explicit `QMenu(...)` construction sites.
- 32 contextual Info topics across 7 registered surfaces: Help, Dashboard,
  Settings, Operations, Attack Map, Red Team, and Advanced Console.
- Settings has 10 functional tabs plus Info. Every functional tab has a real
  source mapping, source-selection target, implementation search anchor,
  enabled sandbox launch button, label, and tooltip.

Reusable class windows covered by the inventory:

- Primary: `MainWindow`, `SettingsDialog`, `OperationsCenterDialog`,
  `AngeronaUpgradeConsole`, `AdaptationWorkbench`, `RedTeamConsole`,
  `AttackHeatmapWindow`, `FlowWindow`, and `WorldViewDialog`.
- Detection/review: `EventsWindow`, `ModulesStatusWindow`, `ThreatWindow`,
  `BlastRadiusDialog`, `CollisionView`, `ModuleInspector`, `AlertDetailDialog`,
  `ResolveCenter`, `IncidentTimelineDialog`, `ThreatIntelDashboard`,
  `CveAnalysisWindow`, `TopTalkersDialog`, `SharkMonitorDialog`, and `AARDialog`.
- Assistance/setup/editing: `AIConsultDialog`, `SourceSandboxDialog`,
  `SandboxEditor`, `HistoryDialog`, `SetupWizard`, `UsbApprovalDialog`, and the
  legacy `RedTeamSimulationDialog`.
- Dashboard details: `FuturisticDetailDialog`, `SystemPulseDetailDialog`,
  `ConsoleDetailDialog`, `AriaDetailDialog`, and `ModuleResourceDialog`.

## Interaction and usability checks

The new durable `tests/test_ui_surface_contract.py` test performs the following
on every run:

- Parses every GUI module and rejects a directly declared push button that has
  no click/press/release/toggle connection, including tuple-loop wiring.
- Rejects a declared menu action that has neither a triggered signal nor an
  exact return-value dispatch from its context menu.
- Rejects blank literal tab labels and validates unique contextual Info topics.
- Constructs Settings offscreen, visits all 11 tabs, verifies all 10 scrollable
  functional tabs, validates all 35 current Settings buttons have readable text
  or an icon and a click receiver, checks the per-tab sandbox label/tooltip, and
  exercises Cancel/close behavior.
- Constructs the ATT&CK heatmap at 800x600, visits Live Heat, Coverage, Top
  Techniques, and Info, and proves all three toolbar action buttons remain
  within the client area.
- Rejects regressions of the visible `Adaption` spelling.

Additional regression coverage proves that Settings construction and Red Team
construction survive an intentionally unavailable sandbox directory. The
existing UI-focused suite exercises dialog construction, selection, pagination,
scan cancellation, USB enrollment, SOAR review controls, action Undo, async
close deferral, dashboard scaling, animation lifecycles, setup navigation,
adaptation workflows, red-team narration, device lab controls, upgrade-console
shutdown, and loading indicators.

Focused result after the changes: **153 passed, 0 failed**. The new surface
contract by itself reports **7 passed**. Ruff and Python compilation also pass
for every touched GUI and test file.

## External or environmental actions (not dead UI)

The following controls can legitimately report unavailable, remain disabled
until prerequisites exist, or open an operating-system surface. They were
classified separately from dead buttons and were not made to perform real host
mutations during the offscreen audit:

- Cloud/local-AI consultation when no configured provider or Ollama service is
  reachable.
- File/folder/export pickers when the operator cancels.
- Microsoft Defender, signal-cli, startup registration, credential-store,
  privileged sensor, eBPF, SGX, and fleet-preview actions when their platform
  prerequisite is absent.
- MITRE, NVD, CISA, vendor-advisory, and other explicit browser destinations.
- Actions that require a row, case, alert, package, process, learned candidate,
  enrollment, or reversible Combat receipt to be selected first.
- Sandbox actions when protected working-copy storage is unavailable. The UI now
  states this directly while leaving unrelated functionality available.

This separation prevents a missing external dependency from being mislabeled as
a broken callback while still making the unavailable state discoverable.

## Remaining limits and next checks

- Static wiring proves reachability, not that every external provider, browser,
  platform service, or privileged operating-system API will succeed on every
  host.
- Host-mutating callbacks were not clicked blindly in the UI audit. Their safe
  preconditions, receipts, Undo, and postconditions remain covered by their
  dedicated subsystem tests.
- Emoji rendered as fallback boxes in the minimal offscreen Windows Qt font
  environment. Native Windows runs with the declared Segoe UI/emoji fonts; the
  compact-layout test intentionally validates geometry independently of glyph
  availability.
- A future release candidate should repeat the same inventory on a clean 100%,
  150%, and 200% DPI Windows VM with screen-reader and keyboard-only passes.

## Final closure pass

Re-audited on the final shared Round 9 tree after all concurrent capability and
self-check changes. Counts remain exact and unchanged: **35 reusable window
classes** (32 dialogs and 3 main windows), **11 inline dialogs**, **46 total
window/dialog construction paths**, **46 tab declaration sites**, **244 direct
push-button declaration sites**, **9 actions**, **3 menus**, and **32 Info topics
across 7 surfaces**.

The final pass exercised every Settings sandbox mapping end to end: all **10
functional Settings tabs** opened their isolated editor, selected their declared
implementation file, jumped to the tab's exact `_tab_*` function, exposed every
registered related file, and closed cleanly. The eleventh Settings tab, Info,
correctly follows the last functional tab rather than claiming a separate code
owner. Unavailable protected storage still leaves Settings help and Red Team's
simulation controls usable with explicit disabled-state text and tooltips.

One close-order regression surfaced only when the responsive heatmap test ran
immediately before the upgrade-console destruction test: the Info tab used an
unowned static 180 ms callback that could outlive its deleted spinner. The
callback now runs through a single-shot `QTimer` owned by `ContextInfoTab`, so Qt
cancels it with the widget. The reproducing two-test sequence passes, as does the
complete UI-focused selection: **153 passed, 0 failed**. The final contract,
sandbox, Red Team, and shutdown subset reports **17 passed, 0 failed**. Ruff,
Python compilation, and `git diff --check` are clean for the UI changes.

Honest boundary: construction and signal/dispatch coverage proves that controls
are reachable and callbacks exist. It does not fabricate successful responses
from absent cloud providers, privileged platform services, external browsers,
hardware, or canceled file pickers, and it does not blindly invoke host-mutating
actions. Those paths remain separated as environmental/precondition states and
are verified through their dedicated policy, receipt, rollback, and subsystem
tests.
