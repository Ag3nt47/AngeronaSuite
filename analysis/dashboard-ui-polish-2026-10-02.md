# Dashboard layout and responsiveness — 2026-10-02

## Delivered behavior

The standard dashboard remains the default. Header controls reflow, panel
headings are concise, module search gets its own row, and tables preserve
readable columns with scrolling. Card values fit their available width while
full values remain available through accessibility and tooltips. Narrow windows
stack panels and scroll; fixed accessibility scaling remains available.

Health and estimated-activity ribbons retain every module at a readable size.
They scroll together, slowly pan when motion is enabled, pause on interaction,
and support wheel, scrollbar, and keyboard browsing. A Pause/Resume control
stops automatic movement. Hidden/minimized windows and reduced-motion settings
stop automatic panning. Activity is explicitly an estimate, not measured
per-module CPU use. The user selected ribbons rather than category roll-ups.

Live Alerts offers an optional Details inspector with bounded plain-text
messages and supplied artifact paths. Narrow panels use the full detail dialog.
Allow, Block, and Analyze retain the existing evidence and confirmation paths.
The persistent footer reuses the existing host sampler and posture snapshots.
SOAR continues reconciling signed response receipts even while its tab is hidden.

Settings > Appearance > Dashboard display selects Standard or Orbital. The
optional orbital canvas shows discovered module health around the posture core,
selected-module detail, and bounded network history from existing samples.
Click or use arrow keys and Enter to open module details; the overview links
back to alerts and posture detail. Orbital positions are visual inventory, not
inferred network connections. The existing Classic/Flow startup setting is
independent. Unknown saved display values fall back to Standard.

## Performance boundaries

- Resize events coalesce into one layout/style pass after a 120 ms quiet period.
- Unchanged chip values avoid stylesheet and geometry updates.
- Hidden alert tables defer database snapshots. Hidden SOAR reconciliation stays
  active because signed receipts can age out of the bounded event history.
- Sysmon's fallback inventories PIDs and reads rich metadata only for newly
  observed processes, preserving its polling interval and event contents.
- A five-pair local component benchmark on 268 processes measured median
  inventory time of 103.45 ms before and 5.12 ms after the fallback change. This
  is approximately 95% less time for that inventory step, not an application
  CPU or frame-rate improvement claim.
- The orbital view and footer add no collectors, threads, or animation timers.
  The network history holds at most 60 samples. Existing background snapshots,
  bounded event buffers, critical-event handling, and safe responses remain.

The supplied visual blueprint informed the inspector, persistent metrics,
panel depth, critical borders, and optional orbital presentation. Native blur,
pulsing drop shadows, forced graphics backends, rolling alert counts, and a
wholesale table-model migration were not introduced. They need separate
measurement and compatibility work; they do not themselves guarantee smooth
operation. This update does not claim that all prior sustained sensor-load
stalls are resolved.

## Validation

137 focused UI, accessibility, resize, ribbon, alert-action, snapshot,
configuration, and performance tests passed. Compileall and Ruff passed.
The offline self-check
completed 26 phases with no failures: 66 module self-tests passed, 18 skipped
under existing platform/disabled/prerequisite rules, plus one event-pipeline
pass. Synthetic captures exercise desktop and narrow layouts without starting
defensive sensors or displaying live host data.

The first full-suite run reported 4,473 passed, 23 skipped, and two failures.
One source-inspection assertion read changed line offsets while development
continued; its entire 14-test module passed unchanged in a fresh process. The
other failure rejected a detection-registry capacity fixture; its isolated
test and entire module (10 passed, one skipped) passed unchanged. The original
underlying registry validation cause could not be recovered, so it is not
claimed to be fixed or attributed conclusively to scheduling. No safety gate
or fixture was relaxed. Exact-commit CI results are available through the
published commit's GitHub Actions runs.

Public images are synthetic and reproducible with
`python tools/capture_public_dashboard.py <destination.png>` and the optional
`--orbital` flag. Windows offscreen capture registers existing system fonts;
it neither installs fonts nor starts live sensors.
