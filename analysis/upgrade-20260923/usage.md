# Using the September 23 upgrades

Run the commands below from the repository with its installed Python environment
active. On Windows, use the ordinary-user source environment; do not elevate a
mutable source checkout. Restart Angerona after updating its files.

## Automatic defense and Shark reports

Ollama is optional. Deterministic detection and the configured response worker
operate without a model. In the full workbench, check **Settings → Adversary
Combat** and its current readiness before running a drill. A configured policy
does not make a stopped worker or missing sensor ready.

The repaired YARA path binds a real positive scan to the exact observed file
content. Eligible actions pass through the live worker and produce verified
signed results; supported quarantine actions expose Undo. If the file changed,
the producer restarted, evidence expired or prerequisites are unavailable,
the report must retain that uncertainty. A clean test directory or completed
probe is not evidence of containment. The original 21-step screenshot is not
retroactively converted into a passing run.

## Keep alert copies within limits

Open **Settings → System → Automatic alert archive cleanup**. Defaults are
enabled, **30 days**, and **256 MiB**. Adjust the age to 1–3,650 days or the
storage target to 8–16,384 MiB, then save. Initial setup exposes the same options.
**Clean archives now** uses the saved settings; **Refresh status** shows managed
bytes, removed archives, pins, queue drops and write failures.

The active `diagnostics/runtime_alerts.log` rotates at 4 MiB. Cleanup starts
after a one-minute grace period, ordinarily checks every 15 minutes, and makes
bounded progress through larger directories. Eligible closed archives are
removed by age or oldest-first to reduce managed storage. To retain a specific
closed archive, create an empty sibling named with its complete filename plus
`.keep`. Pinned, active or inaccessible files can keep usage above the target.

This deletes disposable diagnostic copies permanently. It excludes signed event
history, pending events, response/recovery journals, cases, backups and exports.
Disabling cleanup still rotates the active file but lets archives grow. The
settings keys are `alert_retention_enabled`, `alert_retention_days` and
`alert_retention_max_mib`; the UI validates and saves them.

## Run protection independently of the console

Quit the normal workbench using the tray menu's **Quit** action before switching
to the optional detached engine. Closing its window only hides it:

```text
python -m angerona --engine-console
```

The console starts or reconnects to the ordinary-user engine and displays
readiness, module state, recent events and response status. It supports module
enable/disable, restart, self-test, Chill mode and alert-retention settings.
Closing the console leaves the engine running. Use **Stop protection…** when
you intend to stop its workers. The console is a smaller operational interface;
the full workbench's investigation and Lab panels have not all been moved into it.

Command-line status and explicit stop are also available:

```text
python -m angerona.core.persistent_engine status
python -m angerona.core.persistent_engine stop --confirm-stop-protection
```

For optional native per-user startup:

```text
python tools/manage_engine.py install-user
python tools/manage_engine.py remove-user
```

Installation uses an ordinary-user Windows logon task, a macOS LaunchAgent or
a Linux systemd user service. Existing definitions are not silently replaced.
Windows/macOS protection depends on the signed-in user session; Linux depends
on its user service manager. Windows removal deletes automatic startup without
stopping an already running engine; use explicit stop if needed. macOS/Linux
removal unloads/stops the corresponding user service. This workflow does not
install a privileged Windows SCM service.

## Measure resource use over time

The soak tool measures the specified process tree and its retained identities.
Supply `--include-pid` for a separately started process you own, such as Ollama;
it does not infer ownership from a process name. Replace `1234` below with the
actual engine PID shown by its status:

```text
python tools/run_soak.py --profile smoke --pid 1234 --engine-metrics --output engine-smoke.json
python tools/run_soak.py --profile 24h --pid 1234 --engine-metrics --output engine-24h.json
```

Profiles also include `8h` and `7d`. Long profiles require a PID and runtime
metrics. The authenticated engine route measures real queues and marks GUI
latency not applicable. To measure the full GUI, set
`ANGERONA_RUNTIME_METRICS=1` **before launching Angerona**. It writes
`diagnostics/runtime-metrics-PID.json` every ten seconds off the UI thread.
Use that file with the matching process:

```text
python tools/run_soak.py --profile 24h --pid 1234 --metrics-json "PATH/diagnostics/runtime-metrics-1234.json" --output gui-24h.json
```

File metrics must match the exact PID birth and be fresh; stale or incomplete
data does not become zero usage. The console can publish its own GUI metrics,
separate from its engine. A long run needs actual elapsed time and representative
workloads. Short smoke results cannot establish a 24-hour/7-day pass. CPU is
normalized to host logical CPU capacity; process I/O counters are not physical
disk traffic, summed RSS may double-count shared pages, and polling can miss
children that start and exit between samples.

## Enroll AI instruction and tool files

Observe an explicitly selected file, review its digest, then enroll that exact
digest. Example for a file outside Angerona's own runtime:

```text
python tools/manage_agent_integrity.py observe "PATH/AGENTS.md" --kind instruction
python tools/manage_agent_integrity.py enroll "PATH/AGENTS.md" --kind instruction --sha256 REVIEWED_DIGEST --approve
python tools/manage_agent_integrity.py check
```

Supported kinds are `instruction`, `memory` and `tool-definition`. Default
enrollment applies to Angerona's integrated Assistant/broker tools. Repeat
`--tool NAME` to restrict the mapping, or use `--monitor-only` to observe drift
without gating actions. To approve an intentional edit, observe it again and
use `accept-change` with its new exact digest and `--approve`.

The guard checks enrolled bytes and declared tool mappings; it does not decide
that arbitrary file contents are trustworthy. Windows retains file custody
during mapped actions. POSIX read-only drift checks are available, but mapped
mutations are withheld without immutable consumer custody. Enrollment does not
police external agents or enforce their network connections. Full local-state
rollback requires an independent authority beyond this local baseline.

## Test encrypted recovery

Start with three small inert files:

```text
python tools/run_recovery_drill.py --fixture
python tools/run_recovery_drill.py --verify "DRILL_DIRECTORY_FROM_RESULT"
```

To test selected real files, use an existing source directory and repeat
`--file` for explicit relative selections:

```text
python tools/run_recovery_drill.py --source "PATH/Documents" --file "example.txt" --output-parent "PATH/ExistingDrills"
```

The workflow makes an encrypted archive and restores into a new private drill
directory. It does not overwrite original files. Private plaintext restored
copies remain; temporary snapshots are removed after successful verification.
Archive/drill data is excluded from alert cleanup. Keys stay in the current
user's OS credential store. Losing that
account or store can prevent recovery. A same-machine drill verifies the
restore workflow; it does not prove an independent, offline or offsite backup.

## Compare detection packages with labelled events

```text
python tools/evaluate_detections.py --active examples/cohorts/active.json --candidate examples/cohorts/candidate.json --cohort examples/cohorts/labelled.json --output detection-comparison.json
```

The supplied fixtures demonstrate rule tradeoffs with authored synthetic
labels. Add `--max-false-positives` and/or `--max-false-negatives` for a quality
gate; without thresholds the result is measured rather than a promotion pass.
Incomplete or unlabelled evidence withholds quality conclusions. Replay does
not install candidate rules, execute attacks or replace native sensor-to-action
acceptance.
