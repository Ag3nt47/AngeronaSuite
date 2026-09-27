# Cycle 36 — Windows Chill/Full performance verification

**Source:** `5feda7322c44bc0d5cc0149b2ef5031573c557fd`. This was an
offscreen, real `MainWindow` and real module-worker run on the Windows host.
Discovery populated all 84 built-in modules in the UI inventory. The isolated
runtime enabled only Process Monitor, File Integrity Monitor (FIM), and YARA
Scanner; response actions were disabled. FIM and YARA inspected 128 benign
temporary files under one temporary drill root. FIM's supported explicit
watch-only setting and a test-only YARA root override kept personal files out
of the measurement. The production scanner implementations and MainWindow
refresh/mode-transition methods were unchanged.

A precise 20 ms Qt timer recorded event-loop scheduling slip; `psutil` sampled
this process's CPU time, RSS, and thread count each second. Each mode ran for
120 seconds after construction and discovery. CPU percentage below is process
CPU time divided by wall time, where 100% is one logical core.

| Mode | CPU / wall | RSS start → end | Peak RSS | Qt slip p99 / max | Gaps >250 ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Initial Chill | 13.219 / 120.078 s (11.01%) | 120.930 → 129.727 MiB | 129.727 MiB | 12 / 105 ms | 0 / 5,955 beats |
| Full | 41.906 / 120.000 s (34.92%) | 129.902 → 137.215 MiB | 162.613 MiB | 27 / 168 ms | 0 / 5,835 beats |
| Returned Chill | 9.922 / 120.000 s (8.27%) | 137.102 → 137.281 MiB | 137.305 MiB | 12 / 58 ms | 0 / 5,978 beats |

FIM and YARA each completed an actual first work cycle in Full and were
policy-paused on return to Chill. Process Monitor remained running in both
modes. The recorder's FIM receipt says `complete=true`, 128 files visited and
hashed (449,280 bytes), and zero errors. FIM health 45 is the intentional
`approval-required` candidate-baseline status, not a failed scan. A separate
10-second-per-mode repeat exited with code 0, confirmed both scanner cycles,
and measured the synchronous Chill→Full request at 16 ms and Full→Chill at
less than 1 ms. That shorter run's local scratch result is
`.tmp/cycle36_mode_soak_result.json` (ignored, not release evidence).

**Harness-exit diagnostic.** The first six-minute witness completed all
three phases but its `QApplication.quit()` request did not end the event loop.
A live `py-spy` native/Python stack showed the main thread idle inside
`QCoreApplication::exec`, before the harness cleanup block; Process Monitor
and GUI readers were still active. Angerona's `MainWindow.closeEvent`
intentionally ignores Close and hides to tray. An independent minimal
offscreen `QMainWindow` with the same ignored Close reproduced the behavior.
The scratch process was identified by exact PID/command and stopped. The
shorter repeat used `QApplication.exit(0)` as its bounded fallback, delivered
`aboutToQuit`, stopped modules, and exited normally. This is an exit-method
error in the witness harness; no production shutdown regression was found.

**Assessment and next measurement:** No freeze or sustained RSS growth was
reproduced after the return to Chill in this controlled run; Full used about
24 percentage points more of one core than initial Chill while real scanners
were active. Startup settling accounts for much of initial Chill's 8.8 MiB
RSS increase; Full briefly peaked another 32.7 MiB above its starting RSS
before settling. The run covered three selected real workers, an offscreen
platform, and six minutes. It cannot establish performance with all default
workers, a physical display driver, an approved FIM baseline, concurrent
Combat/quarantine I/O, or all-day operation. The next useful investigation is
a bounded physical-display/full-worker reproduction with per-module CPU and
Qt stall-stack attribution; do not change scan cadence or detection controls
on the strength of this isolated result.

| Optimization | Component | Status | Expected or measured win |
| --- | --- | --- | --- |
| Attribute a reported freeze under the full default worker set with Qt stall stacks and per-module CPU samples | MainWindow and worker runtime | **PROPOSED** | Separates GUI-thread blockage from scanner CPU or storage pressure before a behavior-preserving fix |
| Preserve current mode-transition path | MainWindow and selected real sensors | **INVESTIGATED; NO CHANGE** | 16 ms / <1 ms synchronous transition calls in the short repeat; zero >250 ms timer gaps in six minutes |

No product optimization was applied: the selected-worker witness did not
reproduce the reported freezing, and reducing live scan work without an
equivalent security proof would weaken coverage.
