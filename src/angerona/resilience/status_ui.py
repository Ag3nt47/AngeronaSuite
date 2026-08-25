"""status_ui.py — Angerona-themed monitor window for a resilience component.

Gives the standalone Scanner and Watchdog processes a window that matches
Angerona's look (same ``gui/theme.build_qss`` stylesheet). It is a pure PRESENTER
— it only reads the component's shared-memory heartbeat and its
``diagnostics/status_<component>.json`` on a timer, so the sensor stays lean.

Two tabs:
  * Status        — live heartbeat / state / PID / memory / counters + recent log.
  * Info          — what the component does, the modules it controls, related
                    source paths, isolated code copies, diagnostics, and restart.

Usage:
    python -m angerona.resilience.status_ui <component> [--title "..."] [--show]

Degrades gracefully with no PySide6 / no display (prints status on a loop).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from angerona.resilience import heartbeat as hb
from angerona.resilience import diagnostics as diag

# What each component is, in plain language (Info tab).
_DESCRIPTIONS = {
    "scanner": (
        "Telemetry Scanner — a standalone, low-footprint sensor process. It "
        "collects RAW operating-system telemetry (process creation, and more as "
        "sensors are added) with minimal processing and streams it to the Angerona "
        "core over a shared-memory ring. It makes NO security decisions itself — "
        "the core deciphers, correlates, and acts. Running it as its own process "
        "means heavy data collection can never freeze the Angerona UI."
    ),
    "watchdog": (
        "Watchdog — an out-of-process guardian. Angerona and the Watchdog watch "
        "EACH OTHER and restart each other after a crash or an adversary kill; the "
        "Watchdog also restarts the Scanner and BlackBox. It detects suspension "
        "(a frozen but still-present process) via the shared-memory heartbeat, and "
        "honours a signed stand-down token so maintenance can pause the self-healing."
    ),
    "core": (
        "Angerona Core — the brain and UI: AI triage, SOAR automation, correlation, "
        "and the dashboard. It supervises the Scanner and BlackBox and is itself "
        "kept alive by the Watchdog."
    ),
}


def _qss() -> str:
    try:
        from angerona.gui.theme import build_qss
        return build_qss(os.environ.get("ANGERONA_THEME", "cyber"))
    except Exception:
        return ""


def _read_status(component: str) -> dict:
    try:
        return json.loads((diag.diag_dir() / f"status_{component}.json").read_text(encoding="utf-8"))
    except Exception:
        return {}


def _hb_state(component: str) -> str:
    try:
        return hb.HeartbeatReader(component).classify(stale_after_s=3.0)
    except Exception:
        return "unknown"


def _monitor_refresh_interval_ms(*, visible: bool, minimized: bool, active: bool) -> int:
    """Presentation cadence only; supervision remains in the sidecar process."""
    return 1_000 if visible and not minimized and active else 10_000


def build_status_widget(component: str, title: str | None = None):
    """Return a themed, tabbed QWidget presenting <component>. Requires PySide6."""
    from PySide6.QtCore import QEvent, Qt, QTimer
    from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
                                   QGroupBox, QLabel, QTextEdit, QTabWidget,
                                   QListWidget, QPushButton, QMessageBox)

    class MonitorWidget(QWidget):
        def __init__(self):
            super().__init__()
            self.component = component
            root = QVBoxLayout(self)
            hdr = QLabel(title or f"Angerona · {component.capitalize()}")
            hdr.setStyleSheet("font-size:16px; font-weight:bold;")
            root.addWidget(hdr)

            tabs = QTabWidget()
            root.addWidget(tabs)
            tabs.addTab(self._status_tab(), "Status")
            tabs.addTab(self._info_tab(), "Info")

            self._timer = QTimer(self)
            self._timer.timeout.connect(self.refresh)
            self._timer.start(10_000)
            self._last_log_line = ""
            self._last_modules: tuple[str, ...] | None = None
            self.refresh()

        def _sync_refresh_timer(self):
            window = self.window()
            interval = _monitor_refresh_interval_ms(
                visible=bool(window and window.isVisible()),
                minimized=bool(window and window.isMinimized()),
                active=bool(window and window.isActiveWindow()),
            )
            if self._timer.interval() != interval:
                self._timer.setInterval(interval)

        def showEvent(self, event):  # noqa: N802 (Qt signature)
            super().showEvent(event)
            QTimer.singleShot(0, self._sync_refresh_timer)

        def hideEvent(self, event):  # noqa: N802 (Qt signature)
            super().hideEvent(event)
            QTimer.singleShot(0, self._sync_refresh_timer)

        def changeEvent(self, event):  # noqa: N802 (Qt signature)
            super().changeEvent(event)
            if event.type() in (QEvent.WindowStateChange, QEvent.ActivationChange):
                QTimer.singleShot(0, self._sync_refresh_timer)

        # ── Status tab ───────────────────────────────────────────────────────
        def _status_tab(self):
            w = QWidget(); lay = QVBoxLayout(w)
            g = QGroupBox("Live status"); form = QFormLayout(g)
            self._heartbeat = QLabel("—"); self._state = QLabel("—")
            self._pid = QLabel("—"); self._rss = QLabel("—"); self._extra = QLabel("—")
            form.addRow("Heartbeat:", self._heartbeat)
            form.addRow("State:", self._state)
            form.addRow("PID:", self._pid)
            form.addRow("Memory (MB):", self._rss)
            form.addRow("Details:", self._extra)
            lay.addWidget(g)
            lg = QGroupBox("Recent"); lgl = QVBoxLayout(lg)
            self._log = QTextEdit(); self._log.setReadOnly(True)
            lgl.addWidget(self._log); lay.addWidget(lg)
            return w

        # ── Info & Control tab ───────────────────────────────────────────────
        def _info_tab(self):
            w = QWidget(); lay = QVBoxLayout(w)
            desc = QLabel(_DESCRIPTIONS.get(self.component,
                                            f"Angerona resilience component: {self.component}."))
            desc.setWordWrap(True)
            lay.addWidget(desc)

            mg = QGroupBox("Modules under its control")
            mgl = QVBoxLayout(mg)
            self._modules = QListWidget()
            mgl.addWidget(self._modules)
            lay.addWidget(mg)

            from angerona.core.source_sandbox import SourceSandboxWorkspace

            component_paths = {
                "scanner": (
                    "src/angerona/resilience/status_ui.py",
                    "src/angerona/resilience/scanner.py",
                ),
                "watchdog": (
                    "src/angerona/resilience/status_ui.py",
                    "src/angerona/resilience/watchdog.py",
                    "src/angerona/resilience/supervisor.py",
                ),
                "core": (
                    "src/angerona/resilience/status_ui.py",
                    "src/angerona/app.py",
                    "src/angerona/gui/main_window.py",
                ),
            }
            self._source_workspace = SourceSandboxWorkspace(
                f"resilience-{self.component}",
                component_paths.get(
                    self.component,
                    ("src/angerona/resilience/status_ui.py",),
                ),
            )
            locations = QLabel(
                "Related source files\n" + "\n".join(
                    f"  {item.source_path}" for item in self._source_workspace.files
                ) + f"\nSandbox location\n  {self._source_workspace.root}"
            )
            locations.setWordWrap(True)
            locations.setTextInteractionFlags(Qt.TextSelectableByMouse)
            locations.setStyleSheet("color:#94a3b8;font-family:monospace;")
            lay.addWidget(locations)

            btns = QHBoxLayout()
            b_sandbox = QPushButton("Open Code Sandbox")
            b_sandbox.clicked.connect(self._open_sandbox)
            b_reset = QPushButton("Reset Sandbox Changes")
            b_reset.clicked.connect(self._reset_sandbox)
            b_diag = QPushButton("Open Diagnostics Folder")
            b_diag.clicked.connect(self._open_diag)
            b_restart = QPushButton(f"Restart {self.component.capitalize()}")
            b_restart.clicked.connect(self._restart)
            btns.addWidget(b_sandbox); btns.addWidget(b_reset)
            btns.addWidget(b_diag); btns.addWidget(b_restart)
            if self.component == "watchdog":
                b_core = QPushButton("Restart Angerona Core")
                b_core.setObjectName("Danger")
                b_core.setToolTip(
                    "Authenticated manual recovery: clears Core SAFE_MODE and "
                    "asks the Watchdog to terminate and relaunch Angerona."
                )
                b_core.clicked.connect(self._restart_core)
                btns.addWidget(b_core)
            lay.addLayout(btns)
            return w

        # ── actions ──────────────────────────────────────────────────────────
        def _open_sandbox(self):
            try:
                from angerona.gui.context_info import SourceSandboxDialog

                self._source_sandbox_dialog = SourceSandboxDialog(
                    self._source_workspace, self
                )
                self._source_sandbox_dialog.show()
                self._source_sandbox_dialog.raise_()
                self._source_sandbox_dialog.activateWindow()
            except Exception as exc:
                QMessageBox.warning(self, "Sandbox", f"Could not launch the sandbox editor:\n{exc}")

        def _reset_sandbox(self):
            changed = self._source_workspace.changed_paths()
            if not changed:
                QMessageBox.information(
                    self, "Sandbox", "Sandbox copies already match installed source."
                )
                return
            if QMessageBox.question(
                self,
                "Reset sandbox changes",
                f"Discard changes in {len(changed)} isolated working copy file(s)? "
                "Installed code will not be changed.",
            ) != QMessageBox.Yes:
                return
            self._source_workspace.reset()
            QMessageBox.information(
                self, "Sandbox", "Sandbox copies reset; installed code was not changed."
            )

        def _open_diag(self):
            try:
                d = str(diag.diag_dir())
                if os.name == "nt":
                    os.startfile(d)   # type: ignore[attr-defined]
                else:
                    subprocess.Popen(["xdg-open", d])
            except Exception as exc:
                QMessageBox.warning(self, "Diagnostics", f"Could not open the folder:\n{exc}")

        def _restart(self):
            if QMessageBox.question(
                    self, "Restart",
                    f"Restart {self.component}? This clears SAFE_MODE and asks its "
                    "supervisor to relaunch it.") != QMessageBox.Yes:
                return
            self._request_restart(self.component, self.component.capitalize())

        def _restart_core(self):
            if QMessageBox.question(
                    self, "Restart Angerona Core",
                    "Restart the Angerona Core and dashboard now?\n\n"
                    "The Watchdog will clear Core SAFE_MODE, stop the current Core "
                    "if it is still present, and launch a clean replacement."
                    ) != QMessageBox.Yes:
                return
            self._request_restart("core", "Angerona Core")

        def _request_restart(self, target: str, label: str):
            try:
                from angerona.resilience.supervisor import request_restart
                written = request_restart(target)
                if not written:
                    raise RuntimeError(
                        "the authenticated restart request could not be written"
                    )
                QMessageBox.information(
                    self, "Restart requested",
                    f"{label} restart requested. The supervisor will clear "
                    "SAFE_MODE and relaunch it on the next watchdog tick.",
                )
            except Exception as exc:
                QMessageBox.warning(
                    self, "Restart",
                    f"Could not request the {label} restart:\n{exc}",
                )

        # ── refresh ──────────────────────────────────────────────────────────
        def refresh(self):
            st = _read_status(self.component)
            hbst = _hb_state(self.component)
            self._heartbeat.setText(hbst)
            self._state.setText(str(st.get("state", "—")))
            self._pid.setText(str(st.get("pid", "—")))
            self._rss.setText(str(st.get("rss_mb", "—")))
            bits = []
            for k in ("events_forwarded", "dropped", "ring_backpressure",
                      "frames_ingested", "supervised", "safe_mode", "restarts"):
                if k in st:
                    bits.append(f"{k}={st[k]}")
            self._extra.setText(", ".join(bits) if bits else "—")
            ts = st.get("ts_iso") or ""
            if ts:
                line = f"[{ts}] {hbst}"
                if self._last_log_line != line:
                    self._log.append(line)
                    self._last_log_line = line
            # modules list
            if self.component == "scanner":
                modules = tuple(
                    [f"● {s}" for s in st.get("sensors", []) or ["(sensor list pending)"]]
                    + ["— downstream: core modules act on this raw feed —"]
                )
            elif self.component == "watchdog":
                modules = tuple(
                    f"● keeps alive: {s}"
                    for s in st.get("supervised", []) or ["(none yet)"]
                )
            else:
                modules = tuple(f"● {s}" for s in st.get("supervised", []))
            if modules != self._last_modules:
                self._modules.clear()
                self._modules.addItems(list(modules))
                self._last_modules = modules

    return MonitorWidget()


def run_window(component: str, title: str | None = None, show: bool = False) -> int:
    try:
        from PySide6.QtWidgets import QApplication, QMainWindow
    except Exception:
        return _run_headless(component)
    app = QApplication.instance() or QApplication(sys.argv)
    qss = _qss()
    if qss:
        app.setStyleSheet(qss)
    win = QMainWindow()
    win.setWindowTitle(title or f"Angerona — {component.capitalize()} Monitor")
    win.setCentralWidget(build_status_widget(component, title))
    win.resize(560, 520)
    try:
        from angerona.core.config import Config
        motion_config = Config.load()
    except Exception:
        motion_config = None
    if show:
        from angerona.gui.header_controls import show_with_window_reveal
        show_with_window_reveal(win, config=motion_config)
    else:
        from angerona.gui.header_controls import install_global_window_reveal
        install_global_window_reveal(win, config=motion_config)
        win.showMinimized()
    return app.exec()


def _run_headless(component: str) -> int:
    try:
        while True:
            st = _read_status(component)
            print(f"[{component}] hb={_hb_state(component)} state={st.get('state')} "
                  f"pid={st.get('pid')} rss={st.get('rss_mb')}", flush=True)
            time.sleep(2.0)
    except KeyboardInterrupt:
        return 0


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("component")
    ap.add_argument("--title", default=None)
    ap.add_argument("--show", action="store_true")
    a = ap.parse_args(argv)
    return run_window(a.component, a.title, a.show)


if __name__ == "__main__":
    raise SystemExit(main())
