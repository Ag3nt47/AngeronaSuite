"""status_ui.py — Angerona-themed monitor window for a resilience component.

Gives the standalone Scanner and Watchdog processes a window that matches
Angerona's look (same ``gui/theme.build_qss`` stylesheet). It is a pure PRESENTER
— it only reads the component's shared-memory heartbeat and its
``diagnostics/status_<component>.json`` on a timer, so the sensor stays lean.

Two tabs:
  * Status        — live heartbeat / state / PID / memory / counters + recent log.
  * Info & Control — what the component does, the modules it controls, and
                     buttons (Sandbox code editor, open diagnostics, restart).

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


def build_status_widget(component: str, title: str | None = None):
    """Return a themed, tabbed QWidget presenting <component>. Requires PySide6."""
    from PySide6.QtCore import Qt, QTimer
    from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
                                   QGroupBox, QLabel, QTextEdit, QTabWidget,
                                   QListWidget, QPushButton, QMessageBox)

    pyw = os.environ.get("ANGERONA_PY") or sys.executable

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
            tabs.addTab(self._info_tab(), "Info & Control")

            self._timer = QTimer(self)
            self._timer.timeout.connect(self.refresh)
            self._timer.start(1000)
            self.refresh()

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

            btns = QHBoxLayout()
            b_sandbox = QPushButton("Sandbox Code Editor")
            b_sandbox.clicked.connect(self._open_sandbox)
            b_diag = QPushButton("Open Diagnostics Folder")
            b_diag.clicked.connect(self._open_diag)
            b_restart = QPushButton(f"Restart {self.component.capitalize()}")
            b_restart.clicked.connect(self._restart)
            btns.addWidget(b_sandbox); btns.addWidget(b_diag); btns.addWidget(b_restart)
            lay.addLayout(btns)
            return w

        # ── actions ──────────────────────────────────────────────────────────
        def _open_sandbox(self):
            try:
                subprocess.Popen([pyw, "-m", "angerona.gui.sandbox_editor"])
            except Exception as exc:
                QMessageBox.warning(self, "Sandbox", f"Could not launch the sandbox editor:\n{exc}")

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
            # Kill the component by PID; its supervisor (core manager / watchdog)
            # respawns it automatically.
            st = _read_status(self.component)
            pid = st.get("pid")
            if not pid:
                QMessageBox.information(self, "Restart", "No live PID reported yet.")
                return
            if QMessageBox.question(self, "Restart",
                                    f"Terminate {self.component} (PID {pid})? "
                                    "It will be restarted automatically.") != QMessageBox.Yes:
                return
            try:
                import psutil
                psutil.Process(int(pid)).terminate()
                QMessageBox.information(self, "Restart",
                                        f"{self.component} (PID {pid}) terminated — the supervisor "
                                        "will bring it back.")
            except Exception as exc:
                QMessageBox.warning(self, "Restart", f"Could not terminate PID {pid}:\n{exc}")

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
                cur = self._log.toPlainText().splitlines()[-1:] if self._log.toPlainText() else []
                if cur != [line]:
                    self._log.append(line)
            # modules list
            self._modules.clear()
            if self.component == "scanner":
                for s in st.get("sensors", []) or ["(sensor list pending)"]:
                    self._modules.addItem(f"● {s}")
                self._modules.addItem("— downstream: core modules act on this raw feed —")
            elif self.component == "watchdog":
                for s in st.get("supervised", []) or ["(none yet)"]:
                    self._modules.addItem(f"● keeps alive: {s}")
            else:
                for s in st.get("supervised", []):
                    self._modules.addItem(f"● {s}")

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
    if show:
        win.show()
    else:
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
