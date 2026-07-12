"""Application wiring: builds the core services and the GUI, and ties them
together. Keep this thin — real logic lives in core/ and modules/."""
from __future__ import annotations

from PySide6.QtWidgets import QApplication

from angerona.core import autostart
from angerona.core.config import Config
from angerona.core.eventbus import EventBus
from angerona.core.storage import FlightRecorder
from angerona.core.module_manager import ModuleManager
from angerona.core.status_report import StatusReporter
from angerona.gui.main_window import MainWindow


class AngeronaApp:
    """Owns the lifecycle of every long-lived service."""

    def __init__(self, qt: QApplication) -> None:
        self.qt = qt
        self.config = Config.load()
        # Keep the Windows logon scheduled task in sync with the user's
        # actual setting on every launch — cheap (schtasks /create /f is
        # idempotent) and self-healing if the task was ever removed
        # outside the app. Never allowed to block/break startup.
        try:
            autostart.sync(self.config.autostart_enabled)
        except Exception:
            pass
        self.storage = FlightRecorder(self.config.db_path)
        self.bus = EventBus()

        # Persist every event the moment it is published.
        self.bus.subscribe(self.storage.record)

        # Correlate the flat event stream into scored incidents (O(1)/event).
        from angerona.core.incidents import get_correlator
        self.bus.subscribe(get_correlator().on_event)

        # Initialise the remediation audit log (same DB, separate table).
        from angerona.core.remediation_log import init_log
        init_log(self.config.db_path)

        # Initialise the ATT&CK heat tracker and wire it to every bus event.
        from angerona.core.attack_tracker import init_tracker
        self.bus.subscribe(init_tracker().on_event)

        self.manager  = ModuleManager(self.bus, self.config)
        self.reporter = StatusReporter(self.bus, self.storage, self.manager, self.config)

        # MCP server — opt-in loopback tool server for Claude Desktop / Claude Code.
        # Exposes six read-only security-data tools; nothing leaves the machine.
        # Enable in Settings ▸ MCP, or set mcp_enabled=true in settings.json.
        self._mcp: object | None = None
        if getattr(self.config, "mcp_enabled", False):
            try:
                from angerona.engines.mcp_server import AngeronaMCPServer
                self._mcp = AngeronaMCPServer(
                    self.storage, self.bus, self.manager, self.config)
            except Exception:
                pass   # MCP failure must never block startup

        self.window = MainWindow(self.bus, self.storage, self.manager, self.config)

    def start(self) -> None:
        # Show the window immediately so the user sees a responsive UI.
        # Module discovery (37 importlib.import_module calls) and thread
        # starts are deferred to a background thread via a zero-delay timer
        # so the event loop gets at least one paint cycle first.
        self.window.show()
        self.qt.aboutToQuit.connect(self.shutdown)
        from PySide6.QtCore import QTimer
        # Let the window actually paint and become interactive before kicking off
        # the ~40-module import burst. A zero-delay timer can fire before the OS
        # has composited the first frame; a short delay guarantees a clean, centered
        # first paint so the app *feels* up immediately.
        QTimer.singleShot(120, self._deferred_start)
        # Launch the decoupled Black Box diagnostic recorder alongside the suite
        # (separate process, read-only, survives a suite deadlock). Slightly later
        # so it never competes with the suite's own first paint.
        QTimer.singleShot(800, self._launch_blackbox)

    # ── Black Box diagnostic recorder (decoupled sidecar) ────────────────────
    def _launch_blackbox(self, force: bool = False) -> None:
        """Start blackbox_recorder.py as an independent, tray-resident process.

        Shares nothing with the suite (read-only file tailing) so we spawn it
        detached, with ``--show`` so its window actually appears. Its stdout/stderr
        are captured to ``<data_dir>/logs/blackbox.log`` so a startup crash is
        diagnosable, and a liveness check reports to the console if it dies fast
        (the usual cause: PySide6-Addons/QtCharts missing — now handled gracefully
        in the recorder itself). Single-instance guarded; fail-open."""
        if not force and not getattr(self.config, "blackbox_enabled", True):
            return
        try:
            import os
            import subprocess
            import sys
            from pathlib import Path

            # blackbox_recorder.py lives at the repo root (…/AngeronaSuite/); fall
            # back to the CWD in case the layout differs.
            bb = None
            for cand in (Path(__file__).resolve().parents[2] / "blackbox_recorder.py",
                         Path.cwd() / "blackbox_recorder.py"):
                try:
                    if cand.exists():
                        bb = cand
                        break
                except Exception:
                    continue
            if bb is None:
                self._blackbox_note("blackbox_recorder.py not found — cannot launch.")
                return

            # Single-instance guard: skip if a recorder is already running.
            if not force:
                try:
                    import psutil
                    me = os.getpid()
                    for p in psutil.process_iter(["pid", "cmdline"]):
                        if p.info["pid"] == me:
                            continue
                        if "blackbox_recorder" in " ".join(p.info.get("cmdline") or []).lower():
                            return   # already up — leave it
                except Exception:
                    pass

            # Prefer a windowless interpreter so no console flashes.
            exe = sys.executable
            creationflags = 0
            if sys.platform.startswith("win"):
                pyw = Path(exe).with_name("pythonw.exe")
                if pyw.exists():
                    exe = str(pyw)
                creationflags = 0x08000000  # CREATE_NO_WINDOW

            # Capture output so a crash-on-startup is recoverable.
            try:
                logdir = Path(self.config.data_dir) / "logs"
                logdir.mkdir(parents=True, exist_ok=True)
                logf = open(logdir / "blackbox.log", "ab", buffering=0)
            except Exception:
                logf = subprocess.DEVNULL

            self._blackbox_proc = subprocess.Popen(
                [exe, str(bb), "--show"],
                cwd=str(bb.parent),
                creationflags=creationflags,
                stdin=subprocess.DEVNULL,
                stdout=logf,
                stderr=logf,
                close_fds=True,
            )
            from PySide6.QtCore import QTimer
            QTimer.singleShot(3500, self._check_blackbox_alive)
        except Exception as exc:
            self._blackbox_note(f"failed to launch: {exc}")

    def _check_blackbox_alive(self) -> None:
        proc = getattr(self, "_blackbox_proc", None)
        if proc is None:
            return
        if proc.poll() is None:
            self._blackbox_note("recorder launched — check the system tray "
                                "(Angerona Black Box).")
            return
        code = proc.poll()
        tail = ""
        try:
            from pathlib import Path
            logp = Path(self.config.data_dir) / "logs" / "blackbox.log"
            if logp.exists():
                tail = logp.read_bytes()[-1400:].decode("utf-8", "replace").strip()
        except Exception:
            pass
        self._blackbox_note(
            f"recorder exited immediately (code {code}). Last output:\n"
            + (tail or "(no output captured — see logs/blackbox.log)"))

    def _blackbox_note(self, msg: str) -> None:
        try:
            self.window.console._append("[blackbox] " + msg)
        except Exception:
            pass

    def _deferred_start(self) -> None:
        """Called on the main thread after the first event-loop cycle.
        Spawns a background thread for the slow work so the GUI stays
        responsive while modules import and start."""
        import threading
        threading.Thread(target=self._load_modules, daemon=True,
                         name="ModuleLoader").start()

    def _load_modules(self) -> None:
        """Background thread — no Qt widget access here, only thread-safe
        bus/manager calls. Qt signals emitted by modules are automatically
        queued to the main thread by the Qt runtime."""
        self.manager.discover()        # find built-in + drop-in modules
        self.manager.start_enabled()   # launch the ones that are enabled
        # If the user's saved preference is Eco Mode, pause the heavy scanners now
        # (hops to the GUI thread via a queued signal — no widget access here).
        try:
            self.window.startup_eco_requested.emit()
        except Exception:
            pass
        self.reporter.start()          # begin writing diagnostics/status.txt
        # Start MCP server after modules are loaded so all tools have live data
        if self._mcp is not None:
            try:
                self._mcp.start()
            except Exception:
                self._mcp = None   # port bind failure → silently disable

    def shutdown(self) -> None:
        self.reporter.stop()
        if self._mcp is not None:
            try:
                self._mcp.stop()
            except Exception:
                pass
        self.manager.stop_all()
        self.storage.close()
