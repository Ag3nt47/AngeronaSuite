"""scanner.py — standalone Telemetry Scanner process.

Runs as its OWN low-footprint process (``python -m angerona.resilience.scanner``),
independent of the Angerona core. It collects RAW system telemetry with minimal
processing and streams it into the shared-memory ring (`ipc_ring`) for the core to
decipher and act on — the scanner itself makes no security decisions.

Responsibilities (deliberately thin — the core is the brain):
  * Collect: a low-overhead process-creation sensor (psutil table diff). More
    sensors can be added; each just emits raw frames.
  * Forward: write raw frames into the ring; if the ring signals backpressure,
    omit optional enrichment; raw observations are still forwarded.
  * Stay alive & visible: beat the shared-memory heartbeat every loop, and write
    an atomic ``status`` diagnostic the BlackBox can read.
  * Cooperate: exit cleanly when a signed stand-down token is present; echo a
    ping nonce into its status so the core's self-test can prove the loop.

Config via env / argv:
  ANGERONA_SCANNER_INTERVAL   poll seconds (default 1.0)
  ANGERONA_DATA               data root (heartbeats/ipc live here)
"""
from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
import threading
import time
from typing import Callable, Iterable

from angerona.resilience import ipc_ring
from angerona.resilience import heartbeat as hb
from angerona.resilience import shutdown_token as tok
from angerona.resilience import diagnostics as diag

# Sensor ids (stable, so the core can attribute raw frames).
SENSOR_PROC = 1

SCHEMA = 1

# Liveness is carried by the mmap heartbeat every scanner loop.  The JSON file
# is human-facing diagnostics, so a slower heartbeat is sufficient; ping and
# backpressure transitions still force an immediate update.
STATUS_INTERVAL_S = 30.0
PING_POLL_INTERVAL_S = 2.0
RING_RETRY_INTERVAL_S = 30.0


_COMMAND_SECRET_PATTERNS = (
    re.compile(
        r"(?i)((?:--?|/)?(?:password|passwd|pwd|token|api[-_]?key|"
        r"secret|authorization|credential)(?:\s*[:=]\s*|\s+))"
        r"(?:\"[^\"]*\"|'[^']*'|\S+)"
    ),
    re.compile(r"(?i)(\bBearer\s+)[A-Za-z0-9._~+/=-]+"),
)


def _redact_command_line(parts: object) -> str:
    """Render a useful command line without persisting common inline secrets."""
    if not isinstance(parts, (list, tuple)):
        return ""
    try:
        text = subprocess.list2cmdline([str(part) for part in parts])
    except Exception:
        text = " ".join(str(part) for part in parts)
    text = text.replace("\x00", "")
    for pattern in _COMMAND_SECRET_PATTERNS:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text[:1024]


def _process_evidence(process, parent_name: str, psutil_module) -> dict:
    """Enrich only a newly-created PID, keeping the recurring table diff cheap."""
    location_status = "unavailable"
    command_line_status = "unavailable"
    executable = ""
    command_line = ""
    try:
        executable = str(process.exe() or "").replace("\x00", "")[:1024]
        location_status = "resolved" if executable else "unavailable"
    except psutil_module.AccessDenied:
        location_status = "access_denied"
    except psutil_module.NoSuchProcess:
        location_status = "process_exited"
    except Exception:
        location_status = "unavailable"
    try:
        command_line = _redact_command_line(process.cmdline())
        command_line_status = "resolved" if command_line else "unavailable"
    except psutil_module.AccessDenied:
        command_line_status = "access_denied"
    except psutil_module.NoSuchProcess:
        command_line_status = "process_exited"
    except Exception:
        command_line_status = "unavailable"
    return {
        "exe": executable,
        "location_status": location_status,
        "cmdline": command_line,
        "command_line_status": command_line_status,
        "parent_name": str(parent_name or "").replace("\x00", "")[:512],
    }


class RawProcessSensor:
    """Low-overhead process-creation sensor: diffs the process table and emits a
    raw frame per newly-seen pid. No correlation — just facts."""
    sensor_id = SENSOR_PROC

    def __init__(self) -> None:
        self._known: set[int] = set()
        self._seeded = False

    def poll(self, *, enrich: bool = True) -> Iterable[bytes]:
        try:
            import psutil
        except Exception:
            return []
        current: set[int] = set()
        # The recurring diff needs only the native PID list. process_iter(attrs)
        # still builds/updates a Process.info dictionary per host process, even
        # with just ["pid"]. Construct identity-bound Process objects only for
        # newly observed additions, never for a baseline or shed telemetry.
        for value in psutil.pids():
            try:
                pid = int(value)
                current.add(pid)
            except Exception:
                continue
        frames: list[bytes] = []
        if self._seeded:
            for pid in sorted(current - self._known):
                if not enrich:
                    # Preserve raw additions while omitting optional metadata.
                    # An unauthenticated consumer ACK cannot veto telemetry.
                    frames.append(json.dumps({"type": "process_creation", "pid": pid}).encode())
                    continue
                try:
                    process = psutil.Process(pid)
                    with process.oneshot():
                        parent = process.ppid()
                        name = process.name() or "unknown"
                        parent_name = ""
                        if isinstance(parent, int) and parent > 0:
                            try:
                                parent_name = psutil.Process(parent).name() or ""
                            except Exception:
                                pass
                        evidence = _process_evidence(
                            process,
                            parent_name,
                            psutil,
                        )
                except psutil.NoSuchProcess:
                    # Do not retain a disappeared addition as already seen;
                    # its PID may belong to a replacement on the next poll.
                    current.discard(pid)
                    continue
                except psutil.AccessDenied:
                    continue
                except Exception:
                    continue
                rec = {"type": "process_creation", "pid": pid,
                       "ppid": parent,
                       "name": name,
                       "ts": time.time()}
                rec.update(evidence)
                frames.append(json.dumps(rec, separators=(",", ":")).encode("utf-8"))
        else:
            self._seeded = True     # first pass = baseline, don't flood
        self._known = current
        return frames


class ScannerHost:
    def __init__(self, interval: float = 1.0, ring_name: str = "telemetry",
                 token_raw: bytes | None = None):
        interval = float(interval)
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError("Scanner interval must be a finite positive number")
        self.interval = max(0.05, interval)
        self.ring = None
        self._ring_name = ring_name
        self._ring_state, self._ring_error = "unmeasured", ""
        self._ring_retry_at = 0.0
        self._ring_close_failed = False
        self._ring_failures = 0
        self._ring_drops = 0
        self._events = self._dropped = self._enrichment_omitted = 0
        self._stop = False
        self._shutdown_started = False
        # Set only by the worker after authenticated operator STOP admission.
        # A stopped/failed worker alone must not close the diagnostic window.
        self._authenticated_standdown = False
        self._stop_event = threading.Event()
        self._run_claim = threading.Lock()
        self._last_status = self._last_ping_poll = 0.0
        self._last_ping = ""
        self._last_backpressure = False
        self._last_ring_state = "unmeasured"
        self.sensors = [RawProcessSensor()]
        self._connect_ring(time.monotonic())
        try:
            self.beat = hb.HeartbeatWriter(hb.COMPONENT_SCANNER if hasattr(hb, "COMPONENT_SCANNER")
                                           else "scanner", token_raw=token_raw)
        except BaseException as original:
            try:
                self._close_ring()
            except BaseException as cleanup:
                raise original from cleanup
            raise
        self._last_backpressure = self._pressure(time.monotonic())

    def _ring_fault(self, operation: str, error: Exception, now: float, *, advisory=False):
        self._ring_failures += 1
        self._ring_state = "degraded" if advisory else "unavailable"
        self._ring_error = operation + "/" + type(error).__name__
        if not advisory:
            self._ring_retry_at = now + RING_RETRY_INTERVAL_S

    def _connect_ring(self, now: float) -> bool:
        if self.ring is None and not self._ring_close_failed and now >= self._ring_retry_at:
            try:
                self.ring = ipc_ring.RingWriter(ipc_ring.ring_path(self._ring_name))
                self._ring_drops = self.ring.drops
            except Exception as error:
                self._ring_fault("attach", error, now)
            else:
                self._ring_state, self._ring_error = "available", ""
        return self.ring is not None and now >= self._ring_retry_at

    def _pressure(self, now: float) -> bool:
        if not self._connect_ring(now):
            return True
        try:
            return bool(self.ring.backpressure)
        except Exception as error:
            # A malformed ACK is not permission to discard the raw event. The
            # admitted writer validates layout and uses its own sequence below.
            self._ring_fault("pressure", error, now, advisory=True)
            return True

    # ping: the core writes a nonce here; we echo it into status_scanner.json.
    @staticmethod
    def _ping_path():
        return ipc_ring._data_dir() / "ipc" / "scanner.ping"

    def _read_ping(self) -> str:
        try:
            return self._ping_path().read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    def _coverage(self) -> dict:
        return {"state": self._ring_state, "reason": self._ring_error,
                "rejection_observations": self._ring_failures,
                "unforwarded_observations": self._dropped,
                "close_unresolved": self._ring_close_failed,
                "initial_continuity_verified": False,
                "state_scope": "ring transport; heartbeat measures loop progress",
                "collector_efficacy_verified": False,
                "freshness_scope": "admitted process lifetime; v2 restart rollback unverified",
                "response_authorized": False}

    def _write_status(self, ping: str | None = None) -> None:
        if ping is None:
            ping = self._last_ping
        diag.write_status("scanner", "running" if self._ring_state == "available" else "degraded", {
            "events_forwarded": self._events, "dropped": self._dropped,
            "ring_backpressure": self._last_backpressure,
            "ring_drops": self._ring_drops, "last_ping": ping,
            "drop_unit": "oversize/overwrite opportunities; consumer ACK is unauthenticated",
            "enrichment_omitted": self._enrichment_omitted,
            "ring_coverage": self._coverage(), "interval_s": self.interval,
            "sensors": [f"{type(s).__name__} (sensor_id={getattr(s, 'sensor_id', '?')})"
                        for s in self.sensors],
        })

    def _maybe_write_status(self, now: float) -> bool:
        ping_changed = False
        if now - self._last_ping_poll >= PING_POLL_INTERVAL_S:
            ping = self._read_ping()
            self._last_ping_poll = now
            if ping != self._last_ping:
                self._last_ping, ping_changed = ping, True
        backpressure = self._pressure(now)
        changed = (backpressure != self._last_backpressure
                   or self._ring_state != self._last_ring_state)
        self._last_backpressure, self._last_ring_state = backpressure, self._ring_state
        if ping_changed or changed or now - self._last_status >= STATUS_INTERVAL_S:
            self._write_status()
            self._last_status = now
            return True
        return False

    def run(self) -> None:
        if not self._run_claim.acquire(blocking=False):
            raise RuntimeError("ScannerHost can only run once")
        try:
            self._last_ping = self._read_ping()
            self._write_status()
            self._last_status = self._last_ping_poll = time.monotonic()
            while not self._stop:
                if tok.is_standdown_requested() is True:
                    self._authenticated_standdown = True
                    break
                now = time.monotonic()
                downsample = self._pressure(now)
                self._last_backpressure = downsample
                for sensor in self.sensors:
                    frames = (sensor.poll(enrich=not downsample)
                              if isinstance(sensor, RawProcessSensor) else sensor.poll())
                    for frame in frames:
                        if self._stop:
                            break
                        if downsample and isinstance(sensor, RawProcessSensor):
                            self._enrichment_omitted += 1
                        if not self._connect_ring(now):
                            self._dropped += 1
                            continue
                        try:
                            stored = self.ring.write(frame, schema_ver=SCHEMA, sensor_id=sensor.sensor_id)
                            self._ring_drops = self.ring.drops
                        except Exception as error:
                            self._ring_fault("write", error, now)
                            self._dropped += 1
                            continue
                        self._ring_state, self._ring_error = "available", ""
                        if stored:
                            self._events += 1
                        else:
                            self._dropped += 1
                # Process progress is separate from explicitly degraded coverage.
                self.beat.beat()
                self._maybe_write_status(time.monotonic())
                self._stop_event.wait(self.interval)
        finally:
            self._shutdown()

    def _close_ring(self) -> None:
        if self.ring is not None and not self._ring_close_failed:
            try:
                self.ring.close()
            except Exception as error:
                # One exact close attempt; retain the owner on ambiguous failure.
                self._ring_close_failed = True
                self._ring_fault("close", error, time.monotonic())
                raise
            else:
                self.ring = None

    def _shutdown(self) -> None:
        if self._shutdown_started:
            return
        self._shutdown_started = True
        try:
            self.beat.close()
        finally:
            try:
                self._close_ring()
            finally:
                diag.write_status("scanner", "stopped", {
                    "events_forwarded": self._events, "dropped": self._dropped,
                    "ring_coverage": self._coverage()})

    def stop(self) -> None:
        self._stop = True
        self._stop_event.set()


def _run_gui_worker(host: ScannerHost, on_authenticated_stop: Callable[[], None]) -> None:
    """Queue GUI retirement only after verified STOP and completed cleanup.

    Unexpected failure or ambiguous native cleanup leaves the diagnostic window
    available. This callback carries no STOP, restart or response authority.
    """
    host.run()
    if host._authenticated_standdown is True:
        on_authenticated_stop()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    interval = float(os.environ.get("ANGERONA_SCANNER_INTERVAL", "1.0"))
    if argv and argv[0].replace(".", "", 1).isdigit():
        interval = float(argv[0])
    # Internal component heartbeats use the ACL-protected per-install authority.
    # ANGERONA_WATCHDOG_TOKEN belongs only to the compiled parent handshake and
    # must not silently become a different supervisor trust root.
    host = ScannerHost(interval=interval)

    # Themed window (matches Angerona's look) unless disabled or unavailable.
    # The sensor loop runs on a background thread so the window stays responsive
    # while the sensor itself stays lean.
    worker = None
    if os.environ.get("ANGERONA_SCANNER_UI", "1") not in ("0", "false", "no", "off"):
        try:
            from PySide6.QtWidgets import QApplication, QMainWindow
            from PySide6.QtCore import QObject, Signal, Qt
            from angerona.resilience import status_ui
            app = QApplication.instance() or QApplication(sys.argv)
            qss = status_ui._qss()
            if qss:
                app.setStyleSheet(qss)
            win = QMainWindow()
            win.setWindowTitle("Angerona - Telemetry Scanner")
            win.setCentralWidget(status_ui.build_status_widget("scanner", "Angerona - Telemetry Scanner"))
            win.resize(540, 460)
            from angerona.gui.header_controls import install_global_window_reveal
            try:
                from angerona.core.config import Config
                motion_config = Config.load()
            except Exception:
                motion_config = None
            install_global_window_reveal(win, config=motion_config)
            win.showMinimized()
            # Finish all fallible GUI preparation before starting the sensor.
            # A presentation failure must never start a second host.run loop.
            class _IntentionalStop(QObject):
                requested = Signal()

            intentional_stop = _IntentionalStop(app)
            # A token can be admitted before app.exec(). Explicitly queue quit
            # so that early STOP is delivered once the event loop starts.
            intentional_stop.requested.connect(app.quit, Qt.ConnectionType.QueuedConnection)
            worker = threading.Thread(
                target=_run_gui_worker, args=(host, intentional_stop.requested.emit),
                name="TelemetryScanner", daemon=True,
            )
            worker.start()
            rc = app.exec()
            host.stop()
            worker.join(timeout=2)
            return rc
        except Exception:
            if worker is not None and worker.ident is not None:
                host.stop()
                worker.join(timeout=2)
                return 1
            # No worker started: a GUI setup failure may fall back to headless.

    import signal
    def _sig(_s, _f):
        host.stop()
    try:
        signal.signal(signal.SIGTERM, _sig)
        signal.signal(signal.SIGINT, _sig)
    except Exception:
        pass
    host.run()
    return 0


def self_test() -> tuple[bool, str]:
    """Offline, isolated: run a few scanner loop iterations against a temp ring
    and confirm the process sensor baselines then emits frames, the heartbeat
    advances, and status is written — without spawning a process."""
    from angerona.resilience._selftest_environment import run_isolated_selftest

    return run_isolated_selftest(
        "scanner",
        "scan_selftest_",
        lambda root: {
            "ANGERONA_DATA": str(root),
            "ANGERONA_DIAG_DIR": str(root / "diag"),
        },
        timeout=20.0,
    )


def _isolated_self_test() -> tuple[bool, str]:
    host = ScannerHost(interval=0.05)
    procs: list[subprocess.Popen] = []
    reader = None
    try:
        # First poll = baseline (no frames); spawn a couple procs; second poll emits.
        host.sensors[0].poll()
        procs = [subprocess.Popen([sys.executable, "-c", "import time;time.sleep(0.4)"])
                 for _ in range(2)]
        time.sleep(0.1)
        frames = list(host.sensors[0].poll())
        for fr in frames:
            host.ring.write(fr, sensor_id=SENSOR_PROC); host._events += 1
        c1 = host.beat._counter; host.beat.beat(); c2 = host.beat._counter
        host._write_status("nonce123")

        reader = ipc_ring.RingReader(ipc_ring.ring_path("telemetry"))
        got = reader.read_batch()
        status = json.loads((diag.diag_dir() / "status_scanner.json").read_text(encoding="utf-8"))

        emitted_ok = len(frames) >= 2 and len(got) >= 2
        decode_ok = all(json.loads(g["payload"]).get("type") == "process_creation" for g in got[:2])
        beat_ok = c2 == c1 + 1
        status_ok = status.get("component") == "scanner" and status.get("last_ping") == "nonce123"

        ok = emitted_ok and decode_ok and beat_ok and status_ok
        return ok, ("raw process frames emitted→ring, decoded, heartbeat advanced, "
                    "status(pong) written" if ok else
                    f"failed: emitted={emitted_ok} decode={decode_ok} beat={beat_ok} status={status_ok}")
    finally:
        for process in procs:
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)
        host.ring.close()
        if reader is not None:
            reader.close()
        host.beat.close()


if __name__ == "__main__":
    # Detached + hidden → any startup exception otherwise vanishes and the
    # supervisor just sees the scanner die (SAFE_MODE after 3 fails, no reason).
    # Persist the traceback so the actual cause is visible.
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException:
        try:
            import traceback
            from angerona.resilience import heartbeat as _hb
            _dir = _hb._data_dir() / "diagnostics"
            _dir.mkdir(parents=True, exist_ok=True)
            with open(_dir / "resilience_scanner_crash.log", "a", encoding="utf-8") as _f:
                _f.write(f"\n[{time.strftime('%Y-%m-%dT%H:%M:%S')}] scanner crashed:\n")
                _f.write(traceback.format_exc())
        except Exception:
            pass
        raise
