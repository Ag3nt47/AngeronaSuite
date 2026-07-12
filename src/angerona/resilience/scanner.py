"""scanner.py — standalone Telemetry Scanner process.

Runs as its OWN low-footprint process (``python -m angerona.resilience.scanner``),
independent of the Angerona core. It collects RAW system telemetry with minimal
processing and streams it into the shared-memory ring (`ipc_ring`) for the core to
decipher and act on — the scanner itself makes no security decisions.

Responsibilities (deliberately thin — the core is the brain):
  * Collect: a low-overhead process-creation sensor (psutil table diff). More
    sensors can be added; each just emits raw frames.
  * Forward: write raw frames into the ring; if the ring signals backpressure,
    down-sample at the source (drop INFO-level churn) to shield the core.
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
import os
import sys
import time
from typing import Iterable

from angerona.resilience import ipc_ring
from angerona.resilience import heartbeat as hb
from angerona.resilience import shutdown_token as tok
from angerona.resilience import diagnostics as diag

# Sensor ids (stable, so the core can attribute raw frames).
SENSOR_PROC = 1

SCHEMA = 1


class RawProcessSensor:
    """Low-overhead process-creation sensor: diffs the process table and emits a
    raw frame per newly-seen pid. No correlation — just facts."""
    sensor_id = SENSOR_PROC

    def __init__(self) -> None:
        self._known: set[int] = set()
        self._seeded = False

    def poll(self) -> Iterable[bytes]:
        try:
            import psutil
        except Exception:
            return []
        current: dict[int, dict] = {}
        for p in psutil.process_iter(["pid", "ppid", "name"]):
            try:
                current[p.info["pid"]] = p.info
            except Exception:
                continue
        frames: list[bytes] = []
        if self._seeded:
            for pid in (set(current) - self._known):
                info = current[pid]
                rec = {"type": "process_creation", "pid": pid,
                       "ppid": info.get("ppid"), "name": info.get("name"),
                       "ts": time.time()}
                frames.append(json.dumps(rec, separators=(",", ":")).encode("utf-8"))
        else:
            self._seeded = True     # first pass = baseline, don't flood
        self._known = set(current)
        return frames


class ScannerHost:
    def __init__(self, interval: float = 1.0, ring_name: str = "telemetry",
                 token_raw: bytes = b""):
        self.interval = interval
        self.ring = ipc_ring.RingWriter(ipc_ring.ring_path(ring_name))
        self.beat = hb.HeartbeatWriter(hb.COMPONENT_SCANNER if hasattr(hb, "COMPONENT_SCANNER")
                                       else "scanner", token_raw=token_raw)
        self.sensors = [RawProcessSensor()]
        self._events = 0
        self._dropped = 0
        self._stop = False
        self._last_status = 0.0

    # ping: the core writes a nonce here; we echo it into status.json (pong).
    @staticmethod
    def _ping_path():
        return ipc_ring._data_dir() / "ipc" / "scanner.ping"

    def _read_ping(self) -> str:
        try:
            return self._ping_path().read_text(encoding="utf-8").strip()
        except Exception:
            return ""

    def _write_status(self, ping: str = "") -> None:
        diag.write_status("scanner", "running", {
            "events_forwarded": self._events, "dropped": self._dropped,
            "ring_backpressure": self.ring.backpressure,
            "ring_drops": self.ring.drops, "last_ping": ping,
            "interval_s": self.interval,
            # Sensors this scanner process controls (shown in the window's Info tab).
            "sensors": [f"{type(s).__name__} (sensor_id={getattr(s, 'sensor_id', '?')})"
                        for s in self.sensors],
        })

    def run(self) -> None:
        self._write_status()
        while not self._stop:
            if tok.is_standdown_requested():
                break                                   # graceful maintenance exit
            downsample = self.ring.backpressure         # shed load at the source
            for sensor in self.sensors:
                for frame in sensor.poll():
                    if downsample:
                        self._dropped += 1
                        continue
                    if self.ring.write(frame, schema_ver=SCHEMA, sensor_id=sensor.sensor_id):
                        self._events += 1
                    else:
                        self._dropped += 1
            self.beat.beat()
            now = time.time()
            if now - self._last_status >= 3.0:
                self._write_status(self._read_ping())
                self._last_status = now
            time.sleep(self.interval)                    # low, steady CPU
        self._shutdown()

    def _shutdown(self) -> None:
        try:
            diag.write_status("scanner", "stopped",
                              {"events_forwarded": self._events, "dropped": self._dropped})
        finally:
            try:
                self.beat.close()
            finally:
                self.ring.close()

    def stop(self) -> None:
        self._stop = True


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    interval = float(os.environ.get("ANGERONA_SCANNER_INTERVAL", "1.0"))
    if argv and argv[0].replace(".", "", 1).isdigit():
        interval = float(argv[0])
    token_hex = os.environ.get("ANGERONA_WATCHDOG_TOKEN", "")
    token_raw = bytes.fromhex(token_hex) if token_hex else b""
    host = ScannerHost(interval=interval, token_raw=token_raw)

    # Themed window (matches Angerona's look) unless disabled or unavailable.
    # The sensor loop runs on a background thread so the window stays responsive
    # while the sensor itself stays lean.
    if os.environ.get("ANGERONA_SCANNER_UI", "1") not in ("0", "false", "no", "off"):
        try:
            from PySide6.QtWidgets import QApplication, QMainWindow
            from angerona.resilience import status_ui
            import threading as _th
            _th.Thread(target=host.run, daemon=True).start()
            app = QApplication.instance() or QApplication(sys.argv)
            qss = status_ui._qss()
            if qss:
                app.setStyleSheet(qss)
            win = QMainWindow()
            win.setWindowTitle("Angerona - Telemetry Scanner")
            win.setCentralWidget(status_ui.build_status_widget("scanner", "Angerona - Telemetry Scanner"))
            win.resize(540, 460)
            win.showMinimized()
            rc = app.exec()
            host.stop()
            return rc
        except Exception:
            pass   # no PySide6 / no display → fall through to headless

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
    import tempfile, shutil
    prev = os.environ.get("ANGERONA_DATA")
    prev_diag = os.environ.get("ANGERONA_DIAG_DIR")
    workdir = tempfile.mkdtemp(prefix="scan_selftest_")
    os.environ["ANGERONA_DATA"] = workdir
    os.environ["ANGERONA_DIAG_DIR"] = os.path.join(workdir, "diag")
    try:
        host = ScannerHost(interval=0.05)
        # First poll = baseline (no frames); spawn a couple procs; second poll emits.
        host.sensors[0].poll()
        import subprocess
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
        status = json.loads((diag.diag_dir() / "status.json").read_text(encoding="utf-8"))

        emitted_ok = len(frames) >= 2 and len(got) >= 2
        decode_ok = all(json.loads(g["payload"]).get("type") == "process_creation" for g in got[:2])
        beat_ok = c2 == c1 + 1
        status_ok = status.get("component") == "scanner" and status.get("last_ping") == "nonce123"

        for p in procs:
            try: p.wait(timeout=1)
            except Exception: p.kill()
        host.ring.close(); reader.close(); host.beat.close()
        ok = emitted_ok and decode_ok and beat_ok and status_ok
        return ok, ("raw process frames emitted→ring, decoded, heartbeat advanced, "
                    "status(pong) written" if ok else
                    f"failed: emitted={emitted_ok} decode={decode_ok} beat={beat_ok} status={status_ok}")
    finally:
        for k, v in (("ANGERONA_DATA", prev), ("ANGERONA_DIAG_DIR", prev_diag)):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
