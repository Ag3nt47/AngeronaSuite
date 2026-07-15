"""watchdog.py — standalone Python watchdog process.

Runs as its OWN process (``python -m angerona.resilience.watchdog``) so it works
even when the compiled Go watchdog hasn't been built. It is the out-of-process
guardian that makes the mutual keep-alive real:

  * It writes the ``watchdog`` heartbeat (so the monitor window shows it alive)
    and its ``status_watchdog.json``.
  * It SUPERVISES and restarts the CORE (Angerona), the Scanner, and BlackBox.
    Angerona's own manager can't restart Angerona (a process can't relaunch
    itself after a crash) — THIS process does, via ``ANGERONA_CORE_CMD``.
  * Angerona's manager, in turn, restarts THIS watchdog if it dies — so the two
    watch each other. Adopt-if-alive + the shared spawn lock stop duplicates.
  * A valid signed stand-down token pauses all restarts for maintenance.

Config via environment (set by the core manager when it launches this):
  ANGERONA_CORE_CMD   command line to relaunch Angerona (e.g. '"…pythonw.exe" -m angerona')
  ANGERONA_PY         python launcher for the scanner (default: this interpreter)
  ANGERONA_WATCHDOG_TOKEN  per-launch token (hex) for authenticated heartbeats
"""
from __future__ import annotations

import os
import shlex
import signal
import sys
import time
from pathlib import Path

from angerona.resilience import heartbeat as hb
from angerona.resilience import diagnostics as diag
from angerona.resilience import shutdown_token as tok
from angerona.resilience.supervisor import ProcessSupervisor


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _pythonw() -> str:
    exe = sys.executable
    if os.name == "nt":
        cand = exe.replace("python.exe", "pythonw.exe")
        if os.path.exists(cand):
            return cand
    return exe


def _dequote(token: str) -> str:
    """Strip one matched surrounding quote pair from a token.

    On Windows the core command is parsed with ``shlex.split(..., posix=False)``
    so backslash paths survive — but that mode also RETAINS the quote characters,
    so a quoted launcher (``"…pythonw.exe" -m angerona``) comes back as
    ``'"…pythonw.exe"'`` and the spawn fails with ``WinError 2`` (file not found),
    driving the core into SAFE_MODE. Windows filenames cannot contain a double
    quote, so removing a matched pair is always safe here.
    """
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ('"', "'"):
        return token[1:-1]
    return token


def _blackbox_script():
    p = _repo_root() / "blackbox_recorder.py"
    return p if p.exists() else None


def _cmdline_probe(*needles: str):
    def _probe() -> bool:
        try:
            import psutil
            for pr in psutil.process_iter(["cmdline"]):
                cl = " ".join(pr.info.get("cmdline") or [])
                if cl and all(n in cl for n in needles):
                    return True
        except Exception:
            pass
        return False
    return _probe


def main(argv: list[str] | None = None) -> int:
    token_hex = os.environ.get("ANGERONA_WATCHDOG_TOKEN", "")
    token_raw = bytes.fromhex(token_hex) if token_hex else b""
    beat = hb.HeartbeatWriter("watchdog", token_raw=token_raw)

    pyw = os.environ.get("ANGERONA_PY") or _pythonw()
    sup = ProcessSupervisor(poll_interval=1.0)

    # Core (Angerona) — the thing this watchdog exists to resurrect.
    core_cmd = (os.environ.get("ANGERONA_CORE_CMD") or "").strip()
    if core_cmd:
        try:
            # posix=False keeps backslash paths intact on Windows; _dequote then
            # removes the quote characters that mode leaves around each token.
            core_argv = [_dequote(t) for t in
                         shlex.split(core_cmd, posix=(os.name != "nt"))]
        except Exception:
            core_argv = []
        # If the resolved launcher path is missing/garbled, fall back to this
        # interpreter so the core is still supervised instead of never spawning.
        if not core_argv or (os.sep in core_argv[0] and not os.path.exists(core_argv[0])):
            core_argv = [pyw, "-m", "angerona"]
        sup.add("core", core_argv, stale_after_s=3.0, window="hidden")

    # Scanner + BlackBox (also watched by the core manager; spawn lock avoids dups).
    sup.add("scanner", [pyw, "-m", "angerona.resilience.scanner"],
            stale_after_s=3.0, window="hidden")
    bb = _blackbox_script()
    if bb is not None:
        sup.add("blackbox", [pyw, str(bb)], window="hidden",
                running_probe=_cmdline_probe("blackbox_recorder.py"))

    sup.start()   # adopt-if-alive: never double-starts what's already running

    stop = {"v": False}
    def _sig(_s=None, _f=None):
        stop["v"] = True
    for s in ("SIGINT", "SIGTERM"):
        try:
            signal.signal(getattr(signal, s), _sig)
        except Exception:
            pass

    diag.write_status("watchdog", "running", {"supervised": list(sup.components.keys())})
    n = 0
    while not stop["v"]:
        n += 1
        beat.beat()
        if tok.is_standdown_requested():
            break
        if n % 6 == 0:   # ~ every 3s
            diag.write_status("watchdog", "running", {
                "supervised": list(sup.components.keys()),
                "safe_mode": [k for k, c in sup.components.items() if c.safe_mode],
                "restarts": {k: c.restarts for k, c in sup.components.items()},
            })
        time.sleep(0.5)

    diag.write_status("watchdog", "stopped", {})
    beat.close()
    sup.stop(terminate_children=False)   # leave children running; core manager owns them
    return 0


if __name__ == "__main__":
    # This process runs DETACHED + hidden (no console), so any startup/runtime
    # exception otherwise vanishes — the supervisor just sees it die and, after 3
    # failures, parks it in SAFE_MODE with no clue why. Persist the traceback so
    # the actual cause is visible in diagnostics/resilience_watchdog_crash.log.
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
            with open(_dir / "resilience_watchdog_crash.log", "a", encoding="utf-8") as _f:
                _f.write(f"\n[{time.strftime('%Y-%m-%dT%H:%M:%S')}] watchdog crashed:\n")
                _f.write(traceback.format_exc())
        except Exception:
            pass
        raise
