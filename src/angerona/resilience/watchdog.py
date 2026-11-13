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
import threading
import time
from pathlib import Path

from angerona.resilience import heartbeat as hb
from angerona.resilience import diagnostics as diag
from angerona.resilience import shutdown_token as tok
from angerona.resilience.supervisor import ProcessSupervisor, cached_cmdline_probe

_CORE_STALE_AFTER_SECONDS = 12.0
_SCANNER_STALE_AFTER_SECONDS = 8.0
_SOURCE_REVIEW_INTERVAL_SECONDS = 60.0


def _repo_root() -> Path:
    from angerona.core.data_paths import project_root
    return project_root()


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


def _cmdline_probe(*needles: str, expected_argv=None):
    return cached_cmdline_probe(*needles, expected_argv=expected_argv)


def _refresh_heartbeat(writer, token_raw: bytes | None = None):
    """Recover once from an invalidated heartbeat mapping.

    Sleep/resume, antivirus inspection, and another supervisor replacing the
    backing file can invalidate an mmap without the watchdog process itself
    being unhealthy. Reopening the tiny mapping avoids turning that transient
    filesystem event into a full watchdog crash.
    """
    try:
        writer.beat()
        return writer
    except Exception:
        try:
            writer.close()
        except Exception:
            pass
        replacement = hb.HeartbeatWriter("watchdog", token_raw=token_raw)
        replacement.beat()
        return replacement


def _standdown_requested() -> bool:
    """Treat an unreadable command as invalid without killing supervision."""
    try:
        return tok.is_standdown_requested()
    except Exception as exc:
        diag.write_status(
            "watchdog",
            "degraded",
            {"standdown_check_error": type(exc).__name__},
        )
        return False


def _prepare_source_guard(supervisor):
    """Check source continuity independently of the core's liveness heartbeat."""
    if getattr(sys, "frozen", False):
        return lambda: {"state": "not-applicable", "reason": "Installed executable signing boundary"}
    from angerona.resilience.source_guard import SourceGuard, SourceGuardError

    guard = None
    state = {"state": "unavailable", "reason": "Source continuity unavailable; peer launches held"}
    lock = threading.Lock()
    try:
        guard = SourceGuard.capture(
            _repo_root(), expected_digest=os.environ.get("ANGERONA_PEER_SOURCE_DIGEST"))
    except (SourceGuardError, OSError, ValueError):
        pass
    else:
        os.environ["ANGERONA_PEER_SOURCE_DIGEST"] = guard.digest
        state = {"state": "verified", "reason": "Source bytes match the current session seal",
                 "digest": guard.digest}

    def check(_component=None):
        nonlocal state
        with lock:
            if guard is None or state["state"] in {"changed", "unavailable"}:
                return False
            try:
                result = guard.check()
            except Exception:
                from angerona.resilience.source_guard import SourceCheck

                result = SourceCheck(False, "unavailable", "Source observation failed; peer launches held")
            state = {"state": result.state, "reason": result.reason,
                     "digest": guard.digest, "changed": list(result.changed),
                     "repair": "After STOP, use start-angerona.bat for pinned recovery; preserve and review user edits"}
            return result.ok

    def snapshot():
        # State is replaced atomically after each observation. Never wait for
        # filesystem custody while the independent heartbeat loop reads status.
        return dict(state)

    supervisor.launch_guard = check
    supervisor.source_integrity_check = check
    return snapshot


def _source_review_loop(supervisor, stopped):
    while not stopped.wait(_SOURCE_REVIEW_INTERVAL_SECONDS):
        check = getattr(supervisor, "source_integrity_check", None)
        if check is not None:
            check()



def _finish_deadman(owner, supervisor, writer, publish, reason):
    """Keep pulses responsive while the one owner retires bounded STOP work."""
    owner.request_stop(reason)
    pulse_unavailable_reported = False
    while not owner.done and not owner.shutdown_expired(grace=2.0):
        if supervisor.heartbeat_allowed():
            try:
                writer = _refresh_heartbeat(writer)
            except Exception:
                if not pulse_unavailable_reported:
                    pulse_unavailable_reported = True
                    publish("MEDIUM", "Watchdog pulse unavailable during bounded dead-man cleanup; health is unverified.",
                            {"deadman": "cleanup_pending", "heartbeat_unavailable": True,
                             "disposition": "health", "response_authorized": False})
        time.sleep(0.1)
    if not owner.join(timeout=0.0):
        snapshot = owner.snapshot()
        publish("CRITICAL" if snapshot.get("owned_rule_evidence") else "MEDIUM",
                "Dead-man shutdown ended without owner retirement; rule cleanup remains unresolved.",
                {"deadman": "cleanup_unresolved", "cleanup_pending": True,
                 "worker_retired": False, "owned_rule_evidence": bool(snapshot.get("owned_rule_evidence")),
                 "enforcement_verified": False, "response_authorized": False, "disposition": "health"})
    return writer


def main(argv: list[str] | None = None) -> int:
    token_hex = os.environ.get("ANGERONA_WATCHDOG_TOKEN", "")
    try:
        token_raw = bytes.fromhex(token_hex) if token_hex else b""
    except ValueError:
        diag.write_status("watchdog", "refused", {"reason": "malformed launch token"})
        return 2
    # The external token authenticates the compiled-parent handshake only.
    # Peer heartbeats share the ACL-protected per-install authority instead.
    beat = hb.HeartbeatWriter("watchdog")

    pyw = os.environ.get("ANGERONA_PY") or _pythonw()
    # Core death is the event this process exists to report, and the core's bus
    # is down at that moment: persist MEDIUM+ supervisor events durably.
    try:
        from angerona.resilience.peer_alerts import PeerAlertOutbox
        outbox_event = PeerAlertOutbox("peer-watchdog").supervisor_callback()
        from angerona.resilience.crash_hunter import CrashHunter
        hunter = CrashHunter(outbox_event)

        def forward_event(level: str, msg: str, details: dict) -> None:
            outbox_event(level, msg, details)
            try:  # Read-only evidence sweep for the unobserved interval.
                hunter.on_supervisor_event(level, msg, details)
            except Exception:
                pass
    except Exception:
        forward_event = None
    sup = ProcessSupervisor(
        poll_interval=1.0,
        on_event=forward_event,
        state_namespace="peer-watchdog",
    )
    source_integrity = _prepare_source_guard(sup)

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
        # Child processes do not observe later changes to the parent's mode
        # environment. Even a pre-captured Full command must recover in Chill;
        # local AI requires a fresh manual Full selection in the new core.
        if "--chill" not in core_argv:
            core_argv.append("--chill")
        # Core can briefly hold Python's GIL during boot-time sensor work. Three
        # seconds produced false "suspended" decisions, duplicate launch
        # attempts, and SAFE_MODE while the original Core was healthy. A real
        # exit is still detected immediately by HeartbeatReader's PID check;
        # only a live-but-delayed process receives this scheduling grace.
        sup.add(
            "core",
            core_argv,
            stale_after_s=_CORE_STALE_AFTER_SECONDS,
            window="hidden",
        )

    # Scanner + BlackBox (also watched by the core manager; spawn lock avoids dups).
    sup.add(
        "scanner",
        [pyw, "-m", "angerona.resilience.scanner"],
        stale_after_s=_SCANNER_STALE_AFTER_SECONDS,
        window="hidden",
    )
    bb = _blackbox_script()
    blackbox_enabled = os.environ.get("ANGERONA_BLACKBOX_ENABLED", "1").strip().lower() not in (
        "0", "false", "no", "off",
    )
    if bb is not None and blackbox_enabled:
        sup.add("blackbox", [pyw, str(bb)], window="hidden",
                running_probe=_cmdline_probe("blackbox_recorder.py", expected_argv=[pyw, str(bb)]))

    sup.start()   # adopt-if-alive: never double-starts what's already running

    stop = {"v": False}
    def _sig(_s=None, _f=None):
        stop["v"] = True
    for s in ("SIGINT", "SIGTERM"):
        try:
            signal.signal(getattr(signal, s), _sig)
        except Exception:
            pass

    diag.write_status("watchdog", "running", {
        "supervised": list(sup.components.keys()), "source_integrity": source_integrity()})
    source_stopped = threading.Event()
    source_thread = threading.Thread(
        target=_source_review_loop, args=(sup, source_stopped),
        name="watchdog-source-integrity", daemon=True)
    source_thread.start()
    deadman = None
    if forward_event is not None and "core" in sup.components:
        try:  # Off unless an administrator signed the opt-in policy.
            from angerona.resilience.deadman import DeadManOwner
            deadman = DeadManOwner(forward_event)
            deadman.start()
        except Exception:
            deadman = None
    deadman_state = "disabled"
    shutdown_reason = "watchdog shutdown"
    n = 0
    while not stop["v"]:
        n += 1
        supervision_current = sup.heartbeat_allowed()
        if supervision_current:
            beat = _refresh_heartbeat(beat)
        if _standdown_requested():
            shutdown_reason = "authenticated stand-down"
            if deadman is not None:
                deadman.request_stop(shutdown_reason)
            break
        if deadman is not None and n % 6 == 0:
            try:
                deadman.submit(sup.components["core"].last_state if supervision_current else "unknown")
                deadman_state = deadman.snapshot()["state"]
            except Exception:
                pass
        if n % 6 == 0:   # ~ every 3s
            source_state = source_integrity()
            progress = sup.supervision_status()
            healthy = (source_state["state"] in {"verified", "not-applicable"}
                       and progress["state"] in {"starting", "running"})
            diag.write_status("watchdog", "running" if healthy else "degraded", {
                "supervised": list(sup.components.keys()),
                "safe_mode": [k for k, c in sup.components.items() if c.safe_mode],
                "restarts": {k: c.restarts for k, c in sup.components.items()},
                "restart_pressure": {k: c.pressure_level for k, c in sup.components.items()
                                     if c.pressure_level},
                "deadman": deadman_state,
                "deadman_work": deadman.snapshot() if deadman is not None else {},
                "source_integrity": source_state,
                "supervision_progress": progress,
            })
        time.sleep(0.5)

    if deadman is not None:
        beat = _finish_deadman(deadman, sup, beat, forward_event, shutdown_reason)
    diag.write_status("watchdog", "stopped", {
        "deadman_work": deadman.snapshot() if deadman is not None else {}})
    source_stopped.set()
    source_thread.join(timeout=1.0)
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
            _dir = diag.diag_dir()
            _dir.mkdir(parents=True, exist_ok=True)
            with open(_dir / "resilience_watchdog_crash.log", "a", encoding="utf-8") as _f:
                _f.write(f"\n[{time.strftime('%Y-%m-%dT%H:%M:%S')}] watchdog crashed:\n")
                _f.write(traceback.format_exc())
        except Exception:
            pass
        raise
