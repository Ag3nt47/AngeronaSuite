"""supervisor.py — detached-process supervision for the resilience ecosystem.

Angerona's side of the mutual keep-alive. It launches the watchdog and scanner as
DETACHED processes (not children in the same process tree — so a process-group
kill can't take them all down together), then keeps them alive:

  * Death detection: a blocking waiter thread per component sleeps at ~0% CPU
    until the process exits, then flags it — no busy polling.
  * Suspension detection: the component's shared-memory heartbeat is checked; a
    live PID with a frozen tick is treated as compromised (SIGSTOP/blinding).
  * Respawn with backoff: after repeated failures inside a short window the
    component enters SAFE_MODE — respawns stop (no thrash) and a CRITICAL record
    is written for the BlackBox. Recovers automatically once it stays healthy.
  * Graceful stand-down: if a valid signed stand-down token is present, the
    supervisor stops respawning (the compiled watchdog honours the same token),
    so maintenance doesn't fight the self-healing loop.

The compiled Go watchdog does the symmetric job for the core using native
event-driven waits; this Python supervisor is the core-side counterpart and a
backstop for the scanner.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional

from angerona.resilience import heartbeat as hb
from angerona.resilience import diagnostics as diag
from angerona.resilience import shutdown_token as tok


def spawn_detached(argv: list[str], env: Optional[dict] = None) -> subprocess.Popen:
    """Start a process fully detached from this one's process group/tree."""
    kwargs: dict = {"env": {**os.environ, **(env or {})}}
    if os.name == "nt":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_NO_WINDOW = 0x08000000
        kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
        kwargs["close_fds"] = True
    else:
        # New session (setsid): detaches from our process group so a group-kill
        # of this process does not reach the child.
        kwargs["start_new_session"] = True
        kwargs["close_fds"] = True
    return subprocess.Popen(argv, **kwargs)


@dataclass
class Component:
    name: str                      # heartbeat name + identity
    argv: list                     # command to (re)launch it
    stale_after_s: float = 3.0     # heartbeat freeze threshold ⇒ suspended
    max_failures: int = 3          # failures within window ⇒ SAFE_MODE
    window_s: float = 60.0
    # runtime state
    proc: Optional[subprocess.Popen] = None
    reader: Optional[hb.HeartbeatReader] = None
    _dead: bool = False
    _failures: deque = field(default_factory=deque)
    safe_mode: bool = False
    restarts: int = 0


class ProcessSupervisor:
    def __init__(self, poll_interval: float = 1.0,
                 on_event: Optional[Callable[[str, str, dict], None]] = None):
        self.components: dict[str, Component] = {}
        self.poll_interval = poll_interval
        self.on_event = on_event
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── registration ─────────────────────────────────────────────────────────
    def add(self, name: str, argv: list, **kw) -> Component:
        c = Component(name=name, argv=list(argv), **kw)
        c.reader = hb.HeartbeatReader(name)
        self.components[name] = c
        return c

    def _emit(self, level: str, msg: str, **details) -> None:
        if self.on_event:
            try:
                self.on_event(level, msg, details)
            except Exception:
                pass
        if level == "CRITICAL":
            diag.record_selftest_failure(f"supervisor/{details.get('component','?')}", msg,
                                         component="supervisor")

    # ── spawning ─────────────────────────────────────────────────────────────
    def _spawn(self, c: Component) -> None:
        try:
            c.proc = spawn_detached(c.argv)
            c._dead = False
            c.restarts += 1
            # Blocking waiter → 0% CPU until the process exits.
            threading.Thread(target=self._waiter, args=(c, c.proc), daemon=True,
                             name=f"wait-{c.name}").start()
            self._emit("INFO", f"launched {c.name} (pid {c.proc.pid})",
                       component=c.name, pid=c.proc.pid, restarts=c.restarts)
        except Exception as exc:
            self._emit("CRITICAL", f"failed to spawn {c.name}: {exc}", component=c.name)

    def _waiter(self, c: Component, proc: subprocess.Popen) -> None:
        try:
            proc.wait()
        except Exception:
            pass
        # Only flag death if this is still the current process object.
        if c.proc is proc:
            c._dead = True

    def start(self) -> None:
        for c in self.components.values():
            self._spawn(c)
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="supervisor")
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.poll_interval):
            try:
                self.tick()
            except Exception as exc:
                self._emit("ERROR", f"supervisor tick error: {exc}", component="supervisor")

    # ── one monitoring pass (public for tests) ───────────────────────────────
    def tick(self) -> dict:
        """Evaluate every component once; respawn as needed. Returns a summary."""
        actions: dict = {}
        standdown = tok.is_standdown_requested()
        for name, c in self.components.items():
            state = self._assess(c)
            actions[name] = state
            if standdown:
                continue                       # honour maintenance stand-down
            if state in ("dead", "suspended") and not c.safe_mode:
                if self._register_failure(c):
                    c.safe_mode = True
                    self._emit("CRITICAL",
                               f"{name} entered SAFE_MODE after {c.max_failures} failures "
                               f"in {c.window_s:.0f}s — respawns halted to prevent thrash.",
                               component=name)
                    actions[name] = "safe_mode"
                    continue
                if state == "suspended":
                    self._terminate(c)         # can't trust a suspended process
                self._spawn(c)
                actions[name] = f"respawned({state})"
        return actions

    def _assess(self, c: Component) -> str:
        # A returned proc.wait() (real process exit) is authoritative for death.
        if c._dead:
            return "dead"
        # Otherwise consult the heartbeat — this is what catches SUSPENSION
        # (pid alive but tick frozen).
        hb_state = c.reader.classify(stale_after_s=c.stale_after_s) if c.reader else "unknown"
        if hb_state == "alive":
            self._decay(c)          # healthy → allow leaving SAFE_MODE
            return "alive"
        if hb_state == "suspended":
            return "suspended"
        if hb_state == "dead":
            return "dead"
        return hb_state             # 'stopped'/'unknown' → no respawn

    def _register_failure(self, c: Component) -> bool:
        now = time.time()
        c._failures.append(now)
        while c._failures and now - c._failures[0] > c.window_s:
            c._failures.popleft()
        return len(c._failures) >= c.max_failures

    def _decay(self, c: Component) -> None:
        now = time.time()
        while c._failures and now - c._failures[0] > c.window_s:
            c._failures.popleft()
        if c.safe_mode and not c._failures:
            c.safe_mode = False
            self._emit("INFO", f"{c.name} left SAFE_MODE (healthy again).", component=c.name)

    def _terminate(self, c: Component) -> None:
        if c.proc and c.proc.poll() is None:
            try:
                c.proc.terminate()
                try:
                    c.proc.wait(timeout=3)
                except Exception:
                    c.proc.kill()
            except Exception:
                pass

    def stop(self, terminate_children: bool = True) -> None:
        self._stop.set()
        if terminate_children:
            for c in self.components.values():
                self._terminate(c)


def self_test() -> tuple[bool, str]:
    """Live (Linux/Unix) test: spawn a detached child that heartbeats then exits;
    verify death is detected and it is respawned; verify SAFE_MODE after repeated
    instant failures; verify a stand-down token halts respawns."""
    import tempfile as _tf
    workdir = _tf.mkdtemp(prefix="sup_selftest_")
    _prev_diag = os.environ.get("ANGERONA_DIAG_DIR")
    try:
        os.environ["ANGERONA_DATA"] = workdir   # isolate heartbeats/tokens here
        os.environ["ANGERONA_DIAG_DIR"] = os.path.join(workdir, "diag")  # isolate diagnostics

        # A tiny child that writes a heartbeat named on argv, beats N times, exits.
        child = os.path.join(workdir, "child.py")
        with open(child, "w") as f:
            f.write(
                "import sys,time\n"
                "sys.path.insert(0, %r)\n" % os.path.join(os.getcwd(), "src") +
                "from angerona.resilience import heartbeat as hb\n"
                "name=sys.argv[1]; beats=int(sys.argv[2])\n"
                "w=hb.HeartbeatWriter(name)\n"
                "for _ in range(beats):\n"
                "    w.beat(); time.sleep(0.1)\n"
                "w.close()\n"
            )
        py = sys.executable

        sup = ProcessSupervisor(poll_interval=0.2)
        c = sup.add("scanner", [py, child, "scanner", "30"], stale_after_s=1.0,
                    max_failures=3, window_s=60.0)
        sup._spawn(c)
        time.sleep(0.5)
        alive_ok = c.reader.classify(stale_after_s=1.0) == "alive"

        # Kill it → the blocking waiter flags death → a tick must respawn it.
        before = c.restarts
        try:
            c.proc.kill()
        except Exception:
            pass
        time.sleep(0.4)             # let the waiter thread observe the exit
        for _ in range(6):
            sup.tick(); time.sleep(0.15)
            if c.restarts > before:
                break
        respawn_ok = c.restarts > before

        # SAFE_MODE: a child that exits instantly, forced through failures.
        c2 = sup.add("flaky", [py, "-c", "raise SystemExit(1)"], stale_after_s=0.5,
                     max_failures=3, window_s=60.0)
        c2._dead = True
        for _ in range(6):
            c2._dead = True
            sup.tick(); time.sleep(0.1)
            if c2.safe_mode:
                break
        safemode_ok = c2.safe_mode

        # Stand-down halts respawns.
        tok.request_standdown("selftest")
        c3 = sup.add("halted", [py, "-c", "pass"], stale_after_s=0.5, max_failures=99)
        c3._dead = True
        r_before = c3.restarts
        sup.tick()
        standdown_ok = c3.restarts == r_before
        tok.clear_standdown()

        sup.stop()
        ok = alive_ok and respawn_ok and safemode_ok and standdown_ok
        return ok, ("detached spawn + heartbeat-alive + respawn-on-death + SAFE_MODE "
                    "backoff + stand-down honoured" if ok else
                    f"failed: alive={alive_ok} respawn={respawn_ok} "
                    f"safemode={safemode_ok} standdown={standdown_ok}")
    finally:
        import shutil as _sh
        os.environ.pop("ANGERONA_DATA", None)
        if _prev_diag is None:
            os.environ.pop("ANGERONA_DIAG_DIR", None)
        else:
            os.environ["ANGERONA_DIAG_DIR"] = _prev_diag
        _sh.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    print(self_test())
