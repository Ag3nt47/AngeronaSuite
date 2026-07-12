"""supervisor.py — detached-process supervision for the resilience ecosystem.

Angerona's side of the mutual keep-alive. It launches the watchdog, scanner, and
BlackBox as DETACHED, MINIMIZED processes (their own windows, not children in the
same process tree — so a process-group kill can't take them all down together),
then keeps them alive:

  * Death detection: a blocking waiter thread per component sleeps at ~0% CPU
    until the process exits, then flags it — no busy polling. For components with
    no heartbeat (BlackBox) liveness is a process probe instead.
  * Suspension detection: the component's shared-memory heartbeat is checked; a
    live PID with a frozen tick is treated as compromised (SIGSTOP/blinding).
  * No duplicates: before (re)launching anything the supervisor checks whether an
    instance is ALREADY running (fresh heartbeat / process probe) and adopts it
    instead of starting a second one. A cross-process spawn lock stops the core
    and the watchdog — which both supervise the scanner and BlackBox — from
    racing and double-spawning.
  * Respawn with backoff: after repeated failures inside a short window the
    component enters SAFE_MODE — respawns stop (no thrash) and a CRITICAL record
    is written for the BlackBox. Recovers automatically once it stays healthy.
  * Graceful stand-down: a valid signed stand-down token halts all respawns.

The compiled Go watchdog does the symmetric job for the core; this Python
supervisor is the core-side counterpart.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from angerona.resilience import heartbeat as hb
from angerona.resilience import diagnostics as diag
from angerona.resilience import shutdown_token as tok


# ── detached, windowed spawning ──────────────────────────────────────────────
def spawn_detached(argv: list[str], env: Optional[dict] = None,
                   window: str = "minimized") -> subprocess.Popen:
    """Start a process fully detached from this one's process group/tree.

    window: 'minimized' (own console, minimized), 'hidden' (no window), or
    'normal' (own console, foreground). On POSIX the window hint is ignored and
    the child is placed in a new session (setsid)."""
    kwargs: dict = {"env": {**os.environ, **(env or {})}, "close_fds": True}
    if os.name == "nt":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_NEW_CONSOLE = 0x00000010
        CREATE_NO_WINDOW = 0x08000000
        if window == "hidden":
            kwargs["creationflags"] = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
        else:
            # Own console window so the process is independently visible.
            kwargs["creationflags"] = CREATE_NEW_CONSOLE | CREATE_NEW_PROCESS_GROUP
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            # 7 = SW_SHOWMINNOACTIVE (minimized, don't steal focus); 1 = SW_SHOWNORMAL
            si.wShowWindow = 7 if window == "minimized" else 1
            kwargs["startupinfo"] = si
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(argv, **kwargs)


# ── cross-process spawn lock (core + watchdog both supervise) ─────────────────
def _ipc_dir() -> Path:
    d = hb._data_dir() / "ipc"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _spawnlock_path(name: str) -> Path:
    return _ipc_dir() / f"{name}.spawnlock"


def try_claim_spawn(name: str, ttl: float = 15.0) -> bool:
    """Atomically claim the right to spawn `name`. Returns False if another
    supervisor already holds a fresh claim (so we don't double-spawn)."""
    p = _spawnlock_path(name)
    try:
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        os.write(fd, f"{os.getpid()} {time.time()}".encode())
        os.close(fd)
        return True
    except FileExistsError:
        try:
            if time.time() - p.stat().st_mtime > ttl:   # stale lock → steal it
                p.unlink()
                return try_claim_spawn(name, ttl)
        except Exception:
            pass
        return False
    except Exception:
        return True   # fail-open: better to (rarely) risk a race than never spawn


def release_spawn(name: str) -> None:
    try:
        _spawnlock_path(name).unlink()
    except Exception:
        pass


@dataclass
class Component:
    name: str                      # heartbeat name + identity
    argv: list                     # command to (re)launch it
    stale_after_s: float = 3.0     # heartbeat freeze threshold ⇒ suspended
    max_failures: int = 3          # failures within window ⇒ SAFE_MODE
    window_s: float = 60.0
    window: str = "minimized"      # spawn window mode
    running_probe: Optional[Callable[[], bool]] = None  # liveness for heartbeat-less procs
    # runtime state
    proc: Optional[subprocess.Popen] = None
    reader: Optional[hb.HeartbeatReader] = None
    _dead: bool = False
    _failures: deque = field(default_factory=deque)
    safe_mode: bool = False
    restarts: int = 0
    adopted: bool = False


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

    # ── liveness (stateless; a stale leftover heartbeat is NOT 'alive') ───────
    def _is_running(self, c: Component) -> bool:
        if c.running_probe is not None:
            try:
                return bool(c.running_probe())
            except Exception:
                return False
        if c.reader is None:
            return False
        rec = c.reader.read()
        if not rec or rec.get("flags") == 0:
            return False
        age = (time.time_ns() - rec["ts_ns"]) / 1e9
        # Fresh tick AND the writer's pid still alive ⇒ genuinely running.
        return age <= max(c.stale_after_s, 2.0) and hb.pid_alive(rec.get("pid", 0))

    # ── spawning (adopt-if-alive + cross-process lock) ───────────────────────
    def _spawn(self, c: Component) -> None:
        # Already up (perhaps started by the other supervisor)? Adopt it.
        if self._is_running(c):
            c._dead = False
            if not c.adopted:
                c.adopted = True
                self._emit("INFO", f"adopted already-running {c.name} (no duplicate started)",
                           component=c.name)
            return
        # Only one supervisor may spawn a given component at a time.
        if not try_claim_spawn(c.name):
            return
        try:
            if self._is_running(c):     # double-check under the lock
                return
            c.proc = spawn_detached(c.argv, window=c.window)
            c._dead = False
            c.adopted = False
            c.restarts += 1
            threading.Thread(target=self._waiter, args=(c, c.proc), daemon=True,
                             name=f"wait-{c.name}").start()
            self._emit("INFO", f"launched {c.name} ({c.window}) pid {c.proc.pid}",
                       component=c.name, pid=c.proc.pid, restarts=c.restarts)
        except Exception as exc:
            self._emit("CRITICAL", f"failed to spawn {c.name}: {exc}", component=c.name)
        finally:
            # Hold the lock until the child is detectably up (or 5 s), so the peer
            # supervisor doesn't also spawn during the startup gap.
            threading.Thread(target=self._release_when_up, args=(c,), daemon=True).start()

    def _release_when_up(self, c: Component) -> None:
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if self._is_running(c):
                break
            time.sleep(0.2)
        release_spawn(c.name)

    def _waiter(self, c: Component, proc: subprocess.Popen) -> None:
        try:
            proc.wait()
        except Exception:
            pass
        if c.proc is proc:
            c._dead = True

    def start(self) -> None:
        # Adopt-if-alive: never start a second instance of something already up.
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
        actions: dict = {}
        standdown = tok.is_standdown_requested()
        for name, c in self.components.items():
            state = self._assess(c)
            actions[name] = state
            if standdown:
                continue
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
                    self._terminate(c)
                self._spawn(c)
                actions[name] = f"respawned({state})"
        return actions

    def _assess(self, c: Component) -> str:
        # Heartbeat-less components (BlackBox): liveness is the process probe.
        if c.running_probe is not None:
            return "alive" if self._is_running(c) else "dead"
        # A returned proc.wait() (real process exit) is authoritative for death.
        if c._dead:
            return "dead"
        hb_state = c.reader.classify(stale_after_s=c.stale_after_s) if c.reader else "unknown"
        if hb_state == "alive":
            self._decay(c)
            return "alive"
        if hb_state == "suspended":
            return "suspended"
        if hb_state == "dead":
            return "dead"
        return hb_state

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
    verify respawn-on-death, SAFE_MODE backoff, stand-down halt, AND adopt-if-alive
    (a second _spawn while the child is alive does NOT start a duplicate)."""
    import tempfile as _tf
    workdir = _tf.mkdtemp(prefix="sup_selftest_")
    _prev_diag = os.environ.get("ANGERONA_DIAG_DIR")
    try:
        os.environ["ANGERONA_DATA"] = workdir
        os.environ["ANGERONA_DIAG_DIR"] = os.path.join(workdir, "diag")

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
        c = sup.add("scanner", [py, child, "scanner", "40"], stale_after_s=1.0,
                    max_failures=3, window_s=60.0, window="normal")
        sup._spawn(c)
        time.sleep(0.6)
        alive_ok = sup._is_running(c)

        # adopt-if-alive: a second _spawn must NOT start another instance.
        before_restarts = c.restarts
        sup._spawn(c)
        time.sleep(0.2)
        no_dup_ok = c.restarts == before_restarts and c.adopted

        # Kill it → waiter flags death → a tick respawns exactly one.
        before = c.restarts
        try:
            c.proc.kill()
        except Exception:
            pass
        time.sleep(0.5)
        for _ in range(8):
            sup.tick(); time.sleep(0.15)
            if c.restarts > before:
                break
        respawn_ok = c.restarts == before + 1

        # SAFE_MODE
        c2 = sup.add("flaky", [py, "-c", "raise SystemExit(1)"], stale_after_s=0.5,
                     max_failures=3, window_s=60.0)
        for _ in range(6):
            c2._dead = True
            sup.tick(); time.sleep(0.1)
            if c2.safe_mode:
                break
        safemode_ok = c2.safe_mode

        # Stand-down
        tok.request_standdown("selftest")
        c3 = sup.add("halted", [py, "-c", "pass"], stale_after_s=0.5, max_failures=99)
        c3._dead = True
        r_before = c3.restarts
        sup.tick()
        standdown_ok = c3.restarts == r_before
        tok.clear_standdown()

        sup.stop()
        ok = alive_ok and no_dup_ok and respawn_ok and safemode_ok and standdown_ok
        return ok, ("minimized detached spawn + adopt-if-alive (no duplicate) + "
                    "respawn-on-death + SAFE_MODE + stand-down verified" if ok else
                    f"failed: alive={alive_ok} no_dup={no_dup_ok} respawn={respawn_ok} "
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
