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
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from angerona.resilience import heartbeat as hb
from angerona.resilience import diagnostics as diag
from angerona.resilience import shutdown_token as tok
from angerona.resilience.recovery_state import (
    RecoveryStateError,
    RecoveryStateStore,
    safe_name,
)

# After a component hits SAFE_MODE (crash-loop), wait this long, then retry once —
# so supervision recovers automatically instead of giving up permanently.
_SAFE_MODE_COOLDOWN = 120.0
_VALID_RESTART_TARGETS = {
    "core", "scanner", "blackbox", "watchdog", "watchdog_ui", "scanner_ui", "*",
}
_SPAWN_LOCK_ERRORS: dict[str, str] = {}
_SPAWN_LOCK_ERRORS_GUARD = threading.Lock()


def _invocation_matches(process, command, expected: tuple[str, ...]) -> bool:
    """Match a real interpreter invocation, never mentions in arbitrary text.

    This establishes liveness identity, not signed-build or runtime integrity.
    Resolve a relative script against that process's cwd, not our own cwd.
    """
    if not _invocation_arguments_match(process, command, expected):
        return False
    normalize = lambda path: os.path.normcase(os.path.realpath(path))
    executable = normalize(expected[0])
    allowed = {executable}
    basename = os.path.basename(executable)
    if os.name == "nt" and basename in {"python.exe", "pythonw.exe"}:
        sibling = "pythonw.exe" if basename == "python.exe" else "python.exe"
        allowed.add(normalize(os.path.join(os.path.dirname(executable), sibling)))
    return normalize(process.exe()) in allowed


def _invocation_arguments_match(process, command, expected) -> bool:
    if (not expected or not isinstance(command, (list, tuple)) or len(command) < len(expected)
            or not all(isinstance(part, str) for part in command)):
        return False
    if len(expected) == 1:
        return True
    # Presentation launches may add harmless interpreter options. Never scan
    # past -c/stdin or treat their code text as a script path.
    index = 1
    for _ in range(16):
        if index >= len(command):
            return False
        token = command[index]
        if token in {"-u", "-B", "-E", "-I", "-s", "-S", "-P", "-O", "-OO", "-q"}:
            index += 1
        elif token in {"-X", "-W"} and index + 1 < len(command):
            index += 2
        else:
            break
    command = [command[0], *command[index:]]
    if len(command) < len(expected):
        return False
    normalize = lambda path: os.path.normcase(os.path.realpath(path))
    if len(expected) > 2 and expected[1] == "-m":
        if tuple(command[1:len(expected)]) != expected[1:]:
            return False
    else:
        if len(expected) < 2 or command[1].startswith("-"):
            return False
        script = command[1]
        if not os.path.isabs(script):
            script = os.path.join(process.cwd(), script)
        if (normalize(script) != normalize(expected[1])
                or tuple(command[2:len(expected)]) != expected[2:]):
            return False
    return True


def _invocation_identity(process, expected):
    """Capture one exact invocation generation, including a venv redirector."""
    command = process.cmdline() or []
    birth, image = float(process.create_time()), str(process.exe())
    parent_identity = None
    if not _invocation_matches(process, command, expected):
        if (os.name != "nt" or len(expected) < 2
                or os.path.basename(expected[0]).casefold() not in {"python.exe", "pythonw.exe"}
                or not _invocation_arguments_match(process, command, expected)):
            return None
        # Shared base Python alone never authorizes adoption. It must be a
        # live child of the exact expected venv redirector and invocation.
        base = Path(getattr(sys, "_base_executable", sys.executable))
        allowed_base = {os.path.normcase(str(base.resolve())),
                        os.path.normcase(str(base.with_name("pythonw.exe").resolve()))}
        if os.path.normcase(str(Path(image).resolve())) not in allowed_base:
            return None
        import psutil
        parent = psutil.Process(process.ppid())
        if not _invocation_matches(parent, parent.cmdline() or [], expected):
            return None
        parent_identity = (int(parent.pid), float(parent.create_time()), str(parent.exe()))
        if birth < parent_identity[1] or not parent.is_running():
            return None
    if not process.is_running():
        return None
    return {"pid": int(process.pid), "birth": birth, "image": image,
            "parent": parent_identity}


def _venv_redirector(process, expected):
    if os.name != "nt" or len(expected) < 2:
        return False
    executable = Path(process.exe())
    return (executable.name.casefold() in {"python.exe", "pythonw.exe"}
            and executable.parent.name.casefold() == "scripts"
            and (executable.parent.parent / "pyvenv.cfg").is_file()
            and os.path.normcase(str(executable.resolve())) != os.path.normcase(
                str(Path(getattr(sys, "_base_executable", sys.executable)).resolve())))


def cached_cmdline_probe(*needles: str, psutil_module=None,
                         expected_argv=None) -> Callable[[], bool]:
    """Return a liveness probe that scans the process table only on adoption.

    Heartbeat-less sidecars used to call ``process_iter(cmdline)`` on every
    supervisor tick in both the Core and peer Watchdog. Once a matching process
    is found, psutil's ``Process.is_running`` preserves PID-reuse identity and is
    sufficient until that exact process exits. A dead cached process triggers an
    immediate full rescan, preserving adopt/restart behavior without perpetual
    whole-host enumeration.

    ``psutil_module`` is an injection seam for deterministic regression tests.
    """
    cached_process = None
    cached_identity = None
    loaded_psutil = psutil_module
    expected = tuple(expected_argv) if expected_argv is not None else None
    if expected is not None and (not expected or not all(
            isinstance(part, str) and part for part in expected)):
        raise ValueError("An exact executable or module/script invocation is required")

    def _probe() -> bool:
        nonlocal cached_process, cached_identity, loaded_psutil
        if cached_process is not None:
            try:
                status_reader = getattr(cached_process, "status", None)
                zombie = getattr(loaded_psutil, "STATUS_ZOMBIE", "zombie")
                is_zombie = (
                    callable(status_reader) and status_reader() == zombie
                )
                if cached_process.is_running() and not is_zombie:
                    return True
            except Exception:
                pass
            cached_process = None
            cached_identity = None
        try:
            if loaded_psutil is None:
                import psutil as loaded_psutil_module
                loaded_psutil = loaded_psutil_module
            for process in loaded_psutil.process_iter(["cmdline"]):
                try:
                    command = process.info.get("cmdline") or []
                    if expected is not None:
                        if not _invocation_arguments_match(process, command, expected):
                            continue
                        # Capture the actual interpreter child, whose proof
                        # includes this redirector's exact generation. Killing
                        # only a redirector would strand the real sidecar.
                        if _venv_redirector(process, expected):
                            continue
                        # process_iter info can be cached: confirm fresh argv
                        # and PID generation before adopting this sidecar.
                        identity = _invocation_identity(process, expected)
                        if identity is None:
                            continue
                        cached_identity = identity
                    elif not command or not all(needle in command for needle in needles):
                        continue
                    cached_process = process
                    return True
                except Exception:
                    # One denied/exited process must not hide a later valid one.
                    continue
        except Exception:
            cached_process = None
        return False

    _probe.retained_identity = lambda: dict(cached_identity) if cached_identity else None
    return _probe


# ── detached, windowed spawning ──────────────────────────────────────────────
def spawn_detached(argv: list[str], env: Optional[dict] = None,
                   window: str = "minimized", *, cwd=None):
    """Start a process fully detached from this one's process group/tree.

    window: 'minimized' (own console, minimized), 'hidden' (no window), or
    'normal' (own console, foreground). On POSIX the window hint is ignored and
    the child is placed in a new session (setsid)."""
    from angerona.core.privilege import sanitized_child_environment

    # Sidecars need local runtime/heartbeat coordinates, not the core's cloud,
    # mail, webhook, fleet, or provider credentials. Building the block from an
    # allowlist also prevents proxy/Python controls from crossing this boundary.
    kwargs: dict = {
        "env": sanitized_child_environment(env),
        "close_fds": True,
    }
    if cwd is not None:
        kwargs["cwd"] = cwd
    if os.name == "nt":
        from angerona.core.windows_child_job import launch_windows_child

        # A peer watchdog survives a core crash. Its private job closes without
        # killing; explicit STOP terminates the retained job and descendants.
        return launch_windows_child(
            argv, kwargs["env"], cwd=cwd, window=window, kill_on_close=False,
        )
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
    with _SPAWN_LOCK_ERRORS_GUARD:
        _SPAWN_LOCK_ERRORS.pop(name, None)
    created = False
    fd: int | None = None
    try:
        fd = os.open(str(p), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        created = True
        os.write(fd, f"{os.getpid()} {time.time()}".encode())
        os.close(fd)
        fd = None
        return True
    except FileExistsError:
        try:
            if time.time() - p.stat().st_mtime > ttl:   # stale lock → steal it
                p.unlink()
                return try_claim_spawn(name, ttl)
        except FileNotFoundError:
            return try_claim_spawn(name, ttl)
        except Exception as exc:
            with _SPAWN_LOCK_ERRORS_GUARD:
                _SPAWN_LOCK_ERRORS[name] = type(exc).__name__
        return False
    except Exception as exc:
        # A lock I/O failure cannot safely grant spawn authority: doing so lets
        # both supervisors launch the same component. Record a bounded diagnostic
        # and let the next supervisor tick retry.
        with _SPAWN_LOCK_ERRORS_GUARD:
            _SPAWN_LOCK_ERRORS[name] = type(exc).__name__
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if created:
            try:
                p.unlink()
            except OSError:
                pass
        return False


def spawn_lock_error(name: str) -> str:
    """Return the latest bounded lock error name, if claiming failed on I/O."""
    with _SPAWN_LOCK_ERRORS_GUARD:
        return _SPAWN_LOCK_ERRORS.get(name, "")


def release_spawn(name: str) -> None:
    try:
        _spawnlock_path(name).unlink()
    except Exception:
        pass


def request_restart(*names: str) -> list[Path]:
    """Ask the supervisor(s) to force-restart the named components on the next tick
    (clears SAFE_MODE too). Pass '*' or no name for ALL. Cross-process via a file.

    Hardening: the command is HMAC-signed with the per-install key (same bus.key as
    the stand-down command), so a lower-privileged local process can't drop a
    restart.cmd to poke the elevated supervisor. Unsigned/forged files are rejected
    AND raised as a tamper alert by the reader."""
    import hashlib
    import hmac
    import json
    import secrets
    import time as _t
    written: list[Path] = []
    try:
        from angerona.resilience import shutdown_token as _tok
        key = _tok._load_key()
        requested = [
            str(n).strip().lower() for n in (names or ("*",))
            if str(n).strip().lower() in _VALID_RESTART_TARGETS
        ] or ["*"]
        # Use one target-specific inbox per explicit component. Multiple
        # supervisors share the runtime directory; a single restart.cmd let the
        # wrong supervisor consume and delete a "core" request before the
        # watchdog saw it. Only a supervisor that owns the target now reads its
        # file. Wildcard keeps the legacy shared inbox.
        groups = [["*"]] if "*" in requested else [[target] for target in requested]
        for targets in groups:
            nonce = secrets.token_hex(16)
            ts = int(_t.time())
            payload = f"{nonce}\x00{ts}\x00{','.join(targets)}"
            sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
            cmd = {"nonce": nonce, "ts": ts, "targets": targets, "sig": sig}
            suffix = "" if targets == ["*"] else f".{targets[0]}"
            p = _ipc_dir() / f"restart{suffix}.cmd"
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text(json.dumps(cmd), encoding="utf-8")
            os.replace(tmp, p)          # atomic publish
            written.append(p)
    except Exception:
        return []
    return written


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
    safe_mode_since: float = 0.0    # when SAFE_MODE was entered (for cooldown recovery)
    next_restart_at: float = 0.0
    last_state: str = "unknown"
    last_diagnostic_sha256: str = ""
    state_fault: bool = False
    restarts: int = 0
    adopted: bool = False
    adopted_identity: Optional[dict] = None
    auth_notice: str = ""


class ProcessSupervisor:
    def __init__(self, poll_interval: float = 1.0,
                 on_event: Optional[Callable[[str, str, dict], None]] = None,
                 *,
                 state_namespace: Optional[str] = None,
                 state_store: Optional[RecoveryStateStore] = None,
                 clock: Callable[[], float] = time.time,
                 initial_backoff_s: float = 1.0,
                 max_backoff_s: float = 60.0):
        if initial_backoff_s <= 0 or max_backoff_s < initial_backoff_s:
            raise ValueError("invalid supervisor restart backoff")
        self.components: dict[str, Component] = {}
        self.poll_interval = poll_interval
        self.on_event = on_event
        self._clock = clock
        self.initial_backoff_s = float(initial_backoff_s)
        self.max_backoff_s = float(max_backoff_s)
        self.state_namespace = safe_name(state_namespace or "ephemeral")
        self._state_store = state_store
        if self._state_store is None and state_namespace:
            self._state_store = RecoveryStateStore(
                self.state_namespace,
                clock=clock,
            )
        self._stop = threading.Event()
        self._lifecycle_lock = threading.RLock()
        self._thread: Optional[threading.Thread] = None

    # ── registration ─────────────────────────────────────────────────────────
    def add(self, name: str, argv: list, **kw) -> Component:
        c = Component(name=name, argv=list(argv), **kw)
        c.reader = hb.HeartbeatReader(name)
        if self._state_store is not None:
            try:
                record = self._state_store.component(name)
                c._failures.extend(record["failures"])
                c.safe_mode = record["safe_mode"]
                c.safe_mode_since = record["safe_mode_since"]
                c.next_restart_at = record["next_restart_at"]
                c.last_state = record["last_state"]
                c.last_diagnostic_sha256 = record["last_diagnostic_sha256"]
                c.state_fault = record["state_fault"]
            except RecoveryStateError as exc:
                c.safe_mode = True
                c.safe_mode_since = self._clock()
                c.state_fault = True
                self._emit(
                    "CRITICAL",
                    f"{name} recovery state failed authentication; automatic "
                    "respawns are paused until an authenticated manual restart.",
                    component=name,
                    error=type(exc).__name__,
                )
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
    @staticmethod
    def _authenticated_record(c: Component) -> tuple[Optional[dict], str]:
        if c.reader is None:
            return None, "missing"
        rec = c.reader.read()
        if rec is None:
            return None, "missing"
        verifier = getattr(c.reader, "authentication_status", None)
        if not callable(verifier):
            # Test doubles and heartbeat-less compatibility probes do not cross
            # this production boundary. Real HeartbeatReader always verifies.
            return rec, "authenticated"
        return rec, str(verifier(record=rec))

    def _report_auth_state(self, c: Component, status: str) -> None:
        if status == "authenticated":
            c.auth_notice = ""
            return
        if status == c.auth_notice:
            return
        c.auth_notice = status
        if status == "legacy":
            message = (
                f"{c.name} exposes a legacy unauthenticated heartbeat; it will "
                "not be adopted, terminated, or treated as healthy. Upgrade the "
                "peer for v2 authenticated heartbeat support."
            )
        else:
            message = (
                f"Rejected {c.name} heartbeat ({status}); full-field proof or "
                "anti-replay validation failed. Automatic destructive recovery "
                "is paused for this observation."
            )
        self._emit("HIGH", message, component=c.name, heartbeat_auth=status)

    def _is_running(self, c: Component) -> bool:
        if c.running_probe is not None:
            try:
                return bool(c.running_probe())
            except Exception:
                return False
        if c.reader is None:
            return False
        rec, auth = self._authenticated_record(c)
        if auth != "authenticated":
            if auth != "missing":
                self._report_auth_state(c, auth)
            return False
        self._report_auth_state(c, auth)
        if not rec or rec.get("flags") == 0:
            return False
        age = (time.time_ns() - rec["ts_ns"]) / 1e9
        # Fresh tick AND the writer's pid still alive ⇒ genuinely running.
        return abs(age) <= max(c.stale_after_s, 2.0) and hb.pid_alive(
            rec.get("pid", 0)
        )

    # ── spawning (adopt-if-alive + cross-process lock) ───────────────────────
    def _spawn(self, c: Component) -> bool:
        with self._lifecycle_lock:
            return self._spawn_locked(c)

    def _respawn_blocked(self) -> bool:
        return self._stop.is_set() or tok.is_standdown_requested()

    def _spawn_locked(self, c: Component) -> bool:
        if self._respawn_blocked():
            return False
        # Already up (perhaps started by the other supervisor)? Adopt it.
        if self._is_running(c):
            captured = getattr(c.running_probe, "retained_identity", None)
            if callable(captured):
                c.adopted_identity = captured()
            c._dead = False
            if not c.adopted:
                c.adopted = True
                self._emit("INFO", f"adopted already-running {c.name} (no duplicate started)",
                           component=c.name)
            return True
        # Only one supervisor may spawn a given component at a time.
        rec, auth = self._authenticated_record(c)
        if rec and auth != "authenticated":
            if hb.pid_alive(int(rec.get("pid", 0))):
                self._report_auth_state(c, auth)
                return False
        if not try_claim_spawn(c.name):
            error = spawn_lock_error(c.name)
            if error:
                self._emit(
                    "HIGH",
                    f"{c.name}: spawn lock I/O failed closed; launch deferred "
                    "and will retry on the next supervisor tick.",
                    component=c.name,
                    lock_error=error,
                )
            return False
        try:
            if self._is_running(c):     # double-check under the lock
                return True
            if self._respawn_blocked():
                return False
            # This flag only inhibits startup. It grants no trust or privilege.
            # A child launched just before STOP must never clear its stop token.
            env = dict(os.environ)
            if c.name == "core":
                env["ANGERONA_SUPERVISED_RECOVERY"] = "1"
            c.proc = spawn_detached(c.argv, env=env, window=c.window)
            if self._respawn_blocked():
                self._terminate(c)
                return False
            c._dead = False
            c.adopted = False
            c.adopted_identity = None
            c.restarts += 1
            threading.Thread(target=self._waiter, args=(c, c.proc), daemon=True,
                             name=f"wait-{c.name}").start()
            self._emit("INFO", f"launched {c.name} ({c.window}) pid {c.proc.pid}",
                       component=c.name, pid=c.proc.pid, restarts=c.restarts)
            return True
        except Exception as exc:
            self._emit("CRITICAL", f"failed to spawn {c.name}: {exc}", component=c.name)
            return False
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
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._start_locked()

    def _start_locked(self) -> None:
        self._stop.clear()
        if tok.is_standdown_requested():
            return
        # Adopt-if-alive: never start a second instance of something already up.
        for c in self.components.values():
            if c.safe_mode and not self._is_running(c):
                self._emit(
                    "HIGH",
                    f"{c.name} remains stopped because durable SAFE_MODE is active.",
                    component=c.name,
                )
                continue
            self._spawn(c)
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
        with self._lifecycle_lock:
            return self._tick_locked()

    def _tick_locked(self) -> dict:
        actions: dict = {}
        standdown = self._respawn_blocked()
        forced = self._pop_restart_requests()       # operator/console manual restart
        if standdown:
            return {name: "standdown" for name in self.components}
        now = self._clock()
        for name, c in self.components.items():
            # Manual restart: force a respawn now, clearing SAFE_MODE.
            if name in forced or "*" in forced:
                self._capture_recovery_snapshot(c, "manual_restart")
                c.safe_mode = False
                c.safe_mode_since = 0.0
                c.next_restart_at = 0.0
                c.state_fault = False
                c._failures.clear()
                if self._state_store is not None:
                    try:
                        self._state_store.clear_component(
                            name,
                            authenticated_reset=True,
                        )
                    except Exception as exc:
                        self._emit(
                            "HIGH",
                            f"{name}: manual restart could not reset durable state.",
                            component=name,
                            error=type(exc).__name__,
                        )
                if not self._terminate(c):
                    actions[name] = "manual_restart_failed"
                    self._emit(
                        "HIGH",
                        f"{name}: manual restart refused because the current "
                        "process could not be safely terminated.",
                        component=name,
                    )
                    continue
                self._spawn(c)
                actions[name] = "manual_restart"
                self._emit("INFO", f"{name}: manual restart — respawned.", component=name)
                continue
            # SAFE_MODE recovery: never give up forever. After a cooldown, clear it
            # and allow a retry — a transient crash-loop (or a since-fixed bug) then
            # recovers automatically instead of staying permanently dead.
            if (
                c.safe_mode
                and not c.state_fault
                and now - c.safe_mode_since >= _SAFE_MODE_COOLDOWN
            ):
                c.safe_mode = False
                c.safe_mode_since = 0.0
                c.next_restart_at = 0.0
                c._failures.clear()
                self._persist(c)
                self._emit("INFO", f"{name} leaving SAFE_MODE after "
                           f"{_SAFE_MODE_COOLDOWN:.0f}s cooldown — retrying.", component=name)
            state = self._assess(c)
            state_changed = state != c.last_state
            if state_changed:
                c.last_state = state
            actions[name] = state
            if standdown:
                if state_changed:
                    self._persist(c)
                continue
            if state in ("dead", "suspended") and not c.safe_mode:
                if c.next_restart_at and now < c.next_restart_at:
                    actions[name] = f"backoff({state})"
                    if state_changed:
                        self._persist(c)
                    continue
                if not c.next_restart_at:
                    entered_safe_mode = self._register_failure(c)
                    if entered_safe_mode:
                        c.safe_mode = True
                        c.safe_mode_since = now
                        c.next_restart_at = 0.0
                    self._capture_recovery_snapshot(c, state)
                    if entered_safe_mode:
                        self._persist(c)
                        self._emit(
                            "CRITICAL",
                            f"{name} entered SAFE_MODE after {c.max_failures} failures in "
                            f"{c.window_s:.0f}s; respawns paused, auto-retry in "
                            f"{_SAFE_MODE_COOLDOWN:.0f}s (or use manual restart).",
                            component=name,
                        )
                        actions[name] = "safe_mode"
                        continue
                    delay = min(
                        self.max_backoff_s,
                        self.initial_backoff_s * (2 ** max(0, len(c._failures) - 1)),
                    )
                    c.next_restart_at = now + delay
                    if not self._persist(c):
                        c.safe_mode = True
                        c.safe_mode_since = now
                        c.state_fault = True
                        actions[name] = "safe_mode(persistence_fault)"
                        continue
                    actions[name] = f"backoff({state})"
                    self._emit(
                        "INFO",
                        f"{name}: {state} observed; restart scheduled after "
                        f"{delay:.1f}s backoff.",
                        component=name,
                        delay_s=delay,
                    )
                    continue
                if state == "suspended":
                    if not self._terminate(c):
                        c.next_restart_at = now + self.max_backoff_s
                        self._persist(c)
                        actions[name] = "termination_failed"
                        continue
                spawned = self._spawn(c)
                c.next_restart_at = 0.0
                self._persist(c)
                actions[name] = (
                    f"respawned({state})" if spawned else f"restart_deferred({state})"
                )
            elif state == "alive":
                if c.next_restart_at:
                    c.next_restart_at = 0.0
                    state_changed = True
                if state_changed:
                    self._persist(c)
            elif state_changed:
                self._persist(c)
        return actions

    def _capture_recovery_snapshot(self, c: Component, state: str) -> None:
        heartbeat = None
        try:
            heartbeat = c.reader.read() if c.reader else None
        except Exception:
            heartbeat = None
        try:
            digest = diag.write_recovery_snapshot(
                c.name,
                state,
                namespace=self.state_namespace,
                heartbeat=heartbeat,
                failure_count=len(c._failures),
                restart_count=c.restarts,
                safe_mode=c.safe_mode,
                next_restart_at=c.next_restart_at,
            )
            if digest:
                c.last_diagnostic_sha256 = digest
            else:
                self._emit(
                    "HIGH",
                    f"{c.name}: pre-restart diagnostic snapshot could not be written.",
                    component=c.name,
                )
        except Exception as exc:
            self._emit(
                "HIGH",
                f"{c.name}: pre-restart diagnostic capture failed.",
                component=c.name,
                error=type(exc).__name__,
            )

    def _persist(self, c: Component) -> bool:
        if self._state_store is None:
            return True
        try:
            self._state_store.update_component(
                c.name,
                {
                    "failures": list(c._failures),
                    "safe_mode": c.safe_mode,
                    "safe_mode_since": c.safe_mode_since,
                    "next_restart_at": c.next_restart_at,
                    "last_state": c.last_state,
                    "last_diagnostic_sha256": c.last_diagnostic_sha256,
                    "state_fault": c.state_fault,
                },
            )
            return True
        except Exception as exc:
            self._emit(
                "HIGH",
                f"{c.name}: durable recovery state could not be saved; automatic "
                "restart is paused to prevent an unbudgeted crash loop.",
                component=c.name,
                error=type(exc).__name__,
            )
            return False

    # ── manual restart (operator-triggered, cross-process via a command file) ──
    @staticmethod
    def _restart_cmd_path() -> Path:
        return _ipc_dir() / "restart.cmd"

    def _pop_restart_requests(self) -> set:
        paths = [self._restart_cmd_path()]
        paths.extend(
            _ipc_dir() / f"restart.{name}.cmd"
            for name in sorted(self.components)
        )
        import hashlib
        import hmac
        import json
        import time as _t
        forced: set[str] = set()
        for p in paths:
            try:
                if not p.exists():
                    continue
                raw = p.read_text(encoding="utf-8")
                p.unlink()
            except Exception:
                continue
            try:
                from angerona.resilience import shutdown_token as _tok
                cmd = json.loads(raw)
                nonce = str(cmd.get("nonce", ""))
                ts = int(cmd.get("ts", 0))
                targets = cmd.get("targets", [])
                sig = str(cmd.get("sig", ""))
                if not isinstance(targets, list):
                    continue
                # A restart is immediate; ignore anything older than 30s.
                if _t.time() - ts > 30:
                    continue
                payload = f"{nonce}\x00{ts}\x00{','.join(str(x) for x in targets)}"
                expected = hmac.new(_tok._load_key(), payload.encode("utf-8"),
                                    hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, sig):
                    self._emit(
                        "HIGH",
                        "Rejected an UNSIGNED/forged restart command in ipc/ — a "
                        "lower-privileged local process may be probing the supervisor.",
                        component="supervisor",
                    )
                    continue
                valid = {
                    str(n).strip() for n in targets
                    if str(n).strip() == "*" or str(n).strip() in self.components
                }
                if valid:
                    forced.update(valid)
                    self._emit(
                        "INFO",
                        f"Authenticated restart command for: {', '.join(sorted(valid))}.",
                        component="supervisor",
                    )
            except Exception:
                continue
        return forced

    def _assess(self, c: Component) -> str:
        # Heartbeat-less components (BlackBox): liveness is the process probe.
        if c.running_probe is not None:
            return "alive" if self._is_running(c) else "dead"
        # A returned proc.wait() (real process exit) is authoritative for death.
        if c._dead:
            return "dead"
        rec, auth = self._authenticated_record(c)
        if auth != "authenticated":
            if auth == "missing":
                return "dead"
            self._report_auth_state(c, auth)
            return "legacy_unverified" if auth == "legacy" else f"unauthenticated_{auth}"
        self._report_auth_state(c, auth)
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
        now = self._clock()
        c._failures.append(now)
        while c._failures and now - c._failures[0] > c.window_s:
            c._failures.popleft()
        return len(c._failures) >= c.max_failures

    def _decay(self, c: Component) -> None:
        now = self._clock()
        while c._failures and now - c._failures[0] > c.window_s:
            c._failures.popleft()
        if c.safe_mode and not c.state_fault and not c._failures:
            c.safe_mode = False
            self._emit("INFO", f"{c.name} left SAFE_MODE (healthy again).", component=c.name)

    def _terminate(self, c: Component) -> bool:
        if c.proc is not None and getattr(c.proc, "owns_descendants", False):
            try:
                c.proc.terminate()
                c.proc.wait(timeout=3.0)
                c.proc.wait_tree(timeout=3.0)
                c.proc.close()
                c.proc = None
                c._dead = True
                return True
            except Exception:
                # Keep custody for retry; do not discover shared siblings.
                return False
        if c.proc and c.proc.poll() is None:
            try:
                c.proc.terminate()
                try:
                    c.proc.wait(timeout=3)
                except Exception:
                    c.proc.kill()
                    c.proc.wait(timeout=3)
                c._dead = True
                return True
            except Exception:
                return False
        # A peer supervisor commonly *adopts* the already-running Core from its
        # heartbeat, so it has no Popen handle. Manual restart and suspended-core
        # recovery must still be able to stop that exact process before _spawn(),
        # otherwise the fresh heartbeat makes _spawn() re-adopt it and the
        # restart button appears to do nothing.
        try:
            adopted = c.adopted_identity
            if adopted is not None:
                pid = int(adopted["pid"])
            else:
                rec, auth = self._authenticated_record(c)
                if auth != "authenticated":
                    self._report_auth_state(c, auth)
                    return False
                pid = int((rec or {}).get("pid") or 0)
            if not pid or not hb.pid_alive(pid):
                return True
            import psutil
            proc = psutil.Process(pid)
            expected = tuple(str(part) for part in c.argv)
            # Full/Chill is presentation intent, not a distinct core identity.
            if c.name == "core":
                expected = tuple(part for part in expected if part != "--chill")
            identity = _invocation_identity(proc, expected)
            if identity is None or (adopted is not None and identity != adopted):
                self._emit(
                    "HIGH",
                    f"Refused to terminate adopted {c.name}: invocation identity mismatch.",
                    component=c.name,
                    pid=pid,
                )
                return False
            if os.name == "nt":
                from angerona.core.windows_process_lease import WindowsProcessLease

                # Birth/image checks and termination use one retained native
                # handle. A reused heartbeat PID cannot target a shared Python.
                with ExitStack() as stack:
                    parent = identity["parent"]
                    parent_lease = (stack.enter_context(WindowsProcessLease(
                        parent[0], parent[1], parent[2], lifetime=10.0,
                    )) if parent is not None else None)
                    lease = stack.enter_context(WindowsProcessLease(
                        pid, identity["birth"], identity["image"], lifetime=10.0,
                    ))
                    if _invocation_identity(proc, expected) != identity:
                        return False
                    lease.terminate()
                    lease.wait_terminated(timeout=3.0)
                    if parent_lease is not None:
                        parent_lease.wait_terminated(timeout=3.0)
            else:
                # psutil's signal methods revalidate this cached PID generation.
                if not proc.is_running() or proc.create_time() != identity["birth"]:
                    return False
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
                    proc.wait(timeout=3)
            c._dead = True
            return True
        except Exception as exc:
            self._emit(
                "ERROR",
                f"Could not terminate adopted {c.name}: {exc}",
                component=c.name,
            )
            return False

    def stop(self, terminate_children: bool = True) -> None:
        self._stop.set()
        with self._lifecycle_lock:
            if terminate_children:
                for c in self.components.values():
                    self._terminate(c)
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def request_stop(self) -> None:
        """Close respawn admission without waiting on an in-flight launch."""
        self._stop.set()


def self_test() -> tuple[bool, str]:
    """Live (Linux/Unix) test: spawn a detached child that heartbeats then exits;
    verify respawn-on-death, SAFE_MODE backoff, stand-down halt, AND adopt-if-alive
    (a second _spawn while the child is alive does NOT start a duplicate)."""
    from angerona.resilience._selftest_environment import run_isolated_selftest

    return run_isolated_selftest(
        "supervisor",
        "sup_selftest_",
        lambda root: {
            "ANGERONA_DATA": str(root),
            "ANGERONA_DIAG_DIR": str(root / "diag"),
        },
        timeout=25.0,
    )


def _isolated_self_test() -> tuple[bool, str]:
    workdir = os.environ["ANGERONA_DATA"]
    sup = ProcessSupervisor(
        poll_interval=0.2,
        initial_backoff_s=0.05,
        max_backoff_s=0.2,
    )
    try:
        child = os.path.join(workdir, "child.py")
        with open(child, "w") as f:
            f.write(
                "import sys,time\n"
                "sys.path.insert(0, %r)\n" % str(__import__(
                    "angerona.core.data_paths", fromlist=["project_root"]
                ).project_root() / "src") +
                "from angerona.resilience import heartbeat as hb\n"
                "name=sys.argv[1]; beats=int(sys.argv[2])\n"
                "w=hb.HeartbeatWriter(name)\n"
                "for _ in range(beats):\n"
                "    w.beat(); time.sleep(0.1)\n"
                "w.close()\n"
            )
        py = sys.executable

        c = sup.add("scanner", [py, child, "scanner", "40"], stale_after_s=1.0,
                    max_failures=3, window_s=60.0, window="normal")
        sup._spawn(c)
        ready_deadline = time.time() + 4.0
        alive_ok = False
        while time.time() < ready_deadline:
            alive_ok = sup._is_running(c)
            if alive_ok:
                break
            time.sleep(0.05)

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

        ok = alive_ok and no_dup_ok and respawn_ok and safemode_ok and standdown_ok
        return ok, ("minimized detached spawn + adopt-if-alive (no duplicate) + "
                    "respawn-on-death + SAFE_MODE + stand-down verified" if ok else
                    f"failed: alive={alive_ok} no_dup={no_dup_ok} respawn={respawn_ok} "
                    f"safemode={safemode_ok} standdown={standdown_ok}")
    finally:
        tok.clear_standdown()
        sup.stop()


if __name__ == "__main__":
    print(self_test())
