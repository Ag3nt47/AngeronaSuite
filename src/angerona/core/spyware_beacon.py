"""Explicitly authorized, minimal SpywareGuard emergency notifications.

The independent watcher owns no response authority. It can report only a lost
heartbeat or the disappearance of one exact engine process. A verified normal
stop, a revoked setting, ambiguous process identity, or invalid IPC stops it
without notification. Power loss, network isolation, and a compromised watcher
can prevent delivery; this is a best-effort notification, not a recovery agent.

No credentials are written to sidecars, command lines, logs, or snapshots. The
watcher receives its per-run authority and configured destinations through an
anonymous stdin pipe. Tests inject transports and never send live messages.
"""
from __future__ import annotations

from collections import OrderedDict, deque
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import queue
import re
import secrets
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from typing import Callable

from angerona.connectors.channel_push import ChannelPush, Level, Target

_DOMAIN = b"angerona/spyware-beacon-watch/v1\0"
_MAX_WIRE = 16384
_MAX_QUEUE = 64
_MAX_SEEN = 512
_DEDUP_SECONDS = 600.0
_MAX_ATTEMPTS = 3
_WINDOW_SECONDS = 60.0
_WINDOW_ATTEMPTS = 3
# A full host audit plus bounded research fetches can exceed 30 seconds. Exact
# parent death remains immediate; a stalled worker receives a two-minute lease.
_HEARTBEAT_TIMEOUT = 120.0
_EOF_EXIT_GRACE = 0.25
_CONFIG_FIELDS = (
    "spyware_beacon_enabled", "spyware_beacon_channel", "spyware_beacon_signal",
    "aria_push_enabled", "aria_push_url", "aria_push_kind", "mobile_enabled",
    "mobile_signal_cli", "mobile_signal_cli_sha256", "mobile_signal_cli_publisher",
    "mobile_host_number", "mobile_dest_number",
)
_BOOL_FIELDS = frozenset({
    "spyware_beacon_enabled", "spyware_beacon_channel", "spyware_beacon_signal",
    "aria_push_enabled", "mobile_enabled",
})
_MOBILE_FIELDS = tuple(name for name in _CONFIG_FIELDS if name.startswith("mobile_"))
_RULE = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _config_snapshot(config) -> dict:
    values = {}
    for name in _CONFIG_FIELDS:
        value = getattr(config, name, False if name in _BOOL_FIELDS else "")
        values[name] = value is True if name in _BOOL_FIELDS else str(value or "")[:4096]
    return values


def _channel_enabled(config) -> bool:
    return (getattr(config, "spyware_beacon_channel", False) is True
            and getattr(config, "aria_push_enabled", False) is True
            and bool(getattr(config, "aria_push_url", "")))


def _signal_enabled(config) -> bool:
    if not (getattr(config, "spyware_beacon_signal", False) is True
            and getattr(config, "mobile_enabled", False) is True):
        return False
    # A phone target is a configured E.164 identity, never incident-controlled.
    from angerona.modules.mobile_bridge import _signal_identity
    return bool(getattr(config, "mobile_signal_cli", "")
                and _signal_identity(getattr(config, "mobile_host_number", ""))
                and _signal_identity(getattr(config, "mobile_dest_number", "")))


def _authorized(config) -> bool:
    return (getattr(config, "spyware_beacon_enabled", False) is True
            and (_channel_enabled(config) or _signal_enabled(config)))


def _identity_state(pid: int, birth: float) -> str:
    """Distinguish death from PID reuse and inability to verify identity."""
    try:
        import psutil
        try:
            process = psutil.Process(pid)
            if abs(process.create_time() - birth) > 0.001:
                return "reused"
            if not process.is_running() or process.status() == psutil.STATUS_ZOMBIE:
                return "gone"
            return "alive"
        except psutil.NoSuchProcess:
            return "gone"
        except (psutil.AccessDenied, psutil.Error):
            return "unknown"
    except (ImportError, OSError, ValueError):
        return "unknown"


def _settings_authorized(path: Path, initial: dict) -> bool:
    """Fresh persisted opt-in is required; unreadable settings are no authority."""
    try:
        from angerona.core.secure_store import _path_traverses_reparse
        from angerona.core.engine_transport import verify_private
        if _path_traverses_reparse(path):
            return False
        verify_private(path)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            return False
        with path.open("rb") as stream:
            held = os.fstat(stream.fileno())
            if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
                return False
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return False
        saved = json.loads(raw)
        if not isinstance(saved, dict) or saved.get("spyware_beacon_enabled") is not True:
            return False
        # A changed destination/configuration requires a new watcher run. A
        # webhook secret is deliberately absent from ordinary settings.json.
        for field in _CONFIG_FIELDS:
            if field == "aria_push_url":
                continue
            if saved.get(field, False if field in _BOOL_FIELDS else "") != initial[field]:
                return False
        return True
    except Exception:
        return False


def _stored_destination_current(path: Path, initial: dict) -> bool:
    """A removed/rotated protected webhook also revokes the old watcher."""
    if not (initial.get("spyware_beacon_channel") is True
            and initial.get("aria_push_enabled") is True):
        return True
    try:
        from angerona.core.secure_store import read_secret_values
        stored = read_secret_values(("ANGERONA_ARIA_PUSH_URL",), path.parent, strict=True)
        return (bool(initial.get("aria_push_url"))
                and stored.get("ANGERONA_ARIA_PUSH_URL") == initial["aria_push_url"])
    except Exception:
        return False


def _wrap(body: dict, key: bytes) -> dict:
    return {"body": body, "mac": hmac.new(key, _DOMAIN + _canonical(body),
                                         hashlib.sha256).hexdigest()}


def _verify(message: object, key: bytes, run: str, previous: int) -> dict | None:
    try:
        if not isinstance(message, dict) or set(message) != {"body", "mac"}:
            return None
        body, mac = message["body"], message["mac"]
        if (not isinstance(body, dict) or set(body) != {"run", "seq", "kind"}
                or body.get("run") != run or type(body.get("seq")) is not int
                or body["seq"] <= previous or body.get("kind") not in {"heartbeat", "stop"}
                or not isinstance(mac, str) or len(mac) != 64):
            return None
        expected = _wrap(body, key)["mac"]
        return body if hmac.compare_digest(mac, expected) else None
    except (ValueError, TypeError, RecursionError):
        return None


class EmergencyBeacon:
    """Bounded, deduplicated notifier; call tick from the module worker.

    Enqueue does no network I/O. The first eligible tick attempts delivery;
    failures retry at most twice, with a global three-attempt/minute limit.
    Successful destinations are never retried for the same incident.
    """

    def __init__(self, config, *, clock: Callable[[], float] = time.time,
                 transport=None, signal_sender=None) -> None:
        self.config = config
        self.clock = clock
        self._transport = transport
        self._signal_sender = signal_sender
        self._lock = threading.RLock()
        self._pending: deque[dict] = deque()
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._attempt_times: deque[float] = deque()
        self._sent = 0
        self._failed = 0
        self._dropped = 0
        self._last_attempt = 0.0
        self._last_state = "disabled" if not _authorized(config) else "ready"
        self._last_reason = ""
        self._watch_process = None
        self._watch_key = b""
        self._watch_run = ""
        self._watch_seq = 0
        self._watch_config: dict = {}
        self._watch_state = "stopped"
        self._closed = False
        self._last_snapshot: dict = {}
        self._inflight = False

    def enqueue(self, incident: dict) -> bool:
        if not isinstance(incident, dict):
            return False
        with self._lock:
            if self._closed or not _authorized(self.config):
                return False
            now = float(self.clock())
            if not math.isfinite(now):
                return False
            while self._seen and next(iter(self._seen.values())) <= now - _DEDUP_SECONDS:
                self._seen.popitem(last=False)
            rule = incident.get("rule_code", incident.get("code", incident.get("rule", "UNKNOWN")))
            rule = rule if isinstance(rule, str) and _RULE.fullmatch(rule) else "UNKNOWN"
            severity = str(incident.get("severity", "CRITICAL")).upper()
            if severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                severity = "CRITICAL"
            pid = incident.get("pid")
            payload = {"incident_id": secrets.token_hex(8), "timestamp": int(now),
                       "rule_code": rule, "severity": severity}
            if type(pid) is int and 0 < pid < 2**32:
                payload["pid"] = pid
            identity = str(incident.get("incident_id", incident.get("id", "")))[:256]
            dedupe = hashlib.sha256(_canonical([identity, rule, payload.get("pid")])).hexdigest()
            if dedupe in self._seen:
                return False
            if len(self._pending) >= _MAX_QUEUE:
                self._dropped += 1
                return False
            self._seen[dedupe] = now
            while len(self._seen) > _MAX_SEEN:
                self._seen.popitem(last=False)
            self._pending.append({"payload": payload, "created": now, "due": now,
                                  "attempts": 0, "delivered": set()})
            self._last_state = "queued"
            return True

    def _send_channel(self, text: str) -> bool:
        try:
            if not (getattr(self.config, "spyware_beacon_enabled", False) is True
                    and _channel_enabled(self.config)):
                return False
            kind = str(getattr(self.config, "aria_push_kind", "webhook"))
            if kind not in {"slack", "teams", "ntfy", "webhook"}:
                return False
            channel = ChannelPush(enabled=True, min_level=Level.CRITICAL,
                                  targets=[Target(kind, self.config.aria_push_url, "emergency")],
                                  transport=self._transport)
            results = channel.push(text, level=Level.CRITICAL)
            return bool(results) and all(result.ok for result in results)
        except Exception:
            return False

    def _send_signal(self, text: str) -> bool:
        try:
            if not (getattr(self.config, "spyware_beacon_enabled", False) is True
                    and _signal_enabled(self.config)):
                return False
            if self._signal_sender is not None:
                return self._signal_sender(text) is True
            # Reuse the sealed binary identity, launch, timeout, and verified
            # receipt path. This notifier never receives remote commands.
            from angerona.modules.mobile_bridge import MobileResponseBridge
            bridge = MobileResponseBridge()
            bridge._config = self.config
            return bridge._send(text) is True
        except Exception:
            return False

    def tick(self) -> None:
        with self._lock:
            if self._closed or self._inflight:
                return
            if not _authorized(self.config):
                self._pending.clear()
                self._last_state = "disabled"
                return
            now = float(self.clock())
            while self._attempt_times and self._attempt_times[0] <= now - _WINDOW_SECONDS:
                self._attempt_times.popleft()
            if len(self._attempt_times) >= _WINDOW_ATTEMPTS:
                self._last_state = "rate_limited"
                return
            selected = None
            for _ in range(len(self._pending)):
                item = self._pending.popleft()
                if now - item["created"] > _DEDUP_SECONDS:
                    self._dropped += 1
                elif selected is None and item["due"] <= now:
                    selected = item
                else:
                    self._pending.append(item)
            if selected is None:
                return
            self._attempt_times.append(now)
            self._last_attempt = now
            selected["attempts"] += 1
            self._inflight = True
        # I/O runs on the caller's worker without holding the snapshot lock.
        # Dashboard reads and configuration revocation remain responsive.
        text = "Angerona SpywareGuard emergency beacon\n" + _canonical(selected["payload"]).decode("ascii")
        required = []
        if _channel_enabled(self.config):
            required.append("channel")
            if "channel" not in selected["delivered"] and self._send_channel(text):
                selected["delivered"].add("channel")
        if getattr(self.config, "spyware_beacon_enabled", False) is True and _signal_enabled(self.config):
            required.append("signal")
            if "signal" not in selected["delivered"] and self._send_signal(text):
                selected["delivered"].add("signal")
        with self._lock:
            self._inflight = False
            if required and all(target in selected["delivered"] for target in required):
                self._sent += 1
                self._last_state = "delivered"
                self._last_reason = ""
            elif (not self._closed and selected["attempts"] < _MAX_ATTEMPTS
                  and _authorized(self.config)):
                selected["due"] = now + (5.0 if selected["attempts"] == 1 else 30.0)
                self._pending.append(selected)
                self._last_state = "retry_pending"
                self._last_reason = "configured destination delivery failed"
            else:
                self._failed += 1
                self._last_state = "delivery_failed"
                self._last_reason = "configured destination delivery failed"

    drain = tick

    def snapshot(self) -> dict:
        if not self._lock.acquire(blocking=False):
            return dict(self._last_snapshot, refreshing=True,
                        enabled=getattr(self.config, "spyware_beacon_enabled", False) is True)
        try:
            result = {"enabled": getattr(self.config, "spyware_beacon_enabled", False) is True,
                    "channel_configured": _channel_enabled(self.config),
                    "signal_configured": _signal_enabled(self.config),
                    "pending": len(self._pending), "sent": self._sent,
                    "sending": self._inflight,
                    "failed": self._failed, "dropped": self._dropped,
                    "last_attempt": self._last_attempt, "state": self._last_state,
                    "reason": self._last_reason, "watchdog": self._watch_state}
            self._last_snapshot = result
            return dict(result)
        finally:
            self._lock.release()

    def _watch_write(self, kind: str) -> bool:
        try:
            self._watch_seq += 1
            message = _wrap({"run": self._watch_run, "seq": self._watch_seq,
                             "kind": kind}, self._watch_key)
            self._watch_process.stdin.write(_canonical(message) + b"\n")
            self._watch_process.stdin.flush()
            return True
        except Exception:
            self._watch_state = "unavailable"
            return False

    def start_watchdog(self) -> bool:
        with self._lock:
            if self._closed or not _authorized(self.config):
                return False
            if self._watch_process is not None and self._watch_process.poll() is None:
                return True
            process = None
            try:
                import psutil
                from angerona.core.engine_transport import private_directory
                from angerona.core.secure_store import _path_traverses_reparse
                settings = Path(self.config.data_dir).absolute() / "settings.json"
                config = _config_snapshot(self.config)
                if not _settings_authorized(settings, config):
                    raise ValueError("persisted authorization unavailable")
                if not _stored_destination_current(settings, config):
                    raise ValueError("protected destination authorization unavailable")
                if _path_traverses_reparse(settings.parent):
                    raise ValueError("unsafe data directory")
                # Existing custody helper establishes a private per-user
                # boundary before launch. No secrets or files are stored here.
                private_directory(settings.parent / "spyware-beacon")
                birth = psutil.Process(os.getpid()).create_time()
                self._watch_key = secrets.token_bytes(32)
                self._watch_run = secrets.token_hex(16)
                self._watch_seq = 0
                if getattr(sys, "frozen", False):
                    command = [sys.executable, "--spyware-beacon-watch"]
                else:
                    source = str(Path(__file__).resolve().parents[2])
                    bootstrap = (f"import sys;sys.path.insert(0,{source!r});"
                                 "from angerona.core.spyware_beacon import watch_main;"
                                 "raise SystemExit(watch_main())")
                    command = [sys.executable, "-I", "-c", bootstrap]
                from angerona.core.persistent_engine import _child_environment
                environment = _child_environment()
                environment["ANGERONA_DATA"] = str(settings.parent)
                kwargs = {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE,
                          "stderr": subprocess.DEVNULL, "close_fds": True, "env": environment}
                if os.name == "nt":
                    kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                else:
                    kwargs["start_new_session"] = True
                process = subprocess.Popen(command, **kwargs)
                self._watch_process = process
                self._watch_config = config
                startup = {"version": 1, "run": self._watch_run, "key": self._watch_key.hex(),
                           "pid": os.getpid(), "birth": birth,
                           "settings": str(settings), "config": config}
                wire = _canonical(startup)
                if len(wire) > _MAX_WIRE:
                    raise ValueError("watch configuration too large")
                process.stdin.write(wire + b"\n")
                process.stdin.flush()
                if not self._watch_write("heartbeat"):
                    raise OSError("watcher unavailable")
                ready: queue.Queue = queue.Queue(maxsize=1)
                def read_ready():
                    try:
                        ready.put(process.stdout.readline(32))
                    except Exception:
                        ready.put(b"")
                threading.Thread(target=read_ready, daemon=True).start()
                if ready.get(timeout=5.0).strip() != b"READY":
                    raise OSError("watcher did not verify its bootstrap")
                process.stdout.close()
                self._watch_state = "running"
                return True
            except Exception:
                self._watch_state = "unavailable: protected settings or process identity required"
                if process is not None:
                    self._watch_write("stop")
                    try:
                        process.stdin.close()
                    except Exception:
                        pass
                return False

    def heartbeat(self) -> None:
        with self._lock:
            if self._watch_process is None:
                return
            if (not _authorized(self.config)
                    or _config_snapshot(self.config) != self._watch_config):
                self._stop_watchdog(graceful=True)
                if not self._closed and _authorized(self.config):
                    self.start_watchdog()
                return
            if self._watch_process.poll() is not None:
                self._watch_state = "stopped unexpectedly"
                return
            self._watch_write("heartbeat")

    def _stop_watchdog(self, *, graceful: bool) -> None:
        process = self._watch_process
        if process is not None:
            if graceful:
                self._watch_write("stop")
            try:
                process.stdin.close()
            except Exception:
                pass
        self._watch_process = None
        self._watch_key = b""
        self._watch_config = {}
        self._watch_state = "stopped" if graceful else "detached"

    def close(self, graceful: bool = True) -> None:
        with self._lock:
            self._closed = True
            self._pending.clear()
            self._stop_watchdog(graceful=graceful)


def _read_watch_messages(stream, messages: queue.Queue, fault: threading.Event,
                         stop: threading.Event) -> None:
    try:
        if os.name != "nt":
            try:
                descriptor = stream.fileno()
            except (AttributeError, OSError, ValueError):
                descriptor = None
            if descriptor is not None:
                _read_watch_pipe(stream, descriptor, messages, stop)
                return
        while not stop.is_set():
            raw = stream.readline(_MAX_WIRE + 1)
            if stop.is_set():
                return
            if not raw:
                messages.put_nowait(("eof", None))
                return
            if len(raw) > _MAX_WIRE or not raw.endswith(b"\n"):
                messages.put_nowait(("invalid", None))
                return
            messages.put_nowait(("message", json.loads(raw)))
    except Exception:
        fault.set()
        try:
            messages.put_nowait(("invalid", None))
        except queue.Full:
            pass


def _read_watch_pipe(stream, descriptor: int, messages: queue.Queue,
                     stop: threading.Event) -> None:
    """POSIX pipe reads remain interruptible even after an incomplete frame.

    Read through BufferedReader.read1 so a bootstrap readline's prefetched
    heartbeat is retained. Nonblocking mode plus select bounds shutdown without
    leaving a daemon holding stdin's buffered-reader lock during finalization.
    """
    import select
    previous = os.get_blocking(descriptor)
    os.set_blocking(descriptor, False)
    pending = bytearray()
    read = getattr(stream, "read1", stream.read)
    try:
        while not stop.is_set():
            raw = read(_MAX_WIRE + 1)
            if not raw:
                ready, _, _ = select.select([descriptor], [], [], 0.05)
                if not ready or stop.is_set():
                    continue
                raw = read(_MAX_WIRE + 1)
                if not raw:
                    messages.put_nowait(("invalid" if pending else "eof", None))
                    return
            pending.extend(raw)
            while b"\n" in pending:
                end = pending.index(b"\n") + 1
                if end > _MAX_WIRE:
                    messages.put_nowait(("invalid", None))
                    return
                frame = bytes(pending[:end])
                del pending[:end]
                messages.put_nowait(("message", json.loads(frame)))
            if len(pending) > _MAX_WIRE:
                messages.put_nowait(("invalid", None))
                return
    finally:
        os.set_blocking(descriptor, previous)


def _stop_watch_reader(reader: threading.Thread, stop: threading.Event) -> None:
    """Retire only this watcher's reader before Python finalizes stdin."""
    stop.set()
    if os.name != "nt":
        reader.join(timeout=0.25)
        return
    try:
        import ctypes
        kernel = ctypes.WinDLL("kernel32", winmode=0x800)
        open_thread = kernel.OpenThread
        open_thread.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        open_thread.restype = ctypes.c_void_p
        cancel = kernel.CancelSynchronousIo
        cancel.argtypes = [ctypes.c_void_p]
        cancel.restype = ctypes.c_int
        close = kernel.CloseHandle
        close.argtypes = [ctypes.c_void_p]
        close.restype = ctypes.c_int
        handle = open_thread(1, False, reader.native_id) if reader.is_alive() and reader.native_id else None
        if handle:
            try:
                # Retry handles the race between readline's stop check and its
                # synchronous ReadFile call. No thread/process is terminated.
                for _attempt in range(3):
                    cancel(handle)
                    reader.join(timeout=0.15)
                    if not reader.is_alive():
                        break
            finally:
                close(handle)
    except (OSError, AttributeError):
        pass
    reader.join(timeout=0.1)


def _watch_loop(stream, startup: dict, *, sender=None,
                identity_probe=_identity_state, authority_probe=_settings_authorized,
                destination_probe=_stored_destination_current, on_ready=None,
                heartbeat_timeout=_HEARTBEAT_TIMEOUT, poll_seconds=0.5) -> str:
    """Testable watcher loop; production entrypoint never accepts a fake sender."""
    try:
        if (not isinstance(startup, dict)
                or set(startup) != {"version", "run", "key", "pid", "birth", "settings", "config"}
                or startup["version"] != 1
                or not re.fullmatch(r"[0-9a-f]{32}", startup["run"])
                or not re.fullmatch(r"[0-9a-f]{64}", startup["key"])
                or type(startup["pid"]) is not int or startup["pid"] <= 0
                or type(startup["birth"]) not in {int, float}
                or not math.isfinite(startup["birth"])
                or not isinstance(startup["config"], dict)
                or set(startup["config"]) != set(_CONFIG_FIELDS)
                or any(type(startup["config"][name]) is not bool for name in _BOOL_FIELDS)):
            return "invalid_bootstrap"
        key = bytes.fromhex(startup["key"])
        run, pid, birth = startup["run"], startup["pid"], startup["birth"]
        settings, initial = Path(startup["settings"]), startup["config"]
        config = SimpleNamespace(**initial)
        if (not settings.is_absolute() or not _authorized(config)
                or not authority_probe(settings, initial)
                or not destination_probe(settings, initial)
                or identity_probe(pid, birth) != "alive"):
            return "unverified_bootstrap"
    except Exception:
        return "invalid_bootstrap"

    messages: queue.Queue = queue.Queue(maxsize=16)
    fault = threading.Event()
    stop = threading.Event()
    reader = threading.Thread(target=_read_watch_messages, args=(stream, messages, fault, stop),
                              name="SpywareBeacon-pipe-read", daemon=True)
    reader.start()
    try:
        return _consume_watch_messages(messages, fault, key=key, run=run, pid=pid, birth=birth,
            settings=settings, initial=initial, config=config, sender=sender,
            identity_probe=identity_probe, authority_probe=authority_probe,
            destination_probe=destination_probe, on_ready=on_ready,
            heartbeat_timeout=heartbeat_timeout, poll_seconds=poll_seconds)
    finally:
        _stop_watch_reader(reader, stop)


def _consume_watch_messages(messages, fault, *, key, run, pid, birth, settings, initial,
                            config, sender, identity_probe, authority_probe, destination_probe,
                            on_ready, heartbeat_timeout, poll_seconds):
    last_seen = time.monotonic()
    previous = 0
    authenticated = False
    eof_at = None
    while True:
        if fault.is_set():
            return "invalid_state"
        try:
            wait = poll_seconds
            if eof_at is not None:
                wait = min(wait, max(0.0, _EOF_EXIT_GRACE - (time.monotonic() - eof_at)))
            kind, message = messages.get(timeout=wait)
            if kind == "invalid":
                return "invalid_state"
            if kind == "eof":
                eof_at = time.monotonic()
            if kind == "message":
                body = _verify(message, key, run, previous)
                if body is None:
                    return "invalid_state"
                previous = body["seq"]
                authenticated = True
                last_seen = time.monotonic()
                if body["kind"] == "stop":
                    return "normal_stop"
                if on_ready is not None:
                    on_ready()
                    on_ready = None
                # Drain ordered pipe messages before testing liveness. A normal
                # stop written immediately before exit must win over a dead PID.
                continue
        except queue.Empty:
            pass
        # No stale or unverifiable authority is allowed to send an emergency.
        if not authority_probe(settings, initial):
            return "authorization_revoked"
        identity = identity_probe(pid, birth)
        if identity in {"unknown", "reused"}:
            return "identity_unverifiable"
        if not authenticated:
            if eof_at is not None or identity != "alive" or time.monotonic() - last_seen > heartbeat_timeout:
                return "unauthenticated_state"
            continue
        # Windows may close a terminating parent's pipe before its process
        # identity reports gone. Reprobe the same PID and birth during this
        # bounded grace; confirmed death still takes the immediate exit path.
        # A live parent with a broken pipe still gets a heartbeat-loss alert.
        now = time.monotonic()
        eof_settled = eof_at is not None and now - eof_at >= _EOF_EXIT_GRACE
        reason = ("SPYWARE_ENGINE_EXIT" if identity == "gone" else
                  "SPYWARE_HEARTBEAT_LOST" if eof_settled or now - last_seen > heartbeat_timeout else "")
        if not reason:
            continue
        # Revalidate immediately before egress. Only the minimal fixed event is
        # sent, not a crash dump or the watcher's private bootstrap material.
        if (not authority_probe(settings, initial)
                or not destination_probe(settings, initial)):
            return "authorization_revoked"
        incident = {"rule_code": reason, "severity": "CRITICAL", "pid": pid}
        if sender is not None:
            sender(incident)
        else:
            beacon = EmergencyBeacon(config)
            beacon.enqueue(incident)
            beacon.tick()
            # Keep this last-chance process bounded even if the destination is
            # down. The normal module queue handles ordinary incident retries.
            beacon.close()
        return reason


def watch_main() -> int:
    """Private subprocess entrypoint; no target/secret/test switch is accepted."""
    try:
        stream = sys.stdin.buffer
        raw = stream.readline(_MAX_WIRE + 1)
        if len(raw) > _MAX_WIRE or not raw.endswith(b"\n"):
            return 2
        def ready():
            sys.stdout.write("READY\n")
            sys.stdout.flush()
        result = _watch_loop(stream, json.loads(raw), on_ready=ready)
        return 0 if result in {"normal_stop", "authorization_revoked", "SPYWARE_ENGINE_EXIT",
                               "SPYWARE_HEARTBEAT_LOST"} else 2
    except Exception:
        return 2


if __name__ == "__main__":
    raise SystemExit(watch_main())
