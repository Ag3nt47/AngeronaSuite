"""etw_realtime_sensor.py — ETW Real-Time Process Sensor (Code: ETWR).

Purpose
    Event-driven, real-time process-creation capture via the
    Microsoft-Windows-Kernel-Process ETW provider (pywintrace). The kernel
    notifies Angerona the instant a process spawns, closing the multi-second
    blind spot that polling sensors (memory/lineage) leave open — a process
    that spawns and exits inside a poll gap is otherwise invisible. Each event
    is normalized and republished onto the AngeronaSuite EventBus as a PROC
    event so triage, the provenance graph, and speculative pre-warming see it
    immediately.

Relationship to etw_listener.py (ETWG)
    ETWG captures process/logon telemetry from the Windows **Security** channel
    (EID 4688) and degrades to psutil diffing. This module (ETWR) uses the
    lower-latency **Kernel-Process** trace session instead. The two are
    complementary: ETWR gives instant detection when the suite runs elevated;
    ETWG/psutil remains the always-on backstop. To avoid double-reporting the
    same spawn, ETWR does NOT run its own psutil fallback — when the ETW session
    can't open (non-Windows, no pywintrace, or not elevated) it reports itself
    unavailable and lets the polling sensors cover process creation.

Requirements / honest limits
    * pip install pywintrace   (pure-Python ctypes wrapper; no compiler needed)
    * MUST run elevated (Administrator) to open the Kernel-Process session. If
      not elevated it reports UNAVAILABLE and stays down; coverage is preserved
      by the polling sensors (you lose real-time, not coverage).
    * pywintrace is unmaintained; under an extreme spawn storm TDH parsing can
      lag. A future Rust (ferrisetw) sidecar can feed the same event contract
      unchanged.
    * Windows only. On import failure the module degrades gracefully.

Safety
    Read-only consumption of local kernel telemetry. Nothing is written, no
    policy is changed, nothing leaves the machine.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Callable, Optional

from angerona.core.module_base import BaseModule, Severity

# Microsoft-Windows-Kernel-Process provider GUID + process-start event id.
KERNEL_PROCESS_GUID = "{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}"
PROCESS_START_EVENT_ID = 1        # "Process/Start"

# Optional import — never crash the module (or the manager) if pywintrace is
# absent or we're off-Windows.
try:
    import etw as _etw            # pywintrace's top-level module
    from etw import ProviderInfo, GUID
    _PYWINTRACE_OK = True
    _IMPORT_ERR: Optional[Exception] = None
except Exception as e:            # ImportError on non-Windows / not installed
    _PYWINTRACE_OK = False
    _IMPORT_ERR = e


def is_available() -> tuple[bool, Optional[str]]:
    """Return (available, reason_if_not)."""
    if not _PYWINTRACE_OK:
        return False, f"pywintrace not importable: {_IMPORT_ERR}"
    return True, None


def _is_elevated() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:
        return False


# ── pid → image-name cache so we can resolve ParentImage cheaply ──────────────
# ETW process-start gives us the child image and the parent pid. To supply
# parent_name (which most downstream consumers key on) we keep a small pid→name
# map, seeded from psutil and kept fresh by every process-start event we see.
_PID_NAME_CACHE_LIMIT = 4096


class _PidNameCache:
    def __init__(self, max_entries: int = _PID_NAME_CACHE_LIMIT) -> None:
        self._max_entries = max(1, int(max_entries))
        self._map: OrderedDict[int, str] = OrderedDict()
        self._lock = threading.Lock()
        self._seed()

    def _seed(self) -> None:
        try:
            import psutil
            for p in psutil.process_iter(["pid", "name"]):
                try:
                    self.set(p.info["pid"], p.info["name"])
                except Exception:
                    continue
        except Exception:
            pass

    def set(self, pid: int, name: str) -> None:
        if pid and name:
            with self._lock:
                self._map[pid] = name
                self._map.move_to_end(pid)
                while len(self._map) > self._max_entries:
                    self._map.popitem(last=False)

    def get(self, pid: Optional[int]) -> Optional[str]:
        if not pid:
            return None
        with self._lock:
            name = self._map.get(pid)
            if name:
                # Active parents stay resident while one-shot/dead children age
                # out. An evicted live parent still resolves through psutil below.
                self._map.move_to_end(pid)
        if name:
            return name
        # Fall back to a live lookup (parent may predate our cache).
        try:
            import psutil
            name = psutil.Process(pid).name()
            self.set(pid, name)
            return name
        except Exception:
            return None


class ETWProcessSensor:
    """Runs an ETW real-time session for process-creation events and invokes a
    callback per event. Started in its own thread by pywintrace; the owning
    module drives start()/stop()."""

    def __init__(self, on_event: Callable[[dict], None], logger=None) -> None:
        self.on_event = on_event
        self._log = logger
        self._job = None
        self._cache = _PidNameCache()
        self._running = False
        self._events_seen = 0
        self._parse_failures = 0
        self._callback_failures = 0
        self._last_event_monotonic = 0.0
        self._started_monotonic = 0.0
        self._loss_count = 0
        self.last_error: str = ""

    def _info(self, m: str) -> None:
        if self._log:
            self._log.info("ETW", m)

    def _warn(self, m: str) -> None:
        self.last_error = m
        if self._log:
            self._log.warning("ETW", m)

    # ── event parsing ────────────────────────────────────────────────────────
    def _parse(self, record: dict) -> Optional[dict]:
        """pywintrace hands us a flat dict of the event's TDH-parsed fields.
        Field names come from the manifest; Kernel-Process/Start exposes
        ProcessID, ParentProcessID, ImageName, CommandLine (names vary slightly
        by Windows build, so we look them up defensively)."""
        try:
            data = record

            def g(*keys, default=None):
                for k in keys:
                    if k in data and data[k] not in (None, ""):
                        return data[k]
                return default

            pid = g("ProcessID", "ProcessId", "NewProcessId")
            ppid = g("ParentProcessID", "ParentProcessId")
            image = g("ImageName", "ImageFileName", "Image")
            cmdline = g("CommandLine", "Commandline", default="")

            if pid is None and image is None:
                return None  # not a process-start record we can use

            try:
                pid = int(pid) if pid is not None else None
            except (ValueError, TypeError):
                pid = None
            try:
                ppid = int(ppid) if ppid is not None else None
            except (ValueError, TypeError):
                ppid = None

            # Derive bare name from the image path.
            name = None
            if image:
                name = str(image).replace("/", "\\").split("\\")[-1]

            # Keep the cache warm and resolve parent name.
            if pid and name:
                self._cache.set(pid, name)
            parent_name = self._cache.get(ppid) if ppid else None

            return {
                "name":        name,
                "image":       image,
                "pid":         pid,
                "ppid":        ppid,
                "parent_name": parent_name,
                "cmdline":     cmdline,
                "user":        g("UserSID", "SubjectUserName"),
                "event_type":  "process_creation",
                "source":      "etw",
                "ts":          time.time(),
            }
        except Exception as e:
            self._parse_failures += 1
            self._warn(f"parse error: {e}")
            return None

    def _callback(self, record) -> None:
        # pywintrace passes (event_id, event_dict) or just a dict by version.
        try:
            if isinstance(record, tuple) and len(record) == 2:
                event_id, data = record
                if event_id != PROCESS_START_EVENT_ID:
                    return
            else:
                data = record
            if not isinstance(data, dict):
                return
            evt = self._parse(data)
            if evt:
                self._events_seen += 1
                self._last_event_monotonic = time.monotonic()
                self.on_event(evt)
        except Exception as e:
            self._callback_failures += 1
            self._warn(f"callback error: {e}")

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> bool:
        ok, reason = is_available()
        if not ok:
            self._warn(f"ETW sensor unavailable ({reason}). Polling sensors remain active.")
            return False
        if not _is_elevated():
            self._warn("Not elevated — cannot open Kernel-Process ETW session. "
                       "Run Angerona as Administrator to enable real-time process "
                       "detection. Polling sensors remain active.")
            return False
        try:
            providers = [ProviderInfo("Microsoft-Windows-Kernel-Process",
                                      GUID(KERNEL_PROCESS_GUID))]
            # event_id_filters limits kernel→user traffic to process-start only.
            self._job = _etw.ETW(
                providers=providers,
                event_callback=self._callback,
                event_id_filters=[PROCESS_START_EVENT_ID],
            )
            self._job.start()
            self._running = True
            self._started_monotonic = time.monotonic()
            receipt = self.status_receipt()
            if not receipt.live:
                raise RuntimeError(receipt.reason or "ETW consumer did not become live")
            self._info("Real-time process-creation ETW session started "
                       "(Kernel-Process). Polling blind spot closed.")
            return True
        except Exception as e:
            self._warn(f"failed to start ETW session: {e}. Polling sensors remain active.")
            try:
                if self._job is not None:
                    self._job.stop()
            except Exception:
                pass
            self._running = False
            self._job = None
            return False

    def stop(self) -> None:
        if self._job:
            try:
                self._job.stop()
            except Exception as e:
                self._warn(f"stop error: {e}")
        self._running = False
        self._job = None
        self._info(f"ETW session stopped. Events seen: {self._events_seen}")

    @property
    def running(self) -> bool:
        return self.status_receipt().live

    @property
    def events_seen(self) -> int:
        return self._events_seen

    def status_receipt(self) -> "ETWSessionReceipt":
        """Actively query the kernel session and its real consumer thread."""
        job = self._job
        if job is None or not self._running:
            return ETWSessionReceipt(
                "ended", False, self._events_seen, self._loss_count,
                self._parse_failures, self._callback_failures,
                self._last_event_monotonic, self.last_error or "session is not attached",
            )
        try:
            consumer = getattr(job, "consumer", None)
            thread = getattr(consumer, "process_thread", None)
            end_capture = getattr(consumer, "end_capture", None)
            thread_alive = bool(thread is not None and thread.is_alive())
            ended = bool(end_capture is not None and end_capture.is_set())
            if not bool(getattr(job, "running", False)) or not thread_alive or ended:
                self._running = False
                reason = "ETW consumer thread/session ended unexpectedly"
                self._warn(reason)
                return ETWSessionReceipt(
                    "ended", False, self._events_seen, self._loss_count,
                    self._parse_failures, self._callback_failures,
                    self._last_event_monotonic, reason,
                )
            properties = job.query()
            losses = sum(
                max(0, int(getattr(properties, field, 0)))
                for field in ("EventsLost", "LogBuffersLost", "RealTimeBuffersLost")
            )
            self._loss_count = max(self._loss_count, losses)
            if self._loss_count:
                state = "lossy"
                reason = f"ETW reported {self._loss_count} lost event/buffer unit(s)"
            elif self._parse_failures or self._callback_failures:
                state = "callback-error"
                reason = (
                    f"parse_failures={self._parse_failures}, "
                    f"callback_failures={self._callback_failures}"
                )
            elif self._events_seen:
                state = "flowing"
                reason = "consumer thread and kernel session query are live"
            else:
                state = "idle-proven"
                reason = "consumer thread live; kernel session query succeeded while idle"
            return ETWSessionReceipt(
                state, True, self._events_seen, self._loss_count,
                self._parse_failures, self._callback_failures,
                self._last_event_monotonic, reason,
            )
        except Exception as exc:
            self._running = False
            reason = f"ETW liveness query failed: {exc}"
            self._warn(reason)
            return ETWSessionReceipt(
                "error", False, self._events_seen, self._loss_count,
                self._parse_failures, self._callback_failures,
                self._last_event_monotonic, reason[:500],
            )


@dataclass(frozen=True)
class ETWSessionReceipt:
    state: str
    live: bool
    events_seen: int
    loss_count: int
    parse_failures: int
    callback_failures: int
    last_event_monotonic: float
    reason: str


# ── Angerona module wrapper ───────────────────────────────────────────────────
class EtwRealtimeSensorModule(BaseModule):
    CODE = "ETWR"
    NAME = "ETW Real-Time Process Sensor"
    name = "ETW Real-Time Process Sensor"
    description = ("Event-driven process-creation capture via the Kernel-Process "
                   "ETW provider (pywintrace); closes the polling blind spot. "
                   "Requires elevation; defers to polling sensors when unavailable.")
    category = "Telemetry"
    version = "1.12.1"

    # How often the run-loop wakes to refresh health while the ETW session
    # streams events asynchronously on its own thread.
    _HEALTH_POLL = 5.0

    def __init__(self) -> None:
        super().__init__()
        self._sensor: Optional[ETWProcessSensor] = None
        self._last_seen = 0
        self._restart_attempts = 0
        self._next_restart_at = 0.0
        self._continuity_gaps = 0

    # Mirror etw_listener.py's exposed surface.
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── bridge: ETW event -> EventBus ────────────────────────────────────────
    def _on_event(self, evt: dict) -> None:
        name = evt.get("name") or "unknown"
        parent = evt.get("parent_name")
        suffix = f" (parent {parent})" if parent else ""
        # Callback runs on pywintrace's thread; emit() publishes to the (thread-
        # safe) EventBus. Keep severity INFO — this is raw telemetry, not a
        # verdict; downstream triage decides significance.
        self.emit(
            f"Process created: {name}{suffix}",
            Severity.INFO,
            name=name,
            pid=evt.get("pid"),
            ppid=evt.get("ppid"),
            parent_name=parent,
            image=evt.get("image"),
            cmdline=evt.get("cmdline", ""),
            user=evt.get("user"),
            event_type="process_creation",
            source="ETW:Kernel-Process",
        )

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        self._sensor = ETWProcessSensor(self._on_event, logger=None)
        started = self._sensor.start()
        if not started:
            # Unavailable by environment (off-Windows / no pywintrace / not
            # elevated). Report clearly and idle — polling sensors (ETWG) cover
            # process creation, so we deliberately do NOT run a duplicate psutil
            # fallback here.
            reason = self._sensor.last_error or "ETW session could not start"
            self.set_health(0, f"unavailable: {reason}; polling sensors cover process creation")
            self.emit(
                f"ETWR unavailable — {reason}. Real-time process detection off; "
                "polling sensors remain active.",
                Severity.LOW,
                unavailable=True,
            )
            # Idle until stopped without burning CPU or churning restarts.
            while not self.stopping:
                self.sleep(self._HEALTH_POLL)
            return

        self.set_health(100, "real-time Kernel-Process capture live")
        self.emit("ETWR online — real-time process-creation capture (Kernel-Process).",
                  Severity.INFO)
        try:
            while not self.stopping:
                self.sleep(self._HEALTH_POLL)
                receipt = self._sensor.status_receipt()
                seen = receipt.events_seen
                if receipt.live and receipt.loss_count == 0 and not (
                    receipt.parse_failures or receipt.callback_failures
                ):
                    health = 100 if self._continuity_gaps == 0 else 75
                    gap = (
                        ""
                        if self._continuity_gaps == 0
                        else f"; {self._continuity_gaps} prior continuity gap(s)"
                    )
                    self.set_health(
                        health,
                        f"{receipt.state}: {seen} process events captured; "
                        f"{receipt.reason}{gap}",
                    )
                    self._restart_attempts = 0
                elif receipt.live:
                    self._continuity_gaps += int(
                        receipt.loss_count > 0 and self._continuity_gaps == 0
                    )
                    self.set_health(
                        35 if receipt.loss_count else 60,
                        f"{receipt.state}: {receipt.reason}; events={seen}",
                    )
                else:
                    self.set_health(20, receipt.reason)
                    now = time.monotonic()
                    if self._restart_attempts < 3 and now >= self._next_restart_at:
                        self._continuity_gaps += 1
                        self._restart_attempts += 1
                        try:
                            self._sensor.stop()
                        except Exception:
                            pass
                        replacement = ETWProcessSensor(self._on_event, logger=None)
                        if replacement.start():
                            self._sensor = replacement
                            self.set_health(
                                70,
                                "ETW session restarted; prior delivery continuity "
                                "gap remains visible",
                            )
                        else:
                            self._next_restart_at = now + min(
                                60.0, 5.0 * (2 ** (self._restart_attempts - 1))
                            )
                            self.last_error = replacement.last_error
                self._last_seen = seen
        finally:
            self._sensor.stop()

    def stop(self) -> None:
        # Ensure the ETW session is torn down promptly on shutdown.
        if self._sensor is not None:
            try:
                self._sensor.stop()
            except Exception:
                pass
        super().stop()

    # ── self-test ─────────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        """Verify the Kernel-Process parser produces a well-formed event, and
        report real-time availability on this host."""
        probe = ETWProcessSensor(lambda _e: None)
        evt = probe._parse({
            "ProcessID": 4242,
            "ParentProcessID": 1000,
            "ImageName": r"C:\Windows\System32\cmd.exe",
            "CommandLine": "cmd.exe /c whoami",
        })
        ok = bool(evt) and evt.get("name") == "cmd.exe" and evt.get("pid") == 4242 \
            and evt.get("event_type") == "process_creation"

        avail, reason = is_available()
        if not avail:
            mode = f"real-time unavailable ({reason}); ETWG/polling covers process creation"
        elif not _is_elevated():
            mode = "pywintrace present but not elevated → run as Administrator for real-time"
        else:
            mode = "pywintrace present + elevated → real-time capture available"

        return (ok, f"Kernel-Process decode verified ({mode})" if ok
                else f"Kernel-Process decode failed: {evt}")


def register() -> EtwRealtimeSensorModule:
    return EtwRealtimeSensorModule()


if __name__ == "__main__":
    # Standalone smoke test (Windows + elevated + pywintrace required).
    avail, why = is_available()
    print(f"pywintrace available: {avail}" + (f" ({why})" if why else ""))
    m = EtwRealtimeSensorModule()
    passed, detail = m.self_test()
    print(f"self_test: {passed} — {detail}")
    if avail:
        def show(evt):
            print(f"  + {evt.get('parent_name')} -> {evt.get('name')} "
                  f"(pid {evt.get('pid')}) : {str(evt.get('cmdline',''))[:80]}")
        s = ETWProcessSensor(show)
        if s.start():
            print("Watching for 15s — spawn some processes...")
            try:
                time.sleep(15)
            finally:
                s.stop()
