"""Read-only heartbeat observations published as bounded immutable memory.

This cache supplies presentation only. A live heartbeat proves recent progress
for its verified process generation, never detector coverage or response trust.
All file/process work belongs to the caller's background loop; snapshot() only
copies the latest in-memory publication and takes no locks.
"""
from __future__ import annotations

from contextlib import contextmanager
import math
import os
from pathlib import Path
import stat
import time
from types import MappingProxyType

from angerona.resilience import heartbeat as hb

ROLES = ("core", "watchdog", "scanner", "blackbox")
DEADLINES = {"core": 10.0, "watchdog": 10.0, "scanner": 8.0, "blackbox": 5.0}
_FILETIME_EPOCH = 116444736000000000


@contextmanager
def _existing_private_file(path: Path, *, limit: int, producer_writes: bool = False):
    """Read custody only: no create, attribute rewrite, ACL repair or rotation."""
    from angerona.core.engine_transport import verify_private
    from angerona.core.source_sandbox import _hold_plain_directories

    if not path.is_absolute() or ".." in path.parts or str(path).startswith(("\\\\", "//")):
        raise ValueError("Heartbeat observation requires the known local producer path")
    with _hold_plain_directories(path.parent):
        verify_private(path)
        descriptor = -1
        try:
            if os.name == "nt":
                import ctypes
                from ctypes import wintypes as w
                import msvcrt
                kernel = ctypes.WinDLL("kernel32", use_last_error=True)
                kernel.CreateFileW.argtypes = (w.LPCWSTR, w.DWORD, w.DWORD, w.LPVOID,
                                               w.DWORD, w.DWORD, w.HANDLE)
                kernel.CreateFileW.restype = w.HANDLE
                kernel.CloseHandle.argtypes = (w.HANDLE,)
                kernel.CloseHandle.restype = w.BOOL
                handle = kernel.CreateFileW(str(path), 0x80000000, 3 if producer_writes else 1,
                                             None, 3, 0x00200000, None)
                if handle == w.HANDLE(-1).value:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY | os.O_NOINHERIT)
                except BaseException:
                    kernel.CloseHandle(handle)
                    raise
            else:
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            before, named = os.fstat(descriptor), path.lstat()
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
                    or identity(before) != identity(named)):
                raise ValueError("Heartbeat observation file is unsafe or exceeds its bound")
            verify_private(path)
            yield descriptor
            after, named = os.fstat(descriptor), path.lstat()
            if (identity(before) != identity(after) or identity(after) != identity(named)
                    or (not producer_writes and before.st_mtime_ns != after.st_mtime_ns)):
                raise ValueError("Heartbeat observation file changed identity during its read")
            verify_private(path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)


class _ExistingHeartbeatReader(hb.HeartbeatReader):
    def read(self):
        # Pin the no-follow leaf against replacement while the normal bounded
        # public reader interprets it. Existing mmap producer writes remain legal.
        with _existing_private_file(self.path, limit=hb.RECORD_SIZE, producer_writes=True):
            return super().read()


class _ExistingHeartbeatReaders:
    def __init__(self, directory: Path | None):
        self.directory = Path(directory) if directory is not None else None
        self._authority = None

    def __call__(self, role: str):
        if self.directory is None or role not in ROLES:
            raise ValueError("The actual producer heartbeat directory is unavailable")
        if self._authority is None:
            authority = self.directory.parent / "shutdown.key"
            with _existing_private_file(authority, limit=128) as descriptor:
                raw = os.read(descriptor, 129)
            encoded = raw.decode("ascii").strip()
            if len(encoded) != 64 or any(char not in "0123456789abcdefABCDEF" for char in encoded):
                raise ValueError("The existing heartbeat authority is malformed")
            key = bytes.fromhex(encoded)
            if len(key) != 32:
                raise ValueError("The existing heartbeat authority is malformed")
            self._authority = key
        # Explicit path/key avoid hb_path mkdir and shutdown_token._load_key's
        # creating/hardening behavior. This observer has no repair authority.
        return _ExistingHeartbeatReader(role, path=self.directory / f"{role}.hb", key_raw=self._authority)


class ProgressHeartbeat:
    """Beat only when an existing real progress loop calls this object."""

    def __init__(self, role: str, *, writer_factory=hb.HeartbeatWriter):
        self._writer = None
        self.failure = ""
        try:
            self._writer = writer_factory(role)
        except Exception as exc:
            self.failure = f"{type(exc).__name__}: {str(exc)[:384]}"

    def beat(self) -> bool:
        if self._writer is None or self.failure:
            return False
        try:
            self._writer.beat()
            return True
        except Exception as exc:
            self.failure = f"{type(exc).__name__}: {str(exc)[:384]}"
            return False

    def close(self):
        writer, self._writer = self._writer, None
        if writer is not None:
            writer.close()


class _ReadOnlyProcessWitness:
    """One query/synchronize handle, with no process mutation capability."""

    def __init__(self, pid: int, expected: tuple[str, ...]):
        from angerona.core.windows_process_lease import _Native
        from angerona.resilience.supervisor import _invocation_identity
        import psutil

        self._native = _Native()
        self._handle = self._native.open(pid, 0x101000, False)
        try:
            self.identity = self._native.identity(self._handle)
            # Open first so the kernel retains this generation while psutil
            # verifies the exact role invocation and any venv redirector parent.
            observed = _invocation_identity(psutil.Process(pid), expected)
            if (not observed or self.identity.pid != pid
                    or abs(self.identity.create_time - observed["birth"]) > 0.001
                    or os.path.normcase(self.identity.image) != os.path.normcase(observed["image"])
                    or not self.validate()):
                raise ValueError("Heartbeat process invocation or native generation is unavailable")
            self.pid = pid
            self.birth_ticks = self.identity.birth_ticks
            self.generation_id = f"{pid}:{self.birth_ticks}"
        except BaseException:
            self.close()
            raise

    def validate(self) -> bool:
        return bool(self._handle is not None and not self._native.wait(self._handle, 0)
                    and self._native.identity(self._handle) == self.identity)

    def close(self):
        if self._handle is not None:
            handle, self._handle = self._handle, None
            self._native.close(handle)  # An ambiguous numeric handle is never retried.


class ComponentHeartbeatCache:
    """A fixed four-role observer, sampled outside Qt by the actual core owner."""

    def __init__(self, expected: dict[str, tuple[str, ...] | None], *,
                 enabled: dict[str, bool] | None = None, heartbeat_directory: Path | None = None,
                 reader_factory=None,
                 identity_factory=_ReadOnlyProcessWitness, clock=time.monotonic,
                 wall_ns=time.time_ns):
        self._expected = {role: expected.get(role) for role in ROLES}
        self._enabled = {role: (enabled or {}).get(role, True) is True for role in ROLES}
        self._readers = {}
        self._witnesses = {}
        self._previous = {}
        self._progress = {}
        self._reader_factory = reader_factory if reader_factory is not None else _ExistingHeartbeatReaders(heartbeat_directory)
        self._identity_factory = identity_factory
        self._clock, self._wall_ns = clock, wall_ns
        self._last_sample_monotonic = None
        self._stopped = False
        self._stopped_publication = tuple(MappingProxyType(self._empty(
            role, state="stopped", reason="The core owner stopped component heartbeat observation.")) for role in ROLES)
        self._publication = tuple(MappingProxyType(self._empty(role)) for role in ROLES)

    @staticmethod
    def _empty(role, *, state="unavailable", reason="No authenticated advancing heartbeat has been observed."):
        return {"role": role, "generation_id": "", "pid": None,
                "last_heartbeat_monotonic": None, "deadline_seconds": DEADLINES[role],
                "state": state, "reason": reason}

    def snapshot(self) -> tuple[dict, ...]:
        publication = self._stopped_publication if self._stopped else self._publication
        return tuple(dict(record) for record in publication)

    def _release_witness(self, role):
        witness = self._witnesses.pop(role, None)
        if witness is not None:
            witness.close()

    def _observe(self, role: str, now: float, wall_ns: int):
        row = self._empty(role)
        if not self._enabled[role]:
            return dict(row, state="disabled", reason="This component is disabled for this core generation.")
        expected = self._expected[role]
        if not expected:
            return dict(row, reason="The component's verified entry point is unavailable.")
        reader = self._readers.get(role)
        if reader is None:
            reader = self._readers[role] = self._reader_factory(role)
        record = reader.read()
        if not record:
            self._release_witness(role)
            return dict(row, reason="No component heartbeat record is available.")
        pid = record.get("pid")
        if type(pid) is not int or not 0 < pid <= 0xFFFFFFFF:
            return dict(row, reason="The heartbeat process identity is invalid.")
        witness = self._witnesses.get(role)
        if witness is None or witness.pid != pid or not witness.validate():
            self._release_witness(role)
            witness = self._identity_factory(pid, expected)
            self._witnesses[role] = witness
        generation = witness.generation_id
        if (type(generation) is not str or not generation or type(witness.birth_ticks) is not int
                or witness.birth_ticks <= _FILETIME_EPOCH):
            return dict(row, reason="The native process generation is unavailable.")
        row.update(pid=pid, generation_id=generation)
        previous = self._previous.get(role)
        if previous and previous[0] != generation:
            # Reused PIDs may legitimately restart their counter. Reset this
            # observer's replay state only after proving the new native object.
            reader = self._readers[role] = self._reader_factory(role)
            previous = None
            self._progress.pop(role, None)
        verifier = getattr(reader, "authentication_status", None)
        if not callable(verifier) or verifier(record=record) != "authenticated":
            return dict(row, reason="The heartbeat failed full-field authentication or replay validation.")
        timestamp, counter = record.get("ts_ns"), record.get("counter")
        if type(timestamp) is not int or type(counter) is not int:
            return dict(row, reason="Heartbeat timing or progress metadata is invalid.")
        # Read clocks after the wire/native observation: a genuine concurrent
        # beat must not look future-dated merely because sampling began earlier.
        observed_now, wall_ns = float(self._clock()), self._wall_ns()
        if not math.isfinite(observed_now) or observed_now < now or type(wall_ns) is not int:
            return dict(row, reason="Heartbeat observation clocks regressed or are unavailable.")
        now = observed_now
        age = (wall_ns - timestamp) / 1e9
        birth_ns = (witness.birth_ticks - _FILETIME_EPOCH) * 100
        if timestamp < birth_ns or not math.isfinite(age) or age < 0:
            return dict(row, reason="Heartbeat timing does not belong to this live process generation.")
        if record.get("flags") != 1:
            return dict(row, state="stopped", reason="The authenticated writer reported a clean stop.")
        if age >= DEADLINES[role]:
            return dict(row, state="stale", reason="The authenticated heartbeat exceeded its freshness deadline.")
        if previous is None:
            self._previous[role] = (generation, timestamp, counter)
            return dict(row, state="starting", reason="Waiting for a second authenticated beat from this exact generation.")
        if counter != previous[2]:
            actual_progress = now - age
            old_progress = self._progress.get(role)
            if not math.isfinite(actual_progress) or actual_progress < 0 or (
                    old_progress is not None and actual_progress <= old_progress):
                return dict(row, reason="Heartbeat and monotonic progress clocks are inconsistent.")
            self._progress[role] = actual_progress
            self._previous[role] = (generation, timestamp, counter)
        progress = self._progress.get(role)
        if progress is None:
            return dict(row, state="starting", reason="The authenticated heartbeat counter has not advanced.")
        if now < progress:
            return dict(row, reason="The monotonic heartbeat observation clock regressed.")
        row["last_heartbeat_monotonic"] = progress
        if now - progress >= DEADLINES[role]:
            return dict(row, state="stale", reason="The real heartbeat counter has stopped advancing.")
        return dict(row, state="running", reason="Authenticated heartbeat advanced for this native process generation; detector coverage is separate.")

    def sample(self, *, held: dict[str, str] | None = None):
        """Perform bounded known-file/process reads on the owning background loop."""
        if self._stopped:
            return
        try:
            raw_now, wall_ns = self._clock(), self._wall_ns()
            now = float(raw_now) if type(raw_now) in (int, float) else float("nan")
        except Exception:
            now, wall_ns = float("nan"), None
        if (not math.isfinite(now) or now < 0 or type(wall_ns) is not int or
                (self._last_sample_monotonic is not None and now < self._last_sample_monotonic)):
            self._publication = tuple(MappingProxyType(self._empty(
                role, reason="Heartbeat observation clocks are unavailable.")) for role in ROLES)
            return
        self._last_sample_monotonic = now
        rows = []
        for role in ROLES:
            if self._stopped:
                return
            try:
                row = self._observe(role, now, wall_ns)
            except Exception as exc:
                row = self._empty(role, reason=f"Heartbeat or native identity validation unavailable ({type(exc).__name__}).")
            if (held or {}).get(role):
                row.update(state="held", reason=str(held[role])[:384])
            rows.append(MappingProxyType(row))
        if not self._stopped:
            self._publication = tuple(rows)

    def mark_stopped(self):
        self._stopped = True
        self._publication = self._stopped_publication

    def close(self):
        self.mark_stopped()
        failure = None
        for role in ROLES:
            try:
                self._release_witness(role)
            except Exception as exc:
                failure = failure or exc
        if failure is not None:
            raise failure
