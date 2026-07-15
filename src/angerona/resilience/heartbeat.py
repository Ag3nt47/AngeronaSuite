"""heartbeat.py — shared-memory heartbeat for the resilience ecosystem.

Each process (core / watchdog / scanner) writes an incrementing tick into its own
small memory-mapped file. Any other process can read it. This gives two things a
plain "is the PID alive?" check cannot:

  * Liveness   — a fresh, advancing tick proves the process is actually running
                 its loop, not just present in the task table.
  * Anti-suspension — if the PID is still alive but the tick has STOPPED advancing
                 (an attacker sent SIGSTOP / suspended the threads), readers detect
                 the frozen heartbeat and treat the process as compromised.

Wire format (little-endian, 32 bytes) — identical to the layout documented in
``core/watchdog_link.py`` so the existing Go watchdog (frz/angerona_watchdog.go)
interoperates byte-for-byte:

    magic  uint32 @0   = 0x41574447 ("AWDG")
    ts_ns  uint64 @4   = wall-clock time.time_ns() of the beat
    pid    uint32 @12  = writer pid
    proof  uint64 @16  = first 8 bytes of SHA-256(token || counter_le), or 0
    count  uint32 @24  = monotonically incrementing beat counter
    flags  uint32 @28  = 1 running, 0 cleanly stopped

No allocation happens per beat — the mmap is written in place.
"""
from __future__ import annotations

import hashlib
import mmap
import os
import struct
import time
from pathlib import Path
from typing import Optional

_MAGIC = 0x41574447           # "AWDG"
_FMT = "<IQIQII"              # magic, ts_ns, pid, proof, counter, flags
_SIZE = struct.calcsize(_FMT)  # 32


def _data_dir() -> Path:
    try:
        from angerona.core.config import _data_dir as core_data_dir
        return Path(core_data_dir())
    except Exception:
        from angerona.core.data_paths import data_dir
        return data_dir()


def hb_dir() -> Path:
    d = _data_dir() / "heartbeats"
    d.mkdir(parents=True, exist_ok=True)
    return d


def hb_path(name: str) -> Path:
    return hb_dir() / f"{name}.hb"


def proof_for(token_raw: bytes, counter: int) -> int:
    """First 8 bytes of SHA-256(token_raw || counter_le) as LE uint64. Matches the
    Go watchdog's tokenProof() so mutual token verification works across languages."""
    if not token_raw:
        return 0
    digest = hashlib.sha256(token_raw + struct.pack("<I", counter & 0xFFFFFFFF)).digest()
    return struct.unpack("<Q", digest[:8])[0]


def pid_alive(pid: int) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        import psutil
        return psutil.pid_exists(pid)
    except Exception:
        pass
    try:
        os.kill(pid, 0)          # POSIX: no signal, just existence check
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True              # exists but not ours
    except (OSError, AttributeError):
        # Windows without psutil — best effort: assume alive.
        return True


class HeartbeatWriter:
    """Writes this process's heartbeat into its mmap slot. Call beat() on the
    process's existing loop cadence — it is O(1) and allocation-free."""

    def __init__(self, name: str, token_raw: bytes = b"", path: Optional[Path] = None):
        self.name = name
        self.token_raw = token_raw
        self.path = Path(path) if path else hb_path(name)
        self._counter = 0
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Ensure the backing file is exactly _SIZE bytes.
        with open(self.path, "ab") as f:
            if f.tell() < _SIZE:
                f.write(b"\x00" * (_SIZE - f.tell()))
        self._f = open(self.path, "r+b")
        self._mm = mmap.mmap(self._f.fileno(), _SIZE)
        self.beat()              # initial beat so readers see us immediately

    def beat(self, running: bool = True) -> int:
        self._counter = (self._counter + 1) & 0xFFFFFFFF
        struct.pack_into(_FMT, self._mm, 0,
                         _MAGIC, time.time_ns(), os.getpid() & 0xFFFFFFFF,
                         proof_for(self.token_raw, self._counter),
                         self._counter, 1 if running else 0)
        return self._counter

    def stop(self) -> None:
        """Mark a clean stop (flags=0) so readers don't treat shutdown as death."""
        try:
            struct.pack_into(_FMT, self._mm, 0,
                             _MAGIC, time.time_ns(), os.getpid() & 0xFFFFFFFF,
                             proof_for(self.token_raw, self._counter),
                             self._counter, 0)
        except Exception:
            pass

    def close(self) -> None:
        try:
            self.stop()
        finally:
            try:
                self._mm.close()
            finally:
                self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class HeartbeatReader:
    """Reads another component's heartbeat and classifies its state."""

    def __init__(self, name: str, path: Optional[Path] = None):
        self.name = name
        self.path = Path(path) if path else hb_path(name)
        self._prev_counter: Optional[int] = None
        self._prev_change_ts: float = time.time()

    def read(self) -> Optional[dict]:
        try:
            with open(self.path, "rb") as f:
                raw = f.read(_SIZE)
            if len(raw) < _SIZE:
                return None
            magic, ts_ns, pid, proof, counter, flags = struct.unpack(_FMT, raw)
            if magic != _MAGIC:
                return None
            return {"ts_ns": ts_ns, "pid": pid, "proof": proof,
                    "counter": counter, "flags": flags}
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def verify_proof(self, token_raw: bytes) -> bool:
        """Confirm the writer knows the shared token (anti-impersonation)."""
        rec = self.read()
        if not rec:
            return False
        return rec["proof"] == proof_for(token_raw, rec["counter"])

    def classify(self, stale_after_s: float = 3.0) -> str:
        """Return one of: 'alive', 'stopped', 'dead', 'suspended', 'unknown'.

        * alive     — tick advancing (or fresh) and flags=running.
        * stopped   — flags=0: the writer shut down cleanly.
        * dead      — no heartbeat file / pid not alive.
        * suspended — pid alive but tick frozen past `stale_after_s`.
        """
        rec = self.read()
        now = time.time()
        if rec is None:
            return "dead"
        if rec["flags"] == 0:
            return "stopped"

        # Track counter movement to distinguish 'advancing' from 'frozen'.
        if self._prev_counter is None or rec["counter"] != self._prev_counter:
            self._prev_counter = rec["counter"]
            self._prev_change_ts = now
            return "alive"

        frozen_for = now - self._prev_change_ts
        if frozen_for < stale_after_s:
            return "alive"

        # Tick has been frozen. Is the process gone (dead) or suspended (alive)?
        if pid_alive(rec["pid"]):
            return "suspended"
        return "dead"


def self_test() -> tuple[bool, str]:
    """Offline: write beats, confirm reader sees advancing ticks, a clean stop,
    and (via a frozen file) the suspended/dead distinction."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="hb_selftest_"))
    try:
        p = d / "core.hb"
        token = b"unit-test-token"
        w = HeartbeatWriter("core", token_raw=token, path=p)
        r = HeartbeatReader("core", path=p)

        c1 = r.classify(); w.beat(); c2 = r.classify()
        advancing = c1 == "alive" and c2 == "alive"
        proof_ok = r.verify_proof(token) and not r.verify_proof(b"wrong")

        w.stop()
        stopped_ok = r.classify() == "stopped"

        # Simulate a live-but-frozen process: point pid at ourselves, freeze tick.
        w.beat()                       # running again, counter advances
        r.classify()                   # observe current counter (baseline)
        # Force the reader's "frozen since" into the past and re-read same counter.
        r._prev_change_ts = time.time() - 10.0
        suspended_ok = r.classify(stale_after_s=3.0) == "suspended"  # our pid is alive

        w.close()
        ok = advancing and proof_ok and stopped_ok and suspended_ok
        return ok, ("heartbeat advance + token proof + clean-stop + suspension "
                    "detection verified" if ok else
                    f"failed: advancing={advancing} proof={proof_ok} "
                    f"stopped={stopped_ok} suspended={suspended_ok}")
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    print(self_test())
