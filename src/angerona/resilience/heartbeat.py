"""heartbeat.py — shared-memory heartbeat for the resilience ecosystem.

Each process (core / watchdog / scanner) writes an incrementing tick into its own
small memory-mapped file. Any other process can read it. This gives two things a
plain "is the PID alive?" check cannot:

  * Liveness   — a fresh, advancing tick proves the process is actually running
                 its loop, not just present in the task table.
  * Anti-suspension — if the PID is still alive but the tick has STOPPED advancing
                 (an attacker sent SIGSTOP / suspended the threads), readers detect
                 the frozen heartbeat and treat the process as compromised.

Wire format (little-endian, fixed 32 bytes). Version 2 retains the compact layout
but sets the high bit in ``flags`` and authenticates the component name plus every
security-relevant field with a per-component key derived from the protected
per-install shutdown authority:

    magic  uint32 @0   = 0x41574447 ("AWDG")
    ts_ns  uint64 @4   = wall-clock time.time_ns() of the beat
    pid    uint32 @12  = writer pid
    proof  uint64 @16  = first 8 bytes of HMAC-SHA256(v2 canonical record)
    count  uint32 @24  = monotonically incrementing beat counter
    flags  uint32 @28  = bit 31 v2-authenticated, bit 0 running

No allocation happens per beat — the mmap is written in place.
"""
from __future__ import annotations

import hashlib
import hmac
import mmap
import os
import struct
import time
from pathlib import Path
from typing import Optional

_MAGIC = 0x41574447           # "AWDG"
_FMT = "<IQIQII"              # magic, ts_ns, pid, proof, counter, flags
_SIZE = struct.calcsize(_FMT)  # 32
_FLAG_RUNNING = 0x00000001
_FLAG_V2_AUTH = 0x80000000
_FLAG_KNOWN = _FLAG_RUNNING | _FLAG_V2_AUTH
_AUTH_CONTEXT = b"angerona-resilience-heartbeat-v2\0"

# Public compatibility boundary for peer writers/readers.  Callers must use
# HeartbeatWriter/HeartbeatReader for field semantics and authentication rather
# than copying the private struct format into another module.
WIRE_VERSION = 2
RECORD_SIZE = _SIZE


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


def legacy_proof_for(token_raw: bytes, counter: int) -> int:
    """Return the v1 counter-only proof for explicit legacy diagnostics."""
    if not token_raw:
        return 0
    digest = hashlib.sha256(token_raw + struct.pack("<I", counter & 0xFFFFFFFF)).digest()
    return struct.unpack("<Q", digest[:8])[0]


def _component_key(name: str, key_raw: bytes | None = None) -> bytes:
    """Derive a component-specific heartbeat key from protected install custody."""
    if key_raw is None or not key_raw:
        from angerona.resilience import shutdown_token
        key_raw = shutdown_token._load_key()
    if not isinstance(key_raw, bytes) or len(key_raw) != 32:
        raise ValueError("heartbeat authority must contain exactly 32 bytes")
    component = str(name).encode("utf-8", "strict")
    return hmac.new(key_raw, _AUTH_CONTEXT + component, hashlib.sha256).digest()


def proof_for(
    key_raw: bytes,
    name: str,
    ts_ns: int,
    pid: int,
    counter: int,
    flags: int,
) -> int:
    """Authenticate every security-relevant v2 field in the fixed 32-byte slot."""
    component = str(name).encode("utf-8", "strict")
    if len(component) > 0xFFFF:
        raise ValueError("heartbeat component name is too long")
    payload = (
        struct.pack("<H", len(component))
        + component
        + struct.pack(
            "<QIII",
            int(ts_ns) & 0xFFFFFFFFFFFFFFFF,
            int(pid) & 0xFFFFFFFF,
            int(counter) & 0xFFFFFFFF,
            int(flags) & 0xFFFFFFFF,
        )
    )
    digest = hmac.new(key_raw, payload, hashlib.sha256).digest()
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

    def __init__(self, name: str, token_raw: bytes | None = None,
                 path: Optional[Path] = None):
        self.name = name
        # Resolve once. Beats never reopen or reread the protected key file.
        self.token_raw = token_raw
        self._key = _component_key(name, token_raw)
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
        ts_ns = time.time_ns()
        pid = os.getpid() & 0xFFFFFFFF
        flags = _FLAG_V2_AUTH | (_FLAG_RUNNING if running else 0)
        struct.pack_into(_FMT, self._mm, 0,
                         _MAGIC, ts_ns, pid,
                         proof_for(self._key, self.name, ts_ns, pid,
                                   self._counter, flags),
                         self._counter, flags)
        return self._counter

    def stop(self) -> None:
        """Mark a clean stop (flags=0) so readers don't treat shutdown as death."""
        try:
            ts_ns = time.time_ns()
            pid = os.getpid() & 0xFFFFFFFF
            flags = _FLAG_V2_AUTH
            struct.pack_into(_FMT, self._mm, 0,
                             _MAGIC, ts_ns, pid,
                             proof_for(self._key, self.name, ts_ns, pid,
                                       self._counter, flags),
                             self._counter, flags)
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

    def __init__(self, name: str, path: Optional[Path] = None,
                 key_raw: bytes | None = None):
        self.name = name
        self.path = Path(path) if path else hb_path(name)
        self._key = _component_key(name, key_raw)
        self._prev_counter: Optional[int] = None
        self._prev_change_ts: float = time.time()
        self._last_verified_ts_ns: Optional[int] = None
        self._last_verified_counter: Optional[int] = None
        self._last_verified_pid: Optional[int] = None

    def read(self) -> Optional[dict]:
        try:
            with open(self.path, "rb") as f:
                raw = f.read(_SIZE)
            if len(raw) < _SIZE:
                return None
            magic, ts_ns, pid, proof, counter, flags = struct.unpack(_FMT, raw)
            if magic != _MAGIC:
                return None
            version = 2 if flags & _FLAG_V2_AUTH else 1
            return {"ts_ns": ts_ns, "pid": pid, "proof": proof,
                    "counter": counter, "flags": flags & _FLAG_RUNNING,
                    "wire_flags": flags, "version": version}
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def authentication_status(self, key_raw: bytes | None = None,
                              record: Optional[dict] = None,
                              *, update_replay_state: bool = True) -> str:
        """Return authenticated, missing, legacy, invalid, or replay.

        Re-reading the same record is valid. A verified record that moves
        backwards in time, or regresses its counter for the same PID, is not.
        """
        rec = record if record is not None else self.read()
        if not rec:
            return "missing"
        if rec.get("version") != 2:
            return "legacy"
        wire_flags = int(rec.get("wire_flags", 0))
        if wire_flags & ~_FLAG_KNOWN:
            return "invalid"
        try:
            key = self._key if key_raw is None else _component_key(self.name, key_raw)
        except (TypeError, ValueError):
            return "invalid"
        expected = proof_for(
            key,
            self.name,
            rec["ts_ns"],
            rec["pid"],
            rec["counter"],
            wire_flags,
        )
        if not hmac.compare_digest(
            struct.pack("<Q", int(rec["proof"])),
            struct.pack("<Q", expected),
        ):
            return "invalid"

        ts_ns = int(rec["ts_ns"])
        counter = int(rec["counter"])
        pid = int(rec["pid"])
        if self._last_verified_ts_ns is not None:
            if ts_ns < self._last_verified_ts_ns:
                return "replay"
            # Windows wall-clock resolution can be coarser than the heartbeat
            # cadence, so two genuine beats may share a timestamp. A forward
            # counter for the same authenticated PID is still progress; a PID
            # substitution at that same timestamp is not.
            if ts_ns == self._last_verified_ts_ns and pid != self._last_verified_pid:
                return "replay"
            if (
                pid == self._last_verified_pid
                and counter < int(self._last_verified_counter or 0)
                and not (
                    int(self._last_verified_counter or 0) > 0xFFFF0000
                    and counter < 0x0000FFFF
                )
            ):
                return "replay"
        if update_replay_state:
            self._last_verified_ts_ns = ts_ns
            self._last_verified_counter = counter
            self._last_verified_pid = pid
        return "authenticated"

    def verify_proof(self, token_raw: bytes | None = None) -> bool:
        """Confirm a v2 record's full-field authentication and anti-replay state."""
        return self.authentication_status(token_raw) == "authenticated"

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
        auth = self.authentication_status(record=rec)
        if auth != "authenticated":
            return "legacy_unverified" if auth == "legacy" else f"unauthenticated_{auth}"
        if rec["flags"] == 0:
            return "stopped"

        record_age = (time.time_ns() - int(rec["ts_ns"])) / 1e9
        if record_age < -max(float(stale_after_s), 5.0):
            # A future-dated but correctly signed record is a clock-integrity
            # problem, not proof of health and not authority to kill/restart.
            return "unauthenticated_clock"
        if record_age >= stale_after_s:
            return "suspended" if pid_alive(rec["pid"]) else "dead"

        # Track counter movement to distinguish 'advancing' from 'frozen'.
        if self._prev_counter is None or rec["counter"] != self._prev_counter:
            self._prev_counter = rec["counter"]
            self._prev_change_ts = now
            return "alive"

        # A longer suspension threshold is necessary for a busy Python Core,
        # but it must not delay recovery from a real process exit. Check the PID
        # as soon as one expected beat is missed; only a still-live process gets
        # the scheduling-jitter grace period below.
        if not pid_alive(rec["pid"]):
            return "dead"

        frozen_for = now - self._prev_change_ts
        if frozen_for < stale_after_s:
            return "alive"

        # The process is still present but its heartbeat has remained frozen
        # beyond the grace window.
        return "suspended"


def self_test() -> tuple[bool, str]:
    """Offline: write beats, confirm reader sees advancing ticks, a clean stop,
    and (via a frozen file) the suspended/dead distinction."""
    import tempfile
    d = Path(tempfile.mkdtemp(prefix="hb_selftest_"))
    try:
        p = d / "core.hb"
        token = bytes(range(32))
        w = HeartbeatWriter("core", token_raw=token, path=p)
        r = HeartbeatReader("core", path=p, key_raw=token)

        c1 = r.classify(); w.beat(); c2 = r.classify()
        advancing = c1 == "alive" and c2 == "alive"
        proof_ok = r.verify_proof(token) and not r.verify_proof(b"wrong-key-material")

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
