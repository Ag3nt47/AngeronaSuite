"""Real authenticated wire progress, native identity and memory-only UI copies."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.resilience import component_status as status
from angerona.resilience import heartbeat as hb


@pytest.fixture
def observation(tmp_path, monkeypatch):
    key = bytes(range(32))
    initial = time.time_ns()
    wire, wall, monotonic = [initial], [initial], [10.0]
    monkeypatch.setattr(hb.time, "time_ns", lambda: wire[0])
    writers = {role: hb.HeartbeatWriter(role, token_raw=key, path=tmp_path / f"{role}.hb")
               for role in status.ROLES}
    births = {role: status._FILETIME_EPOCH + (initial - 1_000_000_000) // 100 for role in status.ROLES}
    witnesses = {role: [] for role in status.ROLES}

    class Witness:
        def __init__(self, role, pid):
            self.pid, self.birth_ticks = pid, births[role]
            self.generation_id = f"{pid}:{self.birth_ticks}"
            self.alive, self.closed = True, False
        def validate(self):
            return self.alive and not self.closed
        def close(self):
            self.closed = True

    def identity(pid, expected):
        role = Path(expected[0]).stem
        witness = Witness(role, pid)
        witnesses[role].append(witness)
        return witness

    factory = lambda role: hb.HeartbeatReader(role, path=tmp_path / f"{role}.hb", key_raw=key)
    cache = status.ComponentHeartbeatCache(
        {role: (f"C:/verified/{role}.exe",) for role in status.ROLES},
        reader_factory=factory, identity_factory=identity,
        clock=lambda: monotonic[0], wall_ns=lambda: wall[0])

    def advance(seconds=0.5, *, beat=True):
        monotonic[0] += seconds
        wall[0] += int(seconds * 1e9)
        wire[0] = wall[0]
        if beat:
            for writer in writers.values():
                writer.beat()

    result = SimpleNamespace(cache=cache, writers=writers, births=births, witnesses=witnesses,
                             advance=advance, wire=wire, wall=wall, monotonic=monotonic,
                             rows=lambda: {row["role"]: row for row in cache.snapshot()})
    try:
        yield result
    finally:
        cache.close()
        for writer in writers.values():
            writer.close()


def test_only_actual_authenticated_progress_pulses_and_polling_cannot_refresh_it(observation):
    sample = observation
    sample.cache.sample()
    assert all(row["state"] == "starting" and row["last_heartbeat_monotonic"] is None
               for row in sample.rows().values())
    sample.advance()
    sample.cache.sample()
    assert all(row["state"] == "running" for row in sample.rows().values())
    progress = {role: row["last_heartbeat_monotonic"] for role, row in sample.rows().items()}
    sample.advance(0.5, beat=False)
    sample.cache.sample()
    assert {role: row["last_heartbeat_monotonic"] for role, row in sample.rows().items()} == progress
    sample.advance(10.0, beat=False)
    # A new valid signed timestamp with the SAME counter is still no progress.
    for writer in sample.writers.values():
        writer._counter -= 1
        writer.beat()
    sample.cache.sample()
    assert all(row["state"] == "stale" for row in sample.rows().values())
    assert all("stopped advancing" in row["reason"] for row in sample.rows().values())


@pytest.mark.parametrize("fault", ["forged", "future", "predates-birth", "clock", "clock-regression", "replay"])
def test_invalid_or_wrong_generation_beats_never_publish_live_progress(observation, fault):
    sample = observation
    sample.cache.sample()
    sample.advance()
    sample.cache.sample()
    if fault == "forged":
        for writer in sample.writers.values():
            writer._mm[16] ^= 1  # Corrupt the existing full-field HMAC proof.
    elif fault == "future":
        sample.wire[0] = sample.wall[0] + 1_000_000_000
        for writer in sample.writers.values():
            writer.beat()
    elif fault == "predates-birth":
        for role in status.ROLES:
            sample.witnesses[role][-1].alive = False
            sample.births[role] += 1_600_000_000 // 100
    elif fault == "clock":
        sample.monotonic[0] = float("nan")
    elif fault == "clock-regression":
        sample.monotonic[0] = 1.0
    else:
        sample.wire[0] -= 1_000_000_000
        for writer in sample.writers.values():
            writer.beat()
    sample.cache.sample()
    assert all(row["state"] == "unavailable" and row["last_heartbeat_monotonic"] is None
               for row in sample.rows().values())


def test_new_native_birth_cannot_reuse_an_old_fresh_authenticated_record(observation):
    sample = observation
    sample.cache.sample()
    sample.advance()
    sample.cache.sample()
    old = sample.rows()
    sample.advance(0.2, beat=False)
    for role in status.ROLES:
        sample.witnesses[role][-1].alive = False
        sample.births[role] = status._FILETIME_EPOCH + (sample.wall[0] - 100_000_000) // 100
    sample.cache.sample()
    assert all(row["state"] == "unavailable" for row in sample.rows().values())
    assert all(row["generation_id"] != old[role]["generation_id"] for role, row in sample.rows().items())
    # A genuinely restarted writer resets its counter only in the proved new
    # native generation, then must provide a second actual beat to pulse.
    for writer in sample.writers.values():
        writer._counter = 0
    sample.advance()
    sample.cache.sample()
    assert all(row["state"] == "starting" for row in sample.rows().values())
    sample.advance()
    sample.cache.sample()
    assert all(row["state"] == "running" for row in sample.rows().values())


def test_snapshot_is_bounded_memory_only_and_cannot_mutate_the_publication(observation):
    sample = observation
    sample.cache.sample()
    sample.advance()
    sample.cache.sample()
    sample.cache._reader_factory = lambda *_a: pytest.fail("GUI copy performed heartbeat I/O")
    sample.cache._identity_factory = lambda *_a: pytest.fail("GUI copy performed native I/O")
    sample.cache._observe = lambda *_a: pytest.fail("GUI copy sampled the host")
    first = sample.cache.snapshot()
    assert type(first) is tuple and len(first) == 4 and all(type(row) is dict for row in first)
    first[0]["state"] = "forged"
    assert sample.cache.snapshot()[0]["state"] == "running"
    sample.cache.mark_stopped()
    sample.cache.sample()
    assert all(row["state"] == "stopped" for row in sample.cache.snapshot())


def test_disabled_missing_and_supervisor_hold_remain_distinct(observation):
    sample = observation
    sample.cache._enabled["blackbox"] = False
    sample.cache._expected["scanner"] = None
    sample.cache.sample(held={"watchdog": "Authenticated recovery is held."})
    rows = sample.rows()
    assert rows["blackbox"]["state"] == "disabled"
    assert rows["scanner"]["state"] == "unavailable"
    assert rows["watchdog"]["state"] == "held"
    assert rows["core"]["state"] == "starting"


def test_stop_flatlines_an_inflight_sampler_and_retires_its_readers(observation, monkeypatch):
    from angerona.resilience.manager import ResilienceManager

    sample = observation
    sample.cache.sample()
    sample.advance()
    sample.cache.sample()
    entered, release = threading.Event(), threading.Event()
    observe = sample.cache._observe
    def delayed(role, *args):
        if role == "core":
            entered.set()
            assert release.wait(3)
        return observe(role, *args)
    monkeypatch.setattr(sample.cache, "_observe", delayed)
    owner = object.__new__(ResilienceManager)
    owner.bus = None
    owner._stop = threading.Event()
    owner._component_heartbeat_cache = sample.cache
    owner._sup = SimpleNamespace(components={}, request_stop=lambda: None)
    thread = threading.Thread(target=owner._component_heartbeat_loop, daemon=False)
    thread.start()
    try:
        assert entered.wait(2)
        owner.request_stop()
        assert all(row["state"] == "stopped" for row in owner.component_heartbeats())
    finally:
        release.set()
        owner.request_stop()
        thread.join(timeout=3)
    assert not thread.is_alive() and sample.cache._witnesses == {}
    assert all(row["state"] == "stopped" for row in owner.component_heartbeats())


def test_progress_writer_never_manufactures_background_beats_and_closes_once():
    calls = []
    writer = SimpleNamespace(beat=lambda: calls.append("beat"), close=lambda: calls.append("close"))
    progress = status.ProgressHeartbeat("blackbox", writer_factory=lambda role: writer)
    assert calls == []
    assert progress.beat() and progress.beat()
    progress.close()
    progress.close()
    assert not progress.beat() and calls == ["beat", "beat", "close"]


def test_progress_writer_failure_stops_further_beats_without_crashing_ui():
    calls = []
    def failed():
        calls.append("beat")
        raise OSError("inert invalidated mapping")
    writer = SimpleNamespace(beat=failed, close=lambda: calls.append("close"))
    progress = status.ProgressHeartbeat("blackbox", writer_factory=lambda role: writer)
    assert not progress.beat() and not progress.beat()
    assert "OSError" in progress.failure and calls == ["beat"]
    progress.close()
    assert calls == ["beat", "close"]


def _private_file(path, raw):
    from angerona.core.engine_transport import create_private_file

    descriptor = create_private_file(path)
    try:
        os.write(descriptor, raw)
    finally:
        os.close(descriptor)


def _forbid_observer_repairs(monkeypatch):
    from angerona.core import hardening
    from angerona.resilience import shutdown_token

    def forbidden(*_args, **_kwargs):
        pytest.fail("Read-only heartbeat observation attempted authority/directory repair")
    monkeypatch.setattr(shutdown_token, "_load_key", forbidden)
    monkeypatch.setattr(hardening, "prepare_sensitive_key", forbidden)
    monkeypatch.setattr(hardening, "secure_sensitive_file", forbidden)
    monkeypatch.setattr(hardening, "ensure_sensitive_parent", forbidden)
    monkeypatch.setattr(Path, "mkdir", forbidden)


def _directory_reparse(path):
    # Path.is_junction is absent on Python3.10/3.11 CI interpreters. Native
    # directory+reparse bits prove the private fixture alias without following it.
    attributes = getattr(path.lstat(), "st_file_attributes", 0)
    return attributes & 0x410 == 0x410


def test_default_reader_uses_only_existing_private_authority_and_known_file(tmp_path, monkeypatch):
    from angerona.core.engine_transport import private_directory

    root = private_directory(tmp_path / "state")
    directory = private_directory(root / "heartbeats")
    key = bytes(range(32))
    authority = root / "shutdown.key"
    _private_file(authority, key.hex().encode("ascii"))
    writer = hb.HeartbeatWriter("blackbox", token_raw=key, path=directory / "blackbox.hb")
    if os.name != "nt":
        os.chmod(writer.path, 0o600)
    before = authority.read_bytes(), authority.stat().st_mtime_ns, authority.stat().st_mode
    try:
        _forbid_observer_repairs(monkeypatch)
        reader = status._ExistingHeartbeatReaders(directory)("blackbox")
        record = reader.read()
        assert reader.authentication_status(record=record) == "authenticated"
        writer.beat()  # Producer mmap writes stay legal while observer is read-only.
        assert reader.read()["counter"] > record["counter"]
        assert (authority.read_bytes(), authority.stat().st_mtime_ns, authority.stat().st_mode) == before
    finally:
        writer.close()


@pytest.mark.parametrize("fault", ["missing-tree", "missing-key", "malformed", "oversized", "hardlink", "symlink"])
def test_observer_refuses_missing_or_unsafe_authority_without_mutation(tmp_path, monkeypatch, fault):
    from angerona.core.engine_transport import private_directory

    root = tmp_path / "state"
    directory = root / "heartbeats"
    authority = root / "shutdown.key"
    target = tmp_path / "independent" / "key"
    raw = b"malformed" if fault == "malformed" else (b"a" * 129 if fault == "oversized" else bytes(range(32)).hex().encode())
    if fault != "missing-tree":
        private_directory(root)
        private_directory(directory)
        if fault != "missing-key":
            if fault == "symlink":
                private_directory(target.parent)
                _private_file(target, raw)
                try:
                    authority.symlink_to(target)
                except OSError as error:
                    pytest.skip(f"This Windows token cannot create the isolated link: {error}")
            else:
                _private_file(authority, raw)
                if fault == "hardlink":
                    os.link(authority, root / "other-link")
    before = tuple(path.name for path in root.iterdir()) if root.exists() else ()
    _forbid_observer_repairs(monkeypatch)
    cache = status.ComponentHeartbeatCache({role: ("C:/verified/component.exe",) for role in status.ROLES},
                                            heartbeat_directory=directory)
    cache.sample()
    assert all(row["state"] == "unavailable" for row in cache.snapshot())
    assert (tuple(path.name for path in root.iterdir()) if root.exists() else ()) == before
    if fault in ("missing-tree", "missing-key"):
        assert not authority.exists()
    elif fault == "symlink":
        assert authority.is_symlink() and target.read_bytes() == raw
    else:
        assert authority.read_bytes() == raw
    cache.close()


def test_observer_refuses_redirected_heartbeat_directory_without_mutation(tmp_path, monkeypatch):
    from angerona.core.engine_transport import private_directory

    root = private_directory(tmp_path / "state")
    outside = private_directory(tmp_path / "independent-heartbeats")
    authority = root / "shutdown.key"
    key = bytes(range(32))
    _private_file(authority, key.hex().encode())
    writer = hb.HeartbeatWriter("core", token_raw=key, path=outside / "core.hb")
    if os.name != "nt":
        os.chmod(writer.path, 0o600)
    redirected = root / "heartbeats"
    try:
        redirected.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        if os.name != "nt":
            writer.close()
            pytest.skip(f"This token cannot create the isolated directory link: {error}")
        # A private fixture junction exercises the real Windows reparse gate
        # without requiring the symbolic-link privilege. Fixed script + argv;
        # no shell-built path commands or recursive deletion are involved.
        script = root / "make-junction.ps1"
        _private_file(script, b"param([string]$Link,[string]$Target)\n$ErrorActionPreference='Stop'\n"
                      b"$null=New-Item -ItemType Junction -Path $Link -Target $Target -ErrorAction Stop\n")
        host = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        try:
            result = subprocess.run([str(host), "-NoProfile", "-NonInteractive", "-File", str(script),
                                     "-Link", str(redirected), "-Target", str(outside)],
                                    capture_output=True, timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
        finally:
            script.unlink()
        if result.returncode != 0:
            writer.close()
            pytest.skip("The isolated directory reparse fixture is unavailable")
    try:
        _forbid_observer_repairs(monkeypatch)
        reader = status._ExistingHeartbeatReaders(redirected)("core")
        with pytest.raises((OSError, ValueError)):
            reader.read()
        assert (redirected.is_symlink() or _directory_reparse(redirected)) and authority.read_bytes() == key.hex().encode()
        assert outside.joinpath("core.hb").stat().st_size == hb.RECORD_SIZE
    finally:
        writer.close()
        redirected.rmdir() if _directory_reparse(redirected) else redirected.unlink()


def test_observer_refuses_native_key_reparse_metadata_without_repair(tmp_path, monkeypatch):
    from angerona.core.engine_transport import private_directory

    root = private_directory(tmp_path / "state")
    directory = private_directory(root / "heartbeats")
    authority = root / "shutdown.key"
    raw = bytes(range(32)).hex().encode()
    _private_file(authority, raw)
    original = Path.lstat
    def metadata(path, *args, **kwargs):
        info = original(path, *args, **kwargs)
        if path == authority:
            return SimpleNamespace(st_mode=info.st_mode, st_nlink=info.st_nlink,
                                   st_file_attributes=0x400)
        return info
    monkeypatch.setattr(Path, "lstat", metadata)
    _forbid_observer_repairs(monkeypatch)
    cache = status.ComponentHeartbeatCache({role: ("C:/verified/component.exe",) for role in status.ROLES},
                                            heartbeat_directory=directory)
    cache.sample()
    assert all(row["state"] == "unavailable" for row in cache.snapshot())
    assert authority.read_bytes() == raw
    cache.close()


def test_app_footer_source_uses_only_copies_and_stops_without_faking_helper_health():
    from angerona.app import AngeronaApp

    app = object.__new__(AngeronaApp)
    app.config = SimpleNamespace(blackbox_enabled=False)
    supplied = ({"role": "core", "state": "running", "generation_id": "71:134377000000000000",
                 "pid": 71, "last_heartbeat_monotonic": 10.0, "deadline_seconds": 10.0},)
    app._resilience = SimpleNamespace(component_heartbeats=lambda: supplied, with_ui=False)
    app._shutdown_requested = threading.Event()
    rows = {row["role"]: row for row in app._component_heartbeats_cached()}
    assert rows["core"]["last_heartbeat_monotonic"] == 10.0
    assert rows["inventory"]["state"] == rows["local_ai"]["state"] == "unavailable"
    assert rows["watchdog_ui"]["state"] == "disabled"
    rows["core"]["state"] = "forged"
    assert supplied[0]["state"] == "running"
    app.config.runtime_chill_ai_blocked = True
    rows = {row["role"]: row for row in app._component_heartbeats_cached()}
    assert rows["local_ai"]["state"] == "disabled"
    assert rows["local_ai"]["last_heartbeat_monotonic"] is None
    app._shutdown_requested.set()
    assert all(row["state"] == "stopped" for row in app._component_heartbeats_cached())


@pytest.mark.skipif(os.name != "nt", reason="Exact native Windows heartbeat generation")
def test_read_only_native_witness_binds_actual_pid_birth_and_rejects_wrong_role():
    from angerona.core.startup_diagnostics import process_identity

    expected = (sys.executable, "-m", "pytest")
    witness = status._ReadOnlyProcessWitness(os.getpid(), expected)
    try:
        assert witness.validate()
        assert str(witness.birth_ticks) == process_identity()["birth_filetime"]
        assert witness.generation_id == f"{os.getpid()}:{witness.birth_ticks}"
    finally:
        witness.close()
    assert not witness.validate()
    with pytest.raises(ValueError, match="invocation"):
        status._ReadOnlyProcessWitness(os.getpid(), (sys.executable, "-m", "angerona.resilience.scanner"))
