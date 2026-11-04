"""Actual optional 32-byte MAC records and native SELF process observation.

No target other than this test process is natively opened. Clock/record faults
are explicit; authentication and the native witness are never replaced by True.
"""
from __future__ import annotations

import os
import struct
import time
from pathlib import Path

import pytest

from angerona.core.source_activation_file import write_new
from angerona.core.startup_recovery import private_directory
from angerona.resilience import component_status as status
from angerona.resilience import heartbeat as hb


class _Time:
    def __init__(self, wall):
        self.wall = wall

    def time_ns(self):
        return self.wall[0]

    def __getattr__(self, name):
        return getattr(time, name)


@pytest.fixture
def optional_root(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("Optional source publishers require native Windows self identity")
    root = tmp_path / "private-data"
    assert private_directory(root, create=True)
    write_new(root / "shutdown.key", (b"s" * 32).hex().encode())
    mono, wall = [100.0], [time.time_ns()]
    monkeypatch.setattr(hb, "time", _Time(wall))
    monkeypatch.setattr(hb, "_OPTIONAL_CLOSE_HOLDS", [])
    return root, mono, wall


def _writer(root, role):
    return hb.OptionalHeartbeatWriter(role, root, "1" * 32,
        **({"guard_nonce": "2" * 32} if role == "activation_broker" else {}))


def _cache(root, writer, mono, wall, *, component=None):
    def own_native(pid, expected):
        if pid != os.getpid() or expected != ("actual-test-process",):
            raise ValueError("A heartbeat cannot choose another process")
        return status._ReadOnlyProcessWitness(pid, None)
    return status.ComponentHeartbeatCache({writer.role: ("actual-test-process",)},
        heartbeat_directory=root / "heartbeats", selected_roles=(writer.role,),
        component_names={writer.role: component or writer.component},
        identity_factory=own_native, clock=lambda: mono[0], wall_ns=lambda: wall[0])


def _advance(mono, wall, seconds=0.5):
    mono[0] += seconds
    wall[0] += int(seconds * 1_000_000_000)


def _row(cache):
    cache.sample()
    rows = cache.snapshot()
    assert len(rows) == 1
    return rows[0]


@pytest.mark.parametrize("role", ["source_startup", "source_update_owner", "activation_broker"])
def test_actual_wire_native_birth_two_beats_stale_and_clean_stop(optional_root, role):
    root, mono, wall = optional_root
    writer = _writer(root, role)
    cache = _cache(root, writer, mono, wall)
    try:
        reader = hb.HeartbeatReader(writer.component, path=writer.path, key_raw=b"s" * 32)
        record = reader.read()
        assert writer.path == root / "heartbeats" / (role + ".hb")
        assert writer.path.stat().st_size == hb.RECORD_SIZE == 32
        assert record["pid"] == os.getpid()
        assert reader.authentication_status(record=record) == "authenticated"
        assert record["ts_ns"] >= (int(writer.birth_ticks) - 116444736000000000) * 100
        first = _row(cache)
        assert first["state"] == "starting"
        assert first["generation_id"] == str(os.getpid()) + ":" + writer.birth_ticks
        _advance(mono, wall)
        writer.beat()
        running = _row(cache)
        assert running["state"] == "running"
        assert running["last_heartbeat_monotonic"] == mono[0]
        # Progress profiles confer no owned native/response DTOs, even if asked.
        cache.refresh_owned_processes()
        assert cache.owned_process_identities() == ()
        _advance(mono, wall, status.DEADLINES[role] + 0.5)
        assert _row(cache)["state"] == "stale"
        writer.close()
        assert _row(cache)["state"] == "stopped"
        assert writer.path.stat().st_size == 32
    finally:
        if not writer.close_held:
            writer.close()
        cache.close()


def test_frozen_counter_does_not_turn_new_sampling_into_progress(optional_root):
    root, mono, wall = optional_root
    writer = _writer(root, "source_update_owner")
    cache = _cache(root, writer, mono, wall)
    try:
        assert _row(cache)["state"] == "starting"
        _advance(mono, wall)
        assert _row(cache)["state"] == "starting"
        _advance(mono, wall, status.DEADLINES[writer.role] + 0.5)
        assert _row(cache)["state"] == "stale"
        assert cache.snapshot()[0]["last_heartbeat_monotonic"] is None
    finally:
        writer.close()
        cache.close()


def test_genuine_older_authenticated_record_is_rejected_as_replay(optional_root):
    root, mono, wall = optional_root
    writer = _writer(root, "source_update_owner")
    cache = _cache(root, writer, mono, wall)
    try:
        original = bytes(writer._mm)
        assert _row(cache)["state"] == "starting"
        _advance(mono, wall)
        writer.beat()
        assert _row(cache)["state"] == "running"
        writer._mm[:] = original
        row = _row(cache)
        assert row["state"] == "unavailable"
        assert "authentication or replay" in row["reason"]
    finally:
        writer.close()
        cache.close()


def test_wrong_native_generation_component_cannot_authenticate_real_record(optional_root):
    root, mono, wall = optional_root
    writer = _writer(root, "source_update_owner")
    wrong = hb.optional_component(writer.role, "1" * 32, str(int(writer.birth_ticks) + 1))
    cache = _cache(root, writer, mono, wall, component=wrong)
    try:
        assert _row(cache)["state"] == "unavailable"
        assert "component birth differs" in cache.snapshot()[0]["reason"]
    finally:
        writer.close()
        cache.close()


@pytest.mark.parametrize("fault", ["foreign-pid", "before-birth", "future"])
def test_even_correct_mac_cannot_authorize_foreign_or_invalid_native_timing(optional_root, fault):
    root, mono, wall = optional_root
    writer = _writer(root, "source_update_owner")
    cache = _cache(root, writer, mono, wall)
    try:
        magic, stamp, pid, _proof, counter, flags = struct.unpack(hb._FMT, bytes(writer._mm))
        if fault == "foreign-pid":
            pid += 1
        elif fault == "before-birth":
            stamp = (int(writer.birth_ticks) - 116444736000000000) * 100 - 1
        else:
            stamp = wall[0] + 1
        proof = hb.proof_for(writer._key, writer.component, stamp, pid, counter, flags)
        writer._mm[:] = struct.pack(hb._FMT, magic, stamp, pid, proof, counter, flags)
        row = _row(cache)
        assert row["state"] == "unavailable"
        assert row["last_heartbeat_monotonic"] is None
    finally:
        writer.close()
        cache.close()


def test_missing_existing_key_cannot_be_created_by_optional_writer(tmp_path, monkeypatch):
    if os.name != "nt":
        pytest.skip("Windows optional publisher")
    root = tmp_path / "private-data"
    assert private_directory(root, create=True)
    from angerona.resilience import shutdown_token

    def forbidden_loader():
        raise AssertionError("Optional publisher reached creating key loader")

    monkeypatch.setattr(shutdown_token, "_load_key", forbidden_loader)
    with pytest.raises(FileNotFoundError):
        _writer(root, "source_update_owner")
    assert not (root / "shutdown.key").exists()
    assert not (root / "heartbeats").exists()


@pytest.mark.parametrize("size", [0, 31, 33, 64])
def test_existing_slot_wrong_size_is_held_without_growth_or_truncation(optional_root, size):
    root, _mono, _wall = optional_root
    directory = root / "heartbeats"
    assert private_directory(directory, create=True)
    target = directory / "source_update_owner.hb"
    write_new(target, b"x" * size)
    before = target.stat()
    with pytest.raises(ValueError, match="exactly 32"):
        _writer(root, "source_update_owner")
    assert target.read_bytes() == b"x" * size
    after = target.stat()
    assert (after.st_dev, after.st_ino, after.st_size) == (before.st_dev, before.st_ino, size)
    assert not hb._OPTIONAL_CLOSE_HOLDS


def test_uncertain_close_is_sticky_and_never_retried(optional_root):
    root, _mono, _wall = optional_root
    writer = _writer(root, "source_update_owner")
    actual = writer._f
    calls = []

    class LostAck:
        def fileno(self):
            return actual.fileno()

        def close(self):
            calls.append("close")
            actual.close()
            raise OSError("inert acknowledgement loss after actual stream close")

    writer._f = LostAck()
    with pytest.raises(ValueError, match="close custody remains held"):
        writer.close()
    assert actual.closed and writer.close_held
    assert calls == ["close"] and hb._OPTIONAL_CLOSE_HOLDS
    with pytest.raises(ValueError, match="close custody remains held"):
        writer.close()
    with pytest.raises(ValueError, match="Prior optional heartbeat"):
        _writer(root, "activation_broker")
    assert calls == ["close"]


@pytest.mark.parametrize("roles", [("unknown",), ("core", "core"), ["core"], (),
                                  ("core",) * 8])
def test_role_selection_is_closed_and_bounded(roles):
    with pytest.raises(ValueError, match="closed tuple"):
        status.ComponentHeartbeatCache({}, selected_roles=roles)


def test_default_four_profiles_remain_and_optional_wrong_role_component_is_refused():
    cache = status.ComponentHeartbeatCache({})
    try:
        assert tuple(row["role"] for row in cache.snapshot()) == (
            "core", "watchdog", "scanner", "blackbox")
        cache.sample()
        assert len(cache.snapshot()) == 4
    finally:
        cache.close()
    name = hb.optional_component("source_startup", "1" * 32, "133000000000000001")
    with pytest.raises(ValueError, match="role or generation is contradictory"):
        status.ComponentHeartbeatCache({}, selected_roles=("source_update_owner",),
            component_names={"source_update_owner": name})


@pytest.mark.parametrize("role,launch,birth,guard", [
    ("foreign", "1" * 32, "133000000000000001", None),
    ("source_startup", "A" * 32, "133000000000000001", None),
    ("source_startup", "1" * 32, "0", None),
    ("source_update_owner", "1" * 32, "133000000000000001", "2" * 32),
    ("activation_broker", "1" * 32, "133000000000000001", None),
])
def test_component_generation_and_guard_binding_are_exact(role, launch, birth, guard):
    with pytest.raises(ValueError):
        hb.optional_component(role, launch, birth, guard_nonce=guard)


@pytest.mark.parametrize("name", ["relative-data", "C:/explicit/../redirect", "//server/share"])
def test_authority_root_rejects_nonlocal_or_traversal_before_file_io(monkeypatch, name):
    from angerona.core import source_activation_file

    def forbidden_path(*_args, **_kwargs):
        raise AssertionError("Rejected authority root reached filesystem discovery")

    monkeypatch.setattr(source_activation_file, "plain_path", forbidden_path)
    with pytest.raises(ValueError, match="explicit and local"):
        hb.read_existing_optional_authority(Path(name))


def test_malformed_existing_master_is_preserved_without_new_slot(optional_root):
    root, _mono, _wall = optional_root
    key = root / "shutdown.key"
    original_id = key.stat().st_ino
    with key.open("r+b") as stream:
        stream.write(b"z" * 64)
        stream.truncate()
    with pytest.raises(ValueError, match="authority is malformed"):
        _writer(root, "source_update_owner")
    assert key.read_bytes() == b"z" * 64 and key.stat().st_ino == original_id
    assert not (root / "heartbeats").exists()


def test_default_created_existing_heartbeat_directory_is_accepted_without_acl_rewrite(optional_root):
    root, mono, wall = optional_root
    directory = root / "heartbeats"
    # This is the real default hb_dir mkdir behavior under a proved private DATA
    # parent, not the special protected directory creator used for new slots.
    directory.mkdir()
    before = directory.stat()
    from angerona.core.startup_recovery import _windows_security
    assert _windows_security(directory, create=False, allow_inherited=True)
    writer = _writer(root, "source_update_owner")
    cache = _cache(root, writer, mono, wall)
    try:
        assert _row(cache)["state"] == "starting"
        _advance(mono, wall)
        writer.beat()
        assert _row(cache)["state"] == "running"
        after = directory.stat()
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino)
        assert _windows_security(directory, create=False, allow_inherited=True)
    finally:
        writer.close()
        cache.close()


def test_genuine_full_mac_for_wrong_component_birth_is_not_native_progress(optional_root):
    root, mono, wall = optional_root
    probe = _writer(root, "source_update_owner")
    actual_birth, path = probe.birth_ticks, probe.path
    probe.close()
    wrong = hb.optional_component("source_update_owner", "1" * 32, str(int(actual_birth) + 1))
    # Real original codec creates a completely valid MAC for this wrong-name
    # record. This is not a verifier stub or merely an old ts_ns negative.
    writer = hb.HeartbeatWriter(wrong, token_raw=b"s" * 32, path=path)
    writer.role, writer.component = "source_update_owner", wrong
    cache = _cache(root, writer, mono, wall)
    try:
        reader = hb.HeartbeatReader(wrong, path=path, key_raw=b"s" * 32)
        assert reader.authentication_status(record=reader.read()) == "authenticated"
        row = _row(cache)
        assert row["state"] == "unavailable"
        assert "component birth differs" in row["reason"]
        assert row["last_heartbeat_monotonic"] is None
    finally:
        writer.close()
        cache.close()


def test_concurrent_real_private_directory_creation_is_reverified(optional_root, monkeypatch):
    root, mono, wall = optional_root
    directory = root / "heartbeats"
    from angerona.core import startup_recovery
    actual = startup_recovery.private_directory
    created = []

    def race(path, *, create):
        if Path(path) == directory and create and not created:
            assert actual(path, create=True)
            created.append(directory.stat().st_ino)
            raise FileExistsError("inert competing creator after actual private mkdir")
        return actual(path, create=create)

    monkeypatch.setattr(startup_recovery, "private_directory", race)
    writer = _writer(root, "source_update_owner")
    cache = _cache(root, writer, mono, wall)
    try:
        assert created == [directory.stat().st_ino]
        assert _row(cache)["state"] == "starting"
        _advance(mono, wall)
        writer.beat()
        assert _row(cache)["state"] == "running"
    finally:
        writer.close()
        cache.close()
