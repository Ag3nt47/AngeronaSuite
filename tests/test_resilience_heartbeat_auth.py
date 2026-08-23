from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest


KEY = bytes(range(32))
WRONG_KEY = bytes(reversed(range(32)))
ROOT = Path(__file__).resolve().parents[1]


def _rewrite(path, *, ts_ns=None, pid=None, counter=None, flags=None) -> None:
    from angerona.resilience import heartbeat

    values = list(struct.unpack(heartbeat._FMT, path.read_bytes()))
    replacements = {1: ts_ns, 2: pid, 4: counter, 5: flags}
    for index, value in replacements.items():
        if value is not None:
            values[index] = value
    with path.open("r+b") as stream:
        stream.seek(0)
        stream.write(struct.pack(heartbeat._FMT, *values))
        stream.flush()


def _overwrite(path, payload: bytes) -> None:
    with path.open("r+b") as stream:
        stream.seek(0)
        stream.write(payload)
        stream.flush()


def test_v2_heartbeat_is_fixed_size_and_wrong_key_is_rejected(tmp_path) -> None:
    from angerona.resilience import heartbeat

    path = tmp_path / "core.hb"
    writer = heartbeat.HeartbeatWriter("core", token_raw=KEY, path=path)
    try:
        assert path.stat().st_size == 32
        assert heartbeat.HeartbeatReader(
            "core", path=path, key_raw=KEY
        ).authentication_status() == "authenticated"
        assert heartbeat.HeartbeatReader(
            "core", path=path, key_raw=WRONG_KEY
        ).authentication_status() == "invalid"
        # The component name is explicitly bound even when the backing path is reused.
        assert heartbeat.HeartbeatReader(
            "scanner", path=path, key_raw=KEY
        ).authentication_status() == "invalid"
    finally:
        writer.close()


@pytest.mark.parametrize("field", ["ts_ns", "pid", "counter", "flags"])
def test_each_authenticated_field_tamper_is_rejected(tmp_path, field) -> None:
    from angerona.resilience import heartbeat

    path = tmp_path / "scanner.hb"
    writer = heartbeat.HeartbeatWriter("scanner", token_raw=KEY, path=path)
    try:
        record = heartbeat.HeartbeatReader(
            "scanner", path=path, key_raw=KEY
        ).read()
        assert record is not None
        value = int(record["wire_flags"] if field == "flags" else record[field])
        _rewrite(path, **{field: value ^ 1})
        reader = heartbeat.HeartbeatReader("scanner", path=path, key_raw=KEY)
        assert reader.authentication_status() == "invalid"
    finally:
        writer.close()


def test_verified_reader_rejects_older_replayed_record(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import heartbeat

    path = tmp_path / "watchdog.hb"
    # Model Windows clock granularity explicitly: advancing a valid heartbeat
    # counter must not be rejected merely because time_ns did not move.
    fixed_time_ns = heartbeat.time.time_ns()
    monkeypatch.setattr(heartbeat.time, "time_ns", lambda: fixed_time_ns)
    writer = heartbeat.HeartbeatWriter("watchdog", token_raw=KEY, path=path)
    reader = heartbeat.HeartbeatReader("watchdog", path=path, key_raw=KEY)
    try:
        old_record = path.read_bytes()
        assert reader.authentication_status() == "authenticated"
        writer.beat()
        assert reader.authentication_status() == "authenticated"
        _overwrite(path, old_record)
        assert reader.authentication_status() == "replay"
        assert reader.classify() == "unauthenticated_replay"
    finally:
        writer.close()


def test_legacy_record_is_visible_but_never_silently_trusted(tmp_path) -> None:
    from angerona.resilience import heartbeat

    path = tmp_path / "legacy.hb"
    path.write_bytes(
        struct.pack(
            heartbeat._FMT,
            heartbeat._MAGIC,
            1,
            os.getpid(),
            heartbeat.legacy_proof_for(KEY, 7),
            7,
            1,
        )
    )
    reader = heartbeat.HeartbeatReader("core", path=path, key_raw=KEY)

    assert reader.authentication_status() == "legacy"
    assert reader.classify() == "legacy_unverified"


def test_supervisor_does_not_adopt_or_spawn_from_forged_fresh_pid(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import heartbeat, supervisor

    path = tmp_path / "core.hb"
    writer = heartbeat.HeartbeatWriter("core", token_raw=WRONG_KEY, path=path)
    events = []
    launches = []
    sup = supervisor.ProcessSupervisor(
        on_event=lambda level, message, details: events.append(
            (level, message, details)
        )
    )
    component = sup.add("core", ["core"])
    component.reader = heartbeat.HeartbeatReader("core", path=path, key_raw=KEY)
    monkeypatch.setattr(
        supervisor, "spawn_detached", lambda *_args, **_kwargs: launches.append(True)
    )
    try:
        assert sup._spawn(component) is False
        assert launches == []
        assert any("Rejected core heartbeat" in message for _, message, _ in events)
        assert sup._assess(component) == "unauthenticated_invalid"
    finally:
        writer.close()


def test_supervisor_never_terminates_pid_from_forged_record(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import heartbeat, supervisor

    path = tmp_path / "core.hb"
    writer = heartbeat.HeartbeatWriter("core", token_raw=WRONG_KEY, path=path)
    sup = supervisor.ProcessSupervisor()
    component = sup.add("core", [os.fsdecode(os.fsencode(os.sys.executable))])
    component.reader = heartbeat.HeartbeatReader("core", path=path, key_raw=KEY)
    touched = []
    monkeypatch.setattr(
        heartbeat,
        "pid_alive",
        lambda _pid: touched.append("pid-probe") or True,
    )
    try:
        assert sup._terminate(component) is False
        # Authentication fails before a process object is opened or signaled.
        assert touched == []
    finally:
        writer.close()


def test_spawn_lock_io_error_fails_closed_and_a_later_retry_can_claim(
    tmp_path, monkeypatch
) -> None:
    from angerona.resilience import supervisor

    path = tmp_path / "scanner.spawnlock"
    monkeypatch.setattr(supervisor, "_spawnlock_path", lambda _name: path)
    real_open = supervisor.os.open
    attempts = {"count": 0}

    def flaky_open(*args, **kwargs):
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise PermissionError("locked")
        return real_open(*args, **kwargs)

    monkeypatch.setattr(supervisor.os, "open", flaky_open)

    assert supervisor.try_claim_spawn("scanner") is False
    assert supervisor.spawn_lock_error("scanner") == "PermissionError"
    assert not path.exists()
    assert supervisor.try_claim_spawn("scanner") is True
    assert supervisor.spawn_lock_error("scanner") == ""
    supervisor.release_spawn("scanner")
    assert not path.exists()


def test_supervisor_surfaces_spawn_lock_failure_and_defers_launch(monkeypatch) -> None:
    from angerona.resilience import supervisor

    events = []
    sup = supervisor.ProcessSupervisor(
        on_event=lambda level, message, details: events.append(
            (level, message, details)
        )
    )
    component = sup.add(
        "blackbox", ["blackbox"], running_probe=lambda: False
    )
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _name: False)
    monkeypatch.setattr(
        supervisor, "spawn_lock_error", lambda _name: "PermissionError"
    )

    assert sup._spawn(component) is False
    assert any(
        level == "HIGH"
        and details.get("lock_error") == "PermissionError"
        and "will retry" in message
        for level, message, details in events
    )


def test_frz_v2_build_is_module_locked_and_matches_runtime_search_path() -> None:
    build = (ROOT / "frz" / "build.bat").read_text(encoding="utf-8")
    module = (ROOT / "frz" / "go.mod").read_text(encoding="utf-8")
    checksums = (ROOT / "frz" / "go.sum").read_text(encoding="utf-8")
    runtime = (
        ROOT / "src" / "angerona" / "modules" / "frz_heartbeat.py"
    ).read_text(encoding="utf-8")
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert "go get" not in build.casefold()
    assert "go mod download" in build
    assert "go mod verify" in build
    assert "-mod=readonly" in build
    assert "-trimpath" in build
    assert "-o frz_watchdog_v2.exe frz_watchdog.go" in build
    assert "golang.org/x/sys v0.47.0" in module
    assert "golang.org/x/sys v0.47.0 h1:" in checksums
    assert '_WATCHDOG_NAME = "frz_watchdog_v2.exe"' in runtime
    assert "project_root() / \"frz\" / _WATCHDOG_NAME" in runtime
    assert "frz/frz_watchdog_v2.exe" in ignore
