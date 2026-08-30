from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import angerona.core.threat as threat_module
import angerona.modules.self_healer as healer_module
import angerona.modules.storage_hygiene as hygiene_module
import angerona.modules.sysmon_listener as sysmon_module
from angerona.core.module_base import sign_crash_snapshot_bundle
from angerona.modules.self_healer import SelfHealer
from angerona.modules.self_integrity import SelfIntegrityEngine, SelfIntegrityMonitor
from angerona.modules.sysmon_listener import SysmonListenerModule


INSTALL_KEY = b"k" * 32
CURSOR_KEY = b"c" * 32


def _configure_healer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> tuple[Path, Path]:
    source_root = tmp_path / "installed" / "angerona"
    source_root.mkdir(parents=True)
    source = source_root / "fixture.py"
    source.write_text("value = 1\n", encoding="utf-8")
    monkeypatch.setattr(healer_module, "_data_base", lambda: tmp_path)
    monkeypatch.setattr(
        SelfHealer, "_trusted_source_roots", staticmethod(lambda: (source_root,))
    )
    (tmp_path / "bus.key").write_text(INSTALL_KEY.hex(), encoding="ascii")
    return source_root, source


def _write_snapshot(path: Path, source: Path) -> None:
    document = sign_crash_snapshot_bundle(
        {
            "module": "Fixture",
            "crashed_at": 1.0,
            "error": "RuntimeError",
            "traceback": f'  File "{source}", line 1, in run',
            "memory": {},
            "last_50_events": [],
        },
        key=INSTALL_KEY,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def test_c09_authenticated_boolean_retry_counter_is_not_integer_compatible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_healer(monkeypatch, tmp_path)
    item_id = "a" * 64
    healer = SelfHealer()
    healer._retries[item_id] = 1
    healer._retry_meta[item_id] = (10.0, 15.0)
    assert healer._persist_state()
    document = json.loads(healer._state_path().read_text(encoding="utf-8"))
    document["retries"][item_id] = True
    body = {key: value for key, value in document.items() if key != "signature"}
    key = healer._state_key()
    assert key is not None
    document["signature"] = healer._state_signature(body, key)
    healer._state_path().write_text(json.dumps(document), encoding="utf-8")

    restarted = SelfHealer()
    assert restarted._load_state() is False
    assert restarted.health == 20
    assert restarted._retries == {}

    in_memory = SelfHealer()
    in_memory._retries[item_id] = True
    in_memory._retry_meta[item_id] = (10.0, 15.0)
    assert in_memory._persist_state() is False
    assert in_memory._state_persist_failed is True


def test_c09_runtime_backoff_uses_monotonic_time_during_wall_rollback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _root, source = _configure_healer(monkeypatch, tmp_path)
    snapshot = tmp_path / "snapshots" / "retry.json"
    _write_snapshot(snapshot, source)
    clock = {"wall": 1_000.0, "mono": 50.0}
    monkeypatch.setattr(healer_module.time, "time", lambda: clock["wall"])
    monkeypatch.setattr(healer_module.time, "monotonic", lambda: clock["mono"])
    healer = SelfHealer()
    monkeypatch.setattr(healer, "_request_fix", lambda *_args: None)

    assert healer.process_snapshots_once(snapshot.parent, respect_backoff=True) == 1
    item_id = next(iter(healer._retries))
    clock.update(wall=0.0, mono=51.0)
    restarted = SelfHealer()
    assert restarted._load_state()
    assert restarted._retry_meta[item_id][1] - clock["wall"] <= 5.0
    assert healer.process_snapshots_once(snapshot.parent, respect_backoff=True) == 0
    assert healer._retries[item_id] == 1
    clock["mono"] = 56.0
    assert healer.process_snapshots_once(snapshot.parent, respect_backoff=True) == 1
    assert healer._retries[item_id] == 2


def test_c09_selected_identity_rejects_link_swap_even_if_alias_becomes_single_link(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _root, source = _configure_healer(monkeypatch, tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    selected = SelfHealer._source_from_traceback(
        f'  File "{source}", line 1, in run'
    )
    assert selected is not None
    source.unlink()
    source.hardlink_to(outside)
    outside.unlink()

    with pytest.raises(ValueError, match="identity"):
        SelfHealer._read_trusted_source(Path(selected))


def test_c09_direct_trusted_read_compatibility_remains_for_single_link_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _root, source = _configure_healer(monkeypatch, tmp_path)
    assert SelfHealer._read_trusted_source(source).splitlines() == ["value = 1"]


def test_c10_threat_dependency_closure_and_unknown_acl_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = "angerona.core.threat:is_active_threat"
    engine = SelfIntegrityEngine()
    assert expected in engine._targets
    assert engine.arm() == engine.expected_count == 19
    monkeypatch.setattr(threat_module, "is_active_threat", lambda _event: False)
    assert any(expected in finding for finding in engine.check())

    monitor = SelfIntegrityMonitor()
    monitor._engine = SimpleNamespace(unresolved={}, manifest_status="verified")
    score, reason = monitor._assurance_health(
        {"status": "unexpected", "reason": "collector terminated"}
    )
    assert score == 35
    assert "ACL" in reason


def test_c17_ordinary_directory_object_swap_is_not_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "legacy"
    destination = tmp_path / "runtime"
    parked = tmp_path / "validated"
    source.mkdir()
    original = hygiene_module._migration_safety_error

    def swap(src: Path, dst: Path) -> str | None:
        result = original(src, dst)
        source.rename(parked)
        source.mkdir()
        return result

    monkeypatch.setattr(hygiene_module, "_migration_safety_error", swap)
    try:
        result = hygiene_module.inspect_stray(source, destination)
        assert result["status"] == "unsafe"
        assert "object changed" in str(result["reason"])
    finally:
        if source.exists():
            source.rmdir()
        if parked.exists():
            parked.rename(source)


def _record(number: int, marker: str) -> SimpleNamespace:
    return SimpleNamespace(
        RecordNumber=number,
        EventID=1,
        TimeGenerated="2026-01-01T00:00:00Z",
        SourceName="Sysmon",
        ComputerName="host",
        StringInserts=[marker],
    )


class _FakeEventLog:
    def __init__(self, records: list[SimpleNamespace]) -> None:
        self.records = records

    def GetOldestEventLogRecord(self, _handle: object) -> int:
        return self.records[0].RecordNumber if self.records else 1

    def GetNumberOfEventLogRecords(self, _handle: object) -> int:
        return len(self.records)

    def ReadEventLog(
        self, _handle: object, flags: int, offset: int
    ) -> list[SimpleNamespace]:
        if flags == sysmon_module._EVTLOG_SEEK_FWD:
            return [row for row in self.records if row.RecordNumber >= offset]
        return []


def test_c19_in_process_authenticated_sequence_rollback_is_rejected(
    tmp_path: Path,
) -> None:
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)
    records = [_record(1, "one"), _record(2, "two")]
    generation = module._generation("observed", 1, module._record_digest(records[0]))
    assert module._save_cursor(
        1, record_anchor=module._record_digest(records[0]), generation=generation
    )
    old = module._cursor_path.read_bytes()
    assert module._save_cursor(
        2, record_anchor=module._record_digest(records[1]), generation=generation
    )
    module._cursor_path.write_bytes(old)

    assert module._load_cursor() == 2
    assert module._cursor_auth_failed is True
    assert module.health < 100


def test_c19_generation_change_replays_prefix_and_allows_lower_new_checkpoint(
    tmp_path: Path,
) -> None:
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)
    module._evtlog_handle = object()
    before = _FakeEventLog(
        [_record(10, "old-first"), _record(11, "old-tail")]
    )
    old_generation, _oldest, _newest = module._capture_channel_generation(before)
    assert module._save_cursor(
        11,
        record_anchor=module._record_digest(before.records[-1]),
        generation=old_generation,
    )
    after = _FakeEventLog([_record(1, "new-first"), _record(2, "new-tail")])
    cursor, newest = module._establish_continuity(after)
    assert (cursor, newest) == (0, 2)
    assert module._continuity_state == "generation-gap-replay"

    new_generation = module._channel_generation
    assert new_generation is not None and new_generation != old_generation
    assert module._save_cursor(
        1,
        record_anchor=module._record_digest(after.records[0]),
        generation=new_generation,
    )
    assert module._durable_record == 1
    assert module._cursor_sequence == 2


def test_c19_anchor_hashes_full_admitted_data_and_rejects_oversize() -> None:
    prefix = "A" * 4_096
    assert SysmonListenerModule._record_digest(
        _record(7, prefix + "old")
    ) != SysmonListenerModule._record_digest(_record(7, prefix + "new"))
    oversized = _record(
        8, "B" * (sysmon_module._MAX_RECORD_ANCHOR_CHARS + 1)
    )
    with pytest.raises(ValueError, match="safety bound"):
        SysmonListenerModule._record_digest(oversized)
