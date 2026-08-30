from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import angerona.modules.self_healer as healer_module
import angerona.modules.self_integrity as integrity_module
import angerona.modules.storage_hygiene as hygiene_module
import angerona.modules.sysmon_listener as sysmon_module
from angerona.core.module_base import sign_crash_snapshot_bundle
from angerona.modules.self_healer import SelfHealer
from angerona.modules.self_integrity import SelfIntegrityEngine, SelfIntegrityMonitor
from angerona.modules.storage_hygiene import StorageHygieneModule
from angerona.modules.sysmon_listener import SysmonListenerModule


KEY = b"c" * 32


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
    (tmp_path / "bus.key").write_text((b"k" * 32).hex(), encoding="ascii")
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
        key=b"k" * 32,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document), encoding="utf-8")


def test_c09_initial_state_persistence_failure_cannot_be_bypassed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_healer(monkeypatch, tmp_path)
    snapshots = tmp_path / "snapshots"
    snapshots.mkdir()
    calls = []

    def denied(*_args, **_kwargs):
        calls.append(True)
        raise OSError("durable store denied")

    monkeypatch.setattr(healer_module, "replace_with_retry", denied)
    healer = SelfHealer()

    assert healer.process_snapshots_once(snapshots) == 0
    assert healer.process_snapshots_once(snapshots) == 0
    assert healer._state_ready is False
    assert healer.health == 25
    assert len(calls) == 2


def test_c09_retry_backoff_is_durable_and_never_reports_green(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _root, source = _configure_healer(monkeypatch, tmp_path)
    snapshot = tmp_path / "snapshots" / "retry.json"
    _write_snapshot(snapshot, source)
    healer = SelfHealer()
    monkeypatch.setattr(healer, "_request_fix", lambda *_args: None)

    assert healer.process_snapshots_once(snapshot.parent, respect_backoff=True) == 1
    item_id = next(iter(healer._retries))
    attempts = healer._retries[item_id]
    first_seen, next_due = healer._retry_meta[item_id]
    assert next_due > first_seen
    assert healer.health == 65

    assert healer.process_snapshots_once(snapshot.parent, respect_backoff=True) == 0
    assert healer._retries[item_id] == attempts
    assert healer.health == 65


def test_c09_unreadable_snapshot_coverage_is_not_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_healer(monkeypatch, tmp_path)
    healer = SelfHealer()
    monkeypatch.setattr(
        healer, "_snapshot_candidates", lambda _path: ([], "unreadable")
    )

    assert healer.process_snapshots_once(tmp_path / "snapshots") == 0
    assert healer.health == 35


def test_c10_missing_dependency_is_mandatory_coverage_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = integrity_module._resolve
    missing = "angerona.resilience.heartbeat:proof_for"
    monkeypatch.setattr(
        integrity_module,
        "_resolve",
        lambda spec: None if spec == missing else original(spec),
    )
    engine = SelfIntegrityEngine()

    assert engine.arm() == engine.expected_count - 1
    assert missing in engine.unresolved
    assert any(missing in finding for finding in engine.check())


def test_c10_tofu_cannot_reach_full_health_and_approved_manifest_can_verify() -> None:
    observed = SelfIntegrityEngine()
    assert observed.arm() == observed.expected_count
    manifest = {
        spec: {
            "fingerprint": observed.evidence(spec)["fingerprint"],
            "file_sha256": observed.evidence(spec)["file_sha256"],
        }
        for spec in observed._targets
    }
    approved = SelfIntegrityEngine(approved_manifest=manifest)
    assert approved.arm() == approved.expected_count
    assert approved.manifest_status == "verified"

    monitor = SelfIntegrityMonitor()
    monitor._engine.arm()
    score, reason = monitor._assurance_health({"status": "ok"})
    assert score < 100
    assert "tofu" in reason
    acl_score, acl_reason = monitor._assurance_health(
        {"status": "collection-failed", "reason": "access denied"}
    )
    assert acl_score == 35
    assert "ACL collection failed" in acl_reason


def test_c10_runtime_finding_carries_exact_source_path_and_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = "angerona.core.threat:threat_level"
    engine = SelfIntegrityEngine((spec,))
    assert engine.arm() == 1
    import angerona.core.threat as threat

    monkeypatch.setattr(threat, "threat_level", lambda *_args, **_kwargs: None)
    finding = engine.check()[0]
    evidence = engine.evidence(spec)
    assert str(evidence["source_file"]) in finding
    assert f":{evidence['source_line']}" in finding


def test_c17_environment_cannot_redirect_privileged_spill_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import angerona.core.privilege as privilege

    trusted = tmp_path / "trusted-local-app-data"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "attacker"))
    monkeypatch.setattr(hygiene_module.sys, "platform", "win32")
    monkeypatch.setattr(privilege, "_windows_known_folder", lambda _csidl: trusted)

    assert hygiene_module.default_c_location() == trusted / "Angerona"


def test_c17_pathname_move_and_purge_execution_are_retired(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "legacy"
    dest = tmp_path / "runtime"
    source.mkdir()
    marker = source / "keep.txt"
    marker.write_text("preserve", encoding="utf-8")
    monkeypatch.setattr(
        hygiene_module.shutil,
        "move",
        lambda *_args, **_kwargs: pytest.fail("shutil.move must not execute"),
    )
    monkeypatch.setattr(hygiene_module, "default_c_location", lambda: source)
    monkeypatch.setattr(hygiene_module, "canonical_root", lambda: dest)

    migration = hygiene_module.migrate_stray(source, dest)
    purge = StorageHygieneModule().purge_stray(confirm=True)

    assert migration["moved"] == []
    assert "mutation retired" in migration["errors"][0]
    assert purge["ok"] is False and "purge retired" in purge["error"]
    assert marker.read_text(encoding="utf-8") == "preserve"
    assert not dest.exists()


def test_c17_unavailable_inspection_never_reports_clean(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(hygiene_module, "default_c_location", lambda: tmp_path / "legacy")
    monkeypatch.setattr(hygiene_module, "canonical_root", lambda: tmp_path / "runtime")
    monkeypatch.setattr(
        hygiene_module,
        "inspect_stray",
        lambda *_args: {
            "status": "unavailable", "reason": "access denied", "items": []
        },
    )
    module = StorageHygieneModule()
    module._pass()
    assert module.health == 30
    assert "unavailable" in module.health_note


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
        self.calls: list[tuple[str, int]] = []

    def GetOldestEventLogRecord(self, _handle):
        return self.records[0].RecordNumber if self.records else 1

    def GetNumberOfEventLogRecords(self, _handle):
        return len(self.records)

    def ReadEventLog(self, _handle, flags: int, offset: int):
        if flags == sysmon_module._EVTLOG_SEEK_FWD:
            self.calls.append(("seek", offset))
            return [row for row in self.records if row.RecordNumber >= offset]
        self.calls.append(("sequential", offset))
        return []


def test_c19_same_range_clear_refill_changes_generation_and_forces_replay(
    tmp_path: Path,
) -> None:
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=KEY)
    module._evtlog_handle = object()
    before = _FakeEventLog([_record(1, "old-1"), _record(2, "old-2"), _record(3, "old-3")])
    generation, _oldest, _newest = module._capture_channel_generation(before)
    module._channel_generation = generation
    assert module._save_cursor(
        3, record_anchor=module._record_digest(before.records[-1]), generation=generation
    )

    after = _FakeEventLog([_record(1, "new-1"), _record(2, "new-2"), _record(3, "new-3")])
    cursor, newest = module._establish_continuity(after)

    assert (cursor, newest) == (0, 3)
    assert module._continuity_state == "generation-gap-replay"
    assert module.health < 100
    assert module._continuity_evidence["previous_generation"] != (
        module._continuity_evidence["current_generation"]
    )


def test_c19_persistence_failure_degrades_and_reopen_explicitly_reseeks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=KEY)
    module._evtlog_handle = object()
    backend = _FakeEventLog([_record(1, "one"), _record(2, "two")])
    generation, _oldest, _newest = module._capture_channel_generation(backend)
    module._channel_generation = generation
    assert module._save_cursor(
        1, record_anchor=module._record_digest(backend.records[0]), generation=generation
    )

    backend.calls.clear()
    monkeypatch.setattr(module, "_process_record", lambda _record: None)
    module._reseek_and_drain(backend)
    assert ("seek", 2) in backend.calls
    assert module._load_cursor() == 2
    assert module._continuity_evidence["state"] == "verified"

    monkeypatch.setattr(sysmon_module.os, "replace", lambda *_args: (_ for _ in ()).throw(OSError("denied")))
    assert module._save_cursor(
        3, record_anchor="a" * 64, generation=generation
    ) is False
    assert module._cursor_persist_failed is True
    assert module.health == 25
