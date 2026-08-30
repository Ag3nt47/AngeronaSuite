from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import angerona.core.threat as threat_module
import angerona.modules.self_healer as healer_module
import angerona.modules.self_integrity as integrity_module
import angerona.modules.storage_hygiene as hygiene_module
import angerona.modules.sysmon_listener as sysmon_module
from angerona.core.module_base import sign_crash_snapshot_bundle
from angerona.modules.self_healer import SelfHealer
from angerona.modules.self_integrity import SelfIntegrityEngine, SelfIntegrityMonitor
from angerona.modules.storage_hygiene import StorageHygieneModule
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


def test_c09_retry_and_dead_letter_tamper_is_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_healer(monkeypatch, tmp_path)
    healer = SelfHealer()
    item_id = "a" * 64
    healer._dead_letters[item_id] = "manual review"
    assert healer._persist_state()

    document = json.loads(healer._state_path().read_text(encoding="utf-8"))
    document["dead_letters"][item_id] = "attacker-cleared"
    healer._state_path().write_text(json.dumps(document), encoding="utf-8")

    restarted = SelfHealer()
    assert restarted._load_state() is False
    assert restarted.health == 20
    assert restarted._dead_letters == {}


def test_c09_bounded_deep_state_cannot_escape_fail_closed_loader(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _configure_healer(monkeypatch, tmp_path)
    state_path = SelfHealer._state_path()
    state_path.parent.mkdir(parents=True)
    # Well below the byte cap, but deep enough to exhaust CPython's JSON recursion.
    state_path.write_bytes(b"[" * 1_100 + b"0" + b"]" * 1_100)
    healer = SelfHealer()

    try:
        loaded = healer._load_state()
    except RecursionError as exc:  # pragma: no cover - the hostile gate is red today
        pytest.fail(f"bounded unauthenticated state escaped fail-closed parsing: {exc}")

    assert loaded is False
    assert healer.health <= 20


def test_c09_wall_clock_rollback_cannot_expand_retry_beyond_bound(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _root, source = _configure_healer(monkeypatch, tmp_path)
    snapshot = tmp_path / "snapshots" / "retry.json"
    _write_snapshot(snapshot, source)
    clock = {"now": 1_000.0}
    monkeypatch.setattr(healer_module.time, "time", lambda: clock["now"])
    healer = SelfHealer()
    monkeypatch.setattr(healer, "_request_fix", lambda *_args: None)

    assert healer.process_snapshots_once(snapshot.parent, respect_backoff=True) == 1
    item_id = next(iter(healer._retry_meta))
    assert healer._retry_meta[item_id][1] == 1_005.0

    # Simulate a restart after an administrator/NTP wall-clock rollback.
    clock["now"] = 0.0
    restarted = SelfHealer()
    assert restarted._load_state()
    _first_seen, next_due = restarted._retry_meta[item_id]
    assert next_due - clock["now"] <= healer_module._RETRY_MAX_SECONDS


def test_c09_validated_source_identity_swap_cannot_escape_source_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _root, source = _configure_healer(monkeypatch, tmp_path)
    outside = tmp_path / "outside" / "sensitive.py"
    outside.parent.mkdir()
    outside.write_text("outside_secret = 'do-not-ingest'\n", encoding="utf-8")

    selected = SelfHealer._source_from_traceback(
        f'  File "{source}", line 1, in run'
    )
    assert selected == str(source.resolve())

    # Deterministic stand-in for the validation/open race: retain the trusted
    # pathname but swap its object to an out-of-root hard-link before open.
    source.unlink()
    os.link(outside, source)
    with pytest.raises(ValueError, match="trusted|root|identity"):
        SelfHealer._read_trusted_source(Path(selected))


def test_c10_unlisted_security_dependency_monkeypatch_is_detected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = SelfIntegrityEngine()
    assert engine.arm() == engine.expected_count

    # active_threat_events calls this global for every candidate. Replacing it
    # with false suppresses the whole threat posture without changing either of
    # the two callables currently listed for the threat-level target.
    monkeypatch.setattr(threat_module, "is_active_threat", lambda _event: False)
    findings = engine.check()

    assert any(
        "is_active_threat" in finding or "active_threat_events" in finding
        for finding in findings
    )


def test_c10_unknown_acl_collector_state_cannot_score_full_health() -> None:
    monitor = SelfIntegrityMonitor()
    monitor._engine = SimpleNamespace(unresolved={}, manifest_status="verified")

    score, reason = monitor._assurance_health(
        {"status": "collector-crashed", "reason": "unexpected termination"}
    )

    assert score < 100
    assert "ACL" in reason


def test_c10_approved_manifest_remains_distinct_from_live_tofu() -> None:
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
    assert observed.manifest_status == "tofu-unapproved"
    assert approved.manifest_status == "verified"
    for spec in approved._targets:
        evidence = approved.evidence(spec)
        assert Path(str(evidence["source_file"])).is_file()
        assert int(evidence["source_line"]) >= 1


def _create_directory_redirect(link: Path, target: Path) -> None:
    if os.name == "nt":
        completed = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if completed.returncode != 0:
            pytest.skip(f"temporary junction unavailable: {completed.stderr.strip()}")
    else:
        link.symlink_to(target, target_is_directory=True)


def _remove_directory_redirect(link: Path) -> None:
    if os.name == "nt":
        link.rmdir()
    else:
        link.unlink()


def test_c17_environment_cannot_redirect_os_authoritative_windows_source(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import angerona.core.privilege as privilege

    trusted = tmp_path / "os-profile"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "attacker-local"))
    monkeypatch.setenv("HOME", str(tmp_path / "attacker-home"))
    monkeypatch.setattr(hygiene_module.sys, "platform", "win32")
    monkeypatch.setattr(privilege, "_windows_known_folder", lambda _csidl: trusted)

    assert hygiene_module.default_c_location() == trusted / "Angerona"


def test_c17_hardlink_spill_cannot_reactivate_retired_mutation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "legacy"
    destination = tmp_path / "runtime"
    outside = tmp_path / "outside.txt"
    source.mkdir()
    outside.write_text("preserve", encoding="utf-8")
    alias = source / "alias.txt"
    os.link(outside, alias)
    monkeypatch.setattr(
        hygiene_module.shutil,
        "move",
        lambda *_args, **_kwargs: pytest.fail("retired move route executed"),
    )
    monkeypatch.setattr(
        hygiene_module.shutil,
        "rmtree",
        lambda *_args, **_kwargs: pytest.fail("retired purge route executed"),
    )
    monkeypatch.setattr(hygiene_module, "default_c_location", lambda: source)
    monkeypatch.setattr(hygiene_module, "canonical_root", lambda: destination)

    migration = hygiene_module.migrate_stray(source, destination, dry_run=False)
    purge = StorageHygieneModule().purge_stray(confirm=True)

    assert migration["moved"] == [] and migration["errors"]
    assert purge["ok"] is False and "retired" in purge["error"]
    assert outside.read_text(encoding="utf-8") == "preserve"
    assert alias.read_text(encoding="utf-8") == "preserve"
    assert not destination.exists()


def test_c17_source_object_swap_cannot_turn_reparse_collection_green(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    source = tmp_path / "legacy"
    destination = tmp_path / "runtime"
    redirected = tmp_path / "redirected"
    parked = tmp_path / "validated-source"
    source.mkdir()
    redirected.mkdir()
    original_safety = hygiene_module._migration_safety_error

    def swap_after_validation(src: Path, dst: Path) -> str | None:
        result = original_safety(src, dst)
        source.rename(parked)
        _create_directory_redirect(source, redirected)
        return result

    monkeypatch.setattr(
        hygiene_module, "_migration_safety_error", swap_after_validation
    )
    try:
        assessment = hygiene_module.inspect_stray(source, destination)
        assert assessment["status"] in {"unsafe", "unavailable"}
    finally:
        if os.path.lexists(source):
            _remove_directory_redirect(source)
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
        self.calls: list[tuple[str, int]] = []

    def GetOldestEventLogRecord(self, _handle: object) -> int:
        return self.records[0].RecordNumber if self.records else 1

    def GetNumberOfEventLogRecords(self, _handle: object) -> int:
        return len(self.records)

    def ReadEventLog(
        self, _handle: object, flags: int, offset: int
    ) -> list[SimpleNamespace]:
        if flags == sysmon_module._EVTLOG_SEEK_FWD:
            self.calls.append(("seek", offset))
            return [row for row in self.records if row.RecordNumber >= offset]
        self.calls.append(("sequential", offset))
        return []


def test_c19_authenticated_cursor_rollback_is_not_accepted_in_process(
    tmp_path: Path,
) -> None:
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)
    records = [_record(1, "one"), _record(2, "two")]
    generation = module._generation("observed", 1, module._record_digest(records[0]))
    assert module._save_cursor(
        1, record_anchor=module._record_digest(records[0]), generation=generation
    )
    old_authenticated_state = module._cursor_path.read_bytes()
    assert module._save_cursor(
        2, record_anchor=module._record_digest(records[1]), generation=generation
    )
    assert module._cursor_sequence == 2 and module._durable_record == 2

    module._cursor_path.write_bytes(old_authenticated_state)
    loaded = module._load_cursor()

    assert loaded >= 2 or module._cursor_auth_failed


def test_c19_same_range_refill_with_unchanged_cursor_record_forces_gap_replay(
    tmp_path: Path,
) -> None:
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)
    module._evtlog_handle = object()
    before = _FakeEventLog(
        [_record(1, "old-1"), _record(2, "old-2"), _record(3, "stable-tail")]
    )
    generation, _oldest, _newest = module._capture_channel_generation(before)
    assert module._save_cursor(
        3,
        record_anchor=module._record_digest(before.records[-1]),
        generation=generation,
    )

    after = _FakeEventLog(
        [_record(1, "new-1"), _record(2, "new-2"), _record(3, "stable-tail")]
    )
    cursor, newest = module._establish_continuity(after)

    assert (cursor, newest) == (0, 3)
    assert module._continuity_state == "generation-gap-replay"
    assert module.health < 100


def test_c19_exact_record_anchor_covers_security_data_after_four_kibibytes() -> None:
    prefix = "<Event>" + ("A" * 4_096)
    old = _record(7, prefix + "<Image>old.exe</Image></Event>")
    new = _record(7, prefix + "<Image>new.exe</Image></Event>")

    assert SysmonListenerModule._record_digest(old) != (
        SysmonListenerModule._record_digest(new)
    )


def test_c19_bounded_deep_cursor_cannot_escape_fail_closed_loader(
    tmp_path: Path,
) -> None:
    module = SysmonListenerModule(data_root=tmp_path, cursor_key=CURSOR_KEY)
    module._cursor_path.parent.mkdir(parents=True)
    module._cursor_path.write_bytes(b"[" * 1_100 + b"0" + b"]" * 1_100)

    try:
        loaded = module._load_cursor()
    except RecursionError as exc:  # pragma: no cover - the hostile gate is red today
        pytest.fail(f"bounded cursor state escaped fail-closed parsing: {exc}")

    assert loaded == 0
    assert module._cursor_auth_failed is True
