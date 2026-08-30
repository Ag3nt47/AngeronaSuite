from __future__ import annotations

import json

from angerona.modules import yara_scanner
from angerona.modules.yara_scanner import YaraScannerModule


def test_fair_cursor_rotates_past_the_previous_prefix(tmp_path, monkeypatch) -> None:
    root = tmp_path / "Downloads"
    root.mkdir()
    for name in ("a.bin", "b.bin", "c.bin", "d.bin", "e.bin"):
        (root / name).write_bytes(name.encode("ascii"))
    monkeypatch.setattr(yara_scanner, "MAX_FILES_PER_ROOT", 3)

    first = YaraScannerModule._fair_batch(root, "")
    second = YaraScannerModule._fair_batch(root, first.next_cursor)

    assert [path.name for path in first.paths] == ["a.bin", "b.bin", "c.bin"]
    assert [path.name for path in second.paths] == ["d.bin", "e.bin", "a.bin"]
    assert {path.name for path in first.paths + second.paths} == {
        "a.bin", "b.bin", "c.bin", "d.bin", "e.bin",
    }
    assert first.incomplete is True
    assert second.incomplete is True


def test_nested_files_participate_in_one_stable_relative_order(tmp_path, monkeypatch) -> None:
    root = tmp_path / "Downloads"
    (root / "a").mkdir(parents=True)
    (root / "z").mkdir()
    (root / "a" / "2.bin").write_bytes(b"2")
    (root / "a" / "1.bin").write_bytes(b"1")
    (root / "z" / "0.bin").write_bytes(b"0")
    monkeypatch.setattr(yara_scanner, "MAX_FILES_PER_ROOT", 2)

    first = YaraScannerModule._fair_batch(root, "")
    second = YaraScannerModule._fair_batch(root, first.next_cursor)

    relative = lambda path: path.relative_to(root).as_posix()
    assert [relative(path) for path in first.paths] == ["a/1.bin", "a/2.bin"]
    assert [relative(path) for path in second.paths] == ["z/0.bin", "a/1.bin"]


def test_authenticated_cursor_survives_restart_and_tampering_fails_closed(
    tmp_path,
    monkeypatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "bus.key").write_text((b"k" * 32).hex(), encoding="ascii")
    monkeypatch.setattr(yara_scanner, "data_dir", lambda: runtime)

    scanner = YaraScannerModule()
    assert scanner._load_cursor_state() == "new"
    scanner._cursor_state["roots"] = {
        "a" * 64: {"cursor": "z/last.bin", "incomplete_since": 12.0, "wraps": 2}
    }
    assert scanner._save_cursor_state() is True

    restarted = YaraScannerModule()
    assert restarted._load_cursor_state() == "ok"
    assert restarted._cursor_state["roots"]["a" * 64]["cursor"] == "z/last.bin"

    state_path = restarted._cursor_path()
    document = json.loads(state_path.read_text(encoding="utf-8"))
    document["roots"]["a" * 64]["cursor"] = "a/attacker-reset.bin"
    state_path.write_text(json.dumps(document), encoding="utf-8")

    attacked = YaraScannerModule()
    assert attacked._load_cursor_state() == "invalid"
    original = state_path.read_bytes()
    assert attacked._save_cursor_state() is False
    assert state_path.read_bytes() == original


def test_missing_cursor_key_is_explicit_and_never_writes_unsigned_state(
    tmp_path,
    monkeypatch,
) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(yara_scanner, "data_dir", lambda: runtime)
    scanner = YaraScannerModule()

    assert scanner._load_cursor_state() == "key-unavailable"
    assert scanner._save_cursor_state() is False
    assert not scanner._cursor_path().exists()


def test_file_scan_failure_is_counted_instead_of_silently_green(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"safe")

    class _BrokenScanner:
        @staticmethod
        def scan_file(_path):
            raise TimeoutError("bounded scanner timeout")

    scanner = YaraScannerModule()
    assert scanner._scan_file(_BrokenScanner(), sample) == "failed"
    assert "timeout" in scanner.last_error
