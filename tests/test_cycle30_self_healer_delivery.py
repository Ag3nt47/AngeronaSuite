from __future__ import annotations

import hashlib
import json
from pathlib import Path

import angerona.modules.self_healer as healer_module
from angerona.core.module_base import sign_crash_snapshot_bundle
from angerona.modules.self_healer import SelfHealer


def _configure(monkeypatch, tmp_path: Path, source_root: Path) -> None:
    monkeypatch.setattr(healer_module, "_data_base", lambda: tmp_path)
    monkeypatch.setattr(
        SelfHealer, "_trusted_source_roots", staticmethod(lambda: (source_root,))
    )
    (tmp_path / "bus.key").write_text((b"k" * 32).hex(), encoding="ascii")


def _snapshot(path: Path, source: Path) -> str:
    document = sign_crash_snapshot_bundle(
        {
            "module": "Fixture",
            "crashed_at": 1.0,
            "error": "RuntimeError",
            "traceback": f'Traceback:\n  File "{source}", line 1, in run\nRuntimeError',
            "memory": {},
            "last_50_events": [],
        },
        key=b"k" * 32,
    )
    body = json.dumps(document).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)
    return hashlib.sha256(body).hexdigest()


def test_prelaunch_snapshot_retries_durably_then_stages_once(
    monkeypatch, tmp_path: Path,
) -> None:
    source_root = tmp_path / "installed" / "angerona"
    source_root.mkdir(parents=True)
    source = source_root / "fixture.py"
    source.write_text("value = 1\n", encoding="utf-8")
    snapshot_id = _snapshot(tmp_path / "snapshots" / "before-launch.json", source)
    _configure(monkeypatch, tmp_path, source_root)

    first = SelfHealer()
    monkeypatch.setattr(first, "_request_fix", lambda *_args: None)
    assert first.process_snapshots_once(tmp_path / "snapshots") == 1
    assert first._retries[snapshot_id] == 1

    restarted = SelfHealer()
    monkeypatch.setattr(restarted, "_request_fix", lambda *_args: "value = 2\n")
    assert restarted.process_snapshots_once(tmp_path / "snapshots") == 1
    assert snapshot_id in restarted._completed
    staged = tmp_path / "staged_patches" / f"fixture_fix_{snapshot_id[:16]}.py"
    assert staged.exists()
    assert restarted.process_snapshots_once(tmp_path / "snapshots") == 0


def test_failed_snapshot_moves_to_authenticated_bounded_dead_letter(
    monkeypatch, tmp_path: Path,
) -> None:
    source_root = tmp_path / "installed" / "angerona"
    source_root.mkdir(parents=True)
    source = source_root / "fixture.py"
    source.write_text("value = 1\n", encoding="utf-8")
    snapshot_id = _snapshot(tmp_path / "snapshots" / "failure.json", source)
    _configure(monkeypatch, tmp_path, source_root)
    healer = SelfHealer()
    monkeypatch.setattr(healer, "_request_fix", lambda *_args: None)

    assert [healer.process_snapshots_once(tmp_path / "snapshots") for _ in range(3)] == [1, 1, 1]
    assert snapshot_id in healer._dead_letters
    assert snapshot_id not in healer._retries
    restarted = SelfHealer()
    monkeypatch.setattr(restarted, "_request_fix", lambda *_args: "value = 2\n")
    assert restarted.process_snapshots_once(tmp_path / "snapshots") == 0


def test_forged_delivery_state_fails_closed(monkeypatch, tmp_path: Path) -> None:
    source_root = tmp_path / "installed" / "angerona"
    source_root.mkdir(parents=True)
    _configure(monkeypatch, tmp_path, source_root)
    state = tmp_path / "diagnostics" / "self_healer_state.json"
    state.parent.mkdir(parents=True)
    state.write_text(
        json.dumps(
            {
                "schema": 1,
                "completed": [["a" * 64, 1.0]],
                "retries": {},
                "dead_letters": {},
                "signature": "0" * 64,
            }
        ),
        encoding="utf-8",
    )

    healer = SelfHealer()
    assert healer.process_snapshots_once(tmp_path / "snapshots") == 0
    assert healer.health == 20
    assert not healer._state_ready


def test_traceback_cannot_select_source_outside_installed_package(
    monkeypatch, tmp_path: Path,
) -> None:
    source_root = tmp_path / "installed" / "angerona"
    source_root.mkdir(parents=True)
    outside = tmp_path / "outside.py"
    outside.write_text("secret = True\n", encoding="utf-8")
    _snapshot(tmp_path / "snapshots" / "outside.json", outside)
    _configure(monkeypatch, tmp_path, source_root)
    called: list[bool] = []
    healer = SelfHealer()
    monkeypatch.setattr(
        healer, "_request_fix", lambda *_args: called.append(True) or "secret = False\n"
    )

    assert healer.process_snapshots_once(tmp_path / "snapshots") == 1
    assert called == []
    assert not list((tmp_path / "staged_patches").glob("*.py"))


def test_unauthenticated_snapshot_never_reaches_model(
    monkeypatch, tmp_path: Path,
) -> None:
    source_root = tmp_path / "installed" / "angerona"
    source_root.mkdir(parents=True)
    source = source_root / "fixture.py"
    source.write_text("value = 1\n", encoding="utf-8")
    snapshot = tmp_path / "snapshots" / "forged.json"
    snapshot.parent.mkdir(parents=True)
    snapshot.write_text(
        json.dumps(
            {
                "module": "Fixture",
                "traceback": f'  File "{source}", line 1, in run',
            }
        ),
        encoding="utf-8",
    )
    _configure(monkeypatch, tmp_path, source_root)
    called: list[bool] = []
    healer = SelfHealer()
    monkeypatch.setattr(
        healer, "_request_fix", lambda *_args: called.append(True) or "value = 2\n"
    )

    assert healer.process_snapshots_once(snapshot.parent) == 1
    assert called == []
    assert list(healer._retries.values()) == [1]
