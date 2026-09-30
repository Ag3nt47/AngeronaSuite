"""Adversarial history-viewer checks using a real signed report pair."""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest

from angerona.core import report_attest
from angerona.gui import aar_history


def _signed_pair(root: Path, *, name: str = "redteam_aar_20260930_123000.txt",
                 generated: str = "2026-09-30 12:30:00") -> Path:
    root.mkdir(exist_ok=True)
    body = b"SIGNED DRILL: verified containment 2/3\n"
    path = root / name
    path.write_bytes(body)
    metadata = report_attest.attest({
        "run_id": f"cycle37-{name}",
        "report_basename": "redteam_aar",
        "report_kind": "red_team",
        "generated": generated,
        "report_text_sha256": hashlib.sha256(body).hexdigest(),
    })
    path.with_suffix(".json").write_text(json.dumps(metadata), encoding="utf-8")
    return path


@pytest.fixture
def signed_root(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(report_attest, "_load_key", lambda: bytes(range(32)))
    root = tmp_path / "aar_history"
    _signed_pair(root)
    return root


def test_history_accepts_signed_pair_and_rejects_forged_or_swapped_content(signed_root) -> None:
    name = "redteam_aar_20260930_123000.txt"
    assert aar_history.load_verified_history_text(signed_root, name).startswith("SIGNED DRILL:")

    path = signed_root / name
    path.write_text("FORGED VERIFIED SIMULATION CONTAINMENT 37/37\n", encoding="utf-8")
    with pytest.raises(ValueError, match="signed metadata"):
        aar_history.load_verified_history_text(signed_root, name)

    metadata = path.with_suffix(".json")
    payload = json.loads(metadata.read_text(encoding="utf-8"))
    payload["report_text_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    metadata.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="signature"):
        aar_history.load_verified_history_text(signed_root, name)

    payload.pop(report_attest.SIG_FIELD)
    metadata.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="signature"):
        aar_history.load_verified_history_text(signed_root, name)


def test_history_rejects_path_escape_links_and_oversize_files(signed_root, tmp_path, monkeypatch) -> None:
    name = "redteam_aar_20260930_123000.txt"
    with pytest.raises(ValueError, match="name"):
        aar_history.load_verified_history_text(signed_root, "../other.txt")

    text_path = signed_root / name
    text_path.unlink()
    outside = tmp_path / "unrelated-user-document.txt"
    outside.write_text("unrelated", encoding="utf-8")
    os.link(outside, text_path)
    with pytest.raises(ValueError, match="unsafe identity"):
        aar_history.load_verified_history_text(signed_root, name)

    text_path.unlink()
    text_path.write_bytes(b"x" * 513)
    monkeypatch.setattr(aar_history, "_MAX_MEMBER_BYTES", 512)
    with pytest.raises(ValueError, match="unsafe identity"):
        aar_history.load_verified_history_text(signed_root, name)


def test_history_list_has_a_fixed_scan_and_render_budget(signed_root, monkeypatch) -> None:
    (signed_root / "redteam_aar_99999999_999999.txt").write_text(
        "invalid timestamp", encoding="utf-8"
    )
    for minute in range(12):
        _signed_pair(
            signed_root,
            name=f"redteam_aar_20260930_12{minute:02d}00.txt",
            generated=f"2026-09-30 12:{minute:02d}:00",
        )
    monkeypatch.setattr(aar_history, "_MAX_MEMBERS", 4)
    listing = aar_history.list_history(signed_root)
    assert len(listing.rows) == 4
    assert listing.limited
    assert all(name.endswith(".txt") for name, _mtime, _kind in listing.rows)
    monkeypatch.setattr(aar_history, "_MAX_METADATA_CANDIDATES", 2)
    assert len(aar_history.list_history(signed_root).rows) == 2


def test_history_replay_uses_signed_time_and_deduplicates(signed_root) -> None:
    old = signed_root / "redteam_aar_20260930_123000.txt"
    newer = signed_root / "redteam_aar_20990101_000000.txt"
    newer.write_bytes(old.read_bytes())
    newer.with_suffix(".json").write_bytes(old.with_suffix(".json").read_bytes())
    assert aar_history.load_verified_history_text(signed_root, newer.name).startswith("SIGNED DRILL:")
    listing = aar_history.list_history(signed_root)
    assert len(listing.rows) == 1
    assert listing.rows[0][0] == old.name
    assert listing.rows[0][1] == aar_history.datetime(2026, 9, 30, 12, 30).timestamp()


def test_history_accepts_signed_report_when_archive_write_is_delayed(signed_root) -> None:
    delayed = _signed_pair(
        signed_root,
        name="redteam_aar_20260930_123045.txt",
        generated="2026-09-30 12:30:00",
    )
    assert aar_history.load_verified_history_text(signed_root, delayed.name).startswith("SIGNED DRILL:")
    listing = aar_history.list_history(signed_root)
    assert len(listing.rows) == 2
    assert listing.rows[0][1] == listing.rows[1][1]


def test_console_history_only_renders_authenticated_text(signed_root, monkeypatch) -> None:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    os.environ.setdefault("QT_QPA_FONTDIR", str(Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"))
    from PySide6.QtWidgets import QApplication
    from angerona.gui.red_team_console import RedTeamConsole

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(RedTeamConsole, "_history_dir", lambda _self: signed_root)
    dialog = RedTeamConsole(None)

    def wait_for(predicate) -> None:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            app.processEvents()
            if predicate():
                return
            time.sleep(0.01)
        raise AssertionError(f"history UI did not settle: {dialog._hist_view.toPlainText()}")

    try:
        wait_for(lambda: "SIGNED DRILL:" in dialog._hist_view.toPlainText())
        assert dialog._hist_list.currentItem().text().startswith("✓ ")
        path = signed_root / "redteam_aar_20260930_123000.txt"
        path.write_text("FORGED VERIFIED SIMULATION CONTAINMENT 37/37\n", encoding="utf-8")
        dialog._load_history()
        wait_for(lambda: "authenticity could not be verified" in dialog._hist_view.toPlainText())
        assert dialog._hist_list.currentItem().text().startswith("⚠ ")
        assert "FORGED VERIFIED" not in dialog._hist_view.toPlainText()
    finally:
        dialog.close()
        app.processEvents()
