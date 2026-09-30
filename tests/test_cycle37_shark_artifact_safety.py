"""Shark drill artifacts must never overwrite or clean up unrelated files."""

from __future__ import annotations

import os
import hashlib
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.shark.shark_attack import SharkAttackEngine, _file_has_marker
from angerona.modules.intel_sync import (
    BYOVD_DRILL_DRIVER, BYOVD_DRILL_MARKER, is_known_bad_driver,
)
from angerona.core.practice_scope import provenance_for_event


def _engine(tmp_path: Path) -> SharkAttackEngine:
    engine = SharkAttackEngine(tmp_path / "data", documents_dir=tmp_path / "markers")
    engine.run_id = "shark-artifact-safety-test"
    return engine


def test_byovd_step_refuses_preexisting_file(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    engine.documents_dir.mkdir()
    marker = engine.documents_dir / "angerona_byovd_drill.sys"
    marker.write_bytes(b"original operator file")

    engine._step_simulated_byovd((0.0, 0.0))

    assert marker.read_bytes() == b"original operator file"
    assert not engine.steps[-1].ok
    engine.stop_and_clean()
    assert marker.read_bytes() == b"original operator file"


def test_byovd_step_refuses_hardlink_alias(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    engine.documents_dir.mkdir()
    original = tmp_path / "original.bin"
    original.write_bytes(b"hardlink target")
    marker = engine.documents_dir / "angerona_byovd_drill.sys"
    try:
        os.link(original, marker)
    except OSError as exc:
        pytest.skip(f"hardlinks unavailable: {exc}")

    engine._step_simulated_byovd((0.0, 0.0))

    assert original.read_bytes() == b"hardlink target"
    assert marker.read_bytes() == b"hardlink target"
    assert not engine.steps[-1].ok
    engine.stop_and_clean()
    assert marker.exists()


def test_cleanup_keeps_replacement_at_owned_marker_name(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    engine._step_simulated_byovd((0.0, 0.0))
    assert engine.steps[-1].ok
    marker = Path(engine.steps[-1].artifact_paths[0])
    assert marker.name == BYOVD_DRILL_DRIVER
    assert BYOVD_DRILL_MARKER in marker.read_text(encoding="utf-8")
    assert is_known_bad_driver(marker.name)["drill"] is True
    info = marker.stat()
    event = SimpleNamespace(details={
        "path": str(marker),
        "observed_file_identity": {"device": int(info.st_dev), "inode": int(info.st_ino),
                                   "birthtime_ns": int(getattr(info, "st_birthtime_ns", 0) or 0)},
        "observed_content_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
    })
    assert provenance_for_event(event).run_id == engine.run_id
    moved = tmp_path / "moved-original.sys"
    marker.rename(moved)
    marker.write_bytes(b"unrelated replacement")
    replacement_info = marker.stat()
    replacement = SimpleNamespace(details={
        "path": str(marker),
        "observed_file_identity": {"device": int(replacement_info.st_dev), "inode": int(replacement_info.st_ino)},
        "observed_content_sha256": hashlib.sha256(marker.read_bytes()).hexdigest(),
    })
    assert provenance_for_event(replacement) is None
    assert provenance_for_event(event).run_id == engine.run_id

    engine.stop_and_clean()

    assert marker.read_bytes() == b"unrelated replacement"
    assert moved.exists()


def test_moved_marker_revokes_practice_provenance_at_reused_name(
    tmp_path: Path,
) -> None:
    engine = _engine(tmp_path)
    engine.documents_dir.mkdir()
    marker = engine.documents_dir / "moving-marker.txt"
    moved = tmp_path / "moved-marker.txt"

    def write_and_move(descriptor: int) -> None:
        os.write(descriptor, b"inert drill marker")
        try:
            marker.rename(moved)
        except OSError as exc:
            pytest.skip(f"open-file rename unavailable: {exc}")

    engine._create_artifact(marker, write_and_move)
    assert moved.exists() and not marker.exists()
    marker.write_bytes(b"unrelated replacement")
    event = SimpleNamespace(details={"artifact_path": str(marker)})
    assert provenance_for_event(event) is None
    engine.stop_and_clean()
    assert marker.read_bytes() == b"unrelated replacement"


@pytest.mark.parametrize("variant", ["plain_text", "zipped"])
def test_initial_access_variants_keep_exact_content_and_clean_owned_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str,
) -> None:
    engine = _engine(tmp_path)
    monkeypatch.setattr("angerona.shark.shark_attack.random.choice", lambda _values: variant)
    engine._step_initial_access((0.0, 0.0))
    assert engine.steps[-1].ok
    marker = Path(engine.steps[-1].artifact_paths[0])
    assert marker.exists() and _file_has_marker(marker)

    engine.stop_and_clean()
    assert marker.exists() is (os.name != "nt")


def test_double_persistence_markers_clean_exact_owned_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(tmp_path)
    monkeypatch.setattr(
        "angerona.shark.shark_attack.random.choice",
        lambda _values: "double_marker",
    )
    engine._step_simulated_persistence((0.0, 0.0))
    assert engine.steps[-1].ok
    markers = [Path(value) for value in engine.steps[-1].artifact_paths]
    assert len(markers) == 2 and all(path.exists() for path in markers)

    engine.stop_and_clean()
    assert all(path.exists() is (os.name != "nt") for path in markers)


def test_stale_sweep_keeps_unowned_lookalike(tmp_path: Path) -> None:
    engine = _engine(tmp_path)
    engine.documents_dir.mkdir()
    marker = engine.documents_dir / "angerona_byovd_drill.sys"
    marker.write_text("ANGERONA-BYOVD-DRILL-BENIGN-MARKER", encoding="ascii")
    old = time.time() - 3600
    os.utime(marker, (old, old))

    engine._cleanup_stale_artifacts()

    assert marker.exists()


def test_marker_probe_refuses_oversized_content(tmp_path: Path) -> None:
    marker = tmp_path / "old-marker.txt"
    marker.write_bytes(b"ANGERONA-BYOVD-DRILL-BENIGN-MARKER" + b"A" * 1024 * 1024)
    assert not _file_has_marker(marker)


def test_stale_survey_caps_directory_entries_and_content_probes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(tmp_path)
    engine.documents_dir.mkdir()
    old = time.time() - 3600
    for index in range(100):
        marker = engine.documents_dir / f"_shark_persistence_marker_{index:04d}.txt"
        marker.write_bytes(b"marker-looking fixture")
        os.utime(marker, (old, old))
    probed: list[Path] = []
    monkeypatch.setattr(
        "angerona.shark.shark_attack._file_has_marker",
        lambda path: probed.append(path) or False,
    )

    engine._cleanup_stale_artifacts()

    assert len(probed) <= engine._CLEANUP_MAX_SCAN_ENTRIES
    assert len(list(engine.documents_dir.iterdir())) == 100


@pytest.mark.skipif(os.name != "nt", reason="exact-object noise cleanup is Windows-only")
def test_noise_scratch_refuses_existing_directory_without_touching_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(tmp_path)
    engine.data_dir.mkdir()
    scratch = engine.data_dir / ("_shark_noise_scratch_" + "a" * 32)
    scratch.mkdir()
    existing = scratch / "chunk_0.tmp"
    existing.write_bytes(b"operator data")
    monkeypatch.setattr(
        "angerona.shark.shark_attack.random.choice",
        lambda _values: "many_small_files",
    )
    monkeypatch.setattr(
        "angerona.shark.shark_attack.uuid.uuid4",
        lambda: SimpleNamespace(hex="a" * 32),
    )

    engine._step_noise_injection((0.0, 0.0))

    assert not engine.steps[-1].ok
    assert existing.read_bytes() == b"operator data"
    engine.stop_and_clean()
    assert existing.read_bytes() == b"operator data"


@pytest.mark.skipif(os.name != "nt", reason="exact-object noise cleanup is Windows-only")
def test_noise_scratch_cleans_only_its_200_new_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(tmp_path)
    engine.data_dir.mkdir()
    monkeypatch.setattr(
        "angerona.shark.shark_attack.random.choice",
        lambda _values: "many_small_files",
    )

    engine._step_noise_injection((0.0, 0.0))

    assert engine.steps[-1].ok
    assert not list(engine.data_dir.glob("_shark_noise_scratch_*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX cannot unlink by held file identity")
def test_posix_cleanup_never_moves_a_raced_foreign_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(tmp_path)
    engine._step_simulated_byovd((0.0, 0.0))
    assert engine.steps[-1].ok
    marker = Path(engine.steps[-1].artifact_paths[0])
    moved = tmp_path / "original.sys"
    marker.rename(moved)
    marker.write_bytes(b"foreign replacement")
    def reject_rename(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("cleanup must never move a pathname on POSIX")

    monkeypatch.setattr("angerona.shark.shark_attack.os.rename", reject_rename)
    engine.stop_and_clean()

    assert marker.read_bytes() == b"foreign replacement"
    assert moved.exists()
    assert not list(marker.parent.glob("._angerona_shark_custody_*"))


@pytest.mark.skipif(os.name == "nt", reason="POSIX-only safe noise fallback")
def test_posix_noise_churn_falls_back_to_cpu_without_scratch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = _engine(tmp_path)
    engine.data_dir.mkdir()
    monkeypatch.setattr(
        "angerona.shark.shark_attack.random.choice",
        lambda _values: "many_small_files",
    )
    engine._step_noise_injection((0.0, 0.0))
    assert engine.steps[-1].ok
    assert not list(engine.data_dir.glob("_shark_noise_scratch_*"))
