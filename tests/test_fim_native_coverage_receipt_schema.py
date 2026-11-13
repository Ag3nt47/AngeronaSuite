"""Native receipt coverage uses the current producer schema and strict totals.

These disposable files exercise real FIM collection. They do not enroll a lease
or confer response authority; the existing native-receipt cohorts cover that.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os

import pytest

from angerona.modules import file_integrity, purple_guard


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


@pytest.fixture
def complete_receipt(tmp_path, monkeypatch):
    watched = tmp_path / "watched"
    watched.mkdir()
    (watched / "inert.txt").write_text("inert coverage fixture", encoding="utf-8")
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(watched)])
    module = file_integrity.FileIntegrityModule()
    result = module._scan()
    assert len(result) == 1
    assert module._last_scan_receipt["complete"] is True
    return copy.deepcopy(result._fim_receipt)


def test_current_fim_scan_has_complete_strict_root_coverage(complete_receipt):
    assert purple_guard._fim_scan_coverage_is_complete(complete_receipt)
    assert complete_receipt["root_coverage"][0]["files_visited"] == 1
    assert complete_receipt["deadline_scope"] == (
        "cooperative checks; individual filesystem I/O may block"
    )


@pytest.mark.parametrize("change", [
    "missing-roots", "roots-not-list", "empty-roots", "missing-covered",
    "incomplete", "false-reason", "deadline-overclaim", "errors", "error-count",
    "root-extra-field", "row-not-dict", "root-relative", "root-incomplete",
    "root-complete-int", "root-reason", "root-blocked", "root-budget",
    "root-budget-int", "negative-files", "bool-files", "float-bytes",
    "covered-mismatch", "duplicate-root", "root-digest", "file-total", "byte-total",
])
def test_inconsistent_or_incomplete_root_coverage_never_qualifies(complete_receipt, change):
    receipt = complete_receipt
    row = receipt["root_coverage"][0]
    if change == "missing-roots":
        receipt.pop("root_coverage")
    elif change == "roots-not-list":
        receipt["root_coverage"] = tuple(receipt["root_coverage"])
    elif change == "empty-roots":
        receipt["root_coverage"] = []
        receipt["covered_roots"] = []
    elif change == "missing-covered":
        receipt.pop("covered_roots")
    elif change == "incomplete":
        receipt["complete"] = False
    elif change == "false-reason":
        receipt["reason"] = "partial"
    elif change == "deadline-overclaim":
        receipt["deadline_scope"] = "all filesystem calls are preemptible"
    elif change == "errors":
        receipt["errors"] = ["collector unavailable"]
    elif change == "error-count":
        receipt["error_count"] = 1
    elif change == "root-extra-field":
        row["response_authorized"] = True
    elif change == "row-not-dict":
        receipt["root_coverage"][0] = "complete"
    elif change == "root-relative":
        row["root"] = "relative"
    elif change == "root-incomplete":
        row["complete"] = False
    elif change == "root-complete-int":
        row["complete"] = 1
    elif change == "root-reason":
        row["reason"] = "not measured"
    elif change == "root-blocked":
        row["blocking_object"] = row["root"]
    elif change == "root-budget":
        row["budget_exhausted"] = True
    elif change == "root-budget-int":
        row["budget_exhausted"] = 0
    elif change == "negative-files":
        row["files_visited"] = -1
    elif change == "bool-files":
        row["files_visited"] = True
    elif change == "float-bytes":
        row["content_bytes_hashed"] = float(row["content_bytes_hashed"])
    elif change == "covered-mismatch":
        receipt["covered_roots"] = [row["root"] + "-different"]
    elif change == "duplicate-root":
        receipt["root_coverage"].append(copy.deepcopy(row))
        receipt["covered_roots"].append(row["root"])
        receipt["files_visited"] *= 2
        receipt["content_bytes_hashed"] *= 2
        receipt["watch_roots_sha256"] = _digest(receipt["covered_roots"])
    elif change == "root-digest":
        receipt["watch_roots_sha256"] = "0" * 64
    elif change == "file-total":
        receipt["files_visited"] += 1
    elif change == "byte-total":
        receipt["content_bytes_hashed"] += 1
    else:
        raise AssertionError(change)
    assert not purple_guard._fim_scan_coverage_is_complete(receipt)


def test_multiple_roots_keep_empty_directory_and_content_totals(tmp_path, monkeypatch):
    empty = tmp_path / "empty"
    first, second = tmp_path / "first", tmp_path / "second"
    for directory in (empty, first, second):
        directory.mkdir()
    first_raw, second_raw = b"inert first root", b"inert second root"
    (first / "first.bin").write_bytes(first_raw)
    (second / "second.bin").write_bytes(second_raw)
    monkeypatch.setattr(file_integrity, "watch_roots",
                        lambda: [str(second), str(empty), str(first)])
    module = file_integrity.FileIntegrityModule()

    result = module._scan()
    receipt = result._fim_receipt

    assert purple_guard._fim_scan_coverage_is_complete(receipt)
    assert len(result) == receipt["files_recorded"] == 2
    assert receipt["files_visited"] == 2
    assert receipt["content_bytes_hashed"] == len(first_raw) + len(second_raw)
    rows = {row["root"]: row for row in receipt["root_coverage"]}
    assert rows[str(empty)]["files_visited"] == 0
    assert rows[str(empty)]["content_bytes_hashed"] == 0
    assert receipt["covered_roots"] == sorted(map(str, (empty, first, second)))


def test_all_empty_roots_are_complete_without_inventing_file_observations(tmp_path, monkeypatch):
    roots = [tmp_path / "empty-one", tmp_path / "empty-two"]
    for directory in roots:
        directory.mkdir()
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: list(map(str, reversed(roots))))
    module = file_integrity.FileIntegrityModule()

    result = module._scan()
    receipt = result._fim_receipt

    assert result == {}
    assert purple_guard._fim_scan_coverage_is_complete(receipt)
    assert receipt["files_recorded"] == receipt["files_visited"] == 0
    assert receipt["content_bytes_hashed"] == 0
    assert receipt["files_hashed"] == receipt["hashes_reused"] == 0
    assert all(row["complete"] is True for row in receipt["root_coverage"])


def test_cached_scan_preserves_complete_roots_with_zero_new_hash_bytes(tmp_path, monkeypatch):
    roots = [tmp_path / "first", tmp_path / "second"]
    for directory in roots:
        directory.mkdir()
        (directory / "inert.bin").write_bytes(b"unchanged cache fixture")
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: list(map(str, roots)))
    module = file_integrity.FileIntegrityModule()
    # Explicit offline mutation-token input makes this cache-accounting test
    # deterministic on filesystems without native USN support. Hashing and
    # object checks remain real; this is not evidence of native token coverage.
    def stable_fixture_identity(path):
        return (*module._file_identity(os.lstat(path)), 37)

    monkeypatch.setattr(module, "_stat", stable_fixture_identity)
    monkeypatch.setattr(module, "_is_high_value", lambda _path: False)
    first = module._scan()
    assert first._fim_receipt["files_hashed"] == 2
    assert first._fim_receipt["content_bytes_hashed"] > 0
    module._evaluate_snapshot(first, adopt_covered=True, emit_changes=False)
    assert module._baseline == first

    second = module._scan()
    receipt = second._fim_receipt

    assert second == first
    assert purple_guard._fim_scan_coverage_is_complete(receipt)
    assert receipt["files_visited"] == receipt["files_recorded"] == 2
    assert receipt["files_hashed"] == 0
    assert receipt["hashes_reused"] == 2
    assert receipt["content_bytes_hashed"] == 0
    assert sum(row["content_bytes_hashed"] for row in receipt["root_coverage"]) == 0


def test_overlapping_roots_preserve_per_root_visits_and_unique_file_count(tmp_path, monkeypatch):
    parent = tmp_path / "parent"
    nested = parent / "nested"
    nested.mkdir(parents=True)
    top_raw, nested_raw = b"inert top-level content", b"inert nested content"
    (parent / "top.bin").write_bytes(top_raw)
    (nested / "nested.bin").write_bytes(nested_raw)
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(nested), str(parent)])
    module = file_integrity.FileIntegrityModule()

    result = module._scan()
    receipt = result._fim_receipt

    assert purple_guard._fim_scan_coverage_is_complete(receipt)
    assert len(result) == receipt["files_recorded"] == 2
    assert receipt["files_visited"] == 3  # Nested object visited in each root.
    assert receipt["content_bytes_hashed"] == len(top_raw) + 2 * len(nested_raw)
    rows = {row["root"]: row for row in receipt["root_coverage"]}
    assert rows[str(parent)]["files_visited"] == 2
    assert rows[str(nested)]["files_visited"] == 1


def test_file_root_is_honestly_incomplete_while_other_directory_is_scanned(tmp_path, monkeypatch):
    file_root = tmp_path / "a-file-root.bin"
    file_root.write_bytes(b"a file is not a directory watch root")
    valid = tmp_path / "z-valid"
    valid.mkdir()
    observed = valid / "inert.bin"
    observed.write_bytes(b"inert valid directory content")
    monkeypatch.setattr(file_integrity, "watch_roots", lambda: [str(file_root), str(valid)])
    module = file_integrity.FileIntegrityModule()

    result = module._scan()
    receipt = result._fim_receipt

    assert set(result) == {str(observed)}
    assert receipt["complete"] is False
    assert not purple_guard._fim_scan_coverage_is_complete(receipt)
    assert receipt["covered_roots"] == [str(valid)]
    rows = {row["root"]: row for row in receipt["root_coverage"]}
    assert rows[str(file_root)]["complete"] is False
    assert "unavailable or unsafe" in rows[str(file_root)]["reason"]
    assert rows[str(valid)]["complete"] is True
    assert rows[str(valid)]["files_visited"] == 1
