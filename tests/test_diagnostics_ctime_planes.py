"""Separate stable named/held ctime planes; no host scan or process action."""
from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import report_attest
from angerona.shark import aar_report as aar


# Synthetic times reproduce the observed Windows relationship without copying
# private host inode/device/timestamp identifiers into a publishable fixture.
_NAMED_CTIME = 10_000_000_000
_HELD_CTIME = 30_000_000_000


def metadata(info, ctime):
    fields = {name: getattr(info, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
    )}
    fields.update(st_mtime_ns=_HELD_CTIME, st_ctime_ns=ctime,
        st_file_attributes=getattr(info, "st_file_attributes", 0))
    return SimpleNamespace(**fields)


def install_planes(path, monkeypatch, *, named_change_at=None, held_change_at=None):
    actual_lstat, actual_fstat = Path.lstat, os.fstat
    counts = {"named": 0, "held": 0}

    def named(candidate, *args, **kwargs):
        info = actual_lstat(candidate, *args, **kwargs)
        if candidate != path:
            return info
        counts["named"] += 1
        changed = named_change_at is not None and counts["named"] >= named_change_at
        return metadata(info, _NAMED_CTIME + int(changed))

    def held(descriptor):
        info = actual_fstat(descriptor)
        counts["held"] += 1
        changed = held_change_at is not None and counts["held"] >= held_change_at
        return metadata(info, _HELD_CTIME + int(changed))

    monkeypatch.setattr(Path, "lstat", named)
    monkeypatch.setattr(os, "fstat", held)
    return counts


def test_different_but_stable_named_and_held_ctime_accept_the_same_actual_file(tmp_path, monkeypatch):
    path = tmp_path / "ordinary.json"
    payload = b"inert ordinary fixture" * 1024
    path.write_bytes(payload)
    counts = install_planes(path, monkeypatch)
    assert aar._read_bounded_report_member(path, len(payload)) == payload
    assert counts == {"named": 3, "held": 2}


@pytest.mark.parametrize("changed_at", [2, 3], ids=["named-opened", "named-after-read"])
def test_changed_named_ctime_is_rejected_even_when_held_ctime_stays_stable(tmp_path, monkeypatch, changed_at):
    path = tmp_path / "ordinary.json"
    path.write_bytes(b"inert same bytes")
    counts = install_planes(path, monkeypatch, named_change_at=changed_at)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)
    assert counts["named"] == changed_at
    assert counts["held"] == (1 if changed_at == 2 else 2)


def test_changed_held_ctime_is_rejected_even_when_named_ctime_stays_stable(tmp_path, monkeypatch):
    path = tmp_path / "ordinary.json"
    path.write_bytes(b"inert same bytes")
    counts = install_planes(path, monkeypatch, held_change_at=2)
    with pytest.raises(ValueError):
        aar._read_bounded_report_member(path, 1024)
    assert counts == {"named": 3, "held": 2}


def test_actual_ordinary_files_pass_explicit_bundle_journal_and_handoff_recheck(tmp_path, monkeypatch):
    # No stat/ctime substitution: this exercises the real host Python/filesystem
    # semantics in Root's isolated gate, using only newly created private files.
    key = b"c" * 32
    key_path = tmp_path / "bus.key"
    key_path.write_text(key.hex(), encoding="ascii")
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    monkeypatch.setattr(report_attest, "_key_path", lambda: key_path)
    row = aar.StepVerdict("Inert ctime fixture", "fixture", "No host action", 100.0, True, category="unmonitored")
    handoff = aar._write_report(tmp_path,
        {"run_id": "ctime-ordinary-fixture", "kind": "shark", "status": "completed"},
        [row], "Inert ordinary ctime fixture")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Explicit recheck used unbounded bytes or install key fallback")

    monkeypatch.setattr(Path, "read_bytes", forbidden)
    monkeypatch.setattr(report_attest, "_load_key", forbidden)
    head, text, report, _head_bytes = aar._read_bound_report_bundle(tmp_path, "shark_aar", verification_key=key)
    assert text == handoff.text_bytes and report == handoff.report_bytes
    assert head["run_id"] == handoff.run_id
    assert aar._load_head_journal(tmp_path / "shark_aar.heads.jsonl", "shark_aar", verification_key=key)
    assert aar.verified_aar_handoff_text(handoff, verification_key=key) == handoff.text
