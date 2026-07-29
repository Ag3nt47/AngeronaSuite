import os

import pytest

from angerona.core.atomic_io import replace_with_retry


def test_atomic_replace_retries_short_sharing_lock(tmp_path):
    source = tmp_path / "new.tmp"
    destination = tmp_path / "state.json"
    source.write_text("new", encoding="utf-8")
    destination.write_text("old", encoding="utf-8")
    calls = []

    def transient(src, dst):
        calls.append((src, dst))
        if len(calls) < 3:
            raise PermissionError("scanner is inspecting the file")
        os.replace(src, dst)

    delays = []
    replace_with_retry(
        source, destination, replace=transient, sleeper=delays.append,
    )
    assert destination.read_text(encoding="utf-8") == "new"
    assert len(calls) == 3
    assert delays == [0.015, 0.03]


def test_atomic_replace_fails_bounded_and_does_not_hide_other_errors(tmp_path):
    source = tmp_path / "new.tmp"
    destination = tmp_path / "state.json"
    source.write_text("new", encoding="utf-8")

    with pytest.raises(PermissionError):
        replace_with_retry(
            source, destination, attempts=2,
            replace=lambda _src, _dst: (_ for _ in ()).throw(PermissionError()),
            sleeper=lambda _seconds: None,
        )
    with pytest.raises(FileNotFoundError):
        replace_with_retry(
            source, destination,
            replace=lambda _src, _dst: (_ for _ in ()).throw(FileNotFoundError()),
            sleeper=lambda _seconds: None,
        )
