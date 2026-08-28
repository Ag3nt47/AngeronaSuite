import pytest

from angerona.core.atomic_io import replace_with_retry


def test_atomic_replace_retries_short_sharing_lock(tmp_path):
    source = tmp_path / "new.tmp"
    destination = tmp_path / "state.json"
    source.write_text("new", encoding="utf-8")
    destination.write_text("old", encoding="utf-8")
    calls = []
    completed = []

    def transient(src, dst):
        calls.append((src, dst))
        if len(calls) < 3:
            raise PermissionError("scanner is inspecting the file")
        # Keep this retry-schedule test deterministic. Calling the real Windows
        # replace here can itself encounter the transient antivirus lock that
        # the product helper is intentionally recovering from, adding a valid
        # fourth attempt and making an exact call-count assertion flaky.
        completed.append((src, dst))

    delays = []
    replace_with_retry(
        source, destination, replace=transient, sleeper=delays.append,
    )
    assert len(calls) == 3
    assert completed == [(source, destination)]
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
