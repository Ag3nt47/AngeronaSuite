"""Exercise the real private receipt, time boundary and nonblocking lock."""
from __future__ import annotations

import json
import os

import pytest

from angerona.core import spyware_scan_schedule as schedule
from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.recorder_metadata_custody import open_private_metadata


_NOW = 1_800_000_000
_DUE = _NOW + schedule.AUTOMATIC_SCAN_INTERVAL_SECONDS


def test_first_due_check_does_not_create_anything_and_claim_survives_restart(tmp_path):
    first = schedule.AutomaticSpywareScanSchedule(tmp_path)
    assert not list(tmp_path.iterdir())
    assert first.check(now=_NOW).status == "due"
    assert not list(tmp_path.iterdir())
    assert first.claim(scope="full", now=_NOW) == schedule.AutomaticScanDecision(
        "claimed", "attempt-recorded", _DUE,
    )
    receipt = tmp_path / "spyware-scan-schedule" / "attempt.json"
    original = receipt.read_bytes()
    assert json.loads(original) == {"schema": 1, "scope": "full", "attempted_at": _NOW}

    restarted = schedule.AutomaticSpywareScanSchedule(tmp_path)
    assert restarted.check(now=_NOW - 1) == schedule.AutomaticScanDecision(
        "held", "clock-before-last-attempt", _DUE,
    )
    assert restarted.claim(scope="quick", now=_NOW - 1).status == "held"
    assert restarted.claim(scope="browser", now=_DUE - 1) == schedule.AutomaticScanDecision(
        "cooldown", "recent-attempt", _DUE,
    )
    assert receipt.read_bytes() == original
    assert restarted.check(now=_DUE).status == "due"
    assert restarted.claim(scope="quick", now=_DUE).status == "claimed"
    assert json.loads(receipt.read_bytes()) == {"schema": 1, "scope": "quick", "attempted_at": _DUE}
    assert first.claim(scope="full", now=_DUE).status == "cooldown"


def test_due_status_does_not_bypass_actual_claim_lock(tmp_path):
    first = schedule.AutomaticSpywareScanSchedule(tmp_path)
    assert first.claim(scope="full", now=_NOW).status == "claimed"
    directory = tmp_path / "spyware-scan-schedule"
    receipt = directory / "attempt.json"
    before = receipt.read_bytes()
    competing = schedule.AutomaticSpywareScanSchedule(tmp_path)
    with ExclusiveFileLease(directory / "claim.lock", opener=open_private_metadata):
        assert competing.check(now=_DUE).status == "due"
        assert competing.claim(scope="browser", now=_DUE).status == "held"
        assert receipt.read_bytes() == before
    assert competing.claim(scope="browser", now=_DUE).status == "claimed"


@pytest.mark.parametrize("raw", [
    b"",
    b"x" * 513,
    b'{"schema":true,"scope":"full","attempted_at":1800000000}',
    b'{"schema":1,"scope":"targeted","attempted_at":1800000000}',
    b'{"schema":1,"scope":"full","attempted_at":true}',
    b'{"schema":1,"scope":"full","attempted_at":1800000000,"schema":1}',
    b'{"schema":1,"scope":"full","attempted_at":1800000000,"extra":1}',
])
def test_corrupt_receipt_holds_without_overwriting_or_resetting_cooldown(tmp_path, raw):
    first = schedule.AutomaticSpywareScanSchedule(tmp_path)
    assert first.claim(scope="full", now=_NOW).status == "claimed"
    receipt = tmp_path / "spyware-scan-schedule" / "attempt.json"
    receipt.write_bytes(raw)
    before = receipt.stat()
    restarted = schedule.AutomaticSpywareScanSchedule(tmp_path)
    assert restarted.check(now=_DUE).status == "held"
    assert restarted.claim(scope="browser", now=_DUE).status == "held"
    assert receipt.read_bytes() == raw
    assert receipt.stat().st_ino == before.st_ino


def test_linked_receipt_is_held_without_touching_either_name(tmp_path):
    first = schedule.AutomaticSpywareScanSchedule(tmp_path)
    assert first.claim(scope="full", now=_NOW).status == "claimed"
    receipt = tmp_path / "spyware-scan-schedule" / "attempt.json"
    other = tmp_path / "retained-copy.json"
    os.link(receipt, other)
    before = receipt.read_bytes()
    assert first.check(now=_DUE).status == "held"
    assert first.claim(scope="browser", now=_DUE).status == "held"
    assert receipt.read_bytes() == other.read_bytes() == before
    assert receipt.stat().st_nlink == other.stat().st_nlink == 2


def test_unacknowledged_publication_does_not_grant_a_run_or_repeat_after_restart(tmp_path, monkeypatch):
    actual_write = schedule._atomic_bytes_write

    def lose_acknowledgement(*args, **kwargs):
        actual_write(*args, **kwargs)
        raise OSError("synthetic acknowledgement loss after actual publication")

    with monkeypatch.context() as patch:
        patch.setattr(schedule, "_atomic_bytes_write", lose_acknowledgement)
        assert schedule.AutomaticSpywareScanSchedule(tmp_path).claim(scope="full", now=_NOW).status == "held"
    assert schedule.AutomaticSpywareScanSchedule(tmp_path).claim(scope="full", now=_NOW).status == "cooldown"


def test_malformed_scope_or_clock_cannot_create_state(tmp_path):
    instance = schedule.AutomaticSpywareScanSchedule(tmp_path)
    for value in ("targeted", "FULL", True, 1):
        assert instance.claim(scope=value, now=_NOW).reason == "invalid-scope"
    for value in (0, True, 1.5, 10**20):
        assert instance.check(now=value).reason == "invalid-clock"
        assert instance.claim(scope="full", now=value).reason == "invalid-clock"
    assert not list(tmp_path.iterdir())
