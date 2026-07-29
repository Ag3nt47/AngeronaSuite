import json
from pathlib import Path

from angerona.modules.kernel_posture_ledger import (
    GENESIS_HASH,
    KernelBoundaryPostureLedger,
    KernelPostureLedger,
    assess,
)


class _Provider:
    def __init__(self, snapshots):
        self.snapshots = list(snapshots)

    def snapshot(self):
        return self.snapshots.pop(0)


def _healthy(driver_hash="a"):
    return {
        "secure_boot": True,
        "vbs_status": 2,
        "hvci": True,
        "testsigning": False,
        "debug": False,
        "nointegritychecks": False,
        "code_integrity_log": True,
        "driver_count": 200,
        "driver_set_sha256": driver_hash,
    }


def test_assessment_never_calls_unknown_healthy():
    result = assess(
        {
            "secure_boot": None,
            "vbs_status": None,
            "hvci": None,
            "testsigning": None,
            "debug": None,
            "nointegritychecks": None,
            "code_integrity_log": None,
        }
    )
    assert result.health < 100
    assert "secure_boot" in result.unknown
    assert not result.risks


def test_assessment_flags_kernel_boundary_weakening():
    snapshot = _healthy()
    snapshot.update(
        secure_boot=False,
        hvci=False,
        testsigning=True,
        nointegritychecks=True,
    )
    result = assess(snapshot)
    assert result.health <= 40
    assert any("Secure Boot" in risk for risk in result.risks)
    assert any("test-signing" in risk for risk in result.risks)


def test_ledger_is_bounded_and_detects_tampering(tmp_path):
    path = tmp_path / "kernel.jsonl"
    ledger = KernelPostureLedger(path, max_records=8, authority_key=b"k" * 32)
    for index in range(12):
        ledger.append(_healthy(str(index)), ts=index)
    rows = ledger.read()
    assert len(rows) == 8
    assert rows[0]["anchor"] is True
    assert rows[0]["previous_record_sha256"] == GENESIS_HASH
    assert ledger.verify()[0]

    raw = path.read_text(encoding="utf-8").splitlines()
    row = json.loads(raw[-1])
    row["snapshot"]["secure_boot"] = False
    raw[-1] = json.dumps(row)
    path.write_text("\n".join(raw) + "\n", encoding="utf-8")
    assert ledger.verify()[0] is False


def test_ledger_refuses_prefix_deletion_and_corrupt_then_append(tmp_path):
    path = tmp_path / "kernel.jsonl"
    ledger = KernelPostureLedger(path, max_records=8, authority_key=b"k" * 32)
    for index in range(10):
        ledger.append(_healthy(str(index)), ts=index)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    assert ledger.verify()[0] is False
    try:
        ledger.append(_healthy("new"))
    except RuntimeError as exc:
        assert "refusing to overwrite" in str(exc)
    else:
        raise AssertionError("corrupt ledger was silently replaced")


def test_ledger_detects_deletion_after_initialization(tmp_path):
    path = tmp_path / "kernel.jsonl"
    ledger = KernelPostureLedger(path, authority_key=b"k" * 32)
    ledger.append(_healthy())
    path.unlink()
    assert ledger.verify()[0] is False


def test_module_reports_driver_set_drift(tmp_path):
    first = _healthy("one")
    second = _healthy("two")
    module = KernelBoundaryPostureLedger(
        provider=_Provider([first, second]),
        ledger_path=tmp_path / "ledger.jsonl",
        authority_key=b"k" * 32,
    )
    _, result1, changes1 = module.observe_once()
    _, result2, changes2 = module.observe_once()
    assert result1.health == result2.health == 100
    assert changes1 == []
    assert "driver_set_sha256" in changes2
    assert module.self_test()[0]
