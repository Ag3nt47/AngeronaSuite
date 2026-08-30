from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from angerona.modules import kernel_posture_ledger


def _healthy_snapshot() -> dict:
    return {
        "secure_boot": True,
        "vbs_status": 2,
        "hvci": True,
        "testsigning": False,
        "debug": False,
        "nointegritychecks": False,
        "code_integrity_log": True,
        "driver_count": 1,
        "driver_set_sha256": "a" * 64,
        "driver_collection_status": "complete",
        "driver_namespace_total": 2,
        "driver_enumerated": 2,
        "driver_skipped": 0,
        "driver_truncated": False,
        "driver_collection_errors": [],
        "driver_collected_at": 1000.0,
    }


def test_driver_inventory_partial_or_inconsistent_can_never_score_100() -> None:
    complete = kernel_posture_ledger.assess(_healthy_snapshot())
    assert complete.health == 100

    for mutation in (
        {"driver_collection_status": "partial"},
        {"driver_enumerated": 1},
        {"driver_skipped": 1},
        {"driver_truncated": True},
        {"driver_namespace_total": None},
    ):
        snapshot = _healthy_snapshot()
        snapshot.update(mutation)
        result = kernel_posture_ledger.assess(snapshot)
        assert result.health < 100
        assert any(item.startswith("driver_inventory:") for item in result.unknown)


def test_driver_collection_reports_namespace_truncation_and_skips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = ["OrdinaryService", "DriverA", "Unreadable", "DriverB"]
    values = {
        "OrdinaryService": {"Type": 0x10},
        "DriverA": {"Type": 0x1, "ImagePath": "a.sys", "Start": 1},
        "DriverB": {"Type": 0x2, "ImagePath": "b.sys", "Start": 2},
    }

    class Key:
        def __init__(self, name: str = "root") -> None:
            self.name = name

    def enum_key(_root, index: int) -> str:
        if index == 2:
            raise OSError("registry key denied")
        return names[index]

    def open_key(_root, name=None, *_args):
        return Key(str(name or "root"))

    def query_value(key: Key, name: str):
        if name not in values[key.name]:
            raise OSError("value missing")
        return values[key.name][name], 0

    fake = SimpleNamespace(
        HKEY_LOCAL_MACHINE=object(),
        KEY_READ=1,
        OpenKey=open_key,
        QueryInfoKey=lambda _root: (len(names), 0, 0),
        EnumKey=enum_key,
        QueryValueEx=query_value,
        CloseKey=lambda _key: None,
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    monkeypatch.setattr(kernel_posture_ledger.os, "name", "nt")

    receipt = kernel_posture_ledger._driver_services(limit=3)
    assert receipt.status == "partial"
    assert receipt.namespace_total == 4
    assert receipt.enumerated == 3
    assert receipt.skipped == 1
    assert receipt.truncated is True
    assert [row["name"] for row in receipt.rows] == ["DriverA"]
    assert any("index 2" in error for error in receipt.errors)
    assert any("safety budget" in error for error in receipt.errors)


def test_provider_serializes_exact_collection_receipt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = kernel_posture_ledger.DriverCollectionReceipt(
        rows=({"name": "DriverA", "image": "a.sys", "start": 1},),
        status="partial",
        namespace_total=10,
        enumerated=8,
        skipped=2,
        truncated=True,
        errors=("service index 3 unavailable",),
        collected_at=1234.5,
    )
    monkeypatch.setattr(kernel_posture_ledger, "_driver_services", lambda: receipt)
    monkeypatch.setattr(kernel_posture_ledger, "_secure_boot", lambda: True)
    monkeypatch.setattr(
        kernel_posture_ledger,
        "_device_guard",
        lambda: {"vbs_status": 2, "hvci": True},
    )
    monkeypatch.setattr(
        kernel_posture_ledger,
        "_boot_flags",
        lambda: {"testsigning": False, "debug": False, "nointegritychecks": False},
    )
    monkeypatch.setattr(kernel_posture_ledger, "_code_integrity_log", lambda: True)

    snapshot = kernel_posture_ledger.KernelPostureProvider().snapshot()
    assert snapshot["driver_collection_status"] == "partial"
    assert snapshot["driver_namespace_total"] == 10
    assert snapshot["driver_enumerated"] == 8
    assert snapshot["driver_skipped"] == 2
    assert snapshot["driver_truncated"] is True
    assert snapshot["driver_collection_errors"] == [
        "service index 3 unavailable"
    ]
    assert kernel_posture_ledger.assess(snapshot).health < 100
