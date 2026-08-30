from __future__ import annotations

from angerona.modules import api_patch_detector
from angerona.modules.api_patch_detector import ApiPatchDetectorModule


class _CompletePE:
    def __init__(self, _data: bytes) -> None:
        return None

    @staticmethod
    def exports() -> dict[str, int]:
        return {}

    @staticmethod
    def prologue(_name: str, _exports: dict[str, int]) -> bytes:
        return b"p" * api_patch_detector._PROLOGUE


def test_disk_failure_is_never_cached_and_next_scan_retries(tmp_path, monkeypatch) -> None:
    system32 = tmp_path / "System32"
    system32.mkdir()
    (system32 / "ntdll.dll").write_bytes(b"not-a-pe")
    monkeypatch.setattr(api_patch_detector, "_system32_dir", lambda: system32.resolve())
    module = ApiPatchDetectorModule()

    assert module._disk_prologues("ntdll.dll") == {}
    assert "ntdll.dll" not in module._disk_cache
    assert "ntdll.dll" in module._baseline_errors

    monkeypatch.setattr(api_patch_detector, "_PE", _CompletePE)
    recovered = module._disk_prologues("ntdll.dll")
    assert set(recovered) == set(api_patch_detector._WATCH["ntdll.dll"])
    assert "ntdll.dll" in module._disk_cache
    assert "ntdll.dll" not in module._baseline_errors


def test_zero_checked_exports_is_explicitly_degraded(monkeypatch) -> None:
    module = ApiPatchDetectorModule()
    monkeypatch.setattr(module, "_disk_prologues", lambda _dll: {})
    monkeypatch.setattr(module, "_mem_prologue", lambda _dll, _fn: None)

    assert module.scan_once() == []
    module._update_coverage_health([])

    expected = sum(len(items) for items in api_patch_detector._WATCH.values())
    assert module._coverage["expected"] == expected
    assert module._coverage["compared"] == 0
    assert len(module._coverage["missing_disk"]) == expected
    assert module.health == 30
    assert "0/" in module.health_note


def test_missing_live_export_can_never_produce_health_100(monkeypatch) -> None:
    module = ApiPatchDetectorModule()
    pristine = b"p" * api_patch_detector._PROLOGUE
    monkeypatch.setattr(
        module,
        "_disk_prologues",
        lambda dll: {name: pristine for name in api_patch_detector._WATCH[dll]},
    )
    first = next(iter(api_patch_detector._WATCH["ntdll.dll"]))
    monkeypatch.setattr(
        module,
        "_mem_prologue",
        lambda dll, fn: None if (dll, fn) == ("ntdll.dll", first) else pristine,
    )

    module.scan_once()
    module._update_coverage_health([])

    assert module.health == 45
    assert module._coverage["missing_memory"] == [f"ntdll.dll!{first}"]


def test_complete_exact_export_set_is_required_for_full_health(monkeypatch) -> None:
    module = ApiPatchDetectorModule()
    pristine = b"p" * api_patch_detector._PROLOGUE
    monkeypatch.setattr(
        module,
        "_disk_prologues",
        lambda dll: {name: pristine for name in api_patch_detector._WATCH[dll]},
    )
    monkeypatch.setattr(module, "_mem_prologue", lambda _dll, _fn: pristine)

    module.scan_once()
    module._update_coverage_health([])

    expected = sum(len(items) for items in api_patch_detector._WATCH.values())
    assert module._coverage["compared"] == expected
    assert module.health == 100
    assert f"all {expected}" in module.health_note


def test_ambient_systemroot_is_not_used_for_baseline_path(monkeypatch) -> None:
    monkeypatch.setenv("SystemRoot", r"C:\attacker-controlled")
    source = api_patch_detector._system32_dir.__code__.co_names

    assert "environ" not in source
    assert "GetSystemDirectoryW" in source
