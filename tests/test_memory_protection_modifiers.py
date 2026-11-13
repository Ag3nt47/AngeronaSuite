"""Synthetic WinNT protection metadata; never query, allocate or inspect a real process."""
from __future__ import annotations

from copy import deepcopy

import pytest

from angerona.core.eventbus import Severity
from angerona.core.spyware_sensors import MemoryProcessIdentity, memory_identity_receipt
from angerona.modules import mem_inject_scanner as memory


# These are metadata controls, not native allocation requests. Windows restricts
# some modifier/base combinations and combinations of the modifiers themselves.
_MODIFIERS = [
    pytest.param(0, id="plain"),
    pytest.param(0x100, id="guard"),
    pytest.param(0x200, id="nocache"),
    pytest.param(0x400, id="writecombine"),
    pytest.param(0x40000000, id="cfg"),
]
_BASES = [
    pytest.param(0x40, id="execute-readwrite"),
    pytest.param(0x80, id="execute-writecopy"),
]
_NOW = 1_700_000_000.0
_BIRTH_TICKS = 116444736000000000 + int((_NOW - 100) * 10_000_000)


class _NoNative:
    def __getattr__(self, name):
        pytest.fail("Inert modifier fixture must not call native API: " + name)


@pytest.fixture
def scanner(monkeypatch):
    module = memory.MemInjectScannerModule()
    module._k32 = _NoNative()
    emissions = []
    monkeypatch.setattr(module, "_enrich_process", lambda _pid: {})
    monkeypatch.setattr(module, "emit", lambda message, severity, **details:
                        emissions.append((message, severity, details)))
    monkeypatch.setattr(memory.time, "time", lambda: _NOW)
    return module, emissions


def _receipt(pid=101):
    identity = MemoryProcessIdentity(pid, _BIRTH_TICKS, 0)
    return memory_identity_receipt(
        source="memory.windows.inject_scanner", request_id="a" * 32, pid=pid,
        expected_create_time=None, before=identity, after=identity,
        started_at=_NOW, finished_at=_NOW, handle_closed=True,
    )


@pytest.mark.parametrize("base", _BASES)
@pytest.mark.parametrize("modifier", _MODIFIERS)
def test_committed_private_executable_writable_base_is_found_with_modifiers(base, modifier):
    assert memory._is_suspicious_region(
        memory.MEM_COMMIT, memory.MEM_PRIVATE, base | modifier, memory._MIN_REGION_BYTES,
    )


@pytest.mark.parametrize("base", [
    pytest.param(0, id="no-base"),
    pytest.param(0x01, id="noaccess"),
    pytest.param(0x04, id="write-no-execute"),
    pytest.param(0x20, id="execute-no-write"),
    pytest.param(0xC0, id="invalid-combined-access-values"),
])
@pytest.mark.parametrize("modifier", _MODIFIERS)
def test_high_modifier_bits_do_not_create_an_executable_writable_base(base, modifier):
    assert not memory._is_suspicious_region(
        memory.MEM_COMMIT, memory.MEM_PRIVATE, base | modifier, memory._MIN_REGION_BYTES,
    )


@pytest.mark.parametrize("state,region_type,size", [
    pytest.param(0x2000, memory.MEM_PRIVATE, 4096, id="reserved"),
    pytest.param(0, memory.MEM_PRIVATE, 4096, id="uncommitted"),
    pytest.param(memory.MEM_COMMIT, 0x40000, 4096, id="mapped"),
    pytest.param(memory.MEM_COMMIT, 0x1000000, 4096, id="image"),
    pytest.param(memory.MEM_COMMIT, memory.MEM_PRIVATE, 4095, id="below-minimum"),
])
def test_modifiers_do_not_bypass_commit_private_or_size_requirements(state, region_type, size):
    assert not memory._is_suspicious_region(state, region_type, 0x40000140, size)


@pytest.mark.parametrize("base", _BASES)
@pytest.mark.parametrize("modifier", _MODIFIERS)
def test_alert_label_prediction_and_raw_protection_keep_the_same_base(scanner, base, modifier):
    module, emissions = scanner
    raw = base | modifier
    regions = [(0x1000, 8192, raw)]
    module._alert(101, "inert.exe", regions, (), memory_identity=_receipt())
    assert len(emissions) == 1
    message, severity, details = emissions[0]
    name = "PAGE_EXECUTE_READWRITE" if base == 0x40 else "PAGE_EXECUTE_WRITECOPY"
    assert details["protection"] == name and details["protection_raw"] == raw
    assert "protect=" + name in message
    assert severity == Severity.MEDIUM and details["active_attack"] is False
    assert details["disposition"] == "observation" and "response_contract" not in details
    assert details["response_eligible"] is True  # Existing exact identity receipt, never modifier authority.
    assert ("PAGE_EXECUTE_WRITECOPY" in details["predicted_technique"]) is (base == 0x80)
    assert regions == [(0x1000, 8192, raw)]
    assert module._reported_regions[(101, _BIRTH_TICKS)].regions == frozenset(regions)


def test_modifier_only_transitions_and_returns_report_without_collapsing_raw_repeat_identity(scanner):
    module, emissions = scanner
    first = [(0x1000, 8192, 0x140)]
    changed = [(0x1000, 8192, 0x40000040)]
    receipt = _receipt()
    module._alert(101, "inert.exe", first, (), memory_identity=receipt)
    original = deepcopy(emissions[0])
    module._alert(101, "inert.exe", first, (), memory_identity=receipt)
    assert len(emissions) == 1 and module._repeat_stats["suppressed"] == 1
    module._alert(101, "inert.exe", changed, (), memory_identity=receipt)
    module._alert(101, "inert.exe", first, (), memory_identity=receipt)
    assert len(emissions) == 3
    assert [row[2]["protection_raw"] for row in emissions] == [0x140, 0x40000040, 0x140]
    assert emissions[1][2]["repeat_suppressed"] == 1
    assert all(row[2]["protection"] == "PAGE_EXECUTE_READWRITE" for row in emissions)
    assert emissions[0] == original and first == [(0x1000, 8192, 0x140)]
    assert changed == [(0x1000, 8192, 0x40000040)]
    assert module._reported_regions[(101, _BIRTH_TICKS)].regions == frozenset(first)


@pytest.mark.parametrize("bound", [False, True])
def test_modifiers_do_not_grant_process_identity_or_response_authority(scanner, bound):
    module, emissions = scanner
    module._alert(101, "inert.exe", [(0x1000, 8192, 0x40000140)], (),
                  memory_identity=_receipt() if bound else None)
    _message, severity, details = emissions[0]
    assert severity == Severity.MEDIUM and details["active_attack"] is False
    assert details["detector_policy"] == "rwx-memory-indicator-alert-only"
    assert details["response_eligible"] is bound and "response_contract" not in details
    assert details.get("response_authorized") is not True
    assert details["memory_identity_status"] == ("bound" if bound else "unavailable")


def test_stopped_selftest_reports_offline_modifier_controls_without_native_work(scanner):
    module, emissions = scanner
    assert module.status == "stopped"
    ok, detail = module.self_test()
    assert ok is True and "modifier controls passed" in detail
    assert "does not establish live traversal coverage or injection efficacy" in detail
    assert "Live native memory queries were not exercised" in detail
    assert not emissions and not module._reported_regions


def test_selftest_rejects_the_old_exact_full_protection_comparison(scanner, monkeypatch):
    module, emissions = scanner
    current_classifier = memory._is_suspicious_region

    def exact_only(state, region_type, protection, size):
        return (protection in {0x40, 0x80}
                and current_classifier(state, region_type, protection, size))

    monkeypatch.setattr(memory, "_is_suspicious_region", exact_only)
    ok, detail = module.self_test()
    assert ok is False and "sample failed base/modifier classification" in detail
    assert not emissions and not module._reported_regions
