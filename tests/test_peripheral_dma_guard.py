from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.peripheral_posture import (
    POSTURE_SCHEMA,
    PeripheralPostureRejected,
    PeripheralPostureSnapshot,
    assess_peripheral_posture,
    observe_system_peripheral_posture,
    snapshot_from_mapping,
)
import angerona.core.peripheral_posture as peripheral_posture
from angerona.modules.peripheral_dma_guard import PeripheralDMAGuardModule


NOW = 1_800_000_000.0


def test_windows_probe_uses_only_the_trusted_powershell_path(
    tmp_path: Path, monkeypatch,
):
    trusted = tmp_path / "trusted-powershell.exe"
    trusted.write_bytes(b"test fixture")
    commands: list[list[str]] = []

    monkeypatch.setattr(peripheral_posture.os, "name", "nt")
    monkeypatch.setattr(
        "angerona.core.privilege.trusted_powershell_path", lambda: trusted
    )

    def fake_run_hidden(command, **_kwargs):
        commands.append(list(command))
        return SimpleNamespace(
            returncode=0,
            stdout='{"pnp_complete":false}',
        )

    monkeypatch.setattr("angerona.core.win.run_hidden", fake_run_hidden)

    assert peripheral_posture._windows_probe() == {"pnp_complete": False}
    assert commands and commands[0][0] == str(trusted.resolve(strict=True))
    assert commands[0][0].casefold() != "powershell.exe"


def snapshot(**overrides) -> PeripheralPostureSnapshot:
    values = {
        "schema": POSTURE_SCHEMA,
        "platform": "windows",
        "kernel_dma_protection": "enabled",
        "iommu": "not-applicable",
        "thunderbolt": "absent",
        "thunderbolt_authorization": "not-present",
        "usb4": "absent",
        "removable_storage": "absent",
        "removable_storage_control": "blocked",
        "device_install_control": "blocked-unapproved",
        "collection_complete": True,
        "collection_sources": (
            "windows-deviceguard",
            "windows-pnp",
            "windows-removable-policy",
        ),
        "observed_at": NOW,
    }
    values.update(overrides)
    return PeripheralPostureSnapshot(**values)


def test_complete_protected_posture_has_no_policy_risk_but_no_firmware_claim():
    result = assess_peripheral_posture(snapshot())
    details = result.event_details(snapshot())

    assert result.state == "peripheral-posture-observed"
    assert result.health == 100
    assert result.risks == ()
    assert result.unknown == ()
    assert result.response_authorized is False
    assert result.malicious_firmware_protection_claimed is False
    assert details["device_control_performed"] is False
    assert details["malicious_firmware_protection_claimed"] is False
    assert details["firmware_and_kernel_tampering_out_of_scope"] is True


def test_external_bus_without_dma_isolation_is_critical():
    exposed = snapshot(
        kernel_dma_protection="disabled",
        thunderbolt="present",
        thunderbolt_authorization="open",
        usb4="present",
        removable_storage="present",
        removable_storage_control="allowed",
        device_install_control="allowed",
    )

    result = assess_peripheral_posture(exposed)

    assert result.state == "dma-exposure-detected"
    assert result.severity == "critical"
    assert {
        "kernel-dma-protection-disabled",
        "thunderbolt-open-authorization",
        "thunderbolt-present-without-kernel-dma-protection",
        "usb4-present-without-dma-isolation",
        "removable-storage-unrestricted",
        "unapproved-device-installation-allowed",
    }.issubset(result.risks)


def test_unknown_evidence_is_never_inferred_safe():
    unknown = PeripheralPostureSnapshot.unknown("macos", NOW)

    result = assess_peripheral_posture(unknown)

    assert result.state == "peripheral-posture-unknown"
    assert result.severity == "medium"
    assert result.health < 100
    assert "kernel_dma_protection" in result.unknown
    assert "collection_complete" in result.unknown


def test_snapshot_schema_is_strict_and_bounded():
    document = asdict(snapshot())
    document["collection_sources"] = list(document["collection_sources"])
    assert snapshot_from_mapping(document) == snapshot()

    document["surprise"] = "ambient-authority"
    with pytest.raises(PeripheralPostureRejected, match="shape"):
        snapshot_from_mapping(document)
    with pytest.raises(PeripheralPostureRejected):
        snapshot(collection_sources=("unknown-source",))
    with pytest.raises(PeripheralPostureRejected):
        snapshot(thunderbolt="absent", thunderbolt_authorization="open")


def test_windows_probe_reports_pnp_and_policy_but_keeps_dma_unknown():
    observed = observe_system_peripheral_posture(
        platform_name="windows",
        windows_probe=lambda: {
            "pnp_complete": True,
            "policy_complete": True,
            "dma_complete": False,
            "thunderbolt_complete": True,
            "usb4_complete": True,
            "removable_complete": True,
            "thunderbolt_present": True,
            "usb4_present": True,
            "removable_present": True,
            "removable_control": "blocked",
            "device_install_control": "blocked-unapproved",
        },
        clock=lambda: NOW,
    )

    assert observed.platform == "windows"
    assert observed.thunderbolt == "present"
    assert observed.usb4 == "present"
    assert observed.removable_storage == "present"
    assert observed.kernel_dma_protection == "unknown"
    assert observed.iommu == "unknown"
    assert observed.collection_complete is False
    assert "kernel_dma_protection" in assess_peripheral_posture(observed).unknown


def test_injected_windows_dma_sensor_can_report_explicit_enabled_or_disabled():
    observed = observe_system_peripheral_posture(
        platform_name="windows",
        windows_probe=lambda: {
            "pnp_complete": True,
            "policy_complete": True,
            "dma_complete": True,
            "kernel_dma_protection": True,
            "iommu": True,
            "thunderbolt_complete": True,
            "usb4_complete": True,
            "removable_complete": True,
            "thunderbolt_present": False,
            "usb4_present": False,
            "removable_present": False,
            "removable_control": "blocked",
            "device_install_control": "blocked-unapproved",
        },
        clock=lambda: NOW,
    )

    assert observed.kernel_dma_protection == "enabled"
    assert observed.iommu == "enabled"
    assert observed.collection_complete is True
    assert "windows-deviceguard" in observed.collection_sources


def test_incomplete_windows_probe_falls_to_unknown_not_absent():
    observed = observe_system_peripheral_posture(
        platform_name="windows",
        windows_probe=lambda: {
            "pnp_complete": False,
            "policy_complete": False,
            "thunderbolt_complete": False,
            "usb4_complete": False,
            "removable_complete": False,
            "thunderbolt_present": False,
            "usb4_present": False,
            "removable_present": False,
        },
        clock=lambda: NOW,
    )

    assert observed.thunderbolt == "unknown"
    assert observed.usb4 == "unknown"
    assert observed.removable_storage == "unknown"
    assert observed.collection_complete is False


def test_windows_name_heuristic_cannot_claim_a_negative_topology():
    observed = observe_system_peripheral_posture(
        platform_name="windows",
        windows_probe=lambda: {
            "pnp_complete": True,
            "policy_complete": True,
            "dma_complete": False,
            "thunderbolt_complete": False,
            "usb4_complete": False,
            "removable_complete": True,
            "thunderbolt_present": False,
            "usb4_present": False,
            "removable_present": False,
            "removable_control": "unknown",
            "device_install_control": "unknown",
        },
        clock=lambda: NOW,
    )

    assert observed.thunderbolt == "unknown"
    assert observed.usb4 == "unknown"
    assert observed.removable_storage == "absent"


def test_linux_sysfs_observation_is_bounded_read_only_and_detects_open_bus(
    tmp_path: Path,
):
    iommu = tmp_path / "kernel" / "iommu_groups" / "0"
    iommu.mkdir(parents=True)
    domain = tmp_path / "bus" / "thunderbolt" / "devices" / "domain0"
    domain.mkdir(parents=True)
    (domain / "security").write_text("none\n", encoding="utf-8")
    block = tmp_path / "block" / "sda"
    block.mkdir(parents=True)
    (block / "removable").write_text("1\n", encoding="utf-8")

    observed = observe_system_peripheral_posture(
        platform_name="linux",
        sys_root=tmp_path,
        clock=lambda: NOW,
    )
    result = assess_peripheral_posture(observed)

    assert observed.kernel_dma_protection == "not-applicable"
    assert observed.iommu == "enabled"
    assert observed.thunderbolt == "present"
    assert observed.thunderbolt_authorization == "open"
    assert observed.removable_storage == "present"
    assert observed.collection_complete is True
    assert "thunderbolt-open-authorization" in result.risks
    assert "removable_storage_control" in result.unknown


def test_missing_linux_sources_remain_unknown(tmp_path: Path):
    observed = observe_system_peripheral_posture(
        platform_name="linux",
        sys_root=tmp_path,
        clock=lambda: NOW,
    )

    assert observed.iommu == "unknown"
    assert observed.thunderbolt == "unknown"
    assert observed.removable_storage == "unknown"
    assert observed.collection_complete is False


def test_bounded_entries_stops_after_first_over_budget_row():
    class SyntheticDirectory:
        def __init__(self):
            self.yielded = 0

        @staticmethod
        def is_dir():
            return True

        def iterdir(self):
            for index in range(100):
                self.yielded += 1
                yield Path(f"row-{index}")

    directory = SyntheticDirectory()
    assert peripheral_posture._bounded_entries(directory, limit=4) is None
    assert directory.yielded == 5


def _make_linux_inventory_roots(tmp_path: Path) -> Path:
    (tmp_path / "kernel" / "iommu_groups").mkdir(parents=True)
    (tmp_path / "bus" / "thunderbolt" / "devices").mkdir(parents=True)
    (tmp_path / "block").mkdir(parents=True)
    return tmp_path / "block"


def _write_linux_thunderbolt_domains(tmp_path: Path, *values: str | None) -> None:
    devices = tmp_path / "bus" / "thunderbolt" / "devices"
    for index, value in enumerate(values):
        domain = devices / f"domain{index}"
        domain.mkdir()
        if value is not None:
            (domain / "security").write_text(f"{value}\n", encoding="utf-8")


def _complete_linux_removable_inventory(block: Path) -> None:
    entry = block / "sda"
    entry.mkdir()
    (entry / "removable").write_text("0\n", encoding="utf-8")


def test_linux_thunderbolt_uses_least_protective_domain_state(tmp_path: Path):
    block = _make_linux_inventory_roots(tmp_path)
    _complete_linux_removable_inventory(block)
    _write_linux_thunderbolt_domains(tmp_path, "secure", "none")

    observed = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )

    assert observed.thunderbolt_authorization == "open"
    assert "linux-thunderbolt" in observed.collection_sources
    assert observed.collection_complete is True


def test_linux_thunderbolt_all_secure_domains_are_complete(tmp_path: Path):
    block = _make_linux_inventory_roots(tmp_path)
    _complete_linux_removable_inventory(block)
    _write_linux_thunderbolt_domains(tmp_path, "secure", "secure")

    observed = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )

    assert observed.thunderbolt_authorization == "secure-connect"
    assert "linux-thunderbolt" in observed.collection_sources
    assert observed.collection_complete is True


def test_linux_thunderbolt_mixed_unreadable_domain_is_unknown_and_incomplete(
    tmp_path: Path,
):
    block = _make_linux_inventory_roots(tmp_path)
    _complete_linux_removable_inventory(block)
    _write_linux_thunderbolt_domains(tmp_path, "secure", None)

    observed = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )

    assert observed.thunderbolt_authorization == "unknown"
    assert "linux-thunderbolt" not in observed.collection_sources
    assert observed.collection_complete is False


def test_linux_thunderbolt_open_survives_unreadable_sibling_but_is_incomplete(
    tmp_path: Path,
):
    block = _make_linux_inventory_roots(tmp_path)
    _complete_linux_removable_inventory(block)
    _write_linux_thunderbolt_domains(tmp_path, None, "none")

    observed = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )

    assert observed.thunderbolt_authorization == "open"
    assert "linux-thunderbolt" not in observed.collection_sources
    assert observed.collection_complete is False


def test_linux_removable_absence_requires_every_stable_valid_zero(tmp_path: Path):
    block = _make_linux_inventory_roots(tmp_path)
    for name in ("sda", "sdb"):
        entry = block / name
        entry.mkdir()
        (entry / "removable").write_text("0\n", encoding="utf-8")

    observed = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )

    assert observed.removable_storage == "absent"
    assert "linux-removable" in observed.collection_sources
    assert observed.collection_complete is True


def test_linux_mixed_zero_and_unreadable_removable_is_unknown(tmp_path: Path):
    block = _make_linux_inventory_roots(tmp_path)
    valid = block / "sda"
    valid.mkdir()
    (valid / "removable").write_text("0\n", encoding="utf-8")
    (block / "sdb").mkdir()  # The enumerated flag is missing.

    observed = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )

    assert observed.removable_storage == "unknown"
    assert "linux-removable" not in observed.collection_sources
    assert observed.collection_complete is False


def test_linux_positive_removable_survives_mixed_unknown_but_is_incomplete(
    tmp_path: Path,
):
    block = _make_linux_inventory_roots(tmp_path)
    present = block / "sda"
    present.mkdir()
    (present / "removable").write_text("1\n", encoding="utf-8")
    invalid = block / "sdb"
    invalid.mkdir()
    (invalid / "removable").write_text("not-a-flag\n", encoding="utf-8")

    observed = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )

    assert observed.removable_storage == "present"
    assert "linux-removable" not in observed.collection_sources
    assert observed.collection_complete is False


def test_linux_empty_or_disappearing_removable_inventory_is_not_complete(
    tmp_path: Path, monkeypatch,
):
    _make_linux_inventory_roots(tmp_path)
    empty = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )
    assert empty.removable_storage == "unknown"
    assert "linux-removable" not in empty.collection_sources
    assert empty.collection_complete is False

    entry = tmp_path / "block" / "sda"
    entry.mkdir()
    flag = entry / "removable"
    flag.write_text("0\n", encoding="utf-8")
    monkeypatch.setattr(
        peripheral_posture,
        "_read_stable_small_text",
        lambda path, _maximum=64: None if path == flag else "0",
    )
    disappeared = observe_system_peripheral_posture(
        platform_name="linux", sys_root=tmp_path, clock=lambda: NOW
    )
    assert disappeared.removable_storage == "unknown"
    assert disappeared.collection_complete is False


def test_macos_injected_inventory_never_infers_dma_or_device_control():
    observed = observe_system_peripheral_posture(
        platform_name="darwin",
        macos_probe=lambda: {
            "complete": True,
            "thunderbolt_present": False,
            "usb4_present": False,
        },
        clock=lambda: NOW,
    )

    assert observed.platform == "macos"
    assert observed.kernel_dma_protection == "not-applicable"
    assert observed.iommu == "unknown"
    assert observed.device_install_control == "unknown"
    assert observed.collection_complete is False


def test_module_emits_observation_only_evidence_and_self_test_passes():
    exposed = snapshot(
        kernel_dma_protection="disabled",
        thunderbolt="present",
        thunderbolt_authorization="open",
        usb4="present",
    )
    module = PeripheralDMAGuardModule(observer=lambda: exposed)
    bus = EventBus()
    module.bind(bus)

    module._tick()
    event = bus.recent(1)[0]

    assert module.health < 100
    assert event.details["observation_only"] is True
    assert event.details["device_control_performed"] is False
    assert event.details["malicious_firmware_protection_claimed"] is False
    assert event.details["response_authorized"] is False
    assert module.self_test()[0] is True


def test_observer_failure_is_unknown_and_never_claims_device_action():
    def broken():
        raise OSError("sensor unavailable")

    module = PeripheralDMAGuardModule(observer=broken)
    bus = EventBus()
    module.bind(bus)
    module._tick()

    event = bus.recent(1)[0]
    assert module.health == 10
    assert event.details["unknown_state"] is True
    assert event.details["device_control_performed"] is False


def test_unsupported_platform_is_rejected_instead_of_guessed():
    with pytest.raises(PeripheralPostureRejected, match="unsupported"):
        observe_system_peripheral_posture(
            platform_name="plan9",
            clock=lambda: NOW,
        )
