from __future__ import annotations

from angerona.modules.hardware_crypto import HardwareCrypto


def test_missing_tpm_binding_cannot_report_hardware_rooted_health_100() -> None:
    module = HardwareCrypto()
    module._set_combined_health(
        True,
        "IPC key verified in DPAPI",
        False,
        "sealing routine is an outline",
    )

    snapshot = module.operational_snapshot()
    assert snapshot["health"] == 75
    assert "TPM binding is not active" in str(snapshot["health_note"])
    assert snapshot["health_evidence"]["source_path"].endswith("hardware_crypto.py")


def test_ipc_failure_dominates_hardware_posture() -> None:
    module = HardwareCrypto()
    module._set_combined_health(False, "protected store unreadable", False, "no TPM")
    assert module.health == 40
    assert "protected store unreadable" in module.health_note


def test_full_health_requires_both_protected_store_and_tpm_binding() -> None:
    module = HardwareCrypto()
    module._set_combined_health(True, "DPAPI verified", True, "TPM sealed")
    assert module.health == 100
    assert module.health_evidence is None
