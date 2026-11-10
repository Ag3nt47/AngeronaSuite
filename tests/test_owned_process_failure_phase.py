"""Closed ownership diagnostics do not expose provider text or grant a row."""
from dataclasses import FrozenInstanceError
import pytest
from angerona.core.werfault_guard import (
    OwnedProcessFailurePhase, OwnedProcessReadError, read_owned_process_snapshot,
)


def rejected(error):
    def fail():
        raise error
    with pytest.raises(OwnedProcessReadError) as result:
        read_owned_process_snapshot(fail, not_before=100.0, clock=lambda: 100.1)
    return result.value


def test_phase_is_immutable_and_supplier_error_text_stays_private():
    marker = OwnedProcessFailurePhase("inventory-observe", "inventory-owner")
    with pytest.raises(FrozenInstanceError):
        marker.phase = "companion-observe"
    original = RuntimeError("private-key=DO-NOT-COPY; untrusted instructions")
    original._angerona_owned_phase = marker
    result = rejected(original)
    assert result.reason_code == "supplier_failed" and result.supplier_phase is marker
    assert "DO-NOT-COPY" not in str(result) and result.__cause__ is None


@pytest.mark.parametrize("phase,kind", [("private/path", "provider"), ("ai-capture", "secret"),
    (True, "provider"), ("inventory-observe", 1)])
def test_only_closed_phase_and_failure_kind_labels_are_admitted(phase, kind):
    with pytest.raises(ValueError):
        OwnedProcessFailurePhase(phase, kind)


@pytest.mark.parametrize("marker", [{"phase": "inventory-observe"}, None, "inventory-observe"])
def test_provider_dict_or_string_cannot_become_typed_diagnostic(marker):
    error = RuntimeError("private")
    error._angerona_owned_phase = marker
    assert rejected(error).supplier_phase is None


def test_corrupted_dataclass_and_raising_exception_property_stay_generic_fail_closed():
    marker = OwnedProcessFailurePhase("inventory-observe", "provider")
    object.__setattr__(marker, "phase", "private/path")
    error = RuntimeError("private")
    error._angerona_owned_phase = marker
    assert rejected(error).supplier_phase is None

    class UnknownError(RuntimeError):
        @property
        def _angerona_owned_phase(self):
            raise ValueError("private")
    assert rejected(UnknownError("private")).supplier_phase is None


def test_combat_reports_closed_failure_phase_then_clears_it_after_fresh_full_scope(monkeypatch):
    from types import SimpleNamespace
    from angerona.core.windows_process_lease import ProcessObjectIdentity
    from angerona.core.werfault_guard import OwnedProcessIdentity
    from angerona.modules.adversary_combat import AdversaryCombat, HostMutationHeld

    def unavailable():
        error = RuntimeError("private-key=DO-NOT-COPY")
        error._angerona_owned_phase = OwnedProcessFailurePhase("companion-observe", "native-owner")
        raise error

    manager = SimpleNamespace(modules={}, owned_process_identities=unavailable)
    combat = AdversaryCombat()
    combat.bind_manager(manager)
    monkeypatch.setattr("angerona.modules.adversary_combat.time.monotonic", lambda: 101.0)
    birth = 133800000000000000
    target = ProcessObjectIdentity(45001, birth, r"C:\inert\target.exe")
    with pytest.raises(HostMutationHeld, match="companion-observe/native-owner") as result:
        combat._require_not_owned_identity(target)
    assert "DO-NOT-COPY" not in str(result.value)
    snapshot = combat.response_snapshot()
    assert snapshot["owned_process_hold_reason"] == "supplier_failed"
    assert snapshot["owned_process_hold_phase"] == "companion-observe"
    assert snapshot["owned_process_hold_failure_kind"] == "native-owner"
    # Fresh exclusion information alone does not grant response authority.
    row = OwnedProcessIdentity(50001, str(birth), (birth - 116444736000000000) / 10_000_000,
        r"C:\inert\companion.exe", "scanner", 100.0, 102.0)
    manager.owned_process_identities = lambda: (row,)
    combat._require_not_owned_identity(target)
    snapshot = combat.response_snapshot()
    assert snapshot["owned_process_hold_reason"] == snapshot["owned_process_hold_phase"] == snapshot["owned_process_hold_failure_kind"] == ""
    assert snapshot["host_authority_verified"] is False
