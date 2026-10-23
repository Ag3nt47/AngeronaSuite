"""Declaration completeness must preserve watchdog and mutation boundaries."""
from __future__ import annotations

import pytest

from angerona.core.eventbus import Event, Severity
from angerona.core.module_base import BaseModule
from angerona.core.module_contract import build_capability_contract
from angerona.core.platforms import availability_for
from angerona.modules.adversary_combat import AdversaryCombat
from angerona.modules.process_monitor import ProcessMonitorModule


@pytest.mark.parametrize("cls", [ProcessMonitorModule, AdversaryCombat])
def test_native_declarations_preserve_existing_runtime_budgets_and_platform(cls):
    module = object.__new__(cls)
    contract = build_capability_contract(
        module, capability_id="angerona.builtin." + cls.__module__.rsplit(".", 1)[-1]
    )
    module._angerona_contract = contract
    assert contract.metadata_level == "native" and contract.metadata_gaps == ()
    # This field feeds the actual lifecycle watchdog, rather than being only
    # descriptive metadata. The declaration must preserve the prior deadline.
    assert BaseModule._watchdog_startup_budget_seconds(module) == 30.0
    assert BaseModule._watchdog_work_budget_seconds(module) == 30.0
    assert contract.resource_budget.throttle_min == 1.0
    assert contract.resource_budget.throttle_max == 8.0
    assert module.adaptive_throttle_allowed is False
    assert module.adaptive_throttle_max == 1.0
    assert availability_for(module, "windows").available is True
    assert availability_for(module, "linux").available is False
    assert availability_for(module, "macos").available is False


def test_native_response_declaration_cannot_authorize_an_uncontracted_event(tmp_path, monkeypatch):
    combat = AdversaryCombat(data_root=tmp_path)
    combat._angerona_contract = build_capability_contract(
        combat, capability_id="angerona.builtin.adversary_combat"
    )
    assert combat._angerona_contract.response_authority == "typed-response"
    monkeypatch.setenv("ANGERONA_ADVERSARY_COMBAT_ENABLED", "1")

    def forbidden(*_args, **_kwargs):
        pytest.fail("a metadata declaration cannot authorize a host mutation")

    for method in ("_block_remote_ip", "_act_on_process", "_quarantine_file",
                   "_isolate_host", "_ensure_honeypots"):
        monkeypatch.setattr(combat, method, forbidden)
    # Explicitly active and critical still lacks the exact response contract.
    combat._handle(Event(
        "Contract Boundary Fixture", "inert uncontracted finding", Severity.CRITICAL,
        details={"active_attack": True},
    ))
    assert combat._response_counts == {"invalid_contract": 1}
    assert not combat.quarantine_root.exists()
    assert not combat.receipt_path.exists()
