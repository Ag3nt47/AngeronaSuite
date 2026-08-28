from __future__ import annotations

import json

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.module_base import BaseModule
from angerona.core.module_contract import (
    CONTRACT_SCHEMA_ID,
    CONTRACT_SCHEMA_VERSION,
    ContractError,
    build_capability_contract,
)
from angerona.core.module_manager import ModuleManager


class _Config:
    module_states: dict[str, bool] = {}

    def save(self) -> None:
        pass


def test_all_builtins_publish_unique_v12_contracts() -> None:
    manager = ModuleManager(EventBus(), _Config(), target_platform="windows")
    manager.discover()

    assert not manager.discovery_errors
    assert len(manager.modules) == 80
    rows = manager.capability_inventory()
    identifiers = {row["capability_id"] for row in rows}
    assert len(identifiers) == len(rows)
    assert all(row["contract_schema"] == CONTRACT_SCHEMA_ID for row in rows)
    assert all(row["contract_schema_version"] == CONTRACT_SCHEMA_VERSION for row in rows)
    assert all(row["implementation_version"] for row in rows)
    assert all(row["operational"]["schema"] == "angerona.module-operational.v12" for row in rows)
    json.dumps(rows, sort_keys=True)


def test_contract_exposes_legacy_gaps_without_inventing_authority() -> None:
    class LegacyModule(BaseModule):
        name = "Legacy test"

        def run(self) -> None:
            return

    contract = build_capability_contract(
        LegacyModule(), capability_id="angerona.test.legacy"
    )
    assert contract.metadata_level == "compatibility-adapter"
    assert contract.maturity == "compatibility"
    assert contract.response_authority == "none"
    assert "permissions" in contract.metadata_gaps
    assert contract.self_test == "readiness-only"


def test_contract_rejects_invalid_identity_version_and_authority() -> None:
    class InvalidModule(BaseModule):
        name = "Invalid"
        version = "twelve"
        response_authority = "shell"

        def run(self) -> None:
            return

    with pytest.raises(ContractError, match="implementation version"):
        build_capability_contract(InvalidModule(), capability_id="angerona.test.invalid")

    InvalidModule.version = "1.0.0"
    with pytest.raises(ContractError, match="response authority"):
        build_capability_contract(InvalidModule(), capability_id="angerona.test.invalid")

    with pytest.raises(ContractError, match="capability_id"):
        build_capability_contract(InvalidModule(), capability_id="../invalid")


def test_operational_snapshot_reports_freshness_loss_and_resource_state() -> None:
    module = BaseModule()
    module._cycle_count = 4
    module._bus_revision = 12
    module._bus_overflow_count = 2
    module.set_throttle_floor(2.0)
    snapshot = module.operational_snapshot()

    assert snapshot["cycle_count"] == 4
    assert snapshot["event_revision"] == 12
    assert snapshot["event_overflow_count"] == 2
    assert snapshot["throttle_floor"] == 2.0
    assert snapshot["thread_alive"] is False
