from __future__ import annotations

from angerona.core.eventbus import EventBus
from angerona.core.module_manager import ModuleManager
from angerona.modules.cloud_escalation import CloudEscalationModule
from angerona.modules.deception import DeceptionModule
from angerona.modules.forensics import ForensicsModule
from angerona.modules.network_monitor import NetworkMonitorModule
from angerona.modules.process_monitor import ProcessMonitorModule
from angerona.modules.soar import SOARModule


class _Config:
    module_states: dict[str, bool] = {}

    def save(self) -> None:
        pass


def test_previously_missing_module_selftests_are_offline_and_pass() -> None:
    modules = (
        CloudEscalationModule(),
        DeceptionModule(),
        ForensicsModule(),
        NetworkMonitorModule(),
        ProcessMonitorModule(),
        SOARModule(),
    )
    results = {module.name: module.self_test() for module in modules}
    assert all(ok for ok, _detail in results.values()), results


def test_every_builtin_v12_contract_has_a_module_specific_selftest() -> None:
    manager = ModuleManager(EventBus(), _Config(), target_platform="windows")
    manager.discover()
    assert not manager.discovery_errors
    readiness_only = [
        row["name"] for row in manager.capability_inventory()
        if row["self_test"] != "module-specific"
    ]
    assert readiness_only == []
