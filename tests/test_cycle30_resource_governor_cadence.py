from __future__ import annotations

from types import SimpleNamespace

from angerona.core.module_base import BaseModule
from angerona.modules import resource_governor as governor_module
from angerona.modules.resource_governor import ResourceGovernor


class _Sensor(BaseModule):
    name = "Real-time Sensor"
    category = "Detection"

    def run(self) -> None:
        return


class _Analytical(BaseModule):
    name = "Bounded Analytical Worker"
    category = "Reporting"
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 2.0

    def run(self) -> None:
        return


class _OverrideAnalytical(_Analytical):
    adaptive_throttle_allowed = True
    adaptive_throttle_max = 2.0

    def set_throttle(self, multiplier: float) -> None:
        self._throttle = 8.0
        raise RuntimeError("extension override must not own governor authority")


def _manager(*modules: BaseModule, external: set[str] | None = None):
    external = external or set()
    inventory = {module.name: module for module in modules}
    trust = {
        name: {
            "origin": "external" if name in external else "builtin",
            "trust": "signed-extension" if name in external else "release",
        }
        for name in inventory
    }
    return SimpleNamespace(modules=inventory, module_trust=trust)


def test_only_release_type_opt_in_workers_receive_bounded_throttle() -> None:
    sensor = _Sensor()
    analytical = _Analytical()
    external = _Analytical()
    external.name = "External Analytical Worker"
    override = _OverrideAnalytical()
    override.name = "Override Analytical Worker"
    for module in (sensor, analytical, external, override):
        module.status = "running"
    governor = ResourceGovernor()
    governor.bind_manager(
        _manager(sensor, analytical, external, override, external={external.name})
    )

    applied, failures = governor._apply(8.0)

    assert applied == 2
    assert failures == ()
    assert sensor._throttle == 1.0
    assert analytical._throttle == 2.0
    assert external._throttle == 1.0
    assert override._throttle == 2.0


def test_level_one_reconciliation_clears_a_stale_governor_lease() -> None:
    analytical = _Analytical()
    analytical.status = "running"
    analytical._throttle = 8.0
    governor = ResourceGovernor()
    governor.bind_manager(_manager(analytical))

    applied, failures = governor._apply(1.0)

    assert applied == 1
    assert failures == ()
    assert analytical._throttle == 1.0


def test_generation_exit_relinquishes_owned_cadence(monkeypatch) -> None:
    analytical = _Analytical()
    analytical.status = "running"
    analytical._throttle = 2.0
    governor = ResourceGovernor()
    governor.bind_manager(_manager(analytical))
    governor._level = 2.0
    governor.stop()

    process = SimpleNamespace(cpu_percent=lambda _interval: 0.0)
    monkeypatch.setattr(
        governor_module,
        "psutil",
        SimpleNamespace(Process=lambda: process, cpu_count=lambda: 4),
    )

    governor.run()

    assert governor._level == 1.0
    assert analytical._throttle == 1.0
