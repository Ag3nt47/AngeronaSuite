"""Initial startup obeys fresh Chill intent; explicit lifecycle authority stays scoped."""
from __future__ import annotations

from collections import OrderedDict
import threading
from types import MethodType, SimpleNamespace

import pytest

from angerona.core.module_manager import ModuleManager


class Module:
    def __init__(self, name, wait=None):
        self.name = name
        self.status = "stopped"
        self.health = 100
        self._chill_paused = False
        self.starts = 0
        self.notes = []
        self._wait = wait

    def start(self):
        self.starts += 1
        self.status = "running"

    def wait_for_first_cycle(self, **_kwargs):
        return self._wait() if self._wait else True

    def set_health(self, *args):
        self.notes.append(args)

    def emit(self, *args, **kwargs):
        self.notes.append((args, kwargs))


def manager(modules, *, quiet=False):
    owner = SimpleNamespace(
        config=SimpleNamespace(eco_mode=False, runtime_chill_active=quiet),
        modules=OrderedDict((mod.name, mod) for mod in modules),
        _module_control_lock=threading.RLock(), _control_generation=0,
        _runtime_active=False, _shutdown=False, _optional_enabled={},
        _NO_STAGGER=ModuleManager._NO_STAGGER,
        is_enabled=lambda _name: True, _ugcap_allows=lambda _mod: True,
    )
    owner._start_current = MethodType(ModuleManager._start_current, owner)
    owner.start_if_enabled = MethodType(ModuleManager.start_if_enabled, owner)
    return owner


def test_full_initial_queue_rechecks_chill_after_previous_first_cycle():
    first = Module("Inert initial setup")
    deep = Module("YARA Scanner")
    live = Module("Network Monitor")
    owner = manager([first, deep, live])
    first._wait = lambda: setattr(owner.config, "runtime_chill_active", True) or True
    skipped = ModuleManager.start_enabled(owner, min_settle=0)
    assert first.starts == live.starts == 1
    assert deep.starts == 0 and deep._chill_paused
    assert skipped == ["YARA Scanner"]
    assert not deep.notes
    assert owner.is_enabled("YARA Scanner")  # Selection was not changed.


def test_chill_during_first_cycle_is_expected_pause_not_false_timeout():
    deep = Module("YARA Scanner")
    owner = manager([deep])
    deep._wait = lambda: setattr(owner.config, "runtime_chill_active", True) or False
    ModuleManager.start_enabled(owner, min_settle=0)
    assert deep.starts == 1 and not deep.notes


@pytest.mark.parametrize("kind", ["operator Full wake", "hourly maintenance"])
def test_initial_hold_does_not_revoke_explicit_wake_or_maintenance(kind):
    deep = Module("YARA Scanner")
    owner = manager([deep], quiet=True)
    skipped = ModuleManager.start_enabled(owner, min_settle=0)
    assert skipped == [deep.name] and deep.starts == 0
    # Both existing callers have separate admission/epoch checks and use this
    # same method. The fixture proves the manager gate has not widened to block
    # their admitted work; it does not bypass those callers' own checks.
    assert owner.start_if_enabled(deep), kind
    assert deep.starts == 1


@pytest.mark.parametrize("denial", ["generation", "shutdown", "replacement", "disabled", "ugcap"])
def test_original_lifecycle_and_ugcap_denials_remain_authoritative(denial):
    deep = Module("YARA Scanner")
    owner = manager([deep])
    if denial == "generation":
        owner._control_generation = 2
    elif denial == "shutdown":
        owner._shutdown = True
    elif denial == "replacement":
        owner.modules[deep.name] = Module(deep.name)
    elif denial == "disabled":
        owner.is_enabled = lambda _name: False
    else:
        owner._ugcap_allows = lambda _module: False
    assert owner._start_current(deep, 0, initial=True) is False
    assert deep.starts == 0 and not deep._chill_paused


def test_ordinary_first_cycle_failure_still_reports_coverage_gap():
    module = Module("Inert failing collector", wait=lambda: False)
    owner = manager([module])
    ModuleManager.start_enabled(owner, min_settle=0)
    assert module.starts == 1 and len(module.notes) == 2
    assert "startup cycle" in module.notes[0][1]
