from types import SimpleNamespace

import pytest

from angerona.telemetry import sensors
from angerona.modules import lsass_guard, shadowcopy_guard


def _row(**values):
    return {"pid": 123, "name": "procdump64.exe", "exe": "C:/procdump64.exe",
            "ppid": 321, "cmdline": ["procdump64.exe", "-ma", "lsass.exe"],
            "create_time": 1234.5, **values}


def test_private_legacy_rows_cannot_poison_cached_evidence(monkeypatch):
    import psutil

    monkeypatch.setattr(psutil, "process_iter", lambda _attrs: [SimpleNamespace(info=_row())])
    sensors.process_snapshot(max_age=0)
    first = sensors.list_processes(max_age=60)
    first[0]["pid"] = 999
    first[0]["cmdline"].clear()
    second = sensors.list_processes(max_age=60)
    assert second[0]["pid"] == 123
    assert second[0]["cmdline"] == ["procdump64.exe", "-ma", "lsass.exe"]
    with pytest.raises(TypeError):
        sensors.process_snapshot(max_age=60).processes[0]["pid"] = 999


def test_partial_enumeration_keeps_visible_evidence_and_loss(monkeypatch):
    import psutil

    def rows(_attrs):
        yield SimpleNamespace(info=_row())
        raise PermissionError("fixture denied remaining processes")

    monkeypatch.setattr(psutil, "process_iter", rows)
    receipt = sensors.process_snapshot(max_age=0)
    assert len(receipt.processes) == 1
    assert receipt.enumerated == 1
    assert not receipt.complete and not receipt.enumeration_complete
    assert "denied" in receipt.error


def test_missing_cmdline_and_invalid_birth_are_unknown_not_empty_success(monkeypatch):
    import psutil

    monkeypatch.setattr(psutil, "process_iter", lambda _attrs: [
        SimpleNamespace(info=_row(cmdline=None, create_time=float("nan"))),
        SimpleNamespace(info=_row(pid=456, cmdline=[object()])),
    ])
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.enumeration_complete and not receipt.complete
    assert receipt.unreadable == 2 and receipt.identity_incomplete == 1
    assert len(receipt.processes) == 2
    assert all(item["cmdline"] is None for item in receipt.processes)


def test_psutil_cached_process_with_reused_pid_cannot_mix_generations(monkeypatch):
    import psutil

    monkeypatch.setattr(psutil, "process_iter", lambda _attrs: [SimpleNamespace(
        info=_row(create_time=100.0), is_running=lambda: False,
    )])
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.processes == ()
    assert receipt.enumerated == 1 and receipt.skipped == 1
    assert not receipt.complete and not receipt.enumeration_complete


def test_credential_and_recovery_detectors_share_one_os_inventory(monkeypatch):
    import psutil

    calls = []
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))
    monkeypatch.setattr(psutil, "process_iter", lambda attrs: (
        calls.append(tuple(attrs)) or [SimpleNamespace(info=_row(cmdline=["benign.exe"]))]
    ))
    for module in (lsass_guard.LsassGuardModule(), shadowcopy_guard.ShadowCopyGuardModule()):
        monkeypatch.setattr(module, "sleep", lambda _seconds, target=module: target.stop())
        module.run()
        assert module._last_coverage["readable"] == 1
    assert len(calls) == 1
    assert "create_time" in calls[0] and "ppid" in calls[0]


@pytest.mark.parametrize("provider, factory", [
    (lsass_guard, lsass_guard.LsassGuardModule),
    (shadowcopy_guard, shadowcopy_guard.ShadowCopyGuardModule),
])
def test_partial_inventory_preserves_prior_generation_deduplication(monkeypatch, provider, factory):
    module = factory()
    prior = (777, "10.000000", "prior.exe")
    module._alerted.add(prior)
    monkeypatch.setattr(provider, "process_snapshot", lambda **_kwargs: sensors.ProcessSnapshot(
        (), 1.0, False, 0, 0, error="fixture lost process table", enumeration_complete=False,
    ))
    monkeypatch.setattr(module, "sleep", lambda _seconds: module.stop())
    module.run()
    assert prior in module._alerted
    assert module.health == 60
    assert "lost process table" in module.health_note
    assert module._last_coverage["enumeration_complete"] is False
