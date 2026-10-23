from types import SimpleNamespace

import pytest

from angerona.telemetry import sensors
from angerona.modules import lsass_guard, shadowcopy_guard


def _row(**values):
    return {"pid": 123, "name": "procdump64.exe", "exe": "C:/procdump64.exe",
            "ppid": 321, "cmdline": ["procdump64.exe", "-ma", "lsass.exe"],
            "create_time": 1234.5, **values}


def _install_rows(monkeypatch, rows, *, after=None, iterator=None):
    """Supply fresh-object reads independently of the PID-only iterator."""
    import psutil
    by_pid = {row["pid"]: row for row in rows}
    reads, enumerations = [], []

    class Process:
        def __init__(self, pid):
            self.pid = pid

        def as_dict(self, *, attrs, ad_value):
            reads.append(tuple(attrs))
            source = after if after is not None and len(attrs) == 3 else by_pid
            return {field: source[self.pid].get(field) for field in attrs}

    def process_iter():
        enumerations.append(True)
        return iterator() if iterator is not None else iter(SimpleNamespace(pid=row["pid"]) for row in rows)

    monkeypatch.setattr(psutil, "process_iter", process_iter)
    monkeypatch.setattr(psutil, "Process", Process)
    monkeypatch.setattr(psutil, "_ppid_map", lambda: {row["pid"]: row["ppid"] for row in rows}, raising=False)
    return reads, enumerations


def test_private_legacy_rows_cannot_poison_cached_evidence(monkeypatch):
    _install_rows(monkeypatch, [_row()])
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
    def rows():
        yield SimpleNamespace(pid=123)
        raise PermissionError("fixture denied remaining processes")

    _install_rows(monkeypatch, [_row()], iterator=rows)
    receipt = sensors.process_snapshot(max_age=0)
    assert len(receipt.processes) == 1
    assert receipt.enumerated == 1
    assert not receipt.complete and not receipt.enumeration_complete
    assert "denied" in receipt.error


def test_missing_cmdline_and_invalid_birth_are_unknown_not_empty_success(monkeypatch):
    _install_rows(monkeypatch, [
        _row(cmdline=None, create_time=float("nan")),
        _row(pid=456, cmdline=[object()]),
    ])
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.enumeration_complete and not receipt.complete
    assert receipt.unreadable == 2 and receipt.identity_incomplete == 1
    assert len(receipt.processes) == 2
    assert all(item["cmdline"] is None for item in receipt.processes)


def test_fresh_process_birth_change_cannot_mix_generations(monkeypatch):
    _install_rows(monkeypatch, [_row(create_time=100.0)], after={123: _row(create_time=200.0)})
    receipt = sensors.process_snapshot(max_age=0)
    assert receipt.processes == ()
    assert receipt.enumerated == 1 and receipt.skipped == 1
    assert not receipt.complete and not receipt.enumeration_complete


def test_credential_and_recovery_detectors_share_one_os_inventory(monkeypatch):
    monkeypatch.setattr(sensors, "_proc_cache", (0.0, None))
    reads, calls = _install_rows(monkeypatch, [_row(cmdline=["benign.exe"])])
    for module in (lsass_guard.LsassGuardModule(), shadowcopy_guard.ShadowCopyGuardModule()):
        monkeypatch.setattr(module, "sleep", lambda _seconds, target=module: target.stop())
        module.run()
        assert module._last_coverage["readable"] == 1
    assert len(calls) == 1
    assert "create_time" in reads[0]
    assert {"pid", "create_time", "exe"} == set(reads[1])


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
