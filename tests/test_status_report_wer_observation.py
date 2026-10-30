"""WER status is a bounded cached admission view, never upstream protection proof."""
from __future__ import annotations

import copy
import json
import threading
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.status_report import StatusReporter, _wer_observation_snapshot

NAME = "Deterministic Fast-Path Interceptor"


def _view(**changes):
    result = dict(
        schema=1, state="admitted-at-last-check", reason_code="", reason="not copied",
        lifecycle_generation=7, observation_generation=7, last_admission_result="admitted",
        attempted_monotonic=101.0, checked_monotonic=101.0, expires_monotonic=102.0,
        checked_age_s=0.25, ownership_cache_current=True, queued=0, queue_capacity=64,
        dropped=0, ingress_lost_records=0, skipped_admission_attempts=0,
        ownership_snapshot_count=1, ownership_reason_code="", owned_roles=("core",),
        response_authorized=False, upstream_delivery_verified=False, advisory_only=True,
    )
    result.update(changes)
    return result


def _manager(source, *, enabled=True):
    def reader():
        return source
    return SimpleNamespace(
        modules={NAME: SimpleNamespace(
            name=NAME, category="AI", version="fixture", status="running", health=100,
            health_state="ok", health_note="", last_error="", wer_coverage_snapshot=reader,
        )},
        is_enabled=lambda _: enabled,
    )


def test_status_persists_wer_projection_without_copying_provider_text(tmp_path):
    source = _view()
    source.update(reason="private command path", scope="private arbitrary scope", key="private-key", pid=999)
    original = copy.deepcopy(source)
    reporter = StatusReporter(
        EventBus(), SimpleNamespace(count_since=lambda _: 0), _manager(source),
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=True, ollama_host="local", ollama_model="fixture"),
    )
    assert reporter._write(force=True)
    view = json.loads((tmp_path / "diagnostics/status.json").read_text())["wer_observation"]
    assert view["state"] == "admitted-at-last-check" and view["ownership_cache_current"] is True
    assert view["expires_monotonic"] == 102 and view["checked_age_s"] == 0.25
    assert view["owned_roles"] == ["core"] and view["upstream_delivery_verified"] is False
    assert "private" not in json.dumps(view) and "pid" not in view and "key" not in view
    assert source == original
    text = (tmp_path / "diagnostics/status.txt").read_text()
    assert "WER       : admitted-at-last-check" in text
    assert "ETW/Sysmon delivery, absent companions and prevention remain unproven" in text


def test_missing_disabled_and_failing_wer_readers_remain_explicit():
    absent = _wer_observation_snapshot(SimpleNamespace(modules={}, is_enabled=lambda _: pytest.fail("missing policy probe")))
    assert absent["state"] == "not-configured" and absent["reason_code"] == "module_absent"
    manager = _manager(_view(), enabled=False)
    manager.modules[NAME].wer_coverage_snapshot = lambda: pytest.fail("disabled reader called")
    disabled = _wer_observation_snapshot(manager)
    assert disabled["state"] == "disabled" and disabled["ownership_cache_current"] is False

    def fail():
        raise RuntimeError("private provider exception")

    manager = _manager(_view())
    manager.modules[NAME].wer_coverage_snapshot = fail
    failed = _wer_observation_snapshot(manager)
    assert failed["state"] == "unavailable" and failed["reason_code"] == "invalid_observation"
    assert "private" not in json.dumps(failed) and "RuntimeError" not in json.dumps(failed)
    manager.modules[NAME].wer_coverage_snapshot = None
    assert _wer_observation_snapshot(manager)["reason_code"] == "reader_unavailable"


@pytest.mark.parametrize("change", [
    {"schema": True}, {"state": "healthy"}, {"reason_code": "private string"},
    {"ownership_reason_code": "private exception"}, {"lifecycle_generation": True},
    {"lifecycle_generation": None, "observation_generation": None}, {"observation_generation": 8},
    {"checked_monotonic": float("nan")}, {"checked_age_s": 1.0}, {"checked_age_s": -1.0},
    {"expires_monotonic": 106.001}, {"queue_capacity": True}, {"queued": 65},
    {"dropped": False}, {"ingress_lost_records": 1}, {"dropped": 1, "ingress_lost_records": 1},
    {"skipped_admission_attempts": True}, {"ownership_snapshot_count": True},
    {"owned_roles": ["core"]}, {"owned_roles": ("core",) * 17}, {"owned_roles": ("private path",)},
    {"response_authorized": True}, {"upstream_delivery_verified": True}, {"advisory_only": False},
    pytest.param({"state": "x" * 4096}, id="oversized-state"),
    pytest.param({"reason_code": "x" * 4096}, id="oversized-reason"),
    pytest.param({"last_admission_result": "x" * 4096}, id="oversized-last-result"),
    pytest.param({"ownership_reason_code": "x" * 4096}, id="oversized-rejection-code"),
])
def test_malformed_or_overstated_cached_wer_projection_is_held(change):
    view = _wer_observation_snapshot(_manager(_view(**change)))
    assert view["state"] == "unavailable" and view["reason_code"] == "invalid_observation"
    assert view["ownership_cache_current"] is False and view["response_authorized"] is False
    assert "private" not in json.dumps(view)


@pytest.mark.parametrize("source", [None, [], {}, {str(index): index for index in range(41)}])
def test_non_contract_or_oversized_wer_results_are_not_exported(source):
    view = _wer_observation_snapshot(_manager(source))
    assert view["state"] == "unavailable" and view["reason_code"] == "invalid_observation"


def test_stale_and_loss_states_do_not_become_current_coverage():
    stale = _wer_observation_snapshot(_manager(_view(
        state="stale", reason_code="lease_expired", ownership_cache_current=False, checked_age_s=1.5,
    )))
    assert stale["state"] == "stale" and stale["last_admission_result"] == "admitted"
    loss = _wer_observation_snapshot(_manager(_view(
        state="unavailable", reason_code="ingress_lost", dropped=1, ingress_lost_records=1,
    )))
    assert loss["state"] == "unavailable" and loss["ownership_cache_current"] is True
    assert loss["ingress_lost_records"] == 1 and loss["upstream_delivery_verified"] is False


@pytest.mark.parametrize("change", ["disable", "replace", "policy-replace", "mutate-source"])
def test_policy_race_and_mutable_result_cannot_export_unchecked_values(change):
    source = _view()
    manager = _manager(source)
    calls = []

    def policy(_):
        calls.append(True)
        if len(calls) == 2:
            if change == "disable":
                return False
            if change in {"replace", "policy-replace"}:
                manager.modules[NAME] = SimpleNamespace()
            else:
                source.update(state="private injected text", reason_code="private injected text")
        return True

    manager.is_enabled = policy
    if change == "replace":
        def reader():
            manager.modules[NAME] = SimpleNamespace()
            return source
        manager.modules[NAME].wer_coverage_snapshot = reader
    view = _wer_observation_snapshot(manager)
    assert "private" not in json.dumps(view)
    if change == "disable":
        assert view["state"] == "disabled" and view["ownership_cache_current"] is False
    elif change in {"replace", "policy-replace"}:
        assert view["state"] == "unmeasured" and view["reason_code"] == "generation_changed"
        assert view["ownership_cache_current"] is False
        assert len(calls) == 2
    else:
        assert view["state"] == "admitted-at-last-check"


def test_wer_status_read_does_not_start_stop_refresh_or_query_a_supplier():
    manager = _manager(_view())
    module = manager.modules[NAME]
    for name in ("start", "stop", "bind_owned_processes", "_owned_process_source", "_drain_wer_events"):
        setattr(module, name, lambda *args, **kwargs: pytest.fail("WER status changed runtime"))
    view = _wer_observation_snapshot(manager)
    assert view["state"] == "admitted-at-last-check" and view["advisory_only"] is True


def test_real_wer_publication_reaches_status_and_expires_without_a_new_warning(tmp_path, monkeypatch):
    from angerona.core.werfault_guard import OwnedProcessIdentity
    from angerona.modules import fast_path

    module = fast_path.FastPathModule()
    module._lifecycle_generation = 4
    module._thread = threading.current_thread()
    module.status = "running"
    clock, supplier_calls, emitted = [101.0], [], []
    monkeypatch.setattr(fast_path, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(module, "emit", lambda *args, **kwargs: emitted.append((args, kwargs)))
    identity = OwnedProcessIdentity(71, "116444746000000000", 1000.0,
                                    r"C:\Inert\suite.exe", "core", 100.0, 102.0)

    def supplier():
        supplier_calls.append(True)
        return (identity,)

    module.bind_owned_processes(supplier)
    module._drain_wer_events()
    manager = SimpleNamespace(modules={NAME: module}, is_enabled=lambda _: True)
    reporter = StatusReporter(
        EventBus(), SimpleNamespace(count_since=lambda _: 0), manager,
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=False, ollama_host="local", ollama_model="fixture"),
    )
    admitted = reporter._snapshot()["wer_observation"]
    assert admitted["state"] == "admitted-at-last-check" and admitted["checked_monotonic"] == 101
    clock[0] = 102.0
    expired = reporter._snapshot()["wer_observation"]
    assert expired["state"] == "stale" and expired["reason_code"] == "lease_expired"
    assert expired["last_admission_result"] == "admitted" and expired["ownership_cache_current"] is False
    assert supplier_calls == [True] and not emitted
    assert "suite.exe" not in json.dumps(expired) and "pid" not in expired
