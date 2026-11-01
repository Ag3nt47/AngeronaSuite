"""Request-stage diagnostics remain bounded, private and separate from authority."""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest

from angerona.core.eventbus import EventBus
from angerona.core.status_report import StatusReporter, _ai_request_snapshot

NAME = "AI Triage (Ollama)"


def view(**changes):
    result = dict(schema=1, state="observed", reason_code="", advisory_only=True,
                  response_authorized=False, lifecycle_generation=7, observation_generation=7,
                  attempt_count=3, stage="refused", outcome="service-refused",
                  started_monotonic=11.0, updated_monotonic=12.0,
                  stage_entries={"service-check": 3, "model-check": 0, "request": 0},
                  completed_stage_timings=[dict(stage="service-check", wall_seconds=1.0,
                                               thread_cpu_seconds=0.01)])
    result.update(changes)
    return result


def manager(source, enabled=True):
    return SimpleNamespace(modules={NAME: SimpleNamespace(request_stage_snapshot=lambda: source)},
                           is_enabled=lambda _: enabled)


def test_projection_preserves_completed_observations_without_private_details_or_io(monkeypatch):
    source = view(scope="private model path", host="private endpoint", prompt="private prompt")
    original = copy.deepcopy(source)
    # Projection itself has no new clock/file/service/model work.
    monkeypatch.setattr("angerona.core.status_report.time.monotonic", lambda: pytest.fail("clock sampled"))
    result = _ai_request_snapshot(manager(source))
    assert result["state"] == "observed" and result["stage_entries"]["model-check"] == 0
    assert result["completed_stage_timings"][0]["wall_seconds"] == 1.0
    assert result["response_authorized"] is False and result["advisory_only"] is True
    assert "private" not in json.dumps(result) and source == original


@pytest.mark.parametrize("changes", [
    {"schema": True}, {"state": "healthy"}, {"reason_code": "private"},
    {"state": "x" * 10000}, {"reason_code": "x" * 10000},
    {"advisory_only": False}, {"response_authorized": True}, {"attempt_count": True},
    {"lifecycle_generation": -1}, {"observation_generation": 6},
    {"stage": "approved"}, {"outcome": "inference-authorized"},
    {"started_monotonic": float("nan")}, {"updated_monotonic": True},
    {"started_monotonic": 13}, {"attempt_count": 0},
    {"stage_entries": {"service-check": 1, "model-check": 0, "request": True}},
    {"stage_entries": {"service-check": 1}},
    {"completed_stage_timings": [{"stage": "request", "wall_seconds": -1, "thread_cpu_seconds": 0}]},
    {"completed_stage_timings": [{"stage": "request", "wall_seconds": 1, "thread_cpu_seconds": 0}] * 2},
    {"completed_stage_timings": [{"stage": "request", "wall_seconds": 1, "thread_cpu_seconds": 0,
                                  "private_path": "untrusted"}]},
    {"completed_stage_timings": [None]}, {"completed_stage_timings": [None] * 4},
    {"completed_stage_timings": [{str(index): 0 for index in range(10000)}]},
])
def test_malformed_projection_is_wholly_unavailable_without_partial_success(changes):
    result = _ai_request_snapshot(manager(view(**changes)))
    assert result["state"] == "unavailable" and result["reason_code"] == "invalid_observation"
    assert "stage_entries" not in result and "completed_stage_timings" not in result


def test_historical_generation_is_explicit_and_never_current():
    source = view(state="unmeasured", reason_code="generation_changed", lifecycle_generation=8,
                  observation_generation=7, stage="idle", outcome="unmeasured")
    result = _ai_request_snapshot(manager(source))
    assert result["state"] == "unmeasured" and result["observation_generation"] == 7
    assert result["lifecycle_generation"] == 8 and result["attempt_count"] == 3


def test_absent_disabled_failed_or_replaced_reader_cannot_export_old_stage():
    assert _ai_request_snapshot(SimpleNamespace(modules={}))["state"] == "not-configured"
    disabled = manager(view(), enabled=False)
    disabled.modules[NAME].request_stage_snapshot = lambda: pytest.fail("disabled reader")
    assert _ai_request_snapshot(disabled)["state"] == "disabled"
    failed = manager(view())
    failed.modules[NAME].request_stage_snapshot = lambda: (_ for _ in ()).throw(RuntimeError("private"))
    assert "private" not in json.dumps(_ai_request_snapshot(failed))
    replaced = manager(view())

    def reader():
        replaced.modules[NAME] = SimpleNamespace()
        return view()

    replaced.modules[NAME].request_stage_snapshot = reader
    result = _ai_request_snapshot(replaced)
    assert result["state"] == "unmeasured" and "completed_stage_timings" not in result


def test_status_json_and_text_include_stage_without_starting_service(tmp_path):
    modules = manager(view())
    module = modules.modules[NAME]
    for key, value in dict(name=NAME, category="AI", version="fixture", status="running",
                           health=30, health_state="critical", health_note="", last_error="").items():
        setattr(module, key, value)
    reporter = StatusReporter(EventBus(), SimpleNamespace(count_since=lambda _: 0), modules,
        SimpleNamespace(data_dir=tmp_path, runtime_chill_active=True,
                        ollama_host="local", ollama_model="fixture"))
    assert reporter._write(force=True)
    result = json.loads((tmp_path / "diagnostics/status.json").read_text())
    assert result["ai_request"]["outcome"] == "service-refused"
    assert result["normal_crashlog"]["os_quota"] is False
    assert result["normal_crashlog"]["native_fault_bytes_limited"] is False
    text = (tmp_path / "diagnostics/status.txt").read_text()
    assert "AI request: observed / refused" in text and "Cached inclusive stage timings" in text
    assert "native/external writers are outside this budget" in text
