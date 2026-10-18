"""Inert proof that every local AI transport stays off until manual Full."""
from __future__ import annotations

import json
import threading
import urllib.request
from collections import OrderedDict
from types import SimpleNamespace

import pytest

from angerona.core import ollama_lifecycle as lifecycle
from angerona.core import url_policy
from angerona.core.chill_mode import set_chill_ai_blocked
from angerona.engines import ollama_client


@pytest.fixture(autouse=True)
def isolated_orchestration(monkeypatch):
    monkeypatch.setattr(lifecycle, "_startup_attempts", OrderedDict())
    monkeypatch.setattr(lifecycle, "_startup_launch_lock", threading.Lock())
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _host: True)
    monkeypatch.setattr(lifecycle, "attest_ollama_service", lambda _host: object())
    monkeypatch.setattr(lifecycle, "list_models", lambda *_a, **_kw: [])
    monkeypatch.setattr(lifecycle, "_spawn_ollama_service", lambda *_a, **_kw:
                        pytest.fail("A blocked test attempted native startup"))


@pytest.mark.parametrize("quiet", [False, True])
def test_ai_lock_denies_sync_async_and_stream_without_preparation(monkeypatch, quiet):
    set_chill_ai_blocked(SimpleNamespace(), True)
    if quiet:
        monkeypatch.setenv("ANGERONA_CHILL_ACTIVE", "1")
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _h: pytest.fail("No probe"))
    monkeypatch.setattr(lifecycle, "_claim_startup", lambda _h: pytest.fail("No worker"))
    monkeypatch.setattr(ollama_client, "guard_payload", lambda _p: pytest.fail("No preparation"))
    for operation in (lifecycle.ensure_ollama_service, lifecycle.request_ollama_start):
        status = operation()
        assert status.state == "blocked" and not status.daemon_ready
        assert "manually" in status.detail
    assert lifecycle.startup_snapshot().state == "blocked"
    assert ollama_client.call({"model": "llama3"})["error_type"] == "ChillMode"
    assert ollama_client.call_stream({"model": "llama3"}, lambda _t: pytest.fail("No tokens"))[
        "error_type"] == "ChillMode"


@pytest.mark.parametrize("path", [
    "/api/chat", "/api/generate", "/api/embed", "/api/embeddings",
    "/api/pull", "/api/create", "/api/tags", "/api/ps", "/api/blobs/sha256:abc",
])
@pytest.mark.parametrize("policy", [url_policy.OLLAMA_SERVICE_POLICY, url_policy.LOCAL_SERVICE_POLICY])
def test_direct_and_generic_transports_cannot_bypass_lock(monkeypatch, path, policy):
    set_chill_ai_blocked(SimpleNamespace(), True)
    monkeypatch.setattr(url_policy, "_pin_loopback_url", lambda _u: pytest.fail("No DNS"))
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_a: pytest.fail("No opener"))
    request = urllib.request.Request("http://127.0.0.1:11434" + path,
                                     data=b'{"model":"llama3"}')
    with pytest.raises(url_policy.UrlPolicyError, match="Switch Chill off manually"):
        url_policy.safe_urlopen(request, policy=policy, timeout=1)


def test_toggle_during_attestation_blocks_before_http_send(monkeypatch):
    config = SimpleNamespace()
    calls = []
    monkeypatch.setattr(lifecycle, "attest_ollama_service",
                        lambda _host: set_chill_ai_blocked(config, True))
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_a:
                        SimpleNamespace(open=lambda *_a, **_kw: calls.append("sent")))
    with pytest.raises(url_policy.UrlPolicyError, match="Chill"):
        url_policy.safe_urlopen("http://127.0.0.1:11434/api/tags",
                                policy=url_policy.OLLAMA_SERVICE_POLICY, timeout=1)
    assert calls == []


def test_only_release_helper_can_send_exact_unload_without_loading_missing_model(monkeypatch):
    set_chill_ai_blocked(SimpleNamespace(), True)
    sent = []

    class Response:
        headers = {}

        def __init__(self, request):
            self.request = request

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def read(self, _size):
            return json.dumps({"models": [{"name": "llama3:latest"},
                                          {"name": "unrelated:latest"}]}).encode()

    def open_request(request, **_kwargs):
        sent.append((request.full_url, request.data))
        return Response(request)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_a:
                        SimpleNamespace(open=open_request))
    assert lifecycle.unload_angerona_models(configured_model="missing") == ["llama3:latest"]
    assert len(sent) == 2
    assert sent[0][0].endswith("/api/ps")
    assert json.loads(sent[1][1]) == {
        "model": "llama3:latest", "prompt": "", "stream": False, "keep_alive": 0,
    }
    # Even the same empty payload outside release custody must be rejected:
    # a raw empty generate request could otherwise load an absent model.
    with pytest.raises(url_policy.UrlPolicyError, match="Chill"):
        url_policy.local_json_request("http://127.0.0.1:11434", "/api/generate",
                                      payload=json.loads(sent[1][1]))
    assert len(sent) == 2


def test_manual_full_restores_service_preparation(monkeypatch):
    config = SimpleNamespace()
    set_chill_ai_blocked(config, True)
    assert lifecycle.ensure_ollama_service().state == "blocked"
    # Incident escalation clears quiet pacing only, never operator AI intent.
    monkeypatch.delenv("ANGERONA_CHILL_ACTIVE", raising=False)
    assert lifecycle.ensure_ollama_service().state == "blocked"
    set_chill_ai_blocked(config, False)
    assert lifecycle.ensure_ollama_service().daemon_ready


def test_single_module_inspector_reports_skip_without_a_false_pass(monkeypatch):
    from angerona.core.selftest import run_module_selftest
    from angerona.modules.ai_triage import AITriageModule

    set_chill_ai_blocked(SimpleNamespace(), True)
    module = AITriageModule()
    monkeypatch.setattr(module, "_ensure_ollama", lambda **_kw: pytest.fail("No startup"))
    passed, detail = run_module_selftest(module)
    assert not passed and detail.startswith("SKIP:")
    passed, detail = module.self_test()
    assert not passed and detail.startswith("SKIP:")


def test_chill_during_startup_stops_exact_owned_child(monkeypatch):
    config = SimpleNamespace()
    stopped = []
    child = SimpleNamespace(poll=lambda: 0 if stopped else None,
                            terminate=lambda: stopped.append("owned"))
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _h: False)

    def spawn(*_args, **_kwargs):
        set_chill_ai_blocked(config, True)
        return child

    monkeypatch.setattr(lifecycle, "_spawn_ollama_service", spawn)
    result = lifecycle.ensure_ollama_service()
    assert result.state == "blocked"
    assert stopped == ["owned"]
    assert lifecycle._owned_services == {}


def test_enter_chill_stops_retained_child_without_process_discovery(monkeypatch):
    set_chill_ai_blocked(SimpleNamespace(), True)
    stopped = []
    child = SimpleNamespace(poll=lambda: 0 if stopped else None,
                            terminate=lambda: stopped.append("owned"))
    lifecycle._owned_services[("http://127.0.0.1:11434", id(child))] = child
    def resident_list(*_args):
        assert not stopped, "resident release must precede service termination"
        return {"models": []}
    monkeypatch.setattr(lifecycle, "_json_request", resident_list)
    assert lifecycle.unload_angerona_models() == []
    assert stopped == ["owned"] and lifecycle._owned_services == {}


def test_failed_startup_retry_cannot_spawn_more_children_before_exit(monkeypatch):
    released = []
    deny_termination = [True]

    def make_child(name):
        def terminate():
            if deny_termination[0]:
                raise OSError("fixture termination denial")
            released.append(name)
        return SimpleNamespace(poll=lambda: 0 if name in released else None, terminate=terminate)

    children = iter((make_child("first"),))
    monkeypatch.setattr(lifecycle, "_startup_port_present", lambda _h: False)
    monkeypatch.setattr(lifecycle, "_spawn_ollama_service", lambda *_a, **_kw: next(children))
    # Fail only after actual child registration; a bounded startup failure must
    # try termination, and a denied termination must keep its exact handle.
    def fail_launch_status(_attempt, state, stage, percent, detail, progress=None):
        if stage == "Service launched":
            raise TimeoutError
        _attempt.status = lifecycle.OllamaStartupStatus(state, stage, percent, detail)
        return _attempt.status

    monkeypatch.setattr(lifecycle, "_notify_startup", fail_launch_status)
    assert lifecycle.ensure_ollama_service().state == "failed"
    assert lifecycle.ensure_ollama_service().state == "failed"
    assert len(lifecycle._owned_services) == 1 and not released
    set_chill_ai_blocked(SimpleNamespace(), True)
    deny_termination[0] = False
    lifecycle.stop_owned_ollama_services()
    assert released == ["first"] and lifecycle._owned_services == {}


def test_release_retains_and_stops_multiple_exact_owned_handles():
    released = []
    for name in ("first", "second"):
        child = SimpleNamespace(poll=lambda label=name: 0 if label in released else None,
                                terminate=lambda label=name: released.append(label))
        lifecycle._owned_services[("http://127.0.0.1:11434", id(child))] = child
    lifecycle.stop_owned_ollama_services()
    assert released == ["first", "second"] and lifecycle._owned_services == {}


def test_termination_without_observed_exit_keeps_custody():
    calls = []
    child = SimpleNamespace(poll=lambda: None, terminate=lambda: calls.append("requested"),
                            wait=lambda **_kw: 0)
    key = ("http://127.0.0.1:11434", id(child))
    lifecycle._owned_services[key] = child
    lifecycle.stop_owned_ollama_services()
    assert calls == ["requested"] and lifecycle._owned_services[key] is child


def test_confirmed_owned_stop_invalidates_cached_ready_status():
    host = "http://127.0.0.1:11434"
    attempt = lifecycle._StartupAttempt()
    attempt.status = lifecycle.OllamaStartupStatus("ready", "Service ready", 100, daemon_ready=True)
    attempt.done.set()
    lifecycle._startup_attempts[host] = attempt
    exited = []
    child = SimpleNamespace(poll=lambda: 0 if exited else None,
                            terminate=lambda: exited.append(True))
    lifecycle._owned_services[(host, id(child))] = child
    lifecycle.stop_owned_ollama_services()
    status = lifecycle.startup_snapshot(host)
    assert status.state == "idle" and not status.daemon_ready and status.percent == 0
