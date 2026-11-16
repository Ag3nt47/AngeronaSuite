"""Explicit suite STOP reaches only retained private AI Jobs; no host AI runs."""
import os
import threading
import pytest
from angerona.core import ollama_lifecycle as ai
from angerona.core import windows_child_job as jobs
from test_ollama_owned_retirement import inert_child_factory, owned

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Job adapter contract")

@pytest.mark.parametrize("operator", [False, True])
def test_ai_stop_uses_operator_job_attempt_only_after_explicit_generation_fence(owned, monkeypatch, operator):
    sample = owned.make()
    foreign = owned.make((9201, 9202), register=False)
    calls = []
    original = jobs.OwnedWindowsChild.terminate_for_operator_stop
    def invoke(owner):
        calls.append(owner)
        return original(owner)
    monkeypatch.setattr(jobs.OwnedWindowsChild, "terminate_for_operator_stop", invoke)
    if operator:
        ai.begin_operator_ollama_shutdown()
    else:
        ai.begin_ollama_shutdown()
    result = ai.stop_owned_ollama_services(timeout=1.0)
    assert calls == ([sample.owner] if operator else [])
    assert result["complete"] is True
    assert not foreign.root.closed and not foreign.job_lifetime.closed
    assert owned.kernel.current(foreign.model) == (9201, 9202)

def test_operator_ai_fence_does_not_carry_into_replaced_generation(owned, monkeypatch):
    ai.begin_operator_ollama_shutdown()
    old = ai._ai_shutdown
    replacement = threading.Event()
    monkeypatch.setattr(ai, "_ai_shutdown", replacement)
    ai.begin_ollama_shutdown()
    assert ai._operator_stop_event is old and ai._operator_stop_event is not replacement
    sample = owned.make()
    monkeypatch.setattr(jobs.OwnedWindowsChild, "terminate_for_operator_stop",
                        lambda _owner: pytest.fail("older operator grant crossed generations"))
    assert ai.stop_owned_ollama_services(timeout=1.0)["complete"] is True
