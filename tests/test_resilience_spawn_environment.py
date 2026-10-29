"""Inherited sidecar environments are inputs to the allowlist, never overrides."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from angerona.core import privilege
from angerona.resilience import supervisor


def test_full_inherited_environment_is_sanitized_before_detached_spawn(monkeypatch):
    captured = {}
    inherited = dict(os.environ, APPDATA=r"C:\untrusted-roaming", PYTHONPATH="untrusted-imports",
                     HTTP_PROXY="http://untrusted-proxy", OPENAI_API_KEY="test-secret",
                     ANGERONA_SUPERVISED_RECOVERY="1", ANGERONA_UNAPPROVED_SETTING="untrusted")
    expected = privilege.sanitized_child_environment(source=inherited)
    sentinel = object()
    if os.name == "nt":
        from angerona.core import windows_child_job
        def spawn(argv, environment, **kwargs):
            captured.update(argv=argv, environment=environment, kwargs=kwargs)
            return sentinel
        monkeypatch.setattr(windows_child_job, "launch_windows_child", spawn)
    else:
        def spawn(argv, **kwargs):
            captured.update(argv=argv, environment=kwargs.pop("env"), kwargs=kwargs)
            return sentinel
        monkeypatch.setattr(supervisor.subprocess, "Popen", spawn)
    assert supervisor.spawn_detached(["fixed-runtime", "-m", "fixed-sidecar"], env=inherited,
                                     window="hidden", cwd="fixed-installation") is sentinel
    assert captured["environment"] == expected
    assert captured["environment"]["ANGERONA_SUPERVISED_RECOVERY"] == "1"
    assert not ({"PYTHONPATH", "HTTP_PROXY", "OPENAI_API_KEY", "ANGERONA_UNAPPROVED_SETTING"}
                & captured["environment"].keys())
    assert captured["kwargs"]["cwd"] == "fixed-installation"


@pytest.mark.parametrize("name", ["APPDATA", "PYTHONPATH", "HTTP_PROXY", "OPENAI_API_KEY"])
def test_explicit_environment_override_rejection_remains_strict(name):
    with pytest.raises(ValueError):
        privilege.sanitized_child_environment({name: "untrusted-value"}, source={})


def test_component_spawn_passes_inherited_environment_and_inhibits_stop_clear(monkeypatch):
    component = supervisor.Component(name="core", argv=["fixed-runtime", "-m", "angerona"])
    instance = supervisor.ProcessSupervisor()
    monkeypatch.setattr(instance, "_respawn_blocked", lambda: False)
    monkeypatch.setattr(instance, "_is_running", lambda _component: False)
    monkeypatch.setattr(instance, "_authenticated_record", lambda _component: (None, "unavailable"))
    monkeypatch.setattr(supervisor, "try_claim_spawn", lambda _name: True)
    monkeypatch.setattr(supervisor.threading, "Thread", lambda **_kwargs: SimpleNamespace(start=lambda: None))
    monkeypatch.setattr(instance, "_emit", lambda *_args, **_kwargs: None)
    captured = {}
    def spawn(argv, *, env, window):
        captured.update(environment=privilege.sanitized_child_environment(source=env))
        return SimpleNamespace(pid=123)
    monkeypatch.setattr(supervisor, "spawn_detached", spawn)
    monkeypatch.setenv("APPDATA", r"C:\untrusted-roaming")
    monkeypatch.setenv("OPENAI_API_KEY", "test-secret")
    assert instance._spawn_locked(component)
    assert captured["environment"]["ANGERONA_SUPERVISED_RECOVERY"] == "1"
    assert "OPENAI_API_KEY" not in captured["environment"]
