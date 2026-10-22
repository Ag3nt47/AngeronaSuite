from __future__ import annotations

import getpass
import os
from types import SimpleNamespace

import pytest

from angerona.core import commands
from angerona.core.commands import CommandConsole
from angerona.core.eventbus import EventBus


def console():
    return CommandConsole(SimpleNamespace(modules={}), EventBus(), SimpleNamespace())


@pytest.mark.parametrize("failure", [ImportError("no pwd"), OSError("no username")])
@pytest.mark.parametrize("collection", ["populated", "empty", "denied", "unavailable"])
def test_missing_display_context_does_not_suppress_independent_session_collection(
    monkeypatch, failure, collection,
):
    def missing_user():
        raise failure

    monkeypatch.setattr(getpass, "getuser", missing_user)
    monkeypatch.setattr(os, "getlogin", lambda: (_ for _ in ()).throw(OSError("unavailable")))
    calls = []

    def users():
        calls.append(True)
        if collection == "denied":
            raise PermissionError("fixture collection denied")
        if collection == "empty":
            return []
        return [SimpleNamespace(name="collected-session", terminal="fixture",
                                host="", started=None)]

    monkeypatch.setattr(commands, "psutil", None if collection == "unavailable"
                        else SimpleNamespace(users=users))
    result = console().run("sessions")
    assert result.startswith("current user: unavailable")
    assert not result.startswith("error:")
    assert calls == ([] if collection == "unavailable" else [True])
    if collection == "populated":
        assert "collected-session" in result
        assert "since ?" in result
    elif collection == "empty":
        assert "no logged-in sessions reported" in result
    elif collection == "denied":
        assert "sessions unavailable: fixture collection denied" in result
    else:
        assert "sessions unavailable: psutil is not installed" in result


@pytest.mark.parametrize("command", ["sessions", "whoami"])
def test_successful_display_context_and_collection_remain_independent(monkeypatch, command):
    monkeypatch.setattr(getpass, "getuser", lambda: "display-context-only")
    monkeypatch.setattr(commands, "psutil", SimpleNamespace(users=lambda: []))
    assert console().run(command) == (
        "current user: display-context-only\n  no logged-in sessions reported"
    )


@pytest.mark.skipif(os.name != "nt", reason="actual Windows missing-environment getpass behavior")
def test_actual_windows_getpass_without_username_environment_keeps_session_evidence(monkeypatch):
    native_username = os.getlogin()
    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(commands, "psutil", SimpleNamespace(users=lambda: [SimpleNamespace(
        name="independent-session-evidence", terminal="", host="", started=None,
    )]))
    result = console().run("sessions")
    assert result.startswith(f"current user: {native_username}\n")
    assert "independent-session-evidence" in result
    assert not result.startswith("error:")
