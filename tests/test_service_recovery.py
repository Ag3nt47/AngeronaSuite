"""SCM recovery for AngeronaProtection: payload, admin gate and posture."""
from __future__ import annotations

import sys
import types

import pytest

from angerona.core import service_recovery as sr
from angerona.resilience import control_authority as ca


class FakeSCM(types.SimpleNamespace):
    SC_MANAGER_CONNECT = 1
    SERVICE_CHANGE_CONFIG = 2
    SERVICE_START = 16
    SERVICE_QUERY_CONFIG = 1

    def __init__(self, installed=True):
        super().__init__(config={}, closed=[], installed=installed)

    def OpenSCManager(self, *_):
        return "scm"

    def OpenService(self, _m, name, _access):
        if not self.installed:
            raise OSError("missing")
        assert name == "AngeronaProtection"
        return "svc"

    def ChangeServiceConfig2(self, _s, level, value):
        self.config[level] = value

    def QueryServiceConfig2(self, _s, level):
        return self.config.get(level)

    def CloseServiceHandle(self, handle):
        self.closed.append(handle)


@pytest.fixture
def scm(monkeypatch):
    fake = FakeSCM()
    monkeypatch.setattr(sr, "_require_windows", lambda: fake)
    return fake


def test_apply_sets_restart_actions_and_non_crash_flag(scm, monkeypatch):
    monkeypatch.setattr(ca, "is_admin", lambda: True)
    result = sr.apply()
    actions = scm.config[2]
    assert actions["ResetPeriod"] == 86400
    assert actions["Actions"] == [(1, 5000), (1, 5000), (1, 30000)]
    assert scm.config[4] is True
    assert result["state"] == "configured"
    assert scm.closed.count("svc") >= 1 and scm.closed.count("scm") >= 1


def test_apply_requires_an_administrator(scm, monkeypatch):
    monkeypatch.setattr(ca, "is_admin", lambda: False)
    with pytest.raises(ca.AdminApprovalRequired):
        sr.apply()
    assert scm.config == {}


def test_verify_reports_missing_recovery_and_missing_service(scm, monkeypatch):
    assert sr.verify()["state"] == "missing_recovery"
    scm.config[2] = {"ResetPeriod": 0, "Actions": [(1, 5000)]}
    assert sr.verify()["state"] == "missing_recovery"  # Non-crash flag still off.
    scm.config[4] = True
    assert sr.verify()["state"] == "configured"
    scm.installed = False
    assert sr.verify()["state"] == "not_installed"


def test_verify_is_unavailable_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert sr.verify()["state"] == "unavailable"
