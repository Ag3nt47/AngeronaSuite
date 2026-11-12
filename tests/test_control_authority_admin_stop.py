"""Administrator-gated STOP: forgery, replay and legacy-bypass resistance."""
from __future__ import annotations

import json
import secrets

import pytest

from angerona.resilience import control_authority as ca
from angerona.resilience import shutdown_token as tok


@pytest.fixture(autouse=True)
def _fresh_admin_probe():
    """The provisioned() probe is cached for hot loops; never leak it between tests."""
    reset = {"until": 0.0, "probe_until": 0.0, "authority": None, "active": False}
    tok._ADMIN_CACHE.update(reset)
    yield
    tok._ADMIN_CACHE.update(reset)


@pytest.fixture
def authority(tmp_path):
    root = tmp_path / "control"
    ca.provision(root, require_admin=False)
    return root


def test_provision_creates_epoch_one_without_a_stop_and_never_rotates(authority):
    state = ca.status(authority)
    assert state["state"] == "protected" and state["epoch"] == 1 and not state["stop_active"]
    with pytest.raises(FileExistsError):
        ca.provision(authority, require_admin=False)


def test_signed_stop_is_honoured_and_resume_retires_it(authority):
    ca.issue("operator-stop", "dashboard STOP", root=authority, require_admin=False)
    assert ca.stop_active(authority)
    ca.resume(root=authority, require_admin=False)
    state = ca.status(authority)
    assert not state["stop_active"] and state["epoch"] == 2


def test_captured_stop_cannot_be_replayed_after_resume(authority):
    ca.issue("operator-stop", "captured", root=authority, require_admin=False)
    captured = (authority / "stop.cmd").read_bytes()
    ca.resume(root=authority, require_admin=False)
    (authority / "stop.cmd").write_bytes(captured)  # Attacker replays a genuine old STOP.
    assert not ca.stop_active(authority)


def test_forged_and_edited_commands_are_never_honoured(authority, tmp_path):
    other = tmp_path / "attacker"
    ca.provision(other, require_admin=False)
    ca.issue("operator-stop", "forged", root=other, require_admin=False)
    (authority / "stop.cmd").write_bytes((other / "stop.cmd").read_bytes())
    assert not ca.stop_active(authority)
    ca.issue("maintenance", "genuine", root=authority, minutes=5, require_admin=False)
    document = json.loads((authority / "stop.cmd").read_text())
    document["kind"] = "operator-stop"  # Try to turn maintenance into a persistent stop.
    (authority / "stop.cmd").write_text(json.dumps(document))
    assert not ca.stop_active(authority)


def test_maintenance_stop_expires_and_is_bounded(authority, monkeypatch):
    ca.issue("maintenance", "update", root=authority, minutes=1, require_admin=False)
    assert ca.stop_active(authority)
    real = ca.time.time
    monkeypatch.setattr(ca.time, "time", lambda: real() + 61)
    assert not ca.stop_active(authority)
    with pytest.raises(ValueError):
        ca.issue("maintenance", "too long", root=authority, minutes=61, require_admin=False)


def test_tampered_epoch_or_public_key_is_compromised_and_honours_no_stop(authority):
    ca.issue("operator-stop", "genuine", root=authority, require_admin=False)
    epoch = json.loads((authority / "epoch.json").read_text())
    epoch["epoch"] = 7
    (authority / "epoch.json").write_text(json.dumps(epoch))
    state = ca.status(authority)
    assert state["state"] == "compromised" and not state["stop_active"]


def test_swapped_public_key_cannot_validate_attacker_commands(authority):
    (authority / "stop-authority.pub").write_text(secrets.token_bytes(32).hex())
    assert ca.status(authority)["state"] == "compromised"
    assert not ca.stop_active(authority)


def test_issue_and_resume_require_an_elevated_administrator(authority, monkeypatch):
    monkeypatch.setattr(ca, "is_admin", lambda: False)
    with pytest.raises(ca.AdminApprovalRequired):
        ca.issue("operator-stop", "x", root=authority)
    with pytest.raises(ca.AdminApprovalRequired):
        ca.resume(root=authority)
    assert ca.main(["stop"]) == ca.EXIT_NOT_ADMIN


def test_directory_acl_never_grants_inheritable_user_access(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(ca, "_icacls", lambda *args: calls.append(args))
    monkeypatch.setattr(ca.os, "name", "nt")
    ca._restrict(ca.Paths(tmp_path))
    (arguments,) = calls
    users = [a for a in arguments if a.startswith("*S-1-5-32-545:")]
    assert users == ["*S-1-5-32-545:(RX)"]  # List only; no (OI)/(CI) inheritance.
    assert "/inheritance:r" in arguments


# ── shutdown_token routing ───────────────────────────────────────────────────
@pytest.fixture
def provisioned_admin(monkeypatch):
    state = {"active": False, "elevated": []}
    monkeypatch.setattr(ca, "provisioned", lambda root=None: True)
    monkeypatch.setattr(ca, "stop_active", lambda root=None: state["active"])
    monkeypatch.setattr(ca, "status", lambda root=None: {"state": "protected", "stop_active": state["active"],
                                                         "stop": {"kind": "operator-stop"}})

    def elevated(action, timeout_s=300.0):
        state["elevated"].append(action)
        if state.get("decline"):
            raise ca.AdminApprovalRequired("declined")
        state["active"] = action == "stop"
        return 0

    monkeypatch.setattr(ca, "request_elevated", elevated)
    tok._ADMIN_CACHE["until"] = 0.0
    yield state
    tok._ADMIN_CACHE["until"] = 0.0


def test_operator_stop_goes_through_uac_and_decline_changes_nothing(provisioned_admin):
    provisioned_admin["decline"] = True
    with pytest.raises(ca.AdminApprovalRequired):
        tok.request_operator_stop()
    assert provisioned_admin["elevated"] == ["stop"]
    assert not tok.is_standdown_requested()
    provisioned_admin["decline"] = False
    assert tok.request_operator_stop() == {"kind": "operator-stop"}
    tok._ADMIN_CACHE["until"] = 0.0
    assert tok.is_standdown_requested()


def test_legacy_user_directory_stop_is_refused_once_provisioned(provisioned_admin, tmp_path, monkeypatch):
    key = secrets.token_bytes(32)
    legacy = tmp_path / "ipc" / "standdown.cmd"
    legacy.parent.mkdir()
    tok.request_operator_stop(key=key, path=legacy)  # Attacker with the user-readable key.
    monkeypatch.setattr(tok, "_standdown_path", lambda: legacy)
    monkeypatch.setattr(tok, "_load_key", lambda: key)
    assert not tok.is_standdown_requested()
    assert not tok.standdown_active_for_storage(tmp_path)
    with pytest.raises(ca.AdminApprovalRequired):
        tok.request_standdown("forged maintenance")


def test_resume_requires_uac_and_strict_resume_reports_decline(provisioned_admin, tmp_path):
    provisioned_admin["active"] = True
    provisioned_admin["decline"] = True
    with pytest.raises(RuntimeError, match="administrator approval"):
        tok.clear_standdown_for_storage(tmp_path)
    tok.clear_standdown()  # Non-strict: no raise, STOP stays.
    assert provisioned_admin["active"]
    provisioned_admin["decline"] = False
    tok.clear_standdown_for_storage(tmp_path)
    assert provisioned_admin["elevated"][-1] == "resume" and not provisioned_admin["active"]


def test_unprovisioned_hosts_keep_the_legacy_contract(tmp_path, monkeypatch):
    monkeypatch.setattr(ca, "provisioned", lambda root=None: False)
    key = secrets.token_bytes(32)
    path = tmp_path / "standdown.cmd"
    tok.request_operator_stop(key=key, path=path)
    assert tok.is_standdown_requested(key=key, path=path)
