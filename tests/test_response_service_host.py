"""Closed host/identity/deployment contracts; never install or start SCM."""
from __future__ import annotations

import base64
from dataclasses import asdict
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from angerona.core import response_service_host as host
from angerona.core.approval_identity import PrincipalCredential, SignedPrincipalProof
from angerona.core.privileged_pipe import NativePeer

USER = "S-1-5-21-100-200-300-1001"
OTHER = "S-1-5-21-100-200-300-1002"
SERVICE = "S-1-5-80-1-2-3-4-5"


def _credential(subject=USER, alias="operator"):
    key = Ed25519PrivateKey.generate()
    record = PrincipalCredential(alias, "windows-token", subject, key.public_key().public_bytes_raw())
    return key, record


def _proof(key, record):
    now = time.time()
    proof = SignedPrincipalProof.unsigned(record, host.DiagnosticBroker.authentication_digest(),
        now - 1, now + 60, "a" * 32)
    return SignedPrincipalProof(**dict(asdict(proof), signature=base64.urlsafe_b64encode(
        key.sign(proof.signing_bytes())).decode().rstrip("=")))


def _peer(subject=USER):
    return NativePeer(subject, "S-1-5-5-1-2", "123", 1234, 1.0)


def _policy(record=None):
    return dict(schema=host.PROVISION_SCHEMA, allowed_user_sids=[USER], credentials=[] if record is None else [
        dict(asdict(record), public_key=base64.b64encode(record.public_key).decode())], candidates=[])


def test_os_subject_and_real_proof_required_but_never_grant_a_mutator():
    key, record = _credential()
    broker = host.DiagnosticBroker([record])
    result = broker.dispatch({"operation": "verify_operator", "proof": asdict(_proof(key, record))}, _peer())
    assert result["principal_id"] == record.principal_id
    assert result["authority"] == [] and result["state"] == "verified-diagnostic-only"
    status = broker.dispatch({"operation": "status"}, _peer())
    assert status["mutating_operations"] == [] and status["os_transport_authenticated"]


@pytest.mark.parametrize("variation", ["other_os_user", "tampered_signature", "wrong_purpose", "revoked", "label"])
def test_signature_and_os_identity_cannot_be_replaced_by_labels_or_aliases(variation):
    key, record = _credential()
    broker = host.DiagnosticBroker([record])
    proof = asdict(_proof(key, record))
    peer = _peer(OTHER) if variation == "other_os_user" else _peer()
    if variation == "tampered_signature":
        proof["signature"] = "A" * 86
    if variation == "wrong_purpose":
        proof["purpose_digest"] = "0" * 64
    if variation == "revoked":
        broker.verifier.revoke(record.credential_id)
    if variation == "label":
        proof = "operator"
    with pytest.raises(PermissionError):
        broker.dispatch({"operation": "verify_operator", "proof": proof}, peer)


@pytest.mark.parametrize("operation", ["execute", "register", "approve", "revoke", "configure", "restore",
    "baseline.replace", "authority.expand", "safeguard.disable", "release-trust.replace", "prevention.configure"])
def test_wire_has_no_register_approval_mutation_or_arbitrary_command_surface(operation):
    with pytest.raises(PermissionError, match="closed diagnostic"):
        host.DiagnosticBroker().dispatch({"operation": operation}, _peer())


def test_candidate_catalogue_is_host_owned_digest_bound_and_held():
    row = host.ChangeCandidate("baseline-v2", "baseline.replace", "1" * 64, "2" * 64)
    broker = host.DiagnosticBroker(candidates=[row])
    request = dict(operation="candidate_status", candidate_id="baseline-v2", expected_old_digest="1" * 64)
    assert broker.dispatch(request, _peer())["state"] == "held"
    for bad in [dict(request, expected_old_digest="3" * 64), dict(request, candidate_id="C:\\target"),
                dict(request, path="C:\\target"), dict(request, candidate_id="../../target")]:
        with pytest.raises(PermissionError):
            broker.dispatch(bad, _peer())
    with pytest.raises(ValueError):
        host.ChangeCandidate("../../file", "baseline.replace", "1" * 64, "2" * 64)


def test_installer_public_policy_binds_credential_to_exact_enrolled_os_user():
    if os.name != "nt":
        pytest.skip("Native canonical SID parser")
    _, record = _credential()
    users, broker = host._parse_policy(_policy(record))
    assert users == {USER} and broker.verifier.status()["credential_count"] == 1
    _, other = _credential(OTHER)
    with pytest.raises(PermissionError, match="enrolled OS user"):
        host._parse_policy(_policy(other))
    with pytest.raises(PermissionError):
        host._parse_policy(dict(_policy(), endpoint="\\\\remote\\pipe\\inject"))
    with pytest.raises((PermissionError, ValueError)):
        host._parse_policy(dict(_policy(), allowed_user_sids=["S-1-1-0"]))


@pytest.mark.parametrize("bad", [dict(schema="wrong"), dict(schema=host.PROVISION_SCHEMA,
    allowed_user_sids=[], credentials=[], candidates=[]), dict(schema=host.PROVISION_SCHEMA,
    allowed_user_sids=[USER] * 65, credentials=[], candidates=[])])
def test_installer_policy_is_closed_and_bounded(bad):
    with pytest.raises((PermissionError, ValueError)):
        host._parse_policy(bad)


def test_native_machine_state_root_ignores_ambient_profile(monkeypatch, tmp_path):
    if os.name != "nt":
        pytest.skip("Windows known-folder API")
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path))
    monkeypatch.setenv("ANGERONA_DATA", str(tmp_path))
    root = host._fixed_state_root()
    assert root.is_absolute() and not root.is_relative_to(tmp_path)
    assert root.parts[-2:] == ("Angerona", "ResponseBroker")


def _descriptor(sddl):
    import win32security
    return win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)


@pytest.mark.parametrize("grant", ["GW", "GA", "WD", "WO", "SD", "0x40"])
def test_acl_rejects_untrusted_mutation_even_when_owner_is_system(grant):
    if os.name != "nt":
        pytest.skip("Native ACL parser")
    with pytest.raises(PermissionError, match="permits mutation"):
        host._check_acl(_descriptor(f"O:SYD:P(A;;GA;;;SY)(A;;{grant};;;{USER})"), {"S-1-5-18"}, 0xD017F)


def test_acl_allows_read_only_users_but_not_untrusted_owner_or_null_dacl():
    if os.name != "nt":
        pytest.skip("Native ACL parser")
    host._check_acl(_descriptor("O:SYD:P(A;;GA;;;SY)(A;;GR;;;BU)"), {"S-1-5-18"}, 0xD017F)
    host._check_acl(_descriptor("O:SYD:P(A;;GA;;;SY)(A;;0x1200a9;;;BU)"), {"S-1-5-18"}, 0xD0156)
    for sddl in [f"O:{USER}D:P(A;;GA;;;SY)", "O:SYD:NO_ACCESS_CONTROL"]:
        with pytest.raises(PermissionError):
            host._check_acl(_descriptor(sddl), {"S-1-5-18"}, 0xD017F)


def test_protected_path_validates_all_ancestors_and_rejects_junction_early(monkeypatch, tmp_path):
    if os.name != "nt":
        pytest.skip("Native installed path ACL")
    import win32security
    item = tmp_path / "broker.exe"
    item.write_bytes(b"inert fixture")
    queried = []
    monkeypatch.setattr(host, "_trusted_writers", lambda service_sid: {"S-1-5-18"})
    def security(path, flags):
        queried.append(Path(path))
        return _descriptor("O:SYD:P(A;;GA;;;SY)(A;;0x1200a9;;;BU)")
    monkeypatch.setattr(win32security, "GetFileSecurity", security)
    host.verify_protected_path(item, SERVICE)
    assert queried == [item, *item.parents]
    host.verify_protected_path(tmp_path, SERVICE, directory=True)
    original = Path.lstat
    def reparse(path, *args, **kwargs):
        if path == tmp_path:
            return SimpleNamespace(st_mode=0o040700, st_file_attributes=0x400)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, "lstat", reparse)
    with pytest.raises(PermissionError, match="reparse"):
        host.verify_protected_path(item, SERVICE)


def test_service_registration_requires_actual_pid_restricted_sid_and_protected_dacl(monkeypatch):
    if os.name != "nt":
        pytest.skip("SCM API composition")
    import win32service
    monkeypatch.setattr(host, "native_service_sid", lambda: SERVICE)
    monkeypatch.setattr(host, "_trusted_writers", lambda sid: {"S-1-5-18", SERVICE})
    monkeypatch.setattr(win32service, "QueryServiceStatusEx", lambda handle: {"ProcessId": 42})
    monkeypatch.setattr(win32service, "QueryServiceConfig2", lambda *args: win32service.SERVICE_SID_TYPE_RESTRICTED)
    monkeypatch.setattr(win32service, "QueryServiceObjectSecurity", lambda *args: _descriptor("O:SYD:P(A;;GA;;;SY)(A;;0x2008d;;;BU)"))
    host.verify_service_registration(object(), 42)
    with pytest.raises(PermissionError, match="process identity"):
        host.verify_service_registration(object(), 43)
    monkeypatch.setattr(win32service, "QueryServiceConfig2", lambda *args: win32service.SERVICE_SID_TYPE_UNRESTRICTED)
    with pytest.raises(PermissionError, match="restricted"):
        host.verify_service_registration(object(), 42)


def test_service_acl_generic_execute_is_mutating_even_though_file_execute_is_read_only(monkeypatch):
    if os.name != "nt":
        pytest.skip("Native service ACL schema")
    import win32service
    monkeypatch.setattr(host, "native_service_sid", lambda: SERVICE)
    monkeypatch.setattr(host, "_trusted_writers", lambda sid: {"S-1-5-18", SERVICE})
    monkeypatch.setattr(win32service, "QueryServiceStatusEx", lambda handle: {"ProcessId": 42})
    monkeypatch.setattr(win32service, "QueryServiceConfig2", lambda *args: win32service.SERVICE_SID_TYPE_RESTRICTED)
    monkeypatch.setattr(win32service, "QueryServiceObjectSecurity", lambda *args: _descriptor("O:SYD:P(A;;GA;;;SY)(A;;GX;;;BU)"))
    with pytest.raises(PermissionError, match="mutation"):
        host.verify_service_registration(object(), 42)


@pytest.mark.parametrize("user,enabled,restricted", [
    ("S-1-5-18", True, True), ("S-1-5-18", True, False),
    ("S-1-5-18", False, True), (USER, True, True),
])
def test_actual_restricted_token_required_not_just_service_configuration(monkeypatch, user, enabled, restricted):
    if os.name != "nt":
        pytest.skip("Native service token schema")
    import win32security
    closed = []
    token = SimpleNamespace(Close=lambda: closed.append(True))
    monkeypatch.setattr(win32security, "OpenProcessToken", lambda *args: token)
    sid = win32security.ConvertStringSidToSid
    values = {
        win32security.TokenUser: (sid(user), 0),
        win32security.TokenGroups: [(sid(SERVICE), 4 if enabled else 0x10)],
        win32security.TokenRestrictedSids: [(sid(SERVICE), 0)] if restricted else [],
    }
    monkeypatch.setattr(win32security, "GetTokenInformation", lambda token, kind: values[kind])
    if user == "S-1-5-18" and enabled and restricted:
        host.verify_service_token(object(), SERVICE)
    else:
        with pytest.raises(PermissionError, match="restricted SCM"):
            host.verify_service_token(object(), SERVICE)
    assert closed == [True]


def test_source_factory_refuses_before_fixed_state_or_listener(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(host, "_fixed_state_root", lambda: pytest.fail("source accessed machine state"))
    monkeypatch.setattr(host, "PrivilegedPipeServer", lambda *args, **kwargs: pytest.fail("source created service listener"))
    with pytest.raises(PermissionError, match="signed frozen"):
        host.prepare_runtime()


def test_frozen_missing_pins_refuses_before_fixed_state_or_listener(monkeypatch):
    from angerona.core import windows_package_identity
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "platform", "win32")
    assert not windows_package_identity.EXPECTED_PACKAGE_FAMILY_NAME
    monkeypatch.setattr(host, "_fixed_state_root", lambda: pytest.fail("unprovisioned service accessed state"))
    with pytest.raises(PermissionError, match="not provisioned"):
        host.prepare_runtime()


@pytest.mark.parametrize("elevated", [False, True])
def test_source_entry_service_cannot_elevate_or_start_graph(monkeypatch, elevated):
    from angerona import __main__ as entry
    from angerona.core import privilege, singleton
    monkeypatch.setattr(sys, "argv", ["angerona", "--response-service"])
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: elevated)
    monkeypatch.setattr(privilege, "ensure_admin", lambda: pytest.fail("source requested elevation"))
    monkeypatch.setattr(singleton, "acquire_single_instance", lambda: pytest.fail("broker imported desktop singleton"))
    assert entry.main() == 2


def test_service_route_conflicts_are_rejected_before_dispatch(monkeypatch):
    from angerona import __main__ as entry
    monkeypatch.setattr(sys, "argv", ["angerona", "--response-service", "--engine-serve"])
    monkeypatch.setattr(entry, "_run_engine_mode", lambda *args, **kwargs: pytest.fail("conflicting route ran"))
    assert entry.main() == 2


def test_broker_import_and_refusal_never_load_gui_or_sensor_graph():
    script = """
import sys
from angerona.core.response_service_host import prepare_runtime
try:
    prepare_runtime()
except PermissionError:
    pass
else:
    raise AssertionError('source service accepted')
assert not any(n.startswith(('PySide6','angerona.app','angerona.modules','angerona.core.module_manager','angerona.core.config')) for n in sys.modules)
print('isolated-host-refused')
"""
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=15, env=env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "isolated-host-refused"


def test_native_provisioning_read_keeps_installer_file_bounded_and_unchanged(monkeypatch, tmp_path):
    if os.name != "nt":
        pytest.skip("Native retained file handle")
    from angerona.core.engine_transport import canonical
    path = tmp_path / "public-provisioning.json"
    value = _policy()
    path.write_bytes(canonical(value))
    observed = []
    # Only this test composes an inert normal-user fixture. The production
    # factory has no bypass flag and always requires installer ACL checks.
    monkeypatch.setattr(host, "verify_protected_path", lambda p, sid: observed.append((p, sid)))
    assert host._read_provisioning(path, SERVICE) == value
    assert observed == [(path, SERVICE)]
    assert path.read_bytes() == canonical(value)
    path.write_bytes(b"x" * (host._MAX_POLICY + 1))
    with pytest.raises(PermissionError, match="custody"):
        host._read_provisioning(path, SERVICE)


def test_native_os_user_plus_real_signature_complete_diagnostic_roundtrip():
    if os.name != "nt":
        pytest.skip("Native pipe OS token capture")
    import uuid
    from angerona.core.approval_identity import current_os_identity
    from angerona.core.privileged_pipe import PrivilegedPipeClient, PrivilegedPipeServer
    identity = current_os_identity()
    key, record = _credential(identity.subject)
    broker = host.DiagnosticBroker([record])
    server = PrivilegedPipeServer(broker.dispatch, server_sid=identity.subject,
        allowed_sids=[identity.subject], endpoint=r"\\.\pipe\Angerona.Test.SignedOperator." + uuid.uuid4().hex)
    server.start()
    try:
        client = PrivilegedPipeClient(endpoint=server.endpoint, expected_pid=os.getpid(),
            _server_verifier=lambda process, pid: None)
        result = client.exchange({"operation": "verify_operator", "proof": asdict(_proof(key, record))})
        assert result["principal_id"] == record.principal_id
        assert result["authenticated_subject"] == identity.subject and result["authority"] == []
    finally:
        assert server.stop(5), server.error
