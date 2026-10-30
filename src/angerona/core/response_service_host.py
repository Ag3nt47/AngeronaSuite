"""Minimal SCM broker host; no desktop, sensor graph, signing keys or mutators.

The independently signed installer must supply immutable MSIX pins, the fixed
restricted service SID, protected installation/state ACLs and public enrollment
policy. This checkout deliberately supplies none of those deployment proofs.
The default v1 wire surface is diagnostic only. Exact opt-in v2 provisioning
can compose the reviewed managed driver-policy backend. Authentication alone
does not register an executor or authorize baseline/firewall/file changes.
"""
from __future__ import annotations

import base64
import ctypes
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import threading

from .approval_identity import ApprovalIdentityVerifier, PrincipalCredential, SignedPrincipalProof
from .engine_transport import canonical, decode
from .privileged_pipe import NativePeer, SERVICE_NAME, PrivilegedPipeServer

PROVISION_SCHEMA = "angerona.response-service.provisioning.v1"
DRIVER_PROVISION_SCHEMA = "angerona.response-service.provisioning.v2"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")
_CHANGE_KINDS = frozenset({"baseline.replace", "authority.expand", "safeguard.disable", "release-trust.replace"})
_MAX_POLICY = 64 * 1024


def native_service_sid():
    import win32security
    sid, _, _ = win32security.LookupAccountName(None, "NT SERVICE\\" + SERVICE_NAME)
    value = win32security.ConvertSidToStringSid(sid)
    if not value.startswith("S-1-5-80-"):
        raise PermissionError("Dedicated SCM service SID unavailable")
    return value


def _trusted_writers(service_sid):
    import win32security
    trusted_installer, _, _ = win32security.LookupAccountName(None, "NT SERVICE\\TrustedInstaller")
    return {"S-1-5-18", "S-1-5-32-544", service_sid,
            win32security.ConvertSidToStringSid(trusted_installer)}


def _check_acl(descriptor, trusted, write_mask):
    """Conservative explicit-ACE check; complex/conditional grants fail closed."""
    import win32security
    owner = descriptor.GetSecurityDescriptorOwner()
    if owner is None or win32security.ConvertSidToStringSid(owner) not in trusted:
        raise PermissionError("Broker object owner is outside installed authority")
    acl = descriptor.GetSecurityDescriptorDacl()
    if acl is None:
        raise PermissionError("Broker object has an unprotected null DACL")
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        kind, flags = ace[0]
        if flags & 0x08:  # INHERIT_ONLY_ACE does not grant access to this object.
            continue
        if kind == win32security.ACCESS_DENIED_ACE_TYPE:
            continue
        if kind != win32security.ACCESS_ALLOWED_ACE_TYPE or len(ace) != 3:
            raise PermissionError("Broker object has unsupported access-control grants")
        sid = win32security.ConvertSidToStringSid(ace[2])
        # GENERIC_ALL/WRITE can include mapped rights absent from the raw mask.
        if sid not in trusted and ace[1] & (write_mask | 0x50000000):
            raise PermissionError("Broker object permits mutation outside installed authority")


def verify_protected_path(path, service_sid, *, directory=False):
    """Read-only validation, including every ancestor; never fixes host ACLs."""
    if os.name != "nt":
        raise PermissionError("Protected broker deployment requires Windows")
    import win32security
    target = Path(path)
    if not target.is_absolute() or target.drive.startswith("\\\\") or ".." in target.parts:
        raise PermissionError("Broker paths must be absolute local installed paths")
    trusted = _trusted_writers(service_sid)
    for index, item in enumerate((target, *target.parents)):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PermissionError("Broker installed paths cannot traverse reparse points")
        if index == 0 and not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise PermissionError("Broker installed object type differs from provisioning")
        if index == 0 and not directory and info.st_nlink != 1:
            raise PermissionError("Broker installed file has multiple links")
        descriptor = win32security.GetFileSecurity(str(item), 0x5)  # owner + DACL
        # An ancestor's writable unrelated child slots alone cannot replace an
        # existing protected child. DELETE_CHILD/DACL/owner changes can.
        writes = 0x000D0040 if index else (0x000D0156 if directory else 0x000D0116)
        _check_acl(descriptor, trusted, writes)


def verify_service_registration(service, pid):
    """Require actual restricted service identity and immutable SCM policy."""
    import win32service
    if win32service.QueryServiceStatusEx(service).get("ProcessId") != pid:
        raise PermissionError("SCM broker process identity differs from the native pipe")
    sid_type = win32service.QueryServiceConfig2(service, win32service.SERVICE_CONFIG_SERVICE_SID_INFO)
    if sid_type != win32service.SERVICE_SID_TYPE_RESTRICTED:
        raise PermissionError("Installer has not provisioned a restricted broker service SID")
    descriptor = win32service.QueryServiceObjectSecurity(service, 0x5)
    # SERVICE_GENERIC_EXECUTE maps to START/STOP/PAUSE/USER_DEFINED_CONTROL;
    # unlike file execute permission it is a service mutation grant.
    _check_acl(descriptor, _trusted_writers(native_service_sid()), 0x200D0172)


def verify_service_token(process, service_sid, *, _owner=None):
    """Configuration alone does not prove the already-running token rotated."""
    import win32security
    if _owner is None:
        from .native_broker_custody import NativeCustodyOwner
        with NativeCustodyOwner() as owner:
            return verify_service_token(process, service_sid, _owner=owner)
    token = _owner.open(win32security.OpenProcessToken, process, 8)
    user = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
    groups = win32security.GetTokenInformation(token, win32security.TokenGroups)
    restricted = win32security.GetTokenInformation(token, win32security.TokenRestrictedSids)
    enabled = any(win32security.ConvertSidToStringSid(sid) == service_sid and flags & 4 and not flags & 0x10
                  for sid, flags in groups)
    isolated = any(win32security.ConvertSidToStringSid(sid) == service_sid for sid, _ in restricted)
    if user not in {service_sid, "S-1-5-18", "S-1-5-19", "S-1-5-20"} or not enabled or not isolated:
        raise PermissionError("Process lacks the actual enabled and restricted SCM service identity")


def _fixed_state_root():
    # Native known-folder query; environment ANGERONA_DATA/PROGRAMDATA ignored.
    buffer = ctypes.create_unicode_buffer(32768)
    function = ctypes.WinDLL("shell32", use_last_error=True).SHGetFolderPathW
    function.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p]
    function.restype = ctypes.c_long
    if function(None, 0x23, None, 0, buffer) != 0:
        raise PermissionError("Machine broker state location unavailable")
    return Path(buffer.value) / "Angerona" / "ResponseBroker"


def _read_provisioning(path, service_sid):
    """Installer-owned public policy, pinned against write/delete while read."""
    from .driver_policy_service import ProtectedArtifactReader
    reader = ProtectedArtifactReader(lambda item: verify_protected_path(item, service_sid))
    return decode(reader(path, _MAX_POLICY))


@dataclass(frozen=True)
class ChangeCandidate:
    candidate_id: str
    kind: str
    expected_old_digest: str
    proposed_digest: str

    def __post_init__(self):
        if (not isinstance(self.candidate_id, str) or not _ID.fullmatch(self.candidate_id)
                or self.kind not in _CHANGE_KINDS
                or not isinstance(self.expected_old_digest, str) or not _HEX.fullmatch(self.expected_old_digest)
                or not isinstance(self.proposed_digest, str) or not _HEX.fullmatch(self.proposed_digest)):
            raise ValueError("Invalid backend-owned critical change candidate")


class DiagnosticBroker:
    """A closed read-only surface. OS identity plus proof never implies action."""
    def __init__(self, credentials=(), candidates=()):
        self.verifier = ApprovalIdentityVerifier(credentials)
        rows = tuple(candidates)
        if len(rows) > 128 or any(not isinstance(row, ChangeCandidate) for row in rows):
            raise ValueError("Invalid bounded backend candidate catalogue")
        self.candidates = {row.candidate_id: row for row in rows}
        if len(self.candidates) != len(rows):
            raise ValueError("Duplicate backend candidate ID")

    @staticmethod
    def authentication_digest():
        return hashlib.sha256(canonical({"protocol": "angerona-os-broker-pipe-v1",
                                         "operation": "verify_operator", "authority": "diagnostic-only"})).hexdigest()

    def dispatch(self, request, peer):
        if not isinstance(peer, NativePeer) or not isinstance(request, dict):
            raise PermissionError("Native authenticated peer required")
        operation = request.get("operation")
        if operation == "status" and set(request) == {"operation"}:
            return dict(state="diagnostic-only", os_transport_authenticated=True,
                        authenticated_subject=peer.user_sid, logon_sid=peer.logon_sid,
                        mutating_operations=[], registered_candidates=len(self.candidates),
                        reason="No reviewed privileged executor is registered; changes remain unavailable")
        if operation == "verify_operator" and set(request) == {"operation", "proof"}:
            if not isinstance(request["proof"], dict):
                raise PermissionError("Typed signed operator proof required")
            proof = SignedPrincipalProof(**request["proof"])
            if proof.issuer != "windows-token" or proof.subject != peer.user_sid:
                raise PermissionError("Credential issuer/subject does not match the actual OS pipe user")
            principal = self.verifier.verify(proof, self.authentication_digest())
            return dict(state="verified-diagnostic-only", principal_id=principal.principal_id,
                        authenticated_subject=peer.user_sid, authority=[], expires_at=principal.expires_at)
        if operation == "candidate_status" and set(request) == {"operation", "candidate_id", "expected_old_digest"}:
            row = self.candidates.get(request["candidate_id"]) if isinstance(request["candidate_id"], str) else None
            if row is None or row.expected_old_digest != request["expected_old_digest"]:
                raise PermissionError("Unknown candidate or stale expected state")
            return dict(candidate_id=row.candidate_id, kind=row.kind, state="held",
                        expected_old_digest=row.expected_old_digest, proposed_digest=row.proposed_digest,
                        reason="A reviewed typed executor and verified outcome are not provisioned")
        raise PermissionError("Operation is outside the closed diagnostic broker surface")


def _parse_policy(value):
    from .privileged_pipe import _sid
    if (not isinstance(value, dict) or set(value) != {"schema", "allowed_user_sids", "credentials", "candidates"}
            or value["schema"] != PROVISION_SCHEMA):
        raise PermissionError("Installer public broker provisioning schema unavailable")
    if (not isinstance(value["allowed_user_sids"], list) or not 1 <= len(value["allowed_user_sids"]) <= 64
            or not isinstance(value["credentials"], list) or len(value["credentials"]) > 128
            or not isinstance(value["candidates"], list) or len(value["candidates"]) > 128):
        raise PermissionError("Installer public broker provisioning exceeds bounds")
    users = frozenset(_sid(sid) for sid in value["allowed_user_sids"])
    credentials = []
    for row in value["credentials"]:
        if not isinstance(row, dict) or set(row) != {"credential_id", "issuer", "subject", "public_key", "enabled", "expires_at"}:
            raise PermissionError("Installer credential schema invalid")
        if row["issuer"] != "windows-token" or row["subject"] not in users:
            raise PermissionError("Installer credential is not bound to an enrolled OS user")
        key = base64.b64decode(row["public_key"], validate=True)
        if base64.b64encode(key).decode() != row["public_key"]:
            raise PermissionError("Noncanonical public credential encoding")
        credentials.append(PrincipalCredential(**dict(row, public_key=key)))
    candidates = [ChangeCandidate(**row) for row in value["candidates"]]
    return users, DiagnosticBroker(credentials, candidates)


def _parse_runtime_policy(value):
    """V1 remains closed diagnostic-only; v2 grants one explicit profile."""
    if isinstance(value, dict) and value.get("schema") == DRIVER_PROVISION_SCHEMA:
        if set(value) != {"schema", "allowed_user_sids", "credentials", "candidates", "driver_policy"}:
            raise PermissionError("Exact installed driver-policy provisioning required")
        profile = value["driver_policy"]
        if (type(profile) is not dict or set(profile) != {"profile", "manifest_sha256"}
                or profile["profile"] != "own-unsigned-multiple-policy"
                or type(profile["manifest_sha256"]) is not str or not _HEX.fullmatch(profile["manifest_sha256"])):
            raise PermissionError("Pinned installed driver-policy profile required")
        users, diagnostic = _parse_policy({key: item for key, item in dict(value, schema=PROVISION_SCHEMA).items()
                                          if key != "driver_policy"})
        return users, diagnostic, profile["manifest_sha256"]
    users, diagnostic = _parse_policy(value)
    return users, diagnostic, None


def prepare_runtime():
    """Production-only factory; fails before storage creation or listener start."""
    from .engine_windows_service import require_package_service
    require_package_service()
    import win32api
    import win32service
    from .privileged_pipe import _package_path, _native_package_string, _process_image
    from .native_broker_custody import NativeCustodyOwner
    service_sid = native_service_sid()
    with NativeCustodyOwner() as owner:
        verify_service_token(win32api.GetCurrentProcess(), service_sid, _owner=owner)
        scm = owner.open(win32service.OpenSCManager, None, None, 1, closer=win32service.CloseServiceHandle)
        service = owner.open(win32service.OpenService, scm, SERVICE_NAME, 0x20005, closer=win32service.CloseServiceHandle)
        verify_service_registration(service, os.getpid())
    process = win32api.GetCurrentProcess()
    package = _package_path(_native_package_string("GetPackageFullName", process))
    image = _process_image(process)
    if not image.is_relative_to(package):
        raise PermissionError("Service image is outside its OS-bound installed package")
    verify_protected_path(package, service_sid, directory=True)
    verify_protected_path(image, service_sid)
    root = _fixed_state_root()
    verify_protected_path(root, service_sid, directory=True)
    policy_path = root / "provisioning.json"
    initial = _read_provisioning(policy_path, service_sid)
    allowed, diagnostic, driver_pin = _parse_runtime_policy(initial)

    if driver_pin is not None:
        from .driver_policy_service import DriverPolicyServiceRuntime, DriverPolicyPipeServer, ProtectedArtifactReader
        driver_root = root / "DriverPolicy"
        verify_protected_path(driver_root, service_sid, directory=True)
        initial_bytes = canonical(initial)

        def guard():
            # No profile reload can silently replace authority or resurrect a
            # proposal. Any enrollment/revocation generation change holds all
            # dispatch/native barriers until the old owner retires safely.
            require_package_service()
            with NativeCustodyOwner() as owner:
                verify_service_token(win32api.GetCurrentProcess(), service_sid, _owner=owner)
                scm_now = owner.open(win32service.OpenSCManager, None, None, 1, closer=win32service.CloseServiceHandle)
                service_now = owner.open(win32service.OpenService, scm_now, SERVICE_NAME, 0x20005, closer=win32service.CloseServiceHandle)
                verify_service_registration(service_now, os.getpid())
            if (_package_path(_native_package_string("GetPackageFullName", process)) != package
                    or _process_image(process) != image):
                return False
            verify_protected_path(package, service_sid, directory=True)
            verify_protected_path(image, service_sid)
            verify_protected_path(root, service_sid, directory=True)
            verify_protected_path(driver_root, service_sid, directory=True)
            return canonical(_read_provisioning(policy_path, service_sid)) == initial_bytes

        reader = ProtectedArtifactReader(lambda path: verify_protected_path(path, service_sid))
        runtime = DriverPolicyServiceRuntime(driver_root, manifest_sha256=driver_pin,
            credentials=tuple(diagnostic.verifier.credentials.values()), installed_guard=guard, read_artifact=reader)
        try:
            def driver_dispatch(request, peer):
                if not runtime._guard():
                    runtime.fence_profile()
                    raise PermissionError("Installed response profile changed or native custody is held")
                return runtime.dispatch(request, peer)
            listener = DriverPolicyPipeServer(driver_dispatch, server_sid=service_sid, allowed_sids=allowed)
            runtime.attach_listener(listener)
            return runtime
        except BaseException:
            runtime.stop()
            raise

    def dispatch(request, peer):
        # Reload protected public bindings/revocations for every diagnostic.
        current_users, backend = _parse_policy(_read_provisioning(policy_path, service_sid))
        if peer.user_sid not in current_users:
            raise PermissionError("OS user was revoked by protected installer policy")
        return backend.dispatch(request, peer)

    return PrivilegedPipeServer(dispatch, server_sid=service_sid, allowed_sids=allowed)


def run_dispatcher():
    """SCM service entry; never builds the desktop/headless sensor graph."""
    from .engine_windows_service import require_package_service
    require_package_service()
    import servicemanager
    import win32service
    import win32serviceutil

    class AngeronaResponseService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = "Angerona Isolated Response Broker"
        _svc_description_ = "OS-authenticated diagnostic broker; privileged executors require separate provisioning"

        def __init__(self, args):
            super().__init__(args)
            self.stop_event = threading.Event()

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            self.stop_event.set()

        def SvcShutdown(self):
            self.SvcStop()

        def SvcDoRun(self):
            server = prepare_runtime()
            try:
                server.start()
                while not self.stop_event.wait(0.1) and not server.stop_event.is_set():
                    pass
            finally:
                if not server.stop():
                    raise RuntimeError(server.error or "Broker native shutdown remains pending")
            if server.error:
                raise RuntimeError(server.error)

    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(AngeronaResponseService)
    servicemanager.StartServiceCtrlDispatcher()
    return 0
