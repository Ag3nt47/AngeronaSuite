"""Proof-carrying detector upgrades for Angerona's benign red-team markers.

The red-team remediation button used to mark database rows PATCHED without
changing a detector.  Purple Guard instead installs narrowly scoped signatures
for the exact inert artifacts a missed drill demonstrated.  A later drill must
flow through marker -> this detector -> EventBus -> flight recorder -> SOAR
before the AAR can report detection or remediation.

It never reads red-team history and it deliberately ignores the benign-noise
marker.  Policies are local, reviewable JSON and affect only ``_redteam_*``
files in Angerona's dedicated drill sandbox.
"""
from __future__ import annotations

import copy
import ctypes
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import sys
import threading
import time
import uuid
import weakref
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeAlias

from angerona.core.atomic_io import replace_with_retry
from angerona.core.data_paths import data_dir as canonical_data_dir
from angerona.core.eventbus import Event, EventBus
from angerona.core.module_base import BaseModule, Severity
from angerona.shark.run_manifest import (
    MAX_ADMITTED_DRILL_SECONDS,
    RED_TEAM_BASE_DETECTION_CONTRACTS,
    RED_TEAM_COMPREHENSIVE_DETECTION_CONTRACTS,
)

_BASE_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("lsass_dump", "T1003", "credential-access marker"),
    ("wmi_subscription", "T1546.003", "WMI-persistence marker"),
    ("amsi_bypass", "T1070", "defense-evasion marker"),
    ("schtask", "T1053.005", "scheduled-task marker"),
    ("runkey", "T1547.001", "Run-key marker"),
    ("psexec", "T1021.002", "lateral-movement marker"),
    ("exfil_stage", "T1074", "exfil-staging marker"),
    ("readme_decrypt", "T1486", "ransomware marker"),
    ("invoice_macro", "T1566.001", "initial-access marker"),
    ("uac_bypass", "T1548.002", "privilege-escalation marker"),
    ("c2_beacon_cfg", "T1071", "command-and-control marker"),
    ("wiper", "T1485", "data-destruction marker"),
)
_COMPREHENSIVE_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("public_app_probe", "T1190", "public-facing-application marker"),
    ("user_execution_probe", "T1204.002", "user-execution marker"),
    ("credential_store_probe", "T1555", "credential-store marker"),
    ("unsecured_credentials_probe", "T1552.001", "unsecured-credentials marker"),
    ("account_discovery_probe", "T1087", "account-discovery marker"),
    ("network_service_probe", "T1046", "network-service-discovery marker"),
    ("network_connections_probe", "T1049", "network-connections-discovery marker"),
    ("software_discovery_probe", "T1518", "software-discovery marker"),
    ("privilege_exploit_probe", "T1068", "privilege-exploitation marker"),
    ("create_account_probe", "T1136.001", "account-persistence marker"),
    ("web_shell_probe", "T1505.003", "web-shell-persistence marker"),
    ("dll_sideload_probe", "T1574.002", "DLL-side-loading marker"),
    ("obfuscated_file_probe", "T1027", "obfuscated-file marker"),
    ("masquerading_probe", "T1036", "masquerading marker"),
    ("impair_defenses_probe", "T1562.001", "impair-defenses marker"),
    ("remote_desktop_probe", "T1021.001", "remote-desktop marker"),
    ("wmi_lateral_probe", "T1047", "WMI-lateral-movement marker"),
    ("tool_transfer_probe", "T1105", "ingress-tool-transfer marker"),
    ("protocol_tunnel_probe", "T1572", "protocol-tunneling marker"),
    ("automated_collection_probe", "T1119", "automated-collection marker"),
    ("local_data_probe", "T1005", "local-system-data marker"),
    ("exfil_c2_probe", "T1041", "exfiltration-over-C2 marker"),
    ("exfil_web_probe", "T1567", "exfiltration-over-web-service marker"),
    ("inhibit_recovery_probe", "T1490", "inhibit-system-recovery marker"),
)
_PATTERNS = (*_BASE_PATTERNS, *_COMPREHENSIVE_PATTERNS)
_PROCESS_TECHNIQUE = "T1059"
_PROCESS_LABEL = "benign tagged execution marker"
_PROCESS_TOKEN = re.compile(r"\bANGERONA_REDTEAM_[0-9a-f]{8}\b", re.I)
_PRACTICE_FILE_TOKEN = re.compile(
    r"_practice_(?P<id>[0-9a-f]{8,64})\.txt$",
    re.I,
)
_SAFE_LINEAGE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_POLICY_CACHE_UNSET = object()
_PathInput: TypeAlias = str | os.PathLike[str]
_RUNTIME_TARGETS: set[Path] = set()
_RUNTIME_TARGETS_LOCK = threading.RLock()
REDTEAM_VALIDATION_TECHNIQUES = frozenset(
    [mitre for _token, mitre, _label in _BASE_PATTERNS] + [_PROCESS_TECHNIQUE]
)
REDTEAM_COMPREHENSIVE_VALIDATION_TECHNIQUES = frozenset(
    [mitre for _token, mitre, _label in _PATTERNS] + [_PROCESS_TECHNIQUE]
)


class RedTeamValidationError(RuntimeError):
    """The drill validation plane could not prove it was ready."""


_LEASE_ISSUER = object()
_LEASE_ACQUIRE_TTL_S = 30.0
_LEASE_DEFAULT_RUN_TTL_S = 600.0
_LEASE_PROCESS_EPOCH = secrets.token_hex(32)
_MAX_VALIDATION_TARGET_MARKERS = 4096


@dataclass(slots=True)
class _LeaseAuthorityState:
    """Issuer-owned authority that is never inferred from lease attributes.

    The public lease is intentionally a small capability handle.  All identity,
    deadlines, enrollment and held artifact descriptors live in this central
    registry so replacing attributes or instance methods cannot rebind the
    capability.  This is an in-process defense-in-depth boundary; hostile
    extensions still require process isolation for a strong memory boundary.
    """

    module: object
    target: Path
    data_root: Path
    manager: object
    bus: object
    recorder: object
    started_temporarily: bool
    target_registered_by_lease: bool
    previous_chill_paused: bool
    readiness: dict[str, Any]
    lease_id: str
    receipt_id: str
    key: bytes
    issued_at: float
    issued_monotonic: float
    acquire_deadline_monotonic: float
    process_epoch: str
    target_handle: int | None
    target_identity: dict[str, object]
    target_created_by_lease: bool
    process_module: object | None = None
    process_started_temporarily: bool = False
    process_inserted_by_lease: bool = False
    process_previous_chill_paused: bool = False
    run_deadline_monotonic: float = 0.0
    consumed: bool = False
    released: bool = False
    bound_run_id: str = ""
    consumed_receipt: dict[str, Any] | None = None
    native_modules: dict[str, object] | None = None
    native_generations: dict[str, int] | None = None
    native_capabilities: dict[str, object] | None = None
    native_verifiers: dict[str, bytes] | None = None
    fim_scan_claims: dict[str, tuple[int, set[str]]] | None = None
    artifact_handles: dict[str, tuple[int, dict[str, object]]] | None = None
    process_challenges: dict[str, dict[str, object]] | None = None
    lock: threading.RLock | None = None

    def __post_init__(self) -> None:
        self.consumed_receipt = {}
        self.native_modules = {}
        self.native_generations = {}
        self.native_capabilities = {}
        self.native_verifiers = {}
        self.fim_scan_claims = {}
        self.artifact_handles = {}
        self.process_challenges = {}
        self.lock = threading.RLock()


_LEASE_AUTHORITY_LOCK = threading.RLock()
_LEASE_AUTHORITIES: "weakref.WeakKeyDictionary[object, _LeaseAuthorityState]" = (
    weakref.WeakKeyDictionary()
)


class _LeaseAuthorityAccess:
    """Opaque exact-lease handle; never return the live state or signing key.

    CPython introspection is not a memory-isolation boundary. This wrapper
    removes the ordinary module API that previously handed callers the central
    state and HMAC key, while retaining compatibility diagnostics through
    narrowly forwarded non-key fields.
    """

    __slots__ = ("__state",)

    _OPAQUE_FIELDS = frozenset(
        {
            "native_modules",
            "native_generations",
            "native_capabilities",
            "native_verifiers",
            "fim_scan_claims",
        }
    )

    def __init__(self, state: _LeaseAuthorityState) -> None:
        object.__setattr__(self, "_LeaseAuthorityAccess__state", state)

    @property
    def key(self) -> bytes:
        """Public verification material, deliberately not the HMAC secret."""
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        return hashlib.sha256(
            b"angerona-redteam-public-verification-v1\0" + state.key
        ).digest()

    def _sign_hmac(self, payload: bytes) -> str:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        return hmac.new(state.key, payload, hashlib.sha256).hexdigest()

    def _verify_hmac(self, supplied: str, payload: bytes) -> bool:
        return hmac.compare_digest(supplied, self._sign_hmac(payload))

    def _rotate_hmac_authority(self) -> None:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        state.key = secrets.token_bytes(32)

    def _native_module(self, module_name: str) -> object | None:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        return (state.native_modules or {}).get(module_name)

    def _native_generation(self, module_name: str) -> int:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        return int((state.native_generations or {}).get(module_name, -1))

    def _native_capability_is(self, module_name: str, capability: object) -> bool:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        return (state.native_capabilities or {}).get(module_name) is capability

    def _native_public_verifier(self, module_name: str) -> bytes | None:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        material = (state.native_verifiers or {}).get(module_name)
        return bytes(material) if isinstance(material, bytes) else None

    def _reset_native_enrollment(self) -> None:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        state.native_modules = {}
        state.native_generations = {}
        state.native_capabilities = {}
        state.native_verifiers = {}
        state.fim_scan_claims = {}

    def _enroll_native(
        self,
        module_name: str,
        producer: object,
        generation: int,
        capability: object,
        public_verifier: bytes,
    ) -> None:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        assert state.native_modules is not None
        assert state.native_generations is not None
        assert state.native_capabilities is not None
        assert state.native_verifiers is not None
        state.native_modules[module_name] = producer
        state.native_generations[module_name] = int(generation)
        state.native_capabilities[module_name] = capability
        state.native_verifiers[module_name] = bytes(public_verifier)

    def _claim_fim_scan(
        self, module_name: str, scan_generation: int, scan_claim: str
    ) -> bool:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        claims = state.fim_scan_claims
        if claims is None:
            return False
        prior_generation, issued_claims = claims.get(module_name, (0, set()))
        if scan_generation < prior_generation:
            return False
        if scan_generation > prior_generation:
            issued_claims = set()
            claims[module_name] = (scan_generation, issued_claims)
        if scan_claim in issued_claims:
            return False
        issued_claims.add(scan_claim)
        return True

    def _fim_scan_claim_was_issued(
        self, module_name: str, scan_generation: object, scan_claim: str
    ) -> bool:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        issued_generation, issued_claims = (state.fim_scan_claims or {}).get(
            module_name, (0, set())
        )
        return scan_generation == issued_generation and scan_claim in issued_claims

    def _revoke_native_enrollment(self) -> None:
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        for name, capability in tuple((state.native_capabilities or {}).items()):
            producer = (state.native_modules or {}).get(name)
            binder = getattr(producer, "bind_redteam_receipt_capability", None)
            if callable(binder):
                try:
                    binder(None, expected=capability)
                except Exception:
                    pass
        (state.native_capabilities or {}).clear()
        (state.native_verifiers or {}).clear()
        (state.fim_scan_claims or {}).clear()

    def __getattr__(self, name: str) -> object:
        if (
            name in self._OPAQUE_FIELDS
            or name.startswith("verify_")
            or name.endswith("_impl")
        ):
            raise AttributeError(name)
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        return getattr(state, name)

    def __setattr__(self, name: str, value: object) -> None:
        if (
            name == "key"
            or name in self._OPAQUE_FIELDS
            or name.startswith("verify_")
            or name.endswith("_impl")
        ):
            raise AttributeError(name)
        state = object.__getattribute__(self, "_LeaseAuthorityAccess__state")
        if not hasattr(state, name):
            raise AttributeError(name)
        setattr(state, name, value)


def _lease_authority(lease: object) -> _LeaseAuthorityAccess:
    """Return an opaque view for one issuer-enrolled exact lease."""
    if type(lease) is not RedTeamValidationLease:
        raise RedTeamValidationError("the exact validation lease type is required")
    with _LEASE_AUTHORITY_LOCK:
        state = _LEASE_AUTHORITIES.get(lease)
    if state is None or state.process_epoch != _LEASE_PROCESS_EPOCH:
        raise RedTeamValidationError("validation lease authority is absent or stale")
    return _LeaseAuthorityAccess(state)


class _ProducerReceiptCapability:
    """One-lease receipt capability bound to one exact producer and code site.

    The capability deliberately exposes no signing key and refuses calls that
    do not originate from the enrolled producer object's canonical observation
    method.  This is still an in-process trust boundary (Python extensions in
    the same interpreter are not a memory-isolation boundary), but it removes
    the former public ``attest_fim_scan_observation`` signing oracle and binds
    every receipt to the detector object, lifecycle generation, observation
    site, and a monotonic one-use serial.
    """

    __slots__ = (
        "__lease_ref",
        "__producer_ref",
        "__kind",
        "__site_code",
        "__site_sha256",
        "__artifact_validator",
        "__process_validator",
        "__serial",
        "__private_signer",
        "__public_verification_material",
    )

    def __init__(
        self,
        *,
        lease: object,
        producer: object,
        kind: str,
        site_code: object,
        artifact_validator: object,
        process_validator: object,
    ) -> None:
        self.__lease_ref = weakref.ref(lease)
        self.__producer_ref = weakref.ref(producer)
        self.__kind = str(kind)
        sites = site_code if isinstance(site_code, tuple) else (site_code,)
        self.__site_code = tuple(sites)
        site_identity = [
            {
                "module": str(getattr(code, "co_filename", "")),
                "name": str(getattr(code, "co_qualname", "")),
                "bytecode_sha256": hashlib.sha256(
                    bytes(getattr(code, "co_code", b""))
                ).hexdigest(),
            }
            for code in sites
        ]
        self.__site_sha256 = _sha256(site_identity)
        self.__artifact_validator = artifact_validator
        self.__process_validator = process_validator
        self.__serial = 0
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        self.__private_signer = Ed25519PrivateKey.generate()
        self.__public_verification_material = (
            self.__private_signer.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
        )

    def public_verification_material(self) -> bytes:
        """Return public-only receipt verification material."""
        return bytes(self.__public_verification_material)

    def _authority(
        self, producer: object
    ) -> tuple[object, _LeaseAuthorityAccess] | None:
        lease = self.__lease_ref()
        enrolled = self.__producer_ref()
        if lease is None or enrolled is None or producer is not enrolled:
            return None
        try:
            state = _lease_authority(lease)
        except RedTeamValidationError:
            return None
        return lease, state

    def _canonical_caller(self, producer: object) -> bool:
        try:
            frame = sys._getframe(2)
            for _depth in range(2):
                if (
                    frame.f_code in self.__site_code
                    and frame.f_locals.get("self") is producer
                ):
                    return True
                if frame.f_back is None:
                    break
                frame = frame.f_back
            return False
        except (AttributeError, ValueError):
            return False
        finally:
            try:
                del frame
            except UnboundLocalError:
                pass

    def issue_fim_observation(
        self,
        producer: object,
        *,
        message: str,
        severity: Severity,
        path: str,
        observed_content_sha256: str,
        change_kind: str,
        scan_proof: dict[str, object],
    ) -> dict[str, object]:
        authority = self._authority(producer)
        if (
            self.__kind != "fim"
            or authority is None
            or not self._canonical_caller(producer)
        ):
            return {}
        lease, state = authority
        assert state.lock is not None
        with state.lock:
            module_name = str(getattr(producer, "name", ""))
            enrollment = getattr(producer, "_angerona_contract", None)
            operational = BaseModule.operational_snapshot(producer)
            artifact_identity = self.__artifact_validator(state, str(path))
            classified = classify_marker(Path(path))
            enrolled_generation = state._native_generation(module_name)
            proof_keys = {
                "fim_scan_receipt",
                "fim_scan_coverage_sha256",
                "fim_scan_coverage_root",
                "fim_scan_path_identity",
                "fim_scan_path_identity_sha256",
            }
            receipt_keys = {
                "schema",
                "scan_generation",
                "producer_generation",
                "started_monotonic_ns",
                "completed_monotonic_ns",
                "watch_roots_sha256",
                "covered_roots",
                "complete",
                "reason",
                "files_visited",
                "files_recorded",
                "files_hashed",
                "hashes_reused",
                "content_bytes_hashed",
                "errors",
                "error_count",
                "errors_sha256",
                "snapshot_sha256",
                "baseline_sha256",
                "cache_assurance",
            }
            identity_keys = {
                "path",
                "device",
                "inode",
                "size",
                "mtime_ns",
                "change_token",
                "observed_content_sha256",
                "baseline_content_sha256",
            }
            scan_receipt = (
                scan_proof.get("fim_scan_receipt")
                if isinstance(scan_proof, dict)
                else None
            )
            scan_identity = (
                scan_proof.get("fim_scan_path_identity")
                if isinstance(scan_proof, dict)
                else None
            )
            coverage_root = str(
                scan_proof.get("fim_scan_coverage_root") or ""
            ) if isinstance(scan_proof, dict) else ""
            try:
                normalized_path = os.path.normcase(os.path.abspath(str(path)))
                normalized_root = os.path.normcase(os.path.abspath(coverage_root))
                path_is_covered = (
                    bool(coverage_root)
                    and os.path.commonpath((normalized_path, normalized_root))
                    == normalized_root
                )
            except (OSError, TypeError, ValueError):
                path_is_covered = False
            scan_valid = bool(
                isinstance(scan_proof, dict)
                and set(scan_proof) == proof_keys
                and isinstance(scan_receipt, dict)
                and set(scan_receipt) == receipt_keys
                and isinstance(scan_identity, dict)
                and set(scan_identity) == identity_keys
                and scan_receipt.get("schema") == "angerona.fim-scan-receipt.v1"
                and type(scan_receipt.get("scan_generation")) is int
                and scan_receipt.get("scan_generation", 0) > 0
                and scan_receipt.get("scan_generation")
                == int(getattr(producer, "_scan_generation", -1))
                and scan_receipt.get("producer_generation")
                == int(getattr(producer, "lifecycle_generation", -1))
                and type(scan_receipt.get("started_monotonic_ns")) is int
                and type(scan_receipt.get("completed_monotonic_ns")) is int
                and 0 < scan_receipt.get("started_monotonic_ns", 0)
                <= scan_receipt.get("completed_monotonic_ns", 0)
                <= time.monotonic_ns()
                and isinstance(scan_receipt.get("covered_roots"), (list, tuple))
                and coverage_root in {
                    os.path.normcase(os.path.abspath(str(root)))
                    for root in scan_receipt.get("covered_roots", ())
                }
                and path_is_covered
                and type(scan_receipt.get("files_visited")) is int
                and type(scan_receipt.get("files_recorded")) is int
                and 1 <= scan_receipt.get("files_recorded", 0)
                <= scan_receipt.get("files_visited", -1)
                and all(
                    type(scan_receipt.get(field)) is int
                    and scan_receipt.get(field, -1) >= 0
                    for field in (
                        "files_hashed",
                        "hashes_reused",
                        "content_bytes_hashed",
                        "error_count",
                    )
                )
                and scan_receipt.get("error_count", -1)
                >= len(scan_receipt.get("errors", ()))
                and _sha256(scan_receipt.get("errors"))
                == scan_receipt.get("errors_sha256")
                and all(
                    re.fullmatch(r"[0-9a-f]{64}", str(scan_receipt.get(field) or ""))
                    is not None
                    for field in (
                        "watch_roots_sha256",
                        "errors_sha256",
                        "snapshot_sha256",
                        "baseline_sha256",
                    )
                )
                and scan_proof.get("fim_scan_coverage_sha256")
                == _sha256(scan_receipt)
                and scan_proof.get("fim_scan_path_identity_sha256")
                == _sha256(scan_identity)
                and os.path.normcase(os.path.abspath(str(scan_identity.get("path") or "")))
                == normalized_path
                and all(
                    type(scan_identity.get(field)) is int
                    for field in (
                        "device",
                        "inode",
                        "size",
                        "mtime_ns",
                        "change_token",
                    )
                )
                and scan_identity.get("device") == artifact_identity.get("device")
                and scan_identity.get("inode") == artifact_identity.get("inode")
                and scan_identity.get("size") == artifact_identity.get("size")
                and scan_identity.get("mtime_ns") == artifact_identity.get("mtime_ns")
                and scan_identity.get("observed_content_sha256")
                == observed_content_sha256
                and (
                    (
                        change_kind == "created"
                        and scan_identity.get("baseline_content_sha256") == ""
                    )
                    or (
                        change_kind == "modified"
                        and re.fullmatch(
                            r"[0-9a-f]{64}",
                            str(scan_identity.get("baseline_content_sha256") or ""),
                        )
                        is not None
                        and scan_identity.get("baseline_content_sha256")
                        != observed_content_sha256
                    )
                )
            )
            if (
                producer is not state._native_module(module_name)
                or not state._native_capability_is(module_name, self)
                or enrollment is None
                or severity < Severity.MEDIUM
                or change_kind not in {"created", "modified"}
                or operational.get("status") != "running"
                or operational.get("thread_alive") is not True
                or int(getattr(producer, "lifecycle_generation", -2))
                != int(enrolled_generation)
                or not state.consumed
                or state.released
                or time.monotonic() > state.run_deadline_monotonic
                or not RedTeamValidationLease._state_matches(lease)
                or not artifact_identity
                or not classified
                or observed_content_sha256 != artifact_identity.get("sha256")
                or not scan_valid
            ):
                return {}
            scan_generation = int(scan_receipt["scan_generation"])
            scan_claim = _sha256(
                {
                    "coverage": scan_proof["fim_scan_coverage_sha256"],
                    "path_identity": scan_proof[
                        "fim_scan_path_identity_sha256"
                    ],
                }
            )
            if not state._claim_fim_scan(
                module_name, scan_generation, scan_claim
            ):
                return {}
            technique, _label = classified
            self.__serial += 1
            evidence_digest = _sha256({
                "message": str(message),
                "severity": int(severity),
                "path": str(path),
                "artifact_identity_sha256": artifact_identity["identity_sha256"],
                "observed_content_sha256": observed_content_sha256,
                "change_kind": change_kind,
                "producer_observation_serial": self.__serial,
                "producer_observation_site_sha256": self.__site_sha256,
                "fim_scan_receipt": scan_receipt,
                "fim_scan_coverage_sha256": scan_proof[
                    "fim_scan_coverage_sha256"
                ],
                "fim_scan_coverage_root": coverage_root,
                "fim_scan_path_identity": scan_identity,
                "fim_scan_path_identity_sha256": scan_proof[
                    "fim_scan_path_identity_sha256"
                ],
            })
            core: dict[str, object] = {
                "redteam_detector_receipt_version": 4,
                "receipt_type": "native_analytic_detection",
                "lease_id": state.lease_id,
                "receipt_id": state.receipt_id,
                "run_id": state.bound_run_id,
                "target": str(state.target),
                "producer_module": module_name,
                "producer_capability_id": str(enrollment.capability_id),
                "producer_generation": int(producer.lifecycle_generation),
                "producer_observation_serial": self.__serial,
                "producer_observation_site_sha256": self.__site_sha256,
                "producer_trust_boundary": "same-process-simulation-validation",
                "technique": technique,
                "artifact_identity_sha256": artifact_identity["identity_sha256"],
                "observed_content_sha256": observed_content_sha256,
                "change_kind": change_kind,
                "process_identity_sha256": "",
                "fim_scan_receipt": scan_receipt,
                "fim_scan_coverage_sha256": scan_proof[
                    "fim_scan_coverage_sha256"
                ],
                "fim_scan_coverage_root": coverage_root,
                "fim_scan_path_identity": scan_identity,
                "fim_scan_path_identity_sha256": scan_proof[
                    "fim_scan_path_identity_sha256"
                ],
                "evidence_digest": evidence_digest,
                "event_nonce": secrets.token_hex(16),
                "observed_at": time.time(),
                "evidence_type": "native_analytic_detection",
                "detector_verdict": "positive",
            }
            return {
                **core,
                "detector_receipt_mac": self.__private_signer.sign(
                    _canonical_json(core)
                ).hex(),
            }

    def issue_process_observation(
        self,
        producer: object,
        *,
        process: dict[str, object],
    ) -> dict[str, object]:
        authority = self._authority(producer)
        if (
            self.__kind != "process"
            or authority is None
            or not self._canonical_caller(producer)
            or not isinstance(process, dict)
        ):
            return {}
        lease, state = authority
        assert state.lock is not None
        with state.lock:
            module_name = str(getattr(producer, "name", ""))
            enrollment = getattr(producer, "_angerona_contract", None)
            operational = BaseModule.operational_snapshot(producer)
            enrolled_generation = state._native_generation(module_name)
            raw_command = process.get("cmdline") or []
            command = (
                " ".join(str(value) for value in raw_command)
                if isinstance(raw_command, (list, tuple))
                else str(raw_command)
            )
            token_match = _PROCESS_TOKEN.search(command)
            token = token_match.group(0) if token_match else ""
            identity = self.__process_validator(
                state,
                pid=process.get("pid"),
                token=token,
                process_create_time=process.get("create_time"),
                # Process Monitor just completed the second direct OS read;
                # compare it to the independently bound identity without
                # repeating psutil while authority is held.
                require_live=False,
                allow_observation_pending=True,
            )
            if (
                producer is not state._native_module(module_name)
                or not state._native_capability_is(module_name, self)
                or enrollment is None
                or operational.get("status") != "running"
                or operational.get("thread_alive") is not True
                or operational.get("event_overflow_count") != 0
                or int(getattr(producer, "lifecycle_generation", -2))
                != int(enrolled_generation)
                or not state.consumed
                or state.released
                or time.monotonic() > state.run_deadline_monotonic
                or not RedTeamValidationLease._state_matches(lease)
                or not identity
            ):
                return {}
            self.__serial += 1
            command_sha256 = hashlib.sha256(command.encode("utf-8")).hexdigest()
            evidence_digest = _sha256({
                "pid": int(identity["pid"]),
                "process_create_time": float(identity["process_create_time"]),
                "command_sha256": command_sha256,
                "process_identity_sha256": identity["identity_sha256"],
                "producer_observation_serial": self.__serial,
                "producer_observation_site_sha256": self.__site_sha256,
            })
            core = {
                "redteam_detector_receipt_version": 3,
                "receipt_type": "native_process_observation",
                "lease_id": state.lease_id,
                "receipt_id": state.receipt_id,
                "run_id": state.bound_run_id,
                "target": str(state.target),
                "producer_module": module_name,
                "producer_capability_id": str(enrollment.capability_id),
                "producer_generation": int(producer.lifecycle_generation),
                "producer_observation_serial": self.__serial,
                "producer_observation_site_sha256": self.__site_sha256,
                "producer_trust_boundary": "same-process-simulation-validation",
                "technique": _PROCESS_TECHNIQUE,
                "artifact_identity_sha256": "",
                "observed_content_sha256": command_sha256,
                "change_kind": "process_created",
                "process_identity_sha256": identity["identity_sha256"],
                "evidence_digest": evidence_digest,
                "event_nonce": secrets.token_hex(16),
                "observed_at": time.time(),
                "evidence_type": "native_sensor_observation",
                "detector_verdict": "observed",
            }
            return {
                **core,
                "detector_receipt_mac": self.__private_signer.sign(
                    _canonical_json(core)
                ).hex(),
            }


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=str,
    ).encode("utf-8")


def _verify_native_signature(
    public_material: object, supplied: object, core: dict[str, object]
) -> bool:
    """Verify a native producer receipt with public-only Ed25519 material."""
    try:
        if not isinstance(public_material, bytes) or len(public_material) != 32:
            return False
        if not isinstance(supplied, str) or re.fullmatch(
            r"[0-9a-f]{128}", supplied
        ) is None:
            return False
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )

        Ed25519PublicKey.from_public_bytes(public_material).verify(
            bytes.fromhex(supplied), _canonical_json(core)
        )
        return True
    except (TypeError, ValueError):
        return False
    except Exception:
        return False


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _close_directory_handle(handle: int | None) -> None:
    if handle is None:
        return
    if os.name == "nt":
        ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(handle))
    else:
        os.close(handle)


def _directory_handle_identity(handle: int) -> dict[str, object]:
    """Read stable directory identity from a held no-reparse handle."""
    if os.name == "nt":
        from ctypes import wintypes

        class _FileTime(ctypes.Structure):
            _fields_ = [
                ("low", wintypes.DWORD),
                ("high", wintypes.DWORD),
            ]

        class _ByHandleFileInformation(ctypes.Structure):
            _fields_ = [
                ("attributes", wintypes.DWORD),
                ("creation", _FileTime),
                ("access", _FileTime),
                ("write", _FileTime),
                ("volume_serial", wintypes.DWORD),
                ("size_high", wintypes.DWORD),
                ("size_low", wintypes.DWORD),
                ("links", wintypes.DWORD),
                ("file_index_high", wintypes.DWORD),
                ("file_index_low", wintypes.DWORD),
            ]

        info = _ByHandleFileInformation()
        if not ctypes.windll.kernel32.GetFileInformationByHandle(
            ctypes.c_void_p(handle), ctypes.byref(info)
        ):
            raise OSError(ctypes.get_last_error(), "directory identity unavailable")
        directory_attribute = 0x10
        reparse_attribute = 0x400
        if not (info.attributes & directory_attribute) or (
            info.attributes & reparse_attribute
        ):
            raise OSError("validation target is not a no-reparse directory")
        return {
            "platform": "windows-file-id",
            "volume_serial": int(info.volume_serial),
            "file_index": (
                int(info.file_index_high) << 32
            ) | int(info.file_index_low),
            "creation_time": (
                int(info.creation.high) << 32
            ) | int(info.creation.low),
            "directory": True,
            "no_reparse": True,
        }
    opened = os.fstat(handle)
    if not stat.S_ISDIR(opened.st_mode):
        raise OSError("validation target is not a directory")
    return {
        "platform": "posix-inode",
        "device": int(opened.st_dev),
        "inode": int(opened.st_ino),
        "directory": True,
        "no_reparse": True,
    }


def _open_directory_identity(path: Path) -> tuple[int, dict[str, object]]:
    candidate = Path(path)
    path_stat = candidate.stat(follow_symlinks=False)
    if (
        candidate.is_symlink()
        or not stat.S_ISDIR(path_stat.st_mode)
        or bool(getattr(path_stat, "st_file_attributes", 0) & 0x400)
    ):
        raise OSError("validation target must be a no-reparse directory")
    if os.name == "nt":
        create_file = ctypes.windll.kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            str(candidate),
            0,
            0x1 | 0x2 | 0x4,
            None,
            3,
            0x02000000 | 0x00200000,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if handle in (None, invalid):
            raise OSError(ctypes.get_last_error(), "validation target cannot be held")
        numeric = int(handle)
    else:
        numeric = os.open(
            candidate,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    try:
        identity = _directory_handle_identity(numeric)
    except Exception:
        _close_directory_handle(numeric)
        raise
    return numeric, {**identity, "identity_sha256": _sha256(identity)}


def _target_identity_matches(state: _LeaseAuthorityState) -> bool:
    if state.target_handle is None:
        return False
    current_handle: int | None = None
    try:
        held = _directory_handle_identity(state.target_handle)
        current_handle, current = _open_directory_identity(state.target)
        held_with_digest = {**held, "identity_sha256": _sha256(held)}
        return held_with_digest == state.target_identity and current == state.target_identity
    except (OSError, RuntimeError, ValueError):
        return False
    finally:
        _close_directory_handle(current_handle)


def _marker_path_identity(
    path: Path,
    *,
    hold: bool,
    delete_access: bool = False,
) -> tuple[int | None, dict[str, object]]:
    """Open one marker without following aliases and return its held identity."""
    candidate = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        if os.name == "nt":
            import msvcrt

            create_file = ctypes.windll.kernel32.CreateFileW
            create_file.argtypes = [
                ctypes.c_wchar_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ]
            create_file.restype = ctypes.c_void_p
            raw_handle = create_file(
                str(candidate),
                0x80000000 | (0x00010000 if delete_access else 0),
                0x1 | 0x2 | 0x4,  # share read/write/delete
                None,
                3,
                0x00200000,  # FILE_FLAG_OPEN_REPARSE_POINT
                None,
            )
            invalid = ctypes.c_void_p(-1).value
            if raw_handle in (None, invalid):
                raise OSError(ctypes.get_last_error(), "marker cannot be held")
            try:
                descriptor = msvcrt.open_osfhandle(
                    int(raw_handle), os.O_RDONLY | getattr(os, "O_BINARY", 0)
                )
            except Exception:
                ctypes.windll.kernel32.CloseHandle(ctypes.c_void_p(raw_handle))
                raise
        else:
            descriptor = os.open(candidate, flags)
        before = os.fstat(descriptor)
        path_stat = candidate.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(path_stat.st_mode)
            or int(getattr(before, "st_nlink", 1)) != 1
            or int(getattr(path_stat, "st_nlink", 1)) != 1
            or bool(getattr(before, "st_file_attributes", 0) & 0x400)
            or bool(getattr(path_stat, "st_file_attributes", 0) & 0x400)
            or (int(before.st_dev), int(before.st_ino))
            != (int(path_stat.st_dev), int(path_stat.st_ino))
            or before.st_size < 0
            or before.st_size > 1024 * 1024
        ):
            raise OSError("marker is not an exclusive regular file")
        digest = hashlib.sha256()
        os.lseek(descriptor, 0, os.SEEK_SET)
        remaining = int(before.st_size)
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise OSError("marker became truncated during identity read")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        final_path = candidate.stat(follow_symlinks=False)
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (after.st_dev, after.st_ino) != (final_path.st_dev, final_path.st_ino)
            or int(getattr(after, "st_nlink", 1)) != 1
            or int(getattr(final_path, "st_nlink", 1)) != 1
        ):
            raise OSError("marker identity changed during validation")
        core: dict[str, object] = {
            "path": str(candidate.resolve(strict=False)),
            "device": int(after.st_dev),
            "inode": int(after.st_ino),
            "size": int(after.st_size),
            "mtime_ns": int(after.st_mtime_ns),
            "link_count": 1,
            "sha256": digest.hexdigest(),
            "regular": True,
            "no_follow": True,
        }
        identity = {**core, "identity_sha256": _sha256(core)}
        if hold:
            return descriptor, identity
        os.close(descriptor)
        return None, identity
    except Exception:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        return None, {}


def _dispose_held_marker(
    descriptor: int,
    candidate: Path,
    enrolled: dict[str, object],
) -> bool:
    """Delete the held object, never a later same-name pathname replacement."""
    if os.name == "nt":
        import msvcrt

        class _DispositionEx(ctypes.Structure):
            _fields_ = [("flags", ctypes.c_uint32)]

        class _Disposition(ctypes.Structure):
            _fields_ = [("delete_file", ctypes.c_ubyte)]

        delete_descriptor, current = _marker_path_identity(
            candidate, hold=True, delete_access=True
        )
        if delete_descriptor is None or current != enrolled:
            if delete_descriptor is not None:
                os.close(delete_descriptor)
            return False
        handle = msvcrt.get_osfhandle(delete_descriptor)
        function = ctypes.windll.kernel32.SetFileInformationByHandle
        function.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        function.restype = ctypes.c_int
        # Windows 10+ exact-object disposition, with a legacy exact-handle
        # fallback. Both target the held file object even if its name moved.
        disposition_ex = _DispositionEx(0x1 | 0x2 | 0x10)
        applied = bool(function(
            ctypes.c_void_p(handle),
            21,  # FileDispositionInfoEx
            ctypes.byref(disposition_ex),
            ctypes.sizeof(disposition_ex),
        ))
        if not applied:
            disposition = _Disposition(1)
            applied = bool(function(
                ctypes.c_void_p(handle),
                13,  # FileDispositionInfo
                ctypes.byref(disposition),
                ctypes.sizeof(disposition),
            ))
        try:
            return applied
        finally:
            os.close(delete_descriptor)

    # POSIX has no portable unlink-by-open-file-descriptor operation. Move the
    # name atomically to a fresh lease-private custody name in the same held
    # directory, verify that the moved object is the enrolled inode, and only
    # then unlink it. A raced replacement is retained in custody for review.
    custody = candidate.with_name(
        f"._angerona_redteam_custody_{secrets.token_hex(16)}"
    )
    try:
        os.replace(candidate, custody)
        _unused, moved = _marker_path_identity(custody, hold=False)
        if moved != enrolled:
            return False
        os.unlink(custody)
        return int(getattr(os.fstat(descriptor), "st_nlink", 1)) == 0
    except OSError:
        return False


def _validation_target_markers_safe(target: Path) -> bool:
    """Reject reparse/multi-link marker aliases at readiness and consumption."""
    root = Path(target)
    if not root.exists():
        return True
    try:
        root_stat = root.stat(follow_symlinks=False)
        if (
            root.is_symlink()
            or not root.is_dir()
            or bool(getattr(root_stat, "st_file_attributes", 0) & 0x400)
        ):
            return False
        count = 0
        with os.scandir(root) as entries:
            for entry in entries:
                if not (
                    entry.name.casefold().startswith("_redteam_")
                    and entry.name.casefold().endswith(".txt")
                ):
                    continue
                count += 1
                if count > _MAX_VALIDATION_TARGET_MARKERS:
                    return False
                descriptor, identity = _marker_path_identity(
                    root / entry.name, hold=False
                )
                if descriptor is not None or not identity:
                    return False
        return True
    except OSError:
        return False


def _policy_identity(root: Path) -> dict[str, object]:
    path = policy_path(root).resolve(strict=False)
    try:
        raw = path.read_bytes()
        stat = path.stat()
        payload = json.loads(raw.decode("utf-8"))
        techniques = payload.get("techniques", {}) if isinstance(payload, dict) else {}
    except (OSError, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise RedTeamValidationError(
            "the simulation policy is unreadable or malformed"
        ) from exc
    active = frozenset(str(key) for key in techniques) if isinstance(techniques, dict) else frozenset()
    if (
        not REDTEAM_VALIDATION_TECHNIQUES.issubset(active)
        or not active.issubset(REDTEAM_COMPREHENSIVE_VALIDATION_TECHNIQUES)
    ):
        raise RedTeamValidationError(
            "the simulation policy is missing its base contracts or contains "
            "an unsupported technique"
        )
    return {
        "path": str(path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": int(stat.st_size),
        "device": int(getattr(stat, "st_dev", 0)),
        "inode": int(getattr(stat, "st_ino", 0)),
        "techniques": sorted(active),
    }


def validate_redteam_recorder(
    recorder: object,
    data_root: Path,
    *,
    bus: object | None = None,
) -> dict[str, object]:
    """Bind readiness/AAR reads to the exact open canonical SQLite ledger."""
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.storage import FlightRecorder

    if type(recorder) is not FlightRecorder:
        raise RedTeamValidationError(
            "the exact built-in FlightRecorder instance is required"
        )
    root = Path(data_root).resolve(strict=False)
    expected_path = root / "flight-recorder.db"
    configured_path = Path(getattr(recorder, "_path", ""))
    expected = expected_path.resolve(strict=False)
    configured = configured_path.resolve(strict=False)
    if (
        configured != expected
        or configured_path.is_symlink()
        or expected_path.is_symlink()
    ):
        raise RedTeamValidationError(
            "flight recorder database does not belong to the simulation data root"
        )
    try:
        lock = getattr(recorder, "_lock")
        connection = getattr(recorder, "_db")
        with lock:
            rows = connection.execute("PRAGMA database_list").fetchall()
        main_paths = [str(row[2]) for row in rows if str(row[1]) == "main"]
        if len(main_paths) != 1:
            raise RuntimeError("SQLite main database descriptor is unavailable")
        opened = Path(main_paths[0]).resolve(strict=True)
        stat = opened.stat()
        path_stat = configured.stat()
    except Exception as exc:
        raise RedTeamValidationError(
            "flight recorder SQLite descriptor is closed or unverifiable"
        ) from exc
    if opened != expected or (
        int(getattr(stat, "st_dev", 0)), int(getattr(stat, "st_ino", 0))
    ) != (
        int(getattr(path_stat, "st_dev", 0)), int(getattr(path_stat, "st_ino", 0))
    ):
        raise RedTeamValidationError(
            "flight recorder open descriptor does not match its canonical database file"
        )
    authority = getattr(recorder, "authority", None)
    if type(authority) is not BusAuthority:
        raise RedTeamValidationError(
            "flight recorder signing authority is not the exact built-in authority"
        )
    if bus is not None:
        if type(bus) is not EventBus:
            raise RedTeamValidationError("the exact built-in EventBus is required")
        if getattr(bus, "_authority", None) is not authority:
            raise RedTeamValidationError(
                "EventBus and flight recorder do not share the exact authority instance"
            )
    identity = {
        "path": str(opened),
        "path_sha256": hashlib.sha256(
            os.path.normcase(str(opened)).encode("utf-8")
        ).hexdigest(),
        "device": int(getattr(stat, "st_dev", 0)),
        "inode": int(getattr(stat, "st_ino", 0)),
        "authority_binding": "exact-shared-instance" if bus is not None else "recorder",
    }
    return {**identity, "identity_sha256": _sha256(identity)}


@dataclass(init=False, eq=False)
class RedTeamValidationLease:
    """A temporary, exact sensor/target lease for one Red Team drill.

    The operator may intentionally keep Purple Guard disabled during normal
    operation.  An explicit simulation still needs its validation sensor, so
    the launcher may start it without changing the saved module preference and
    restores the prior runtime state after the AAR has consumed the evidence.
    """

    module: "PurpleGuard"
    _target: Path
    data_root: Path
    manager: object
    bus: object
    recorder: object
    started_temporarily: bool
    target_registered_by_lease: bool
    previous_chill_paused: bool

    def __init__(
        self,
        *,
        issuer: object,
        module: "PurpleGuard",
        target: Path,
        data_root: Path,
        manager: object,
        bus: object,
        recorder: object,
        readiness: dict[str, Any],
        target_created_by_lease: bool = False,
        started_temporarily: bool = False,
        target_registered_by_lease: bool = False,
        previous_chill_paused: bool = False,
    ) -> None:
        if issuer is not _LEASE_ISSUER:
            raise RedTeamValidationError(
                "validation leases can only be issued by the readiness gate"
            )
        normalized_target = Path(target).resolve(strict=False)
        normalized_root = Path(data_root).resolve(strict=False)
        issued_at = time.time()
        issued_monotonic = time.monotonic()
        target_handle, target_identity = _open_directory_identity(normalized_target)
        # These public attributes remain available for compatibility and
        # diagnostics, but no security decision trusts them.  Exact-class
        # methods always resolve the issuer-owned state below.
        self.module = module
        self._target = normalized_target
        self.data_root = normalized_root
        self.manager = manager
        self.bus = bus
        self.recorder = recorder
        self.started_temporarily = bool(started_temporarily)
        self.target_registered_by_lease = bool(target_registered_by_lease)
        self.previous_chill_paused = bool(previous_chill_paused)
        state = _LeaseAuthorityState(
            module=module,
            target=normalized_target,
            data_root=normalized_root,
            manager=manager,
            bus=bus,
            recorder=recorder,
            started_temporarily=bool(started_temporarily),
            target_registered_by_lease=bool(target_registered_by_lease),
            previous_chill_paused=bool(previous_chill_paused),
            readiness=copy.deepcopy(readiness),
            lease_id=secrets.token_hex(16),
            receipt_id=secrets.token_hex(16),
            key=secrets.token_bytes(32),
            issued_at=issued_at,
            issued_monotonic=issued_monotonic,
            acquire_deadline_monotonic=issued_monotonic + _LEASE_ACQUIRE_TTL_S,
            process_epoch=_LEASE_PROCESS_EPOCH,
            target_handle=target_handle,
            target_identity=target_identity,
            target_created_by_lease=bool(target_created_by_lease),
        )
        with _LEASE_AUTHORITY_LOCK:
            _LEASE_AUTHORITIES[self] = state

    @property
    def target(self) -> Path:
        """The gate-issued target is immutable for this lease's lifetime."""
        return _lease_authority(self).target

    @property
    def readiness(self) -> dict[str, Any]:
        state = _lease_authority(self)
        assert state.lock is not None
        with state.lock:
            value = copy.deepcopy(state.readiness)
            value.update({
                "lease_id": state.lease_id,
                "receipt_id": state.receipt_id,
                "issued_at": state.issued_at,
                "acquire_expires_at": state.issued_at + _LEASE_ACQUIRE_TTL_S,
                "expiry_clock": "monotonic-process-bound",
                "process_epoch_sha256": hashlib.sha256(
                    state.process_epoch.encode("ascii")
                ).hexdigest(),
                "target_identity": copy.deepcopy(state.target_identity),
            })
            return value

    @property
    def active(self) -> bool:
        try:
            state = _lease_authority(self)
        except RedTeamValidationError:
            return False
        assert state.lock is not None
        with state.lock:
            return not state.released

    @staticmethod
    def authority_matches(
        lease: object,
        *,
        recorder: object,
        bus: object,
        manager: object,
    ) -> bool:
        """Validate exact external authorities without reading lease fields."""
        try:
            state = _lease_authority(lease)
        except RedTeamValidationError:
            return False
        assert state.lock is not None
        with state.lock:
            return bool(
                not state.released
                and state.recorder is recorder
                and state.bus is bus
                and state.manager is manager
            )

    def _state_matches(self) -> bool:
        try:
            state = _lease_authority(self)
        except RedTeamValidationError:
            return False
        if state.released or state.process_epoch != _LEASE_PROCESS_EPOCH:
            return False
        if type(state.module) is not PurpleGuard:
            return False
        if getattr(state.module, "_bus", None) is not state.bus:
            return False
        if state.target not in _runtime_targets_snapshot():
            return False
        if not _target_identity_matches(state):
            return False
        if not _validation_target_markers_safe(state.target):
            return False
        modules = getattr(state.manager, "modules", {})
        if (
            getattr(state.manager, "bus", None) is not state.bus
            or not isinstance(modules, dict)
            or modules.get(state.module.name) is not state.module
            or modules.get("Process Monitor") is not state.process_module
            or getattr(state.process_module, "_bus", None) is not state.bus
        ):
            return False
        operational = BaseModule.operational_snapshot(state.module)
        cycle = PurpleGuard.validation_cycle_snapshot(state.module)
        process_operational = (
            BaseModule.operational_snapshot(state.process_module)
            if isinstance(state.process_module, BaseModule)
            else {}
        )
        expected_cycle = state.readiness.get("sensor_cycle_serial")
        expected_generation = state.readiness.get("sensor_generation")
        process_readiness = state.readiness.get("process_sensor") or {}
        if (
            operational.get("status") != "running"
            or operational.get("thread_alive") is not True
            or int(operational.get("health", 0)) < 90
            or int(cycle.get("generation", -1)) != int(expected_generation or -2)
            or int(cycle.get("serial", -1)) < int(expected_cycle or -1)
        ):
            return False
        if (
            process_operational.get("status") != "running"
            or process_operational.get("thread_alive") is not True
            or process_operational.get("first_cycle_complete") is not True
            # Protected/uninspectable unrelated PIDs degrade the general
            # inventory but cannot manufacture credit: T1059 still requires
            # an exact challenge-bound receipt for the enrolled child.
            or int(process_operational.get("health", 0)) < 50
            or int(process_operational.get("event_overflow_count", -1)) != 0
            or int(process_operational.get("lifecycle_generation", -1))
            != int(process_readiness.get("generation", -2))
            or int(process_operational.get("cycle_count", -1))
            < int(process_readiness.get("cycle_count", -2))
            or str(process_readiness.get("capability_id") or "")
            != "angerona.builtin.process_monitor"
        ):
            return False
        if (
            str(state.readiness.get("target") or "") != str(state.target)
            or str(state.readiness.get("data_root") or "") != str(state.data_root)
        ):
            return False
        try:
            return (
                _policy_identity(state.data_root) == state.readiness.get("policy")
                and validate_redteam_recorder(
                    state.recorder, state.data_root, bus=state.bus
                ) == state.readiness.get("recorder_identity")
            )
        except RedTeamValidationError:
            return False

    def consume_for_run(
        self,
        *,
        run_id: str,
        target: Path,
        data_root: Path,
        run_ttl_seconds: float = _LEASE_DEFAULT_RUN_TTL_S,
    ) -> dict[str, Any]:
        """Atomically bind this live lease to exactly one run and target."""
        normalized_target = Path(target).resolve(strict=False)
        normalized_root = Path(data_root).resolve(strict=False)
        state = _lease_authority(self)
        now_wall = time.time()
        now_monotonic = time.monotonic()
        try:
            admitted_ttl = float(run_ttl_seconds)
        except (TypeError, ValueError, OverflowError) as exc:
            raise RedTeamValidationError(
                "validation run deadline is not a finite bounded duration"
            ) from exc
        if (
            not math.isfinite(admitted_ttl)
            or admitted_ttl < 60.0
            or admitted_ttl > MAX_ADMITTED_DRILL_SECONDS
        ):
            raise RedTeamValidationError(
                "validation run deadline is outside the admitted safety bound"
            )
        assert state.lock is not None
        with state.lock:
            if (
                state.consumed
                or state.released
                or now_monotonic > state.acquire_deadline_monotonic
                or normalized_target != state.target
                or normalized_root != state.data_root
                or not RedTeamValidationLease._state_matches(self)
            ):
                raise RedTeamValidationError(
                    "validation lease is stale, released, consumed, or target-mismatched"
                )
            recorder_echo = state.readiness.get("recorder") or {}
            core = {
                **self.readiness,
                "schema": "angerona.redteam-validation-readiness.v4",
                "bound_run_id": str(run_id),
                "bound_target": str(state.target),
                "bound_data_root": str(state.data_root),
                "recorder_nonce": str(recorder_echo.get("nonce") or ""),
                "consumed_at": now_wall,
                # Wall values are display/audit metadata only. Every authority
                # decision uses the process/boot-bound monotonic deadline.
                "run_expires_at": now_wall + admitted_ttl,
                "run_ttl_seconds": admitted_ttl,
                "expiry_clock": "monotonic-process-bound",
                "single_use": True,
            }
            core["lease_mac"] = state._sign_hmac(_canonical_json(core))
            state.consumed = True
            state.bound_run_id = str(run_id)
            # Round the authority deadline inward by one representable step.
            # Binary floating-point addition/subtraction can otherwise report a
            # remaining interval a few picoseconds greater than the admitted
            # TTL, which would technically overgrant this security boundary.
            state.run_deadline_monotonic = math.nextafter(
                now_monotonic + admitted_ttl,
                -math.inf,
            )
            state.consumed_receipt = copy.deepcopy(core)
            return copy.deepcopy(core)

    def verify_run_history(self, history: object) -> bool:
        if not isinstance(history, dict):
            return False
        try:
            state = _lease_authority(self)
        except RedTeamValidationError:
            return False
        assert state.lock is not None
        with state.lock:
            safety = history.get("safety_contract") or {}
            campaign = history.get("campaign") or {}
            budget = safety.get("budget") if isinstance(safety, dict) else {}
            admitted_ttl = (
                budget.get("admitted_run_ttl_seconds")
                if isinstance(budget, dict)
                else None
            )
            receipt_ttl = (state.consumed_receipt or {}).get("run_ttl_seconds")
            steps = history.get("steps") if isinstance(history.get("steps"), list) else []
            try:
                starts = [float(row["ts_start"]) for row in steps if isinstance(row, dict)]
                ends = [
                    float(row.get("ts_end", row["ts_start"]))
                    for row in steps
                    if isinstance(row, dict)
                ]
                timeline_valid = bool(
                    len(starts) == len(steps)
                    and len(ends) == len(steps)
                    and all(math.isfinite(value) for value in (*starts, *ends))
                    and all(end >= start for start, end in zip(starts, ends))
                )
                realized_seconds = (
                    max(ends) - min(starts) if starts and ends else 0.0
                )
                ttl_matches = (
                    math.isfinite(float(admitted_ttl))
                    and math.isfinite(float(receipt_ttl))
                    and float(receipt_ttl) >= float(admitted_ttl)
                    and 60.0 <= float(admitted_ttl) <= MAX_ADMITTED_DRILL_SECONDS
                    and float(receipt_ttl) <= MAX_ADMITTED_DRILL_SECONDS
                    and timeline_valid
                    and 0.0 <= realized_seconds <= float(admitted_ttl)
                )
            except (TypeError, ValueError, OverflowError):
                ttl_matches = False
            readiness_policy = set(
                str(value)
                for value in state.readiness.get("policy_techniques", ())
            )
            manifest_policy = set(
                str(value)
                for value in (
                    campaign.get("policy_techniques", ())
                    if isinstance(campaign, dict)
                    else ()
                )
            )
            readiness_contracts = state.readiness.get("detector_contracts")
            contract_map = (
                {
                    str(row.get("technique") or ""): str(
                        row.get("source_capability_id") or ""
                    )
                    for row in readiness_contracts
                    if isinstance(row, dict)
                }
                if isinstance(readiness_contracts, list)
                else {}
            )
            expected_contract_map = {
                technique: (
                    "angerona.builtin.process_monitor"
                    if technique == _PROCESS_TECHNIQUE
                    else "angerona.builtin.purple_guard"
                )
                for technique in readiness_policy
            }
            comprehensive = safety.get("comprehensive") is True
            expected_readiness_policy = (
                REDTEAM_COMPREHENSIVE_VALIDATION_TECHNIQUES
                if comprehensive
                else REDTEAM_VALIDATION_TECHNIQUES
            )
            expected_detection_contracts = (
                RED_TEAM_BASE_DETECTION_CONTRACTS
                * int(safety.get("cycles", 0) or 0)
                + (
                    RED_TEAM_COMPREHENSIVE_DETECTION_CONTRACTS
                    - RED_TEAM_BASE_DETECTION_CONTRACTS
                    if comprehensive
                    else 0
                )
            )
            if (
                not state.consumed
                or state.released
                or time.monotonic() > state.run_deadline_monotonic
                or not RedTeamValidationLease._state_matches(self)
                or str(history.get("run_id") or "") != state.bound_run_id
                or history.get("validation_readiness") != state.consumed_receipt
                or not isinstance(campaign, dict)
                or readiness_policy != expected_readiness_policy
                or state.readiness.get("comprehensive") is not comprehensive
                or manifest_policy != readiness_policy
                or contract_map != expected_contract_map
                or int(campaign.get("expected_detection_contracts", -1))
                != expected_detection_contracts
                or not ttl_matches
                or (
                    history.get("status") == "completed"
                    and (
                        campaign.get("complete") is not True
                        or campaign.get("score_eligible") is not True
                    )
                )
                or not RedTeamValidationLease._history_artifacts_match_authority(
                    history, state
                )
            ):
                return False
            receipt = dict(state.consumed_receipt or {})
            supplied = str(receipt.pop("lease_mac", ""))
            return bool(
                re.fullmatch(r"[0-9a-f]{64}", supplied)
                and state._verify_hmac(
                    supplied,
                    _canonical_json(receipt),
                )
            )

    def register_artifact_handle(self, path: Path, *, run_id: str) -> dict[str, object]:
        """Bind a newly-created marker's held file identity to this exact run."""
        state = _lease_authority(self)
        candidate = Path(path).resolve(strict=False)
        assert state.lock is not None
        with state.lock:
            try:
                direct_child = candidate.parent == state.target
            except (OSError, RuntimeError):
                direct_child = False
            authority_live = RedTeamValidationLease._state_matches(self)
            if (
                state.released
                or not state.consumed
                or str(run_id) != state.bound_run_id
                or not direct_child
                or not candidate.name.casefold().startswith("_redteam_")
                or not candidate.name.casefold().endswith(".txt")
                or not authority_live
            ):
                purple_state = BaseModule.operational_snapshot(state.module)
                process_state = (
                    BaseModule.operational_snapshot(state.process_module)
                    if isinstance(state.process_module, BaseModule)
                    else {}
                )
                raise RedTeamValidationError(
                    "marker custody is stale, target-mismatched, or not a drill artifact; "
                    f"authority_live={authority_live}, "
                    f"purple={purple_state.get('status')}/"
                    f"{purple_state.get('health')}, "
                    f"process={process_state.get('status')}/"
                    f"{process_state.get('health')}"
                )
            descriptor, identity = _marker_path_identity(candidate, hold=True)
            if descriptor is None or not identity:
                raise RedTeamValidationError(
                    "marker custody requires one regular no-follow single-link identity"
                )
            key = os.path.normcase(str(candidate))
            prior = (state.artifact_handles or {}).get(key)
            if prior is not None:
                os.close(descriptor)
                if prior[1] != identity:
                    raise RedTeamValidationError("marker identity was rebound")
                return copy.deepcopy(identity)
            assert state.artifact_handles is not None
            state.artifact_handles[key] = (descriptor, copy.deepcopy(identity))
            return copy.deepcopy(identity)

    def assert_target_identity(self, *, run_id: str) -> None:
        """Fail before marker/cleanup work if the held directory was replaced."""
        state = _lease_authority(self)
        assert state.lock is not None
        with state.lock:
            if (
                state.released
                or not state.consumed
                or str(run_id) != state.bound_run_id
                or not _target_identity_matches(state)
            ):
                raise RedTeamValidationError(
                    "validation target directory identity changed"
                )

    def remove_registered_artifact(self, path: Path, *, run_id: str) -> bool:
        """Delete only an enrolled marker still at its held file identity."""
        state = _lease_authority(self)
        candidate = Path(path).resolve(strict=False)
        key = os.path.normcase(str(candidate))
        assert state.lock is not None
        with state.lock:
            record = (state.artifact_handles or {}).get(key)
            if (
                state.released
                or not state.consumed
                or str(run_id) != state.bound_run_id
                or candidate.parent != state.target
                or record is None
                or not _target_identity_matches(state)
                or not RedTeamValidationLease._validated_artifact_identity(
                    state, str(candidate)
                )
            ):
                return False
            descriptor, enrolled = record
            disposed = False
            try:
                # Revalidate through the still-held descriptor and then apply
                # disposition to that object. Custody is not released before
                # the destructive operation.
                held = os.fstat(descriptor)
                if (
                    int(held.st_dev) != int(enrolled.get("device", -1))
                    or int(held.st_ino) != int(enrolled.get("inode", -1))
                    or int(getattr(held, "st_nlink", 1)) != 1
                ):
                    return False
                disposed = _dispose_held_marker(descriptor, candidate, enrolled)
                return disposed
            finally:
                try:
                    os.close(descriptor)
                except OSError:
                    disposed = False
                assert state.artifact_handles is not None
                state.artifact_handles.pop(key, None)

    def enroll_process_challenge(self, *, token: str, run_id: str) -> None:
        """Enroll one unpredictable token before the inert child is launched."""
        state = _lease_authority(self)
        normalized = str(token)
        assert state.lock is not None
        with state.lock:
            if (
                state.released
                or not state.consumed
                or str(run_id) != state.bound_run_id
                or _PROCESS_TOKEN.fullmatch(normalized) is None
                or not RedTeamValidationLease._state_matches(self)
            ):
                raise RedTeamValidationError(
                    "process challenge enrollment is stale or run-mismatched"
                )
            assert state.process_challenges is not None
            if normalized in state.process_challenges:
                raise RedTeamValidationError("process challenge token was reused")
            state.process_challenges[normalized] = {
                "token": normalized,
                "state": "enrolled",
                "enrolled_monotonic": time.monotonic(),
            }

    def bind_process_challenge(
        self,
        *,
        token: str,
        pid: int,
        run_id: str,
    ) -> dict[str, object]:
        """Bind an enrolled token to a live OS pid/birth/command identity."""
        import psutil

        state = _lease_authority(self)
        normalized = str(token)
        assert state.lock is not None
        binding_id = secrets.token_hex(16)
        with state.lock:
            challenge = (state.process_challenges or {}).get(normalized)
            if (
                state.released
                or not state.consumed
                or str(run_id) != state.bound_run_id
                or not isinstance(challenge, dict)
                or challenge.get("state") != "enrolled"
                or not RedTeamValidationLease._state_matches(self)
            ):
                raise RedTeamValidationError(
                    "process challenge binding is stale, reused, or run-mismatched"
                )
            assert state.process_challenges is not None
            state.process_challenges[normalized] = {
                **challenge,
                "state": "binding_pending",
                "binding_id": binding_id,
                "binding_thread_id": threading.get_ident(),
            }

        def fail_binding(reason: str) -> None:
            assert state.lock is not None
            with state.lock:
                current = (state.process_challenges or {}).get(normalized)
                if (
                    isinstance(current, dict)
                    and current.get("state") == "binding_pending"
                    and current.get("binding_id") == binding_id
                ):
                    assert state.process_challenges is not None
                    state.process_challenges[normalized] = {
                        "token": normalized,
                        "state": "observation_failed",
                        "observation_failure": reason,
                        "run_id": str(run_id),
                    }

        # Resolve the child identity without holding lease authority across
        # psutil. Release/cancellation can proceed while the exact token remains
        # terminally unavailable to polling in binding_pending.
        try:
            process = psutil.Process(int(pid))
            created = float(process.create_time())
            command = [str(value) for value in process.cmdline()]
            executable = str(process.exe() or "")
            running = process.is_running()
        except (psutil.Error, OSError, ValueError, TypeError) as exc:
            fail_binding("identity_read_failed")
            raise RedTeamValidationError(
                "spawned process identity could not be verified"
            ) from exc
        if (
            int(pid) <= 0
            or not math.isfinite(created)
            or created <= 0
            or not running
            or normalized not in command
        ):
            fail_binding("identity_mismatch")
            raise RedTeamValidationError(
                "spawned process does not carry the enrolled exact token"
            )

        with state.lock:
            current = (state.process_challenges or {}).get(normalized)
            if (
                state.released
                or not state.consumed
                or str(run_id) != state.bound_run_id
                or not isinstance(current, dict)
                or current.get("state") != "binding_pending"
                or current.get("binding_id") != binding_id
                or not RedTeamValidationLease._state_matches(self)
            ):
                if (
                    isinstance(current, dict)
                    and current.get("state") == "binding_pending"
                    and current.get("binding_id") == binding_id
                ):
                    assert state.process_challenges is not None
                    state.process_challenges[normalized] = {
                        "token": normalized,
                        "state": "observation_failed",
                        "observation_failure": "authority_changed",
                        "run_id": str(run_id),
                    }
                raise RedTeamValidationError(
                    "process challenge authority changed during identity binding"
                )
            core: dict[str, object] = {
                "token": normalized,
                "pid": int(pid),
                "process_create_time": created,
                "executable_sha256": hashlib.sha256(
                    os.path.normcase(executable).encode("utf-8")
                ).hexdigest(),
                "run_id": state.bound_run_id,
            }
            bound = {
                **core,
                "state": "bound",
                "identity_sha256": _sha256(core),
            }
            observation_id = secrets.token_hex(16)
            pending = {
                **bound,
                "state": "observation_pending",
                "observation_id": observation_id,
                "observation_thread_id": threading.get_ident(),
            }
            assert state.process_challenges is not None
            state.process_challenges[normalized] = pending
            result = copy.deepcopy(bound)
            observer = state.process_module

        def fail_pending(reason: str) -> None:
            assert state.lock is not None
            with state.lock:
                current = (state.process_challenges or {}).get(normalized)
                if (
                    isinstance(current, dict)
                    and current.get("state") == "observation_pending"
                    and current.get("observation_id") == observation_id
                ):
                    assert state.process_challenges is not None
                    state.process_challenges[normalized] = {
                        **bound,
                        "state": "observation_failed",
                        "observation_failure": reason,
                    }

        # Prepare the exact native receipt without holding authority across
        # psutil reads or synchronous EventBus subscribers. Only this binder
        # thread can mint while the challenge is observation_pending; polling
        # threads reject it. Publication follows the atomic pending -> bound
        # commit, so consumers never drain an uncommitted receipt.
        try:
            from angerona.modules.process_monitor import ProcessMonitorModule

            if type(observer) is not ProcessMonitorModule:
                fail_pending("exact_producer_unavailable")
                raise RedTeamValidationError(
                    "exact process observation producer is unavailable"
                )
            prepared = ProcessMonitorModule.observe_validation_process(
                observer,
                int(pid),
                _prepare_only=True,
            )
        except RedTeamValidationError:
            raise
        except Exception as exc:
            fail_pending("observer_exception")
            raise RedTeamValidationError(
                "exact process observation raised an exception"
            ) from exc
        if not isinstance(prepared, dict):
            fail_pending("observer_rejected")
            raise RedTeamValidationError(
                "exact process observation did not produce a receipt"
            )
        prepared_details = prepared.get("details")
        if not isinstance(prepared_details, dict):
            fail_pending("receipt_shape_invalid")
            raise RedTeamValidationError(
                "exact process observation produced an invalid receipt"
            )
        prepared_event = Event(
            "Process Monitor",
            str(prepared.get("message") or "native process observation"),
            Severity.INFO,
            details=copy.deepcopy(prepared_details),
        )
        if not RedTeamValidationLease.verify_process_observation(
            self,
            prepared_event,
            # The initial binding and exact producer preparation are two
            # independent live reads. This pass verifies the signed prepared
            # receipt without another OS call under authority.
            require_live=False,
            _allow_observation_pending=True,
        ):
            fail_pending("receipt_verification_failed")
            raise RedTeamValidationError(
                "exact process observation receipt could not be verified"
            )

        assert state.lock is not None
        with state.lock:
            current = (state.process_challenges or {}).get(normalized)
            if (
                state.released
                or not state.consumed
                or not isinstance(current, dict)
                or current.get("state") != "observation_pending"
                or current.get("observation_id") != observation_id
                or not RedTeamValidationLease._state_matches(self)
            ):
                if (
                    isinstance(current, dict)
                    and current.get("state") == "observation_pending"
                    and current.get("observation_id") == observation_id
                ):
                    assert state.process_challenges is not None
                    state.process_challenges[normalized] = {
                        **bound,
                        "state": "observation_failed",
                        "observation_failure": "authority_changed",
                    }
                raise RedTeamValidationError(
                    "process challenge authority changed during observation"
                )
            assert state.process_challenges is not None
            state.process_challenges[normalized] = copy.deepcopy(bound)

        try:
            EventBus.publish(
                state.bus,
                Event(
                    "Process Monitor",
                    str(
                        prepared.get("message")
                        or "native process observation"
                    ),
                    Severity.INFO,
                    details=copy.deepcopy(prepared_details),
                ),
            )
        except Exception as exc:
            with state.lock:
                current = (state.process_challenges or {}).get(normalized)
                if (
                    isinstance(current, dict)
                    and current.get("state") == "bound"
                    and current.get("identity_sha256")
                    == bound["identity_sha256"]
                ):
                    assert state.process_challenges is not None
                    state.process_challenges[normalized] = {
                        **bound,
                        "state": "observation_failed",
                        "observation_failure": "publication_exception",
                    }
            raise RedTeamValidationError(
                "exact process observation could not be published"
            ) from exc

        with state.lock:
            current = (state.process_challenges or {}).get(normalized)
            if (
                state.released
                or not state.consumed
                or time.monotonic() > state.run_deadline_monotonic
                or not RedTeamValidationLease._state_matches(self)
                or not isinstance(current, dict)
                or current.get("state") != "bound"
                or current.get("identity_sha256") != bound["identity_sha256"]
                or state._native_module("Process Monitor") is not observer
                or getattr(observer, "_bus", None) is not state.bus
            ):
                if (
                    isinstance(current, dict)
                    and current.get("state") == "bound"
                    and current.get("identity_sha256")
                    == bound["identity_sha256"]
                ):
                    assert state.process_challenges is not None
                    state.process_challenges[normalized] = {
                        **bound,
                        "state": "observation_failed",
                        "observation_failure": "authority_changed_after_publication",
                    }
                raise RedTeamValidationError(
                    "process challenge authority ended during publication"
                )
        return result

    @staticmethod
    def _validated_process_identity(
        state: _LeaseAuthorityState,
        *,
        pid: object,
        token: object,
        process_create_time: object,
        require_live: bool,
        allow_observation_pending: bool = False,
    ) -> dict[str, object]:
        try:
            normalized_pid = int(pid)
            normalized_created = float(process_create_time)
        except (TypeError, ValueError, OverflowError):
            return {}
        challenge = (state.process_challenges or {}).get(str(token))
        challenge_state = (
            str(challenge.get("state") or "")
            if isinstance(challenge, dict)
            else ""
        )
        pending_is_authorized = (
            bool(
                allow_observation_pending
                and challenge_state == "observation_pending"
                and challenge.get("observation_thread_id") == threading.get_ident()
                and isinstance(challenge.get("observation_id"), str)
                and bool(challenge.get("observation_id"))
            )
            if isinstance(challenge, dict)
            else False
        )
        if (
            not isinstance(challenge, dict)
            or (challenge_state != "bound" and not pending_is_authorized)
            or int(challenge.get("pid", -1)) != normalized_pid
            or not math.isfinite(normalized_created)
            or challenge.get("run_id") != state.bound_run_id
        ):
            return {}
        if not require_live and abs(
            float(challenge.get("process_create_time", -1.0))
            - normalized_created
        ) > 0.01:
            return {}
        if require_live:
            try:
                import psutil

                process = psutil.Process(normalized_pid)
                if (
                    not process.is_running()
                    or abs(
                        process.create_time()
                        - float(challenge.get("process_create_time", -1.0))
                    ) > 0.01
                    or str(token) not in [str(value) for value in process.cmdline()]
                ):
                    return {}
            except (psutil.Error, OSError, ValueError, TypeError):
                return {}
        return copy.deepcopy(challenge)

    @staticmethod
    def _validated_artifact_identity(
        state: _LeaseAuthorityState,
        observed_target: str,
    ) -> dict[str, object]:
        try:
            candidate = Path(observed_target).resolve(strict=False)
        except (OSError, RuntimeError, TypeError, ValueError):
            return {}
        record = (state.artifact_handles or {}).get(
            os.path.normcase(str(candidate))
        )
        if record is None:
            return {}
        held_descriptor, enrolled = record
        try:
            held = os.fstat(held_descriptor)
        except OSError:
            return {}
        if (
            int(held.st_dev) != int(enrolled.get("device", -1))
            or int(held.st_ino) != int(enrolled.get("inode", -1))
            or int(getattr(held, "st_nlink", 1)) != 1
        ):
            return {}
        _descriptor, current = _marker_path_identity(candidate, hold=False)
        if not current or current != enrolled:
            return {}
        return copy.deepcopy(current)

    @staticmethod
    def _history_artifacts_match_authority(
        history: dict[str, Any],
        state: _LeaseAuthorityState,
    ) -> bool:
        """Reject histories that themselves recorded an unsafe marker alias."""
        for step in history.get("steps", []):
            if not isinstance(step, dict):
                return False
            evidence = step.get("evidence_receipt") or {}
            receipts = evidence.get("artifact_receipts") or []
            if not isinstance(receipts, list):
                return False
            for receipt in receipts:
                if not isinstance(receipt, dict):
                    return False
                status_value = str(receipt.get("status") or "")
                if status_value in {
                    "symlink-refused",
                    "reparse-refused",
                    "hardlink-refused",
                    "identity-changed",
                    "not-regular",
                }:
                    return False
                if status_value == "hashed" and (
                    int(receipt.get("link_count", 1)) != 1
                    or receipt.get("regular", True) is not True
                ):
                    return False
        return True

    def attest_purple_detection(
        self,
        producer: object,
        *,
        technique: str,
        observed_target: str,
        evidence_kind: str,
        pid: object = None,
        process_create_time: object = None,
        source_event: object = None,
    ) -> dict[str, object]:
        try:
            state = _lease_authority(self)
        except RedTeamValidationError:
            return {}
        assert state.lock is not None
        with state.lock:
            if (
                producer is not state.module
                or not state.consumed
                or state.released
                or time.monotonic() > state.run_deadline_monotonic
                or not RedTeamValidationLease._state_matches(self)
            ):
                return {}
            artifact_identity: dict[str, object] = {}
            process_identity: dict[str, object] = {}
            source_observation_sha256 = ""
            if evidence_kind == "inert_file_marker":
                artifact_identity = RedTeamValidationLease._validated_artifact_identity(
                    state, observed_target
                )
                if not artifact_identity:
                    return {}
            elif evidence_kind == "nonce_tagged_process":
                _pid, separator, token = str(observed_target).partition(":")
                if not separator:
                    return {}
                process_identity = RedTeamValidationLease._validated_process_identity(
                    state,
                    pid=pid,
                    token=token,
                    process_create_time=process_create_time,
                    require_live=True,
                )
                if not process_identity:
                    return {}
                if not RedTeamValidationLease.verify_process_observation(
                    self, source_event, require_live=True
                ):
                    return {}
                source_details = getattr(source_event, "details", {}) or {}
                source_observation_sha256 = _sha256({
                    key: source_details.get(key)
                    for key in (
                        "detector_receipt_mac",
                        "event_nonce",
                        "evidence_digest",
                        "process_identity_sha256",
                        "producer_observation_serial",
                    )
                })
            core: dict[str, object] = {
                "redteam_detector_receipt_version": 1,
                "receipt_type": "purple_simulation_validation",
                "lease_id": state.lease_id,
                "receipt_id": state.receipt_id,
                "run_id": state.bound_run_id,
                "target": str(state.target),
                "target_digest": _sha256(str(state.target)),
                "technique": str(technique),
                "evidence_kind": str(evidence_kind),
                "observed_target_digest": _sha256(str(observed_target)),
                "producer_capability_id": "angerona.builtin.purple_guard",
                "producer_generation": int(state.module.lifecycle_generation),
                "policy_sha256": str(
                    (state.readiness.get("policy") or {}).get("sha256") or ""
                ),
                "artifact_identity_sha256": str(
                    artifact_identity.get("identity_sha256") or ""
                ),
                "process_identity_sha256": str(
                    process_identity.get("identity_sha256") or ""
                ),
                "source_observation_sha256": source_observation_sha256,
                "event_nonce": secrets.token_hex(16),
                "observed_at": time.time(),
                "evidence_type": "simulation_contract_validation",
                "detector_verdict": "positive",
            }
            return {
                **core,
                "detector_receipt_mac": state._sign_hmac(
                    _canonical_json(core)
                ),
                "_validated_process_create_time": process_identity.get(
                    "process_create_time"
                ),
            }

    def verify_purple_event(self, event: object, step: dict) -> bool:
        details = getattr(event, "details", {}) or {}
        try:
            state = _lease_authority(self)
        except RedTeamValidationError:
            return False
        assert state.lock is not None
        with state.lock:
            if (
                getattr(event, "module", "") != state.module.name
                or not state.consumed
                or state.released
                or time.monotonic() > state.run_deadline_monotonic
                or not RedTeamValidationLease._state_matches(self)
            ):
                return False
            supplied = str(details.get("detector_receipt_mac") or "")
            core = {key: value for key, value in details.items() if key != "detector_receipt_mac"}
            required = {
                "redteam_detector_receipt_version",
                "receipt_type",
                "lease_id",
                "receipt_id",
                "run_id",
                "target",
                "target_digest",
                "technique",
                "evidence_kind",
                "observed_target_digest",
                "producer_capability_id",
                "producer_generation",
                "policy_sha256",
                "artifact_identity_sha256",
                "process_identity_sha256",
                "source_observation_sha256",
                "event_nonce",
                "observed_at",
                "evidence_type",
                "detector_verdict",
            }
            signed_core = {key: core.get(key) for key in required}
            evidence_kind = str(details.get("evidence_kind") or "")
            if evidence_kind == "inert_file_marker":
                observed_target = str(
                    details.get("path") or details.get("artifact_path") or ""
                )
            elif evidence_kind == "nonce_tagged_process":
                observed_target = (
                    f"{details.get('pid')}:{details.get('correlation_token')}"
                )
            else:
                observed_target = ""
            artifact_identity = (
                RedTeamValidationLease._validated_artifact_identity(
                    state, observed_target
                )
                if evidence_kind == "inert_file_marker"
                else {}
            )
            process_identity = (
                RedTeamValidationLease._validated_process_identity(
                    state,
                    pid=details.get("pid"),
                    token=details.get("correlation_token"),
                    process_create_time=details.get("process_create_time"),
                    require_live=False,
                )
                if evidence_kind == "nonce_tagged_process"
                else {}
            )
            return bool(
                re.fullmatch(r"[0-9a-f]{64}", supplied)
                and details.get("receipt_type")
                == "purple_simulation_validation"
                and details.get("lease_id") == state.lease_id
                and details.get("receipt_id") == state.receipt_id
                and details.get("run_id") == state.bound_run_id
                and details.get("target") == str(state.target)
                and details.get("target_digest") == _sha256(str(state.target))
                and bool(observed_target)
                and details.get("observed_target_digest")
                == _sha256(observed_target)
                and (
                    evidence_kind != "inert_file_marker"
                    or (
                        bool(artifact_identity)
                        and details.get("artifact_identity_sha256")
                        == artifact_identity.get("identity_sha256")
                    )
                )
                and (
                    evidence_kind != "nonce_tagged_process"
                    or (
                        bool(process_identity)
                        and details.get("process_identity_sha256")
                        == process_identity.get("identity_sha256")
                        and bool(details.get("source_observation_sha256"))
                    )
                )
                and details.get("technique") in set(step.get("attack_ids") or ())
                    | set(re.findall(r"T\d{4}(?:\.\d{3})?", str(step.get("technique") or "")))
                and details.get("producer_generation") == state.module.lifecycle_generation
                and details.get("producer_capability_id")
                == "angerona.builtin.purple_guard"
                and details.get("policy_sha256")
                == str((state.readiness.get("policy") or {}).get("sha256") or "")
                and details.get("evidence_type") == "simulation_contract_validation"
                and details.get("detector_verdict") == "positive"
                and state._verify_hmac(
                    supplied,
                    _canonical_json(signed_core),
                )
            )

    def verify_process_observation(
        self,
        event: object,
        *,
        require_live: bool,
        _allow_observation_pending: bool = False,
    ) -> bool:
        """Verify a T1059 source receipt minted inside exact Process Monitor."""
        details = getattr(event, "details", {}) or {}
        module_name = str(getattr(event, "module", ""))
        try:
            state = _lease_authority(self)
        except RedTeamValidationError:
            return False
        assert state.lock is not None
        with state.lock:
            producer = state._native_module("Process Monitor")
            operational = (
                BaseModule.operational_snapshot(producer)
                if isinstance(producer, BaseModule)
                else {}
            )
            enrollment = getattr(producer, "_angerona_contract", None)
            process_identity = RedTeamValidationLease._validated_process_identity(
                state,
                pid=details.get("pid"),
                token=(
                    _PROCESS_TOKEN.search(
                        str(details.get("cmdline") or details.get("command_line") or "")
                    ).group(0)
                    if _PROCESS_TOKEN.search(
                        str(details.get("cmdline") or details.get("command_line") or "")
                    )
                    else ""
                ),
                process_create_time=details.get("process_create_time"),
                require_live=require_live,
                allow_observation_pending=_allow_observation_pending,
            )
            command = str(
                details.get("cmdline") or details.get("command_line") or ""
            )
            command_sha256 = hashlib.sha256(command.encode("utf-8")).hexdigest()
            required = {
                "redteam_detector_receipt_version",
                "receipt_type",
                "lease_id",
                "receipt_id",
                "run_id",
                "target",
                "producer_module",
                "producer_capability_id",
                "producer_generation",
                "producer_observation_serial",
                "producer_observation_site_sha256",
                "producer_trust_boundary",
                "technique",
                "artifact_identity_sha256",
                "observed_content_sha256",
                "change_kind",
                "process_identity_sha256",
                "evidence_digest",
                "event_nonce",
                "observed_at",
                "evidence_type",
                "detector_verdict",
            }
            core = {key: details.get(key) for key in required}
            expected_digest = _sha256({
                "pid": int(process_identity.get("pid", -1)),
                "process_create_time": float(
                    process_identity.get("process_create_time", -1.0)
                ),
                "command_sha256": command_sha256,
                "process_identity_sha256": process_identity.get(
                    "identity_sha256", ""
                ),
                "producer_observation_serial": details.get(
                    "producer_observation_serial"
                ),
                "producer_observation_site_sha256": details.get(
                    "producer_observation_site_sha256"
                ),
            })
            supplied = str(details.get("detector_receipt_mac") or "")
            return bool(
                module_name == "Process Monitor"
                and producer is state.process_module
                and producer is state._native_module(module_name)
                and enrollment is not None
                and state.consumed
                and not state.released
                and time.monotonic() <= state.run_deadline_monotonic
                and RedTeamValidationLease._state_matches(self)
                and operational.get("status") == "running"
                and operational.get("thread_alive") is True
                and operational.get("event_overflow_count") == 0
                and details.get("event_type") == "process_creation"
                and details.get("redteam_detector_receipt_version") == 3
                and details.get("receipt_type") == "native_process_observation"
                and details.get("lease_id") == state.lease_id
                and details.get("receipt_id") == state.receipt_id
                and details.get("run_id") == state.bound_run_id
                and details.get("target") == str(state.target)
                and details.get("producer_module") == module_name
                and details.get("producer_capability_id")
                == "angerona.builtin.process_monitor"
                and details.get("producer_capability_id") == enrollment.capability_id
                and details.get("producer_generation")
                == int(getattr(producer, "lifecycle_generation", -1))
                and details.get("producer_trust_boundary")
                == "same-process-simulation-validation"
                and details.get("technique") == _PROCESS_TECHNIQUE
                and details.get("artifact_identity_sha256") == ""
                and details.get("observed_content_sha256") == command_sha256
                and details.get("change_kind") == "process_created"
                and bool(process_identity)
                and details.get("process_identity_sha256")
                == process_identity.get("identity_sha256")
                and details.get("evidence_digest") == expected_digest
                and details.get("evidence_type") == "native_sensor_observation"
                and details.get("detector_verdict") == "observed"
                and _verify_native_signature(
                    state._native_public_verifier(module_name),
                    supplied,
                    core,
                )
            )

    def _native_attestation(
        self,
        producer: object,
        message: str,
        severity: Severity,
        details: dict[str, object],
    ) -> dict[str, object]:
        # Deliberately never sign a general-purpose module emission. Native
        # receipts are minted only by ``attest_fim_scan_observation`` after the
        # FIM scan has supplied a custody-bound content digest.
        return {}

    def bind_native_producers(self, manager: object) -> None:
        """Attach one-run object capabilities to exact built-in producers."""
        from angerona.modules.file_integrity import FileIntegrityModule
        from angerona.modules.process_monitor import ProcessMonitorModule

        allowed = {
            "File Integrity Monitor": (
                "angerona.builtin.file_integrity",
                FileIntegrityModule,
                "fim",
                FileIntegrityModule._evaluate_snapshot.__code__,
            ),
            "Process Monitor": (
                "angerona.builtin.process_monitor",
                ProcessMonitorModule,
                "process",
                (
                    ProcessMonitorModule.run.__code__,
                    ProcessMonitorModule.observe_validation_process.__code__,
                ),
            ),
        }
        state = _lease_authority(self)
        modules = getattr(manager, "modules", {})
        assert state.lock is not None
        with state.lock:
            if manager is not state.manager or state.released:
                raise RedTeamValidationError("native producer authority is stale")
            state._reset_native_enrollment()
        for name, (capability_id, cls, kind, site_code) in allowed.items():
            producer = modules.get(name) if isinstance(modules, dict) else None
            contract = getattr(producer, "_angerona_contract", None)
            if (
                type(producer) is not cls
                or contract is None
                or str(contract.capability_id) != capability_id
                or getattr(producer, "_bus", None) is not state.bus
            ):
                continue
            capability = _ProducerReceiptCapability(
                lease=self,
                producer=producer,
                kind=kind,
                site_code=site_code,
                artifact_validator=RedTeamValidationLease._validated_artifact_identity,
                process_validator=RedTeamValidationLease._validated_process_identity,
            )
            with state.lock:
                state._enroll_native(
                    name,
                    producer,
                    int(producer.lifecycle_generation),
                    capability,
                    capability.public_verification_material(),
                )
            binder = getattr(producer, "bind_redteam_receipt_capability", None)
            if not callable(binder):
                raise RedTeamValidationError(
                    f"{name} does not expose its exact receipt-capability binding"
                )
            binder(capability)

    def verify_native_event(self, event: object, manager: object, step: dict) -> bool:
        details = getattr(event, "details", {}) or {}
        module_name = str(getattr(event, "module", ""))
        producer = getattr(manager, "modules", {}).get(module_name)
        try:
            state = _lease_authority(self)
        except RedTeamValidationError:
            return False
        assert state.lock is not None
        with state.lock:
            operational = (
                BaseModule.operational_snapshot(producer)
                if isinstance(producer, BaseModule)
                else {}
            )
            enrolled_generation = state._native_generation(module_name)
            if (
                manager is not state.manager
                or producer is not state._native_module(module_name)
                or getattr(manager, "bus", None) is not state.bus
                or not state.consumed
                or state.released
                or time.monotonic() > state.run_deadline_monotonic
                or not RedTeamValidationLease._state_matches(self)
                or operational.get("status") != "running"
                or operational.get("thread_alive") is not True
                or int(getattr(producer, "lifecycle_generation", -2))
                != int(enrolled_generation)
            ):
                return False
            supplied = str(details.get("detector_receipt_mac") or "")
            required = {
                "redteam_detector_receipt_version", "receipt_type", "lease_id",
                "receipt_id", "run_id", "target", "producer_module",
                "producer_capability_id", "producer_generation",
                "producer_observation_serial", "producer_observation_site_sha256",
                "producer_trust_boundary", "evidence_digest",
                "technique", "artifact_identity_sha256",
                "observed_content_sha256", "change_kind", "process_identity_sha256",
                "fim_scan_receipt", "fim_scan_coverage_sha256",
                "fim_scan_coverage_root", "fim_scan_path_identity",
                "fim_scan_path_identity_sha256",
                "event_nonce", "observed_at", "evidence_type", "detector_verdict",
            }
            core = {key: details.get(key) for key in required}
            contract = getattr(producer, "_angerona_contract", None)
            observed_path = str(
                details.get("path") or details.get("artifact_path") or ""
            )
            artifact_identity = RedTeamValidationLease._validated_artifact_identity(
                state, observed_path
            )
            scan_receipt = details.get("fim_scan_receipt")
            scan_identity = details.get("fim_scan_path_identity")
            coverage_root = str(details.get("fim_scan_coverage_root") or "")
            receipt_keys = {
                "schema",
                "scan_generation",
                "producer_generation",
                "started_monotonic_ns",
                "completed_monotonic_ns",
                "watch_roots_sha256",
                "covered_roots",
                "complete",
                "reason",
                "files_visited",
                "files_recorded",
                "files_hashed",
                "hashes_reused",
                "content_bytes_hashed",
                "errors",
                "error_count",
                "errors_sha256",
                "snapshot_sha256",
                "baseline_sha256",
                "cache_assurance",
            }
            identity_keys = {
                "path",
                "device",
                "inode",
                "size",
                "mtime_ns",
                "change_token",
                "observed_content_sha256",
                "baseline_content_sha256",
            }
            try:
                normalized_path = os.path.normcase(os.path.abspath(observed_path))
                normalized_root = os.path.normcase(os.path.abspath(coverage_root))
                path_is_covered = (
                    bool(coverage_root)
                    and os.path.commonpath((normalized_path, normalized_root))
                    == normalized_root
                )
            except (OSError, TypeError, ValueError):
                path_is_covered = False
            scan_valid = bool(
                isinstance(scan_receipt, dict)
                and set(scan_receipt) == receipt_keys
                and isinstance(scan_identity, dict)
                and set(scan_identity) == identity_keys
                and scan_receipt.get("schema") == "angerona.fim-scan-receipt.v1"
                and type(scan_receipt.get("scan_generation")) is int
                and scan_receipt.get("scan_generation", 0) > 0
                and scan_receipt.get("scan_generation")
                == int(getattr(producer, "_scan_generation", -1))
                and scan_receipt.get("producer_generation")
                == int(getattr(producer, "lifecycle_generation", -1))
                and type(scan_receipt.get("started_monotonic_ns")) is int
                and type(scan_receipt.get("completed_monotonic_ns")) is int
                and 0 < scan_receipt.get("started_monotonic_ns", 0)
                <= scan_receipt.get("completed_monotonic_ns", 0)
                <= time.monotonic_ns()
                and isinstance(scan_receipt.get("covered_roots"), (list, tuple))
                and coverage_root in {
                    os.path.normcase(os.path.abspath(str(root)))
                    for root in scan_receipt.get("covered_roots", ())
                }
                and path_is_covered
                and type(scan_receipt.get("files_visited")) is int
                and type(scan_receipt.get("files_recorded")) is int
                and 1 <= scan_receipt.get("files_recorded", 0)
                <= scan_receipt.get("files_visited", -1)
                and all(
                    type(scan_receipt.get(field)) is int
                    and scan_receipt.get(field, -1) >= 0
                    for field in (
                        "files_hashed",
                        "hashes_reused",
                        "content_bytes_hashed",
                        "error_count",
                    )
                )
                and scan_receipt.get("error_count", -1)
                >= len(scan_receipt.get("errors", ()))
                and _sha256(scan_receipt.get("errors"))
                == scan_receipt.get("errors_sha256")
                and all(
                    re.fullmatch(
                        r"[0-9a-f]{64}", str(scan_receipt.get(field) or "")
                    )
                    is not None
                    for field in (
                        "watch_roots_sha256",
                        "errors_sha256",
                        "snapshot_sha256",
                        "baseline_sha256",
                    )
                )
                and details.get("fim_scan_coverage_sha256")
                == _sha256(scan_receipt)
                and details.get("fim_scan_path_identity_sha256")
                == _sha256(scan_identity)
                and os.path.normcase(
                    os.path.abspath(str(scan_identity.get("path") or ""))
                )
                == normalized_path
                and all(
                    type(scan_identity.get(field)) is int
                    for field in (
                        "device",
                        "inode",
                        "size",
                        "mtime_ns",
                        "change_token",
                    )
                )
                and scan_identity.get("device") == artifact_identity.get("device")
                and scan_identity.get("inode") == artifact_identity.get("inode")
                and scan_identity.get("size") == artifact_identity.get("size")
                and scan_identity.get("mtime_ns") == artifact_identity.get("mtime_ns")
                and scan_identity.get("observed_content_sha256")
                == details.get("observed_content_sha256")
                and (
                    (
                        details.get("change_kind") == "created"
                        and scan_identity.get("baseline_content_sha256") == ""
                    )
                    or (
                        details.get("change_kind") == "modified"
                        and re.fullmatch(
                            r"[0-9a-f]{64}",
                            str(scan_identity.get("baseline_content_sha256") or ""),
                        )
                        is not None
                        and scan_identity.get("baseline_content_sha256")
                        != details.get("observed_content_sha256")
                    )
                )
            )
            expected_digest = _sha256({
                "message": str(getattr(event, "message", "")),
                "severity": int(getattr(event, "severity", Severity.INFO)),
                "path": observed_path,
                "artifact_identity_sha256": details.get(
                    "artifact_identity_sha256"
                ),
                "observed_content_sha256": details.get(
                    "observed_content_sha256"
                ),
                "change_kind": details.get("change_kind"),
                "producer_observation_serial": details.get(
                    "producer_observation_serial"
                ),
                "producer_observation_site_sha256": details.get(
                    "producer_observation_site_sha256"
                ),
                "fim_scan_receipt": scan_receipt,
                "fim_scan_coverage_sha256": details.get(
                    "fim_scan_coverage_sha256"
                ),
                "fim_scan_coverage_root": coverage_root,
                "fim_scan_path_identity": scan_identity,
                "fim_scan_path_identity_sha256": details.get(
                    "fim_scan_path_identity_sha256"
                ),
            })
            scan_claim = _sha256(
                {
                    "coverage": details.get("fim_scan_coverage_sha256"),
                    "path_identity": details.get(
                        "fim_scan_path_identity_sha256"
                    ),
                }
            )
            issuer_claim_valid = bool(
                isinstance(scan_receipt, dict)
                and state._fim_scan_claim_was_issued(
                    module_name,
                    scan_receipt.get("scan_generation"),
                    scan_claim,
                )
            )
            return bool(
                re.fullmatch(r"[0-9a-f]{128}", supplied)
                and details.get("redteam_detector_receipt_version") == 4
                and details.get("receipt_type") == "native_analytic_detection"
                and details.get("lease_id") == state.lease_id
                and details.get("receipt_id") == state.receipt_id
                and details.get("run_id") == state.bound_run_id
                and details.get("target") == str(state.target)
                and contract is not None
                and details.get("producer_module") == module_name
                and details.get("producer_capability_id") == contract.capability_id
                and details.get("producer_generation") == producer.lifecycle_generation
                and type(details.get("producer_observation_serial")) is int
                and details.get("producer_observation_serial", 0) > 0
                and re.fullmatch(
                    r"[0-9a-f]{64}",
                    str(details.get("producer_observation_site_sha256") or ""),
                ) is not None
                and details.get("producer_trust_boundary")
                == "same-process-simulation-validation"
                and bool(artifact_identity)
                and details.get("artifact_identity_sha256")
                == artifact_identity.get("identity_sha256")
                and details.get("observed_content_sha256")
                == artifact_identity.get("sha256")
                and details.get("change_kind") in {"created", "modified"}
                and details.get("process_identity_sha256") == ""
                and scan_valid
                and issuer_claim_valid
                and details.get("technique") in set(step.get("attack_ids") or ())
                    | set(re.findall(
                        r"T\d{4}(?:\.\d{3})?",
                        str(step.get("technique") or ""),
                    ))
                and details.get("evidence_digest") == expected_digest
                and details.get("evidence_type") == "native_analytic_detection"
                and details.get("detector_verdict") == "positive"
                and _verify_native_signature(
                    state._native_public_verifier(module_name),
                    supplied,
                    core,
                )
            )

    def release(self) -> None:
        try:
            state = _lease_authority(self)
        except RedTeamValidationError:
            return
        assert state.lock is not None
        with state.lock:
            if state.released:
                return
            state.released = True
            state._rotate_hmac_authority()
        try:
            PurpleGuard._set_validation_lease(state.module, None, expected=self)
        except Exception:
            pass
        state._revoke_native_enrollment()
        for descriptor, _identity in tuple((state.artifact_handles or {}).values()):
            try:
                os.close(descriptor)
            except OSError:
                pass
        (state.artifact_handles or {}).clear()
        _close_directory_handle(state.target_handle)
        state.target_handle = None
        if state.target_registered_by_lease:
            try:
                unregister_runtime_target(state.target)
            except (OSError, RuntimeError, ValueError):
                pass
        if state.started_temporarily:
            try:
                state.module.stop()
            finally:
                setattr(state.module, "_chill_paused", state.previous_chill_paused)
        if state.process_started_temporarily and state.process_module is not None:
            try:
                state.process_module.stop()
            finally:
                setattr(
                    state.process_module,
                    "_chill_paused",
                    state.process_previous_chill_paused,
                )
        if state.process_inserted_by_lease:
            modules = getattr(state.manager, "modules", None)
            if (
                isinstance(modules, dict)
                and modules.get("Process Monitor") is state.process_module
            ):
                modules.pop("Process Monitor", None)
        # Keep the revoked tombstone while the handle is reachable so replay
        # attempts fail explicitly as released. Weak-key cleanup removes it
        # automatically once no caller retains the lease object.


def _build_validation_dispatch() -> tuple[object, object, object, object]:
    """Capture exact verifier code outside the mutable authority registry.

    The returned closures never resolve verifier callables through a lease,
    registry record, instance attribute, class attribute, or replaceable module
    alias. Same-process native memory is still not an isolation boundary, but
    ordinary module-reachable state can no longer redirect proof acceptance.
    """
    authority_matches_impl = RedTeamValidationLease.authority_matches
    verify_run_impl = RedTeamValidationLease.verify_run_history
    verify_native_impl = RedTeamValidationLease.verify_native_event
    verify_purple_impl = RedTeamValidationLease.verify_purple_event

    def authority_matches(
        lease: object,
        *,
        recorder: object,
        bus: object,
        manager: object,
    ) -> bool:
        try:
            return bool(
                authority_matches_impl(
                    lease, recorder=recorder, bus=bus, manager=manager
                )
            )
        except (AttributeError, RedTeamValidationError, TypeError):
            return False

    def verify_run(lease: object, history: object) -> bool:
        try:
            return bool(verify_run_impl(lease, history))
        except (AttributeError, RedTeamValidationError, TypeError):
            return False

    def verify_native(
        lease: object,
        event: object,
        manager: object,
        step: dict,
        _captured_dispatch: object = verify_native_impl,
    ) -> bool:
        try:
            # Retain the historical closure-cell name for compatibility tests,
            # but never dispatch through that mutable cell. Mutation can at
            # most force a denial; it cannot redirect acceptance.
            if verify_native_impl is None or not callable(_captured_dispatch):
                return False
            return bool(_captured_dispatch(lease, event, manager, step))
        except (AttributeError, RedTeamValidationError, TypeError):
            return False

    def verify_purple(lease: object, event: object, step: dict) -> bool:
        try:
            return bool(verify_purple_impl(lease, event, step))
        except (AttributeError, RedTeamValidationError, TypeError):
            return False

    return authority_matches, verify_run, verify_native, verify_purple


(
    validation_authority_matches,
    verify_validation_run_history,
    verify_validation_native_event,
    verify_validation_purple_event,
) = _build_validation_dispatch()
del _build_validation_dispatch


def attest_fim_scan_observation(
    producer: object,
    *,
    message: str,
    severity: Severity,
    path: str,
    observed_content_sha256: str,
    change_kind: str,
) -> dict[str, object]:
    """Retired compatibility surface; public callers can never mint proof."""
    del producer, message, severity, path, observed_content_sha256, change_kind
    return {}


def _normalize_runtime_target(target: _PathInput, *, require_directory: bool) -> Path:
    """Return a stable local directory path suitable for the drill scanner."""
    try:
        raw = os.fspath(target)
    except TypeError as exc:
        raise ValueError("runtime drill target must be a filesystem path") from exc
    if not raw or not raw.strip() or "\x00" in raw:
        raise ValueError("runtime drill target must be a non-empty local path")
    if len(raw) > 1024:
        raise ValueError("runtime drill target path is too long")
    windows_form = raw.replace("/", "\\")
    if windows_form.startswith(("\\\\", "\\\\?\\", "\\\\.\\")):
        raise ValueError("network and device paths are not runtime drill targets")
    try:
        path = Path(os.path.expandvars(os.path.expanduser(raw))).resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError("runtime drill target path is invalid") from exc
    if path == Path(path.anchor):
        raise ValueError("a filesystem root is not a runtime drill target")
    if path.exists() and not path.is_dir():
        raise ValueError("runtime drill target must be a directory path")
    if require_directory and not path.is_dir():
        raise ValueError("runtime drill target must be an existing directory")
    return path


def register_runtime_target(target: _PathInput) -> Path:
    """Pre-register one local drill directory for this process lifetime.

    Registration never widens marker matching: Purple Guard still inspects only
    direct children whose names match ``_redteam_*.txt``.  The bounded drill
    may create the directory immediately after this call, so absence is valid;
    roots, UNC/device paths, and non-directory values remain non-scannable.
    """
    path = _normalize_runtime_target(target, require_directory=False)
    with _RUNTIME_TARGETS_LOCK:
        _RUNTIME_TARGETS.add(path)
    return path


def unregister_runtime_target(target: _PathInput) -> bool:
    """Remove a runtime target, including one whose directory was deleted."""
    path = _normalize_runtime_target(target, require_directory=False)
    with _RUNTIME_TARGETS_LOCK:
        if path not in _RUNTIME_TARGETS:
            return False
        _RUNTIME_TARGETS.remove(path)
        return True


def _runtime_targets_snapshot() -> tuple[Path, ...]:
    with _RUNTIME_TARGETS_LOCK:
        return tuple(
            sorted(_RUNTIME_TARGETS, key=lambda path: os.path.normcase(str(path)))
        )


def _safe_lineage_details(details: dict) -> dict[str, str]:
    lineage: dict[str, str] = {}
    for key in ("practice_verification_id", "run_id", "step_id"):
        value = str(details.get(key) or "").strip()
        if value and _SAFE_LINEAGE_ID.fullmatch(value):
            lineage[key] = value
    return lineage


def _practice_id_from_marker(path: Path) -> str:
    match = _PRACTICE_FILE_TOKEN.search(path.name)
    return match.group("id").lower() if match else ""


def policy_path(data_root: Path | None = None) -> Path:
    return Path(data_root or canonical_data_dir()) / "shared_logs" / "purple_guard_policy.json"


def _read_policy(data_root: Path | None = None) -> dict:
    path = policy_path(data_root)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def install_policies(findings: list[dict], run_id: str,
                     data_root: Path | None = None) -> dict:
    """Install candidate signatures; no finding is called fixed yet."""
    root = Path(data_root or canonical_data_dir())
    current = _read_policy(root)
    enabled = current.get("techniques", {})
    if not isinstance(enabled, dict):
        enabled = {}
    supported = {mitre: label for _token, mitre, label in _PATTERNS}
    supported[_PROCESS_TECHNIQUE] = _PROCESS_LABEL
    installed, unsupported = [], []
    seen: set[str] = set()
    now = time.time()
    for finding in findings:
        mitre = str(finding.get("mitre") or "").strip().upper()
        if mitre in seen:
            continue
        seen.add(mitre)
        if mitre not in supported:
            unsupported.append(mitre or "unknown")
            continue
        enabled[mitre] = {
            "label": supported[mitre],
            "candidate_from_run": str(run_id or ""),
            "installed_at": now,
            "state": "CANDIDATE_READY",
        }
        installed.append(mitre)
    payload = {"version": 1, "updated_at": now, "techniques": enabled}
    path = policy_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        replace_with_retry(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return {"installed": installed, "unsupported": unsupported, "path": str(path)}


def ensure_redteam_validation_pack(
    data_root: Path | None = None,
    *,
    comprehensive: bool = False,
) -> dict:
    """Activate every fixed, simulation-only Purple Guard signature.

    The Red Team console's Auto-contain option promises an end-to-end validation
    run, not a first-run learning exercise.  These signatures match only inert
    ``_redteam_*`` artifacts (or the nonce-tagged idle process) in explicitly
    registered drill targets.  Existing candidate metadata is preserved so an
    automatic validation run cannot overwrite prior signed remediation lineage.
    """
    root = Path(data_root or canonical_data_dir())
    current = _read_policy(root).get("techniques", {})
    enabled = current if isinstance(current, dict) else {}
    required = (
        REDTEAM_COMPREHENSIVE_VALIDATION_TECHNIQUES
        if comprehensive
        else REDTEAM_VALIDATION_TECHNIQUES
    )
    techniques = tuple(sorted(required))
    missing = [mitre for mitre in techniques if mitre not in enabled]
    result = (
        install_policies(
            [{"mitre": mitre} for mitre in missing],
            "builtin-redteam-validation-v1",
            root,
        )
        if missing
        else {"installed": [], "unsupported": [], "path": str(policy_path(root))}
    )
    verified_policy = _read_policy(root).get("techniques", {})
    if not isinstance(verified_policy, dict):
        raise RedTeamValidationError(
            "simulation detector policy was not readable after activation"
        )
    verified = [
        mitre
        for mitre in techniques
        if isinstance(verified_policy.get(mitre), dict)
        and verified_policy[mitre].get("state") == "CANDIDATE_READY"
    ]
    if set(verified) != required:
        absent = sorted(required.difference(verified))
        raise RedTeamValidationError(
            "simulation detector policy read-back failed for: " + ", ".join(absent)
        )
    return {
        **result,
        "active": verified,
        "already_active": [mitre for mitre in techniques if mitre in enabled],
        "simulation_only": True,
    }


def remove_policies(
    techniques: list[str],
    data_root: Path | None = None,
) -> dict:
    """Rollback exact Purple Guard techniques; unrelated policy is preserved."""
    root = Path(data_root or canonical_data_dir())
    current = _read_policy(root)
    enabled = current.get("techniques", {})
    if not isinstance(enabled, dict):
        enabled = {}
    requested = {str(value or "").strip().upper() for value in techniques if value}
    removed = []
    for technique in sorted(requested):
        if technique in enabled:
            enabled.pop(technique)
            removed.append(technique)
    payload = {
        "version": 1,
        "updated_at": time.time(),
        "techniques": enabled,
    }
    path = policy_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        replace_with_retry(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return {
        "removed": removed,
        "not_present": sorted(requested.difference(removed)),
        "path": str(path),
    }


def classify_marker(path: Path) -> tuple[str, str] | None:
    name = path.name.casefold()
    if (
        not name.startswith("_redteam_")
        or "benign_note" in name
        or name.startswith("_redteam_custom_")
    ):
        return None
    for token, mitre, label in _PATTERNS:
        if token in name:
            return mitre, label
    return None


def classify_process_event(event) -> tuple[str, str, str] | None:
    """Recognize only the drill's random nonce tag on process-creation records."""
    details = getattr(event, "details", {}) or {}
    kind = str(details.get("event_type") or details.get("type") or "")
    if kind != "process_creation":
        return None
    command = str(details.get("cmdline") or details.get("command_line") or "")
    match = _PROCESS_TOKEN.search(command)
    if not match:
        return None
    return _PROCESS_TECHNIQUE, _PROCESS_LABEL, match.group(0)


class PurpleGuard(BaseModule):
    name = "Purple Remediation Guard"
    description = "Turns reviewed red-team misses into exact, rerun-verifiable detector signatures."
    category = "Detection"
    version = "1.12.1"
    enabled_by_default = True

    def __init__(self, data_root: Path | None = None) -> None:
        super().__init__()
        self.data_root = Path(data_root or canonical_data_dir())
        self.sandbox = self.data_root / "drill-sandbox"
        self._seen: set[tuple[str, int, int]] = set()
        self._seen_events: set[tuple[float, str, object, str]] = set()
        # Keep total callback retention at 256 while reserving 64 slots for
        # native receipt envelopes. Merely nonce-shaped rows cannot evict every
        # exact T1059 source receipt before the verifier consumes it.
        self._process_queue: deque[object] = deque(maxlen=192)
        self._native_process_queue: deque[object] = deque(maxlen=64)
        self._process_queue_lock = threading.Lock()
        # An exact native process receipt must not wait behind the idle
        # five-second file-scan cadence. The EventBus callback queues every
        # classified nonce but sets this wake signal only for the expected
        # Process Monitor envelope; the run loop still performs full receipt
        # verification off the publisher thread.
        self._process_wake = threading.Event()
        self._process_subscription_active = False
        self._policy_cache_key: object = _POLICY_CACHE_UNSET
        self._policy_cache: dict = {}
        self._validation_cycle = threading.Condition()
        self._validation_cycle_serial = 0
        self._validation_cycle_generation = 0
        self._validation_cycle_techniques: frozenset[str] = frozenset()
        self._validation_cycle_at = 0.0
        self._had_reviewed_policy = False
        self._policy_loss_reported = False
        self._validation_lease: RedTeamValidationLease | None = None
        self.detected = 0

    def _set_validation_lease(
        self,
        lease: RedTeamValidationLease | None,
        *,
        expected: RedTeamValidationLease | None = None,
    ) -> None:
        with self._validation_cycle:
            if expected is not None and self._validation_lease is not expected:
                return
            self._validation_lease = lease

    def _reserve_validation_lease(self, lease: RedTeamValidationLease) -> None:
        """Atomically reserve this detector for one pending simulation."""
        state = _lease_authority(lease)
        with self._validation_cycle:
            current = self._validation_lease
            if current is not None and current.active:
                raise RedTeamValidationError(
                    "Purple Guard already has an active Red Team validation lease"
                )
            with _RUNTIME_TARGETS_LOCK:
                existed = state.target in _RUNTIME_TARGETS
                _RUNTIME_TARGETS.add(state.target)
                state.target_registered_by_lease = not existed
                lease.target_registered_by_lease = not existed
            self._validation_lease = lease

    def validation_cycle_snapshot(self) -> dict[str, object]:
        """Return the exact policy set observed by the last completed scan."""
        with self._validation_cycle:
            return {
                "serial": int(self._validation_cycle_serial),
                "generation": int(self._validation_cycle_generation),
                "techniques": sorted(self._validation_cycle_techniques),
                "completed_at": float(self._validation_cycle_at),
            }

    def wait_for_validation_cycle(
        self,
        required: set[str] | frozenset[str],
        *,
        after_serial: int,
        timeout: float,
    ) -> bool:
        """Wait for a fresh cycle that consumed all required policy entries."""
        required_set = frozenset(str(value) for value in required)
        deadline = time.monotonic() + max(0.0, float(timeout))
        with self._validation_cycle:
            while True:
                if (
                    self._validation_cycle_serial > int(after_serial)
                    and required_set.issubset(self._validation_cycle_techniques)
                ):
                    return True
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._validation_cycle.wait(timeout=remaining)

    def _capture_process_event(self, event: object) -> None:
        """Bounded EventBus callback retaining only an exact drill nonce."""
        if self.status != "running" or self.stopping:
            return
        if classify_process_event(event) is None:
            return
        details = getattr(event, "details", None)
        native_envelope = bool(
            getattr(event, "module", None) == "Process Monitor"
            and isinstance(details, dict)
            and details.get("event_type") == "process_creation"
            and details.get("redteam_detector_receipt_version") == 3
            and details.get("receipt_type") == "native_process_observation"
            and details.get("producer_module") == "Process Monitor"
            and details.get("producer_capability_id")
            == "angerona.builtin.process_monitor"
            and details.get("producer_trust_boundary")
            == "same-process-simulation-validation"
            and isinstance(details.get("lease_id"), str)
            and bool(details.get("lease_id"))
            and isinstance(details.get("receipt_id"), str)
            and bool(details.get("receipt_id"))
            and re.fullmatch(
                r"[0-9a-f]{128}",
                str(details.get("detector_receipt_mac") or ""),
            )
            is not None
        )
        with self._process_queue_lock:
            if native_envelope:
                self._native_process_queue.append(event)
            else:
                self._process_queue.append(event)
        if native_envelope:
            self._process_wake.set()

    def _process_events(self) -> list[object]:
        if self._process_subscription_active:
            with self._process_queue_lock:
                events = list(self._native_process_queue)
                self._native_process_queue.clear()
                events.extend(self._process_queue)
                self._process_queue.clear()
            return events
        if self._bus is None:
            return []
        # Direct self-tests and compatibility harnesses call scan_process_once
        # without starting the module. Production run() uses the exact-event
        # subscription above instead of rescanning this general-purpose ring.
        return list(self._bus.recent(500))

    def _policy_snapshot(self) -> dict:
        """Return the policy, reparsing only after the file identity changes.

        An installed remediation policy is normally unchanged between drills,
        yet the active detector runs once per second.  A stat-based identity
        check avoids tens of thousands of identical JSON reads per day.  The
        key includes both change timestamps, size, and file identity so atomic
        replacement or an in-place rewrite invalidates the cache immediately.
        """
        path = policy_path(self.data_root)
        try:
            stat = path.stat()
            key: object = (
                int(getattr(stat, "st_dev", 0)),
                int(getattr(stat, "st_ino", 0)),
                int(stat.st_mtime_ns),
                int(stat.st_ctime_ns),
                int(stat.st_size),
            )
        except OSError:
            key = None
        if key == self._policy_cache_key:
            return self._policy_cache
        value = _read_policy(self.data_root).get("techniques", {})
        self._policy_cache = value if isinstance(value, dict) else {}
        self._policy_cache_key = key
        return self._policy_cache

    def scan_once(self, policy: dict | None = None) -> int:
        if policy is None:
            policy = _read_policy(self.data_root).get("techniques", {})
        if not isinstance(policy, dict) or not policy:
            return 0
        hits = 0
        targets = (self.sandbox.resolve(strict=False), *_runtime_targets_snapshot())
        visited: set[Path] = set()
        for target in targets:
            if target in visited or not target.is_dir():
                continue
            visited.add(target)
            try:
                # Direct children only. Broad file scanning or recursive walking
                # would turn this exact drill detector into a general-purpose
                # content scanner, which is intentionally outside its contract.
                paths = list(target.glob("_redteam_*.txt"))
            except OSError:
                continue
            for path in paths:
                classified = classify_marker(path)
                if classified is None:
                    continue
                mitre, label = classified
                if mitre not in policy:
                    continue
                try:
                    path_stat = path.stat(follow_symlinks=False)
                    if (
                        not stat.S_ISREG(path_stat.st_mode)
                        or int(getattr(path_stat, "st_nlink", 1)) != 1
                        or bool(getattr(path_stat, "st_file_attributes", 0) & 0x400)
                    ):
                        continue
                    key = (
                        str(path.resolve()),
                        path_stat.st_mtime_ns,
                        path_stat.st_size,
                    )
                except OSError:
                    continue
                if key in self._seen:
                    continue
                practice_id = _practice_id_from_marker(path)
                practice_details = (
                    {"practice_verification_id": practice_id} if practice_id else {}
                )
                validation_details: dict[str, object] = {}
                lease = self._validation_lease
                if lease is not None:
                    validation_details = RedTeamValidationLease.attest_purple_detection(
                        lease,
                        self,
                        technique=mitre,
                        observed_target=str(path),
                        evidence_kind="inert_file_marker",
                    )
                    # During a live Red Team lease, an unheld or aliased file is
                    # not even a completed detector hit. Keep it retryable so a
                    # legitimate engine registration that wins the race can be
                    # observed on the next bounded scan.
                    if not validation_details:
                        continue
                self._seen.add(key)
                self.emit(
                    f"Purple Guard detected {label} ({mitre}) in a registered drill target.",
                    Severity.HIGH,
                    path=str(path), artifact_path=str(path), mitre=mitre,
                    drill_target=str(target),
                    detector_policy="reviewed-redteam-candidate",
                    response_authorized=True,
                    response_contract={
                        "version": 1,
                        "actions": ["quarantine_file"],
                        "targets": {"path": str(path)},
                    },
                    **{
                        "evidence_type": "simulation_contract_validation",
                        "detector_verdict": "positive",
                        **practice_details,
                        **validation_details,
                    },
                )
                self.detected += 1
                hits += 1
        return hits

    def scan_process_once(self, policy: dict | None = None) -> int:
        if policy is None:
            policy = _read_policy(self.data_root).get("techniques", {})
        if (not isinstance(policy, dict) or _PROCESS_TECHNIQUE not in policy
                or self._bus is None):
            return 0
        hits = 0
        for event in self._process_events():
            classified = classify_process_event(event)
            if classified is None:
                continue
            mitre, label, token = classified
            details = getattr(event, "details", {}) or {}
            key = (float(getattr(event, "ts", 0.0)), str(getattr(event, "module", "")),
                   details.get("pid"), token)
            if key in self._seen_events:
                continue
            command = str(details.get("cmdline") or details.get("command_line") or "")
            pid = details.get("pid")
            raw_created = (
                details.get("process_create_time")
                or details.get("pid_create_time")
                or details.get("create_time")
                or details.get("process_start_time")
            )
            response = {}
            try:
                created = float(raw_created)
            except (TypeError, ValueError, OverflowError):
                created = 0.0
            if isinstance(pid, int) and pid > 0 and created > 0:
                response = {
                    "response_authorized": True,
                    "response_contract": {
                        "version": 1,
                        "actions": [
                            "isolate_program",
                            "suspend_process",
                            "terminate_process",
                        ],
                        "targets": {
                            "pid": pid,
                            "process_create_time": created,
                        },
                    },
                }
            validation_details: dict[str, object] = {}
            lease = self._validation_lease
            if lease is not None:
                validation_details = RedTeamValidationLease.attest_purple_detection(
                    lease,
                    self,
                    technique=mitre,
                    observed_target=f"{pid}:{token}",
                    evidence_kind="nonce_tagged_process",
                    pid=pid,
                    process_create_time=created or raw_created,
                    source_event=event,
                )
                if not validation_details:
                    # A bus row is only transport evidence. During a scored
                    # run it must also match the issuer-enrolled live pid/birth
                    # challenge before Purple Guard may promote it.
                    continue
                verified_created = validation_details.pop(
                    "_validated_process_create_time", None
                )
                try:
                    created = float(verified_created)
                except (TypeError, ValueError, OverflowError):
                    continue
                response = {
                    "response_authorized": True,
                    "response_contract": {
                        "version": 1,
                        "actions": [
                            "isolate_program",
                            "suspend_process",
                            "terminate_process",
                        ],
                        "targets": {
                            "pid": pid,
                            "process_create_time": created,
                        },
                    },
                }
            self._seen_events.add(key)
            self.emit(
                f"Purple Guard detected {label} ({mitre}) in process telemetry.",
                Severity.HIGH, pid=pid, cmdline=command,
                process_create_time=created or raw_created,
                event_type="purple_process_detection", mitre=mitre,
                correlation_token=token,
                detector_policy="reviewed-redteam-candidate",
                **{
                    "evidence_type": "simulation_contract_validation",
                    "detector_verdict": "positive",
                    **response,
                    **_safe_lineage_details(details),
                    **validation_details,
                },
            )
            self.detected += 1
            hits += 1
        if len(self._seen_events) > 4096:
            self._seen_events.clear()
        return hits

    def work_cycle(self) -> tuple[int, int, int]:
        """Run one detector cycle using one coherent policy snapshot.

        The old loop parsed ``purple_guard_policy.json`` three times per
        second (health, file markers, and process markers). A single parse is
        faster and makes every check in the cycle observe one policy version.
        """
        policy = self._policy_snapshot()
        file_hits = self.scan_once(policy)
        process_hits = self.scan_process_once(policy)
        with self._validation_cycle:
            self._validation_cycle_serial += 1
            self._validation_cycle_generation = int(self.lifecycle_generation)
            self._validation_cycle_techniques = frozenset(
                str(key) for key in policy
            )
            self._validation_cycle_at = time.time()
            self._validation_cycle.notify_all()
        return file_hits, process_hits, len(policy)

    def _update_policy_health(self, count: int) -> None:
        if count:
            self._had_reviewed_policy = True
            self._policy_loss_reported = False
            self.set_health(
                100,
                f"{count} reviewed signature(s); {self.detected} verified hit(s)",
            )
            return
        if not self._had_reviewed_policy:
            self.set_health(
                70,
                "No reviewed drill signatures are installed; Purple Guard is "
                "in learning-only mode.",
            )
            return
        self.set_health(
            25,
            "Reviewed Purple Guard policy disappeared or became unreadable; "
            "simulation-specific detection is unavailable.",
        )
        if self._policy_loss_reported:
            return
        self._policy_loss_reported = True
        self.emit(
            "Reviewed Purple Guard policy was lost; validation coverage "
            "is incomplete until an authenticated pack is restored.",
            Severity.HIGH,
            finding_code="purple_guard.policy_lost",
            policy_path=str(policy_path(self.data_root)),
            response_authorized=False,
        )

    def _wait_for_process_evidence(self, seconds: float) -> None:
        """Wait stop-aware until the cadence expires or exact process evidence arrives."""
        with self._throttle_lock:
            throttle = float(self._throttle)
        interval = max(0.0, float(seconds)) * throttle
        self.mark_cycle_complete(interval_seconds=interval)
        deadline = time.monotonic() + interval
        while not self.stopping:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._process_wake.wait(
                timeout=min(0.25, remaining)
            ):
                return

    def run(self) -> None:
        if self._bus is not None:
            self._bus.subscribe(self._capture_process_event)
            self._process_subscription_active = True
        while not self.stopping:
            # Clear before the scan. Evidence racing with the clear is already
            # in the retained queue and is consumed by this work cycle; evidence
            # arriving during/after the scan leaves the event set and wakes the
            # next cycle immediately.
            self._process_wake.clear()
            _file_hits, _process_hits, count = self.work_cycle()
            self._update_policy_health(count)
            if count:
                # The reviewed file policy keeps its one-second cadence, but a
                # nonce-tagged native process receipt must wake the detector
                # immediately rather than landing just after a scan and waiting
                # a full interval before its lease-bound promotion.
                self._wait_for_process_evidence(1.0)
                continue
            # Idle file evidence remains on the low-cost five-second cadence,
            # while an exact process receipt wakes the module immediately. Small
            # stop-aware slices preserve responsive stop/restart semantics and
            # the explicit watchdog deadline without rescanning four times/sec.
            self._wait_for_process_evidence(5.0)

    def self_test(self) -> tuple[bool, str]:
        import tempfile
        with tempfile.TemporaryDirectory(prefix="angerona_purple_guard_") as td:
            root = Path(td)
            install_policies([{"mitre": "T1003"}], "self-test", root)
            sandbox = root / "drill-sandbox"
            sandbox.mkdir(parents=True)
            bad = sandbox / "_redteam_lsass_dump_probe.txt"
            noise = sandbox / "_redteam_benign_note_probe.txt"
            bad.write_text("inert", encoding="utf-8")
            noise.write_text("ordinary note", encoding="utf-8")
            seen = []
            probe = PurpleGuard(root)
            probe.emit = lambda message, severity=Severity.INFO, **details: seen.append(details)
            hits = probe.scan_once()
            process = type("ProcessEvent", (), {
                "details": {"event_type": "process_creation", "pid": 42,
                            "cmdline": "cmd /c rem ANGERONA_REDTEAM_deadbeef"}})()
            process_ok = classify_process_event(process)
            ok = (hits == 1 and len(seen) == 1 and seen[0].get("mitre") == "T1003"
                  and process_ok and process_ok[0] == "T1059")
            return ok, ("exact file/process markers detected; benign noise ignored"
                        if ok else "marker policy self-test failed")


def _wait_for_recorder_echo(
    bus: object,
    recorder: object,
    *,
    timeout: float,
) -> dict[str, object]:
    """Prove EventBus -> authenticated flight-recorder persistence end to end."""
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.storage import FlightRecorder

    if not bool(getattr(bus, "integrity_enabled", False)):
        raise RedTeamValidationError(
            "authenticated EventBus signing is not active"
        )
    authority = getattr(recorder, "authority", None)
    if (
        type(bus) is not EventBus
        or type(recorder) is not FlightRecorder
        or type(authority) is not BusAuthority
    ):
        raise RedTeamValidationError(
            "flight-recorder readiness interfaces are unavailable"
        )
    nonce = uuid.uuid4().hex
    started = time.time()
    before_revision = int(FlightRecorder.revision(recorder))
    EventBus.publish(
        bus,
        Event(
            "Red Team Validation",
            "Authenticated drill-recorder readiness probe.",
            Severity.INFO,
            started,
            {
                "validation_nonce": nonce,
                "simulation_only": True,
                "response_authorized": False,
            },
        )
    )
    deadline = time.monotonic() + max(0.1, float(timeout))
    while time.monotonic() < deadline:
        try:
            rows = FlightRecorder.recent_in_window(
                recorder,
                started - 1.0,
                time.time() + 1.0,
                limit=5000,
            )
        except (OSError, RuntimeError, ValueError):
            rows = []
        for event in rows:
            details = getattr(event, "details", {}) or {}
            after_revision = int(FlightRecorder.revision(recorder))
            if (
                getattr(event, "module", "") == "Red Team Validation"
                and details.get("validation_nonce") == nonce
                and after_revision > before_revision
                and bool(getattr(event, "hmac_sig", ""))
                and details.get("_ledger_integrity") is None
                and bool(EventBus.verify(bus, event))
                and bool(BusAuthority.verify(authority, event))
            ):
                return {
                    "nonce": nonce,
                    "published_at": started,
                    "recorder_revision_before": before_revision,
                    "recorder_revision_after": after_revision,
                    "authenticated": True,
                    "persisted": True,
                }
        time.sleep(0.025)
    raise RedTeamValidationError(
        "authenticated validation event did not reach the flight recorder "
        f"within {max(0.1, float(timeout)):.1f}s"
    )


def acquire_redteam_validation_lease(
    manager: object,
    bus: object,
    recorder: object,
    data_root: Path,
    target: _PathInput,
    *,
    timeout: float = 8.0,
    comprehensive: bool = False,
) -> RedTeamValidationLease:
    """Fail closed unless the complete drill evidence plane is live.

    Policy presence alone is not readiness. This gate proves the exact built-in
    Purple Guard instance is bound to the launcher's bus and data root, starts
    it temporarily when needed, waits for a *fresh* cycle that consumed all 13
    validation contracts, and persists an authenticated sentinel through the
    same recorder the AAR will read.
    """
    root = Path(data_root).resolve(strict=False)
    required_techniques = (
        REDTEAM_COMPREHENSIVE_VALIDATION_TECHNIQUES
        if comprehensive
        else REDTEAM_VALIDATION_TECHNIQUES
    )
    normalized_target = _normalize_runtime_target(target, require_directory=False)
    target_existed = normalized_target.exists()
    try:
        normalized_target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RedTeamValidationError(
            "the simulation target could not be created and held"
        ) from exc
    if not _validation_target_markers_safe(normalized_target):
        raise RedTeamValidationError(
            "the simulation target contains an unsafe marker alias or unverifiable marker"
        )
    modules = getattr(manager, "modules", {})
    if not isinstance(modules, dict):
        raise RedTeamValidationError(
            "the validation manager does not expose an exact module registry"
        )
    module = modules.get("Purple Remediation Guard") if isinstance(modules, dict) else None
    if type(module) is not PurpleGuard:
        raise RedTeamValidationError(
            "the exact built-in Purple Remediation Guard module is unavailable"
        )
    if Path(module.data_root).resolve(strict=False) != root:
        raise RedTeamValidationError(
            "Purple Guard data root does not match this simulation's evidence root"
        )
    if getattr(manager, "bus", None) is not bus or getattr(module, "_bus", None) is not bus:
        raise RedTeamValidationError(
            "Purple Guard is not bound to the simulation EventBus"
        )

    from angerona.core.module_contract import build_capability_contract
    from angerona.modules.process_monitor import ProcessMonitorModule

    process_module = modules.get("Process Monitor")
    process_inserted = False
    if process_module is None:
        # A validation run is allowed to provision this read-only exact sensor
        # for its own lifetime, just as it may temporarily start Purple Guard.
        # Production managers normally already contain it; the fallback keeps
        # headless/offline validation honest instead of silently omitting T1059.
        process_module = ProcessMonitorModule()
        process_module.bind(bus)
        process_module._angerona_contract = build_capability_contract(  # type: ignore[attr-defined]
            process_module,
            capability_id="angerona.builtin.process_monitor",
            origin="builtin",
            trust="release",
            publisher="Angerona",
        )
        modules[process_module.name] = process_module
        process_inserted = True
    process_contract = getattr(process_module, "_angerona_contract", None)
    if (
        type(process_module) is not ProcessMonitorModule
        or getattr(process_module, "_bus", None) is not bus
        or process_contract is None
        or str(process_contract.capability_id) != "angerona.builtin.process_monitor"
    ):
        if process_inserted and modules.get("Process Monitor") is process_module:
            modules.pop("Process Monitor", None)
        raise RedTeamValidationError(
            "the exact built-in Process Monitor producer is unavailable or unbound"
        )

    try:
        recorder_identity = validate_redteam_recorder(recorder, root, bus=bus)
        validation = ensure_redteam_validation_pack(
            root, comprehensive=bool(comprehensive)
        )
        if set(validation.get("active", ())) != required_techniques:
            raise RedTeamValidationError(
                "the requested simulation contract pack was not verified"
            )
        policy_identity = _policy_identity(root)
    except Exception:
        if process_inserted and modules.get("Process Monitor") is process_module:
            modules.pop("Process Monitor", None)
        raise

    baseline = int(module.validation_cycle_snapshot()["serial"])
    registered = normalized_target
    needs_temporary_start = not bool(
        module.operational_snapshot().get("thread_alive")
        and module.status == "running"
    )
    prior_chill = bool(getattr(module, "_chill_paused", False))
    process_prior_chill = bool(getattr(process_module, "_chill_paused", False))
    process_baseline_cycle = int(
        BaseModule.operational_snapshot(process_module).get("cycle_count", 0)
    )
    process_needs_start = not bool(
        process_module.operational_snapshot().get("thread_alive")
        and process_module.status == "running"
    )
    try:
        lease = RedTeamValidationLease(
            issuer=_LEASE_ISSUER,
            module=module,
            target=registered,
            data_root=root,
            manager=manager,
            bus=bus,
            recorder=recorder,
            readiness={},
            target_created_by_lease=not target_existed,
            started_temporarily=False,
            target_registered_by_lease=False,
            previous_chill_paused=prior_chill,
        )
    except Exception:
        if process_inserted and modules.get("Process Monitor") is process_module:
            modules.pop("Process Monitor", None)
        raise
    try:
        state = _lease_authority(lease)
        state.process_module = process_module
        state.process_inserted_by_lease = process_inserted
        state.process_previous_chill_paused = process_prior_chill
        if process_needs_start:
            state.process_started_temporarily = True
            setattr(process_module, "_chill_paused", False)
            process_module.start()
        module._reserve_validation_lease(lease)
        if needs_temporary_start:
            lease.started_temporarily = True
            state.started_temporarily = True
            setattr(module, "_chill_paused", False)
            module.start()
        if not module.wait_for_validation_cycle(
            required_techniques,
            after_serial=baseline,
            timeout=timeout,
        ):
            raise RedTeamValidationError(
                "Purple Guard did not complete a fresh "
                f"{len(required_techniques)}-contract scan cycle "
                f"within {max(0.1, float(timeout)):.1f}s"
            )
        if not module.wait_for_first_cycle(timeout=max(0.1, float(timeout))):
            raise RedTeamValidationError(
                "Purple Guard scanned policy but did not publish its lifecycle boundary"
            )
        # A complete psutil process inventory can take several seconds on a
        # busy Windows host. Preserve the caller's larger budget while giving
        # this exact source sensor the same bounded eight-second readiness
        # allowance as recorder persistence.
        process_deadline = time.monotonic() + min(
            max(8.0, float(timeout)), 30.0
        )
        process_operational: dict[str, object] = {}
        while time.monotonic() < process_deadline:
            process_operational = BaseModule.operational_snapshot(process_module)
            if (
                process_operational.get("status") == "running"
                and process_operational.get("thread_alive") is True
                and process_operational.get("first_cycle_complete") is True
                and int(process_operational.get("cycle_count", 0))
                > process_baseline_cycle
            ):
                break
            time.sleep(0.025)
        if (
            process_operational.get("status") != "running"
            or process_operational.get("thread_alive") is not True
            or process_operational.get("first_cycle_complete") is not True
            or int(process_operational.get("cycle_count", 0))
            <= process_baseline_cycle
            or int(process_operational.get("health", 0)) < 50
            or int(process_operational.get("event_overflow_count", -1)) != 0
        ):
            raise RedTeamValidationError(
                "Process Monitor did not prove a healthy fresh loss-free observation cycle: "
                f"status={process_operational.get('status')}, "
                f"health={process_operational.get('health')}, "
                f"cycle={process_operational.get('cycle_count')}, "
                f"baseline={process_baseline_cycle}, "
                f"error={getattr(process_module, 'last_error', '')}"
            )
        operational = module.operational_snapshot()
        if (
            operational.get("status") != "running"
            or operational.get("thread_alive") is not True
            or operational.get("first_cycle_complete") is not True
            or int(operational.get("health", 0)) < 90
        ):
            raise RedTeamValidationError(
                "Purple Guard did not attest a healthy live first-cycle boundary"
            )
        recorder_echo = _wait_for_recorder_echo(
            bus,
            recorder,
            timeout=min(max(1.0, float(timeout)), 8.0),
        )
        cycle = module.validation_cycle_snapshot()
        assert state.lock is not None
        with state.lock:
            state.readiness = {
                "schema": "angerona.redteam-validation-readiness.v4",
                "simulation_only": True,
                "acquired_at": time.time(),
                "sensor": module.name,
                "sensor_capability_id": "angerona.builtin.purple_guard",
                "sensor_started_temporarily": lease.started_temporarily,
                "sensor_status": operational["status"],
                "sensor_health": int(operational["health"]),
                "sensor_generation": int(cycle["generation"]),
                "sensor_cycle_serial": int(cycle["serial"]),
                "policy_techniques": sorted(required_techniques),
                "policy_count": len(required_techniques),
                "comprehensive": bool(comprehensive),
                "detector_contracts": [
                    {
                        "technique": technique,
                        "source_capability_id": (
                            "angerona.builtin.process_monitor"
                            if technique == _PROCESS_TECHNIQUE
                            else "angerona.builtin.purple_guard"
                        ),
                    }
                    for technique in sorted(required_techniques)
                ],
                "process_sensor": {
                    "module": process_module.name,
                    "capability_id": "angerona.builtin.process_monitor",
                    "generation": int(
                        process_operational["lifecycle_generation"]
                    ),
                    "cycle_count": int(process_operational["cycle_count"]),
                    "first_cycle_complete": True,
                    "event_overflow_count": 0,
                    "started_temporarily": process_needs_start,
                    "provisioned_for_validation": process_inserted,
                },
                "target": str(registered),
                "target_identity": copy.deepcopy(state.target_identity),
                "data_root": str(root),
                "policy": policy_identity,
                "recorder": recorder_echo,
                "recorder_identity": recorder_identity,
            }
        RedTeamValidationLease.bind_native_producers(lease, manager)
        return lease
    except Exception:
        lease.release()
        raise


def register() -> PurpleGuard:
    return PurpleGuard()
