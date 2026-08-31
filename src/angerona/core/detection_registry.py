"""Offline lifecycle registry for verified detection packages.

The registry owns immutable, digest-named package copies and a small atomic
manifest.  Activation and rollback never modify package content; they only
replace the manifest after re-running all loader validation gates.
"""
from __future__ import annotations

import base64
import json
import hashlib
import hmac
import os
import secrets
import stat
import tempfile
import threading
import time
from copy import deepcopy
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from angerona.core.detection_packages import (
    MAX_PACKAGE_BYTES,
    DetectionPackage,
    PackageValidationError,
    load_package,
)

STATES = {"staged", "active", "retired", "quarantined"}
DEFAULT_LOCK_TIMEOUT = 5.0
_GOVERNANCE_SCHEMA = "angerona.detection-registry-governance.v1"
_GOVERNANCE_DOMAIN = b"angerona/detection-registry-governance/v1\x00"
_GOVERNANCE_ANCHOR_SCHEMA = "angerona.detection-registry-governance-anchor.v1"
_GOVERNANCE_ANCHOR_DOMAIN = b"angerona/detection-registry-governance-anchor/v1\x00"
_IDENTITY_AUTHORITIES: dict[str, tuple[object, str]] = {}
_IDENTITY_AUTHORITIES_LOCK = threading.Lock()
_ROOT_POLICY_FLOORS: dict[str, tuple[str | None, bool, str | None]] = {}
_MAX_TRUST_STORE_BYTES = 256 * 1024
_MAX_TRUSTED_KEYS = 1024
_MAX_SIGNATURE_BYTES = 16 * 1024
_TRUST_SNAPSHOT_UNSET = object()


@dataclass(frozen=True)
class _FileStamp:
    path: Path
    metadata: tuple[int, int, int, int, int, int, int]


@dataclass(frozen=True)
class _FileProof:
    stamp: _FileStamp
    sha256: str


@dataclass(frozen=True)
class _TrustStoreSnapshot:
    proof: _FileProof
    canonical_sha256: str
    public_keys: Mapping[str, bytes]


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _has_reparse_attribute(metadata: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & marker)


def _file_metadata(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _same_file_generation(
    left: tuple[int, int, int, int, int, int, int],
    right: tuple[int, int, int, int, int, int, int],
) -> bool:
    # Windows' path and descriptor stat APIs can report different creation-time
    # precision for the same inode. Identity, mode, links, size, and mtime are
    # stable across both APIs; same-API exit checks still compare the full tuple.
    return left[:6] == right[:6] if os.name == "nt" else left == right


def _regular_file_stamp(path: Path, *, maximum: int) -> _FileStamp:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _has_reparse_attribute(metadata)
        or int(metadata.st_nlink) != 1
        or int(metadata.st_size) > maximum
    ):
        raise PackageValidationError(
            f"security metadata file is unsafe or exceeds {maximum} bytes"
        )
    return _FileStamp(Path(path), _file_metadata(metadata))


def _read_stable_file(path: Path, *, maximum: int) -> tuple[bytes, _FileProof]:
    before = _regular_file_stamp(path, maximum=maximum)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        opened_stamp = _FileStamp(Path(path), _file_metadata(opened))
        if not _same_file_generation(opened_stamp.metadata, before.metadata):
            raise PackageValidationError(
                "security metadata file identity changed before read"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > maximum:
            raise PackageValidationError(
                f"security metadata file exceeds {maximum} bytes"
            )
        after = os.fstat(descriptor)
        after_stamp = _FileStamp(Path(path), _file_metadata(after))
        if after_stamp.metadata != opened_stamp.metadata:
            raise PackageValidationError(
                "security metadata file changed during read"
            )
        current = _regular_file_stamp(path, maximum=maximum)
        if not _same_file_generation(current.metadata, opened_stamp.metadata):
            raise PackageValidationError(
                "security metadata file path changed during read"
            )
        return raw, _FileProof(
            current, hashlib.sha256(raw).hexdigest()
        )
    finally:
        os.close(descriptor)


def _assert_file_stamp_unchanged(stamp: _FileStamp, *, maximum: int) -> None:
    try:
        current = _regular_file_stamp(stamp.path, maximum=maximum)
    except OSError as exc:
        raise PackageValidationError(
            "validated security artifact became unavailable"
        ) from exc
    if current.metadata != stamp.metadata:
        raise PackageValidationError(
            "validated security artifact changed during active-set validation"
        )


@dataclass(frozen=True)
class ValidationReport:
    ok: bool
    action: str
    state: str
    package_id: str | None
    digest: str | None
    errors: tuple[str, ...] = ()
    previous_digest: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["errors"] = list(self.errors)
        return result


class DetectionPackageRegistry:
    """A single-host, local package registry with atomic state transitions."""

    def __init__(
        self,
        root: str | Path,
        *,
        trusted_keys: str | Path | None = None,
        require_signed: bool = True,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT,
        transition_authority: object | None = None,
    ) -> None:
        self.root = Path(root).resolve()
        self.packages = self.root / "packages"
        self.quarantine = self.root / "quarantine"
        self.manifest_path = self.root / "registry.json"
        self.governance_anchor_path = self.root / "registry-governance.anchor.json"
        self.lock_path = self.root / "registry.lock"
        self.trusted_keys = Path(trusted_keys).resolve() if trusted_keys else None
        requested_signed = bool(require_signed)
        self.require_signed = requested_signed
        self.lock_timeout = max(0.05, min(float(lock_timeout), 60.0))
        # An identity capability is deliberately installed at construction so
        # governance initialization failure cannot leave a transition window.
        # Standalone/development registries omit it explicitly for compatibility.
        self.__transition_authority = transition_authority
        self.__governance_key = (
            bytes(transition_authority)
            if isinstance(transition_authority, bytes)
            else None
        )
        if self.__governance_key is not None and len(self.__governance_key) != 32:
            raise PackageValidationError(
                "persistent registry governance authority must contain 32 bytes"
            )
        self.packages.mkdir(parents=True, exist_ok=True)
        self.quarantine.mkdir(parents=True, exist_ok=True)
        with self._locked():
            if not self.manifest_path.exists():
                manifest = {
                    "schema_version": 1, "packages": {},
                    "activation_policy": (
                        "signed_only" if self.require_signed
                        else "development_unsigned_override"
                    ),
                }
                manifest["governance"] = self._new_governance_policy(
                    transition_authority
                )
                self._write_manifest(manifest)
                if self.__governance_key is not None:
                    self._write_governance_anchor(
                        manifest["governance"], generation=1
                    )
            else:
                manifest = self._manifest()
                prior_policy = deepcopy(manifest.get("governance"))
                had_governance = isinstance(prior_policy, Mapping)
                prior_anchor: dict[str, object] | None = None
                if (
                    isinstance(prior_policy, Mapping)
                    and prior_policy.get("mode") == "root-hmac"
                ):
                    if not self.governance_anchor_path.exists():
                        raise PackageValidationError(
                            "root-governed registry anchor is missing"
                        )
                    prior_anchor = self._read_governance_anchor()
                    self._assert_governance_anchor(prior_policy, prior_anchor)
                changed = self._load_governance_policy(
                    manifest, transition_authority, requested_signed=requested_signed
                )
                if changed:
                    self._write_manifest(manifest)
                policy = manifest["governance"]
                if isinstance(policy, Mapping) and policy.get("mode") == "root-hmac":
                    if prior_anchor is None:
                        if had_governance:
                            raise PackageValidationError(
                                "existing governance cannot mint a new root anchor"
                            )
                        self._write_governance_anchor(policy, generation=1)
                    elif changed:
                        self._write_governance_anchor(
                            policy, generation=int(prior_anchor["generation"]) + 1
                        )
                    else:
                        self._assert_governance_anchor(policy, prior_anchor)
            self._register_policy_floor(manifest["governance"])

    def _register_policy_floor(self, policy: Mapping[str, object]) -> None:
        root = str(self.root)
        authority_id = (
            str(policy.get("authority_id"))
            if policy.get("authority_id") is not None
            else None
        )
        signed = bool(policy.get("require_signed"))
        trusted_path = (
            str(policy.get("trusted_keys_path"))
            if policy.get("trusted_keys_path") is not None
            else None
        )
        with _IDENTITY_AUTHORITIES_LOCK:
            prior = _ROOT_POLICY_FLOORS.get(root)
            if prior is not None:
                prior_authority, prior_signed, prior_trust = prior
                if (
                    prior_authority is not None
                    and authority_id != prior_authority
                ):
                    raise PackageValidationError(
                        "registry root authority cannot be replaced in-process"
                    )
                if prior_trust is not None and trusted_path != prior_trust:
                    raise PackageValidationError(
                        "registry trusted publisher store cannot be replaced in-process"
                    )
                if prior_signed and not signed:
                    raise PackageValidationError(
                        "registry signature floor cannot be reopened below signed-only"
                    )
                authority_id = prior_authority or authority_id
                signed = bool(prior_signed or signed)
                trusted_path = prior_trust or trusted_path
            _ROOT_POLICY_FLOORS[root] = (authority_id, signed, trusted_path)

    @staticmethod
    def _authority_id(key: bytes) -> str:
        return hashlib.sha256(_GOVERNANCE_DOMAIN + key).hexdigest()

    @staticmethod
    def _governance_unsigned(policy: Mapping[str, object]) -> dict[str, object]:
        return {
            "schema": policy.get("schema"),
            "mode": policy.get("mode"),
            "authority_id": policy.get("authority_id"),
            "require_signed": policy.get("require_signed"),
            "trusted_keys_path": policy.get("trusted_keys_path"),
        }

    def _policy_mac(self, policy: Mapping[str, object]) -> str:
        if self.__governance_key is None:
            return ""
        payload = json.dumps(
            self._governance_unsigned(policy),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hmac.new(
            self.__governance_key, _GOVERNANCE_DOMAIN + payload, hashlib.sha256
        ).hexdigest()

    def _governance_anchor_mac(self, anchor: Mapping[str, object]) -> str:
        if self.__governance_key is None:
            raise PackageValidationError(
                "persistent governance anchor requires root authority"
            )
        unsigned = dict(anchor)
        unsigned.pop("hmac", None)
        payload = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hmac.new(
            self.__governance_key,
            _GOVERNANCE_ANCHOR_DOMAIN + payload,
            hashlib.sha256,
        ).hexdigest()

    def _read_governance_anchor(self) -> dict[str, object]:
        try:
            raw = self.governance_anchor_path.read_bytes()
        except OSError as exc:
            raise PackageValidationError(
                "registry governance anchor is unreadable"
            ) from exc
        if len(raw) > 64 * 1024:
            raise PackageValidationError("registry governance anchor is oversized")
        try:
            anchor = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PackageValidationError(
                "registry governance anchor is malformed"
            ) from exc
        if not isinstance(anchor, dict) or set(anchor) != {
            "schema", "generation", "authority_id", "require_signed",
            "trusted_keys_path", "hmac",
        }:
            raise PackageValidationError("registry governance anchor fields are invalid")
        if (
            anchor["schema"] != _GOVERNANCE_ANCHOR_SCHEMA
            or type(anchor["generation"]) is not int
            or int(anchor["generation"]) < 1
            or type(anchor["require_signed"]) is not bool
        ):
            raise PackageValidationError("registry governance anchor values are invalid")
        if not hmac.compare_digest(
            str(anchor["hmac"]), self._governance_anchor_mac(anchor)
        ):
            raise PackageValidationError(
                "registry governance anchor authority HMAC is invalid"
            )
        return anchor

    def _write_governance_anchor(
        self, policy: Mapping[str, object], *, generation: int
    ) -> None:
        if type(generation) is not int or generation < 1:
            raise PackageValidationError("registry governance generation is invalid")
        anchor: dict[str, object] = {
            "schema": _GOVERNANCE_ANCHOR_SCHEMA,
            "generation": generation,
            "authority_id": policy.get("authority_id"),
            "require_signed": policy.get("require_signed"),
            "trusted_keys_path": policy.get("trusted_keys_path"),
            "hmac": "",
        }
        anchor["hmac"] = self._governance_anchor_mac(anchor)
        payload = json.dumps(
            anchor,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        descriptor, temporary = tempfile.mkstemp(
            prefix=".registry-governance-", suffix=".tmp", dir=self.root
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.governance_anchor_path)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    @staticmethod
    def _assert_governance_anchor(
        policy: Mapping[str, object], anchor: Mapping[str, object]
    ) -> None:
        if (
            anchor.get("authority_id") != policy.get("authority_id")
            or anchor.get("require_signed") != policy.get("require_signed")
            or anchor.get("trusted_keys_path") != policy.get("trusted_keys_path")
        ):
            raise PackageValidationError(
                "registry governance manifest was partially rolled back"
            )
        # This local anchor detects partial policy/manifest rollback. An
        # attacker able to roll back the entire authenticated root, including
        # both files and the package store, remains outside this local boundary.

    def _new_governance_policy(self, authority: object | None) -> dict[str, object]:
        trusted_path = str(self.trusted_keys) if self.trusted_keys is not None else None
        if self.__governance_key is not None:
            policy: dict[str, object] = {
                "schema": _GOVERNANCE_SCHEMA,
                "mode": "root-hmac",
                "authority_id": self._authority_id(self.__governance_key),
                "require_signed": self.require_signed,
                "trusted_keys_path": trusted_path,
                "policy_hmac": "",
            }
            policy["policy_hmac"] = self._policy_mac(policy)
            return policy
        if authority is not None:
            identity = secrets.token_hex(32)
            with _IDENTITY_AUTHORITIES_LOCK:
                _IDENTITY_AUTHORITIES[str(self.root)] = (authority, identity)
            return {
                "schema": _GOVERNANCE_SCHEMA,
                "mode": "process-identity",
                "authority_id": identity,
                "require_signed": self.require_signed,
                "trusted_keys_path": trusted_path,
                "policy_hmac": None,
            }
        return {
            "schema": _GOVERNANCE_SCHEMA,
            "mode": "none",
            "authority_id": None,
            "require_signed": self.require_signed,
            "trusted_keys_path": trusted_path,
            "policy_hmac": None,
        }

    def _load_governance_policy(
        self,
        manifest: dict[str, Any],
        authority: object | None,
        *,
        requested_signed: bool,
    ) -> bool:
        """Load a sticky root policy; a second instance cannot claim authority."""
        policy = manifest.get("governance")
        if not isinstance(policy, dict):
            # Authenticated governance was introduced after registry v1. Existing
            # roots are upgraded in place, preserving the stricter old policy.
            old_signed = manifest.get("activation_policy") == "signed_only"
            self.require_signed = bool(old_signed or requested_signed)
            manifest["activation_policy"] = (
                "signed_only" if self.require_signed
                else "development_unsigned_override"
            )
            manifest["governance"] = self._new_governance_policy(authority)
            return True
        if set(policy) != {
            "schema", "mode", "authority_id", "require_signed",
            "trusted_keys_path", "policy_hmac",
        } or policy.get("schema") != _GOVERNANCE_SCHEMA:
            raise PackageValidationError("registry governance policy is invalid")
        mode = policy.get("mode")
        if mode not in {"none", "process-identity", "root-hmac"}:
            raise PackageValidationError("registry governance mode is invalid")
        stored_signed = policy.get("require_signed")
        if type(stored_signed) is not bool:
            raise PackageValidationError("registry signature policy is invalid")
        if stored_signed and not requested_signed:
            raise PackageValidationError("signed registry policy cannot be downgraded")
        stored_trust = policy.get("trusted_keys_path")
        supplied_trust = str(self.trusted_keys) if self.trusted_keys is not None else None
        if stored_trust is not None and stored_trust != supplied_trust:
            raise PackageValidationError("registry trusted publisher store cannot be substituted")
        changed = False
        if mode == "root-hmac":
            if self.__governance_key is None:
                raise PackageValidationError(
                    "root-bound registry governance authority is required"
                )
            expected_id = self._authority_id(self.__governance_key)
            if not hmac.compare_digest(str(policy.get("authority_id")), expected_id):
                raise PackageValidationError("registry governance authority is invalid")
            expected_mac = self._policy_mac(policy)
            if not hmac.compare_digest(str(policy.get("policy_hmac")), expected_mac):
                raise PackageValidationError("registry governance policy HMAC is invalid")
        elif mode == "process-identity":
            with _IDENTITY_AUTHORITIES_LOCK:
                enrolled = _IDENTITY_AUTHORITIES.get(str(self.root))
            if (
                enrolled is None
                or authority is not enrolled[0]
                or policy.get("authority_id") != enrolled[1]
            ):
                raise PackageValidationError(
                    "process-bound registry authority cannot be reopened or substituted"
                )
        elif authority is not None:
            # Governance can be tightened, but never silently removed again.
            self.require_signed = bool(stored_signed or requested_signed)
            manifest["governance"] = self._new_governance_policy(authority)
            manifest["activation_policy"] = (
                "signed_only" if self.require_signed
                else "development_unsigned_override"
            )
            return True
        self.require_signed = bool(stored_signed or requested_signed)
        if self.require_signed != stored_signed or (
            stored_trust is None and supplied_trust is not None
        ):
            policy["require_signed"] = self.require_signed
            policy["trusted_keys_path"] = supplied_trust
            if mode == "root-hmac":
                policy["policy_hmac"] = self._policy_mac(policy)
            manifest["activation_policy"] = "signed_only"
            changed = True
        expected_activation = (
            "signed_only" if self.require_signed else "development_unsigned_override"
        )
        if manifest.get("activation_policy") != expected_activation:
            raise PackageValidationError("registry activation policy diverges from governance")
        return changed

    @property
    def governance_required(self) -> bool:
        return self.__transition_authority is not None

    @property
    def root_governed(self) -> bool:
        """Whether transitions are authenticated by a restart-stable root key."""
        return self.__governance_key is not None

    def assert_transition_authority(self, capability: object | None) -> None:
        """Verify, without revealing, the registry's identity capability."""
        if self.__transition_authority is None:
            if capability is not None:
                raise PackageValidationError(
                    "transition capability supplied to an ungoverned registry"
                )
            return
        if self.__governance_key is not None:
            if not isinstance(capability, bytes) or not hmac.compare_digest(
                capability, self.__governance_key
            ):
                raise PackageValidationError(
                    "registry transition requires root-bound governance authority"
                )
            return
        if capability is not self.__transition_authority:
            raise PackageValidationError(
                "registry transition requires DetectionForge coordinator authority"
            )

    def _transition_denied(
        self,
        action: str,
        package_id: str,
        digest: str | None,
        capability: object | None,
    ) -> ValidationReport | None:
        try:
            self.assert_transition_authority(capability)
        except PackageValidationError as exc:
            return ValidationReport(
                False,
                action,
                "governance-required",
                package_id,
                digest,
                (str(exc),),
            )
        return None

    def _assert_manifest_policy(
        self, manifest: Mapping[str, object], *, transition: bool
    ) -> bool:
        """Re-check the root policy so a pre-existing weak handle cannot bypass it."""
        policy = manifest.get("governance")
        if not isinstance(policy, Mapping) or set(policy) != {
            "schema", "mode", "authority_id", "require_signed",
            "trusted_keys_path", "policy_hmac",
        }:
            raise PackageValidationError("registry governance policy is invalid")
        if policy.get("schema") != _GOVERNANCE_SCHEMA:
            raise PackageValidationError("registry governance policy schema is invalid")
        mode = policy.get("mode")
        signed = policy.get("require_signed")
        if mode not in {"none", "process-identity", "root-hmac"} or type(signed) is not bool:
            raise PackageValidationError("registry governance policy values are invalid")
        if self.require_signed and not signed:
            raise PackageValidationError(
                "registry signature policy replay would downgrade this instance"
            )
        with _IDENTITY_AUTHORITIES_LOCK:
            floor = _ROOT_POLICY_FLOORS.get(str(self.root))
        if floor is not None:
            floor_authority, floor_signed, floor_trust = floor
            policy_authority = (
                str(policy.get("authority_id"))
                if policy.get("authority_id") is not None
                else None
            )
            policy_trust = (
                str(policy.get("trusted_keys_path"))
                if policy.get("trusted_keys_path") is not None
                else None
            )
            if floor_authority is not None and policy_authority != floor_authority:
                raise PackageValidationError("registry root authority replay detected")
            if floor_signed and not signed:
                raise PackageValidationError("registry signature policy replay detected")
            if floor_trust is not None and policy_trust != floor_trust:
                raise PackageValidationError("registry trust-store replay detected")
        expected_activation = (
            "signed_only" if signed else "development_unsigned_override"
        )
        if manifest.get("activation_policy") != expected_activation:
            raise PackageValidationError("registry activation policy diverges from governance")
        trusted_path = str(self.trusted_keys) if self.trusted_keys is not None else None
        if policy.get("trusted_keys_path") != trusted_path:
            raise PackageValidationError("registry trusted publisher store changed")
        if mode == "root-hmac":
            if self.__governance_key is None:
                raise PackageValidationError("root-bound registry authority is unavailable")
            if not hmac.compare_digest(
                str(policy.get("authority_id")),
                self._authority_id(self.__governance_key),
            ) or not hmac.compare_digest(
                str(policy.get("policy_hmac")), self._policy_mac(policy)
            ):
                raise PackageValidationError("registry governance authority is invalid")
            if not self.governance_anchor_path.exists():
                raise PackageValidationError("registry governance anchor is missing")
            self._assert_governance_anchor(
                policy, self._read_governance_anchor()
            )
        elif mode == "process-identity":
            with _IDENTITY_AUTHORITIES_LOCK:
                enrolled = _IDENTITY_AUTHORITIES.get(str(self.root))
            if (
                enrolled is None
                or self.__transition_authority is not enrolled[0]
                or policy.get("authority_id") != enrolled[1]
            ):
                raise PackageValidationError("registry process authority is invalid")
        elif transition and self.__transition_authority is not None:
            raise PackageValidationError("registry governance mode changed")
        if transition and mode != "none":
            self.assert_transition_authority(self.__transition_authority)
        return signed

    @contextmanager
    def _locked(self):
        """Acquire a bounded OS lock; timeout raises instead of racing onward."""
        self.lock_path.touch(exist_ok=True)
        stream = self.lock_path.open("r+b")
        deadline = time.monotonic() + self.lock_timeout
        acquired = False
        try:
            while not acquired:
                try:
                    if os.name == "nt":
                        import msvcrt
                        stream.seek(0)
                        if stream.read(1) == b"":
                            stream.seek(0)
                            stream.write(b"\0")
                            stream.flush()
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                except (BlockingIOError, OSError):
                    if time.monotonic() >= deadline:
                        raise PackageValidationError("registry lock acquisition timed out")
                    time.sleep(0.025)
            yield
        finally:
            if acquired:
                try:
                    if os.name == "nt":
                        import msvcrt
                        stream.seek(0)
                        msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl
                        fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            stream.close()

    def _manifest(self) -> dict[str, Any]:
        try:
            data = json.loads(self.manifest_path.read_text(encoding="utf-8"))
            if data.get("schema_version") != 1 or not isinstance(data.get("packages"), dict):
                raise ValueError("invalid registry manifest")
            return data
        except Exception as exc:
            raise PackageValidationError(f"registry manifest is invalid: {exc}") from exc

    def _write_manifest(self, data: dict[str, Any]) -> None:
        payload = json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        fd, name = tempfile.mkstemp(prefix=".registry-", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(name, self.manifest_path)
        finally:
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass

    @staticmethod
    def _filename(digest: str) -> str:
        return digest.removeprefix("sha256:") + ".json"

    def _record(self, manifest: dict[str, Any], package_id: str, digest: str) -> dict[str, Any]:
        versions = manifest["packages"].setdefault(package_id, {})
        return versions.setdefault(
            digest,
            {"state": "staged", "previous_digest": None, "trusted": False, "signer": None},
        )

    def _quarantine_bytes(self, raw: bytes, hint: str) -> None:
        import hashlib
        name = hashlib.sha256(raw).hexdigest() + ".json"
        target = self.quarantine / name
        if not target.exists():
            target.write_bytes(raw[:MAX_PACKAGE_BYTES])

    def _signature_path(self, digest: str) -> Path:
        return self.packages / (digest.removeprefix("sha256:") + ".sig.json")

    def _read_trust_store_snapshot(self) -> _TrustStoreSnapshot | None:
        """Return one bounded, immutable publisher-key view for an operation."""
        if self.trusted_keys is None:
            return None
        try:
            raw, proof = _read_stable_file(
                self.trusted_keys, maximum=_MAX_TRUST_STORE_BYTES
            )
            document = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_strict_json_object
            )
            if not isinstance(document, dict) or set(document) != {"keys"}:
                raise ValueError("trusted key store fields are invalid")
            keys = document["keys"]
            if not isinstance(keys, dict) or len(keys) > _MAX_TRUSTED_KEYS:
                raise ValueError("trusted key store key count is invalid")
            decoded: dict[str, bytes] = {}
            for key_id, entry in keys.items():
                if (
                    not isinstance(key_id, str)
                    or not 1 <= len(key_id) <= 128
                    or "\x00" in key_id
                    or not isinstance(entry, dict)
                    or set(entry) != {"public_key"}
                    or not isinstance(entry["public_key"], str)
                ):
                    raise ValueError("trusted key entry is invalid")
                public_raw = base64.b64decode(
                    entry["public_key"], validate=True
                )
                if len(public_raw) != 32:
                    raise ValueError("Ed25519 public key length is invalid")
                decoded[key_id] = public_raw
            normalized = {
                "keys": {
                    key_id: {
                        "public_key": base64.b64encode(public_raw).decode("ascii")
                    }
                    for key_id, public_raw in sorted(decoded.items())
                }
            }
            canonical = json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
            return _TrustStoreSnapshot(
                proof=proof,
                canonical_sha256=hashlib.sha256(canonical).hexdigest(),
                public_keys=MappingProxyType(dict(sorted(decoded.items()))),
            )
        except Exception as exc:
            if isinstance(exc, PackageValidationError):
                raise
            raise PackageValidationError(
                f"publisher trust store is invalid: {exc}"
            ) from exc

    def _assert_trust_store_stable(
        self, snapshot: _TrustStoreSnapshot | None
    ) -> None:
        if snapshot is None:
            if self.trusted_keys is not None:
                raise PackageValidationError(
                    "publisher trust store appeared during active-set validation"
                )
            return
        if self.trusted_keys != snapshot.proof.stamp.path:
            raise PackageValidationError(
                "publisher trust store path changed during active-set validation"
            )
        try:
            _raw, current = _read_stable_file(
                snapshot.proof.stamp.path, maximum=_MAX_TRUST_STORE_BYTES
            )
        except OSError as exc:
            raise PackageValidationError(
                "publisher trust store became unavailable"
            ) from exc
        if (
            current.stamp.metadata != snapshot.proof.stamp.metadata
            or not hmac.compare_digest(current.sha256, snapshot.proof.sha256)
        ):
            raise PackageValidationError(
                "publisher trust store changed during active-set validation"
            )

    @staticmethod
    def _canonical_package_document(document: Mapping[str, object]) -> bytes:
        return json.dumps(
            dict(document),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    def _verify_signature_artifacts(
        self,
        package_path: Path,
        signature_path: Path,
        *,
        trust_snapshot: _TrustStoreSnapshot | None | object = _TRUST_SNAPSHOT_UNSET,
        expected_document: Mapping[str, object] | None = None,
    ) -> tuple[bool, str | None, _FileProof | None, _FileProof | None]:
        """Verify exact stable package/signature bytes against one key snapshot."""
        if self.trusted_keys is None:
            return False, None, None, None
        try:
            os.lstat(signature_path)
        except FileNotFoundError:
            return False, None, None, None
        snapshot = (
            self._read_trust_store_snapshot()
            if trust_snapshot is _TRUST_SNAPSHOT_UNSET
            else trust_snapshot
        )
        if not isinstance(snapshot, _TrustStoreSnapshot):
            return False, None, None, None
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            package_raw, package_proof = _read_stable_file(
                package_path, maximum=MAX_PACKAGE_BYTES
            )
            if expected_document is not None:
                signed_document = json.loads(
                    package_raw.decode("utf-8"),
                    object_pairs_hook=_strict_json_object,
                )
                if not isinstance(signed_document, dict) or not hmac.compare_digest(
                    self._canonical_package_document(signed_document),
                    self._canonical_package_document(expected_document),
                ):
                    raise ValueError(
                        "signed package bytes diverge from the validated package"
                    )
            signature_raw_bytes, signature_proof = _read_stable_file(
                signature_path, maximum=_MAX_SIGNATURE_BYTES
            )
            signature = json.loads(
                signature_raw_bytes.decode("utf-8"),
                object_pairs_hook=_strict_json_object,
            )
            if not isinstance(signature, dict) or set(signature) != {
                "key_id", "signature",
            }:
                raise ValueError("signature metadata fields are invalid")
            key_id = signature["key_id"]
            if (
                not isinstance(key_id, str)
                or key_id not in snapshot.public_keys
                or not isinstance(signature["signature"], str)
            ):
                raise ValueError("publisher key is not trusted")
            signature_raw = base64.b64decode(
                signature["signature"], validate=True
            )
            if len(signature_raw) != 64:
                raise ValueError("Ed25519 signature length is invalid")
            Ed25519PublicKey.from_public_bytes(
                snapshot.public_keys[key_id]
            ).verify(signature_raw, package_raw)
            return True, key_id, package_proof, signature_proof
        except ImportError:
            return False, None, None, None
        except Exception as exc:
            raise PackageValidationError(
                f"publisher signature verification failed: {exc}"
            ) from exc

    def _verify_signature(
        self, package_path: Path, signature_path: Path
    ) -> tuple[bool, str | None]:
        """Verify one signature and reject a concurrent trust-store rotation."""
        snapshot = self._read_trust_store_snapshot()
        trusted, signer, _package_proof, _signature_proof = (
            self._verify_signature_artifacts(
                package_path,
                signature_path,
                trust_snapshot=snapshot,
            )
        )
        self._assert_trust_store_stable(snapshot)
        return trusted, signer

    def stage(
        self,
        source: str | Path,
        *,
        signature: str | Path | None = None,
        now: datetime | None = None,
    ) -> ValidationReport:
        """Validate and retain an immutable package, or quarantine invalid input."""
        path = Path(source)
        try:
            raw = path.read_bytes()
            package = load_package(path, now=now)
            document = package.document
            digest, package_id = str(document["digest"]), package.package_id
            supplied_signature = Path(signature) if signature else None
            trusted, signer = self._verify_signature(path, supplied_signature) if supplied_signature else (False, None)
            with self._locked():
                target = self.packages / self._filename(digest)
                if target.exists() and target.read_bytes() != raw:
                    raise PackageValidationError("digest collision with different package bytes")
                if not target.exists():
                    fd, name = tempfile.mkstemp(prefix=".package-", suffix=".tmp", dir=self.packages)
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(raw)
                            stream.flush()
                            os.fsync(stream.fileno())
                        os.replace(name, target)
                    finally:
                        try:
                            os.unlink(name)
                        except FileNotFoundError:
                            pass
                if trusted and supplied_signature:
                    signature_target = self._signature_path(digest)
                    signature_target.write_bytes(supplied_signature.read_bytes())
                manifest = self._manifest()
                record = self._record(manifest, package_id, digest)
                if record["state"] != "active":
                    record["state"] = "staged"
                record["trusted"], record["signer"] = trusted, signer
                self._write_manifest(manifest)
            return ValidationReport(True, "stage", record["state"], package_id, digest)
        except Exception as exc:
            try:
                self._quarantine_bytes(raw if "raw" in locals() else b"", path.name)
            except Exception:
                pass
            return ValidationReport(False, "stage", "quarantined", None, None, (str(exc),))

    def activate(
        self,
        package_id: str,
        digest: str,
        *,
        now: datetime | None = None,
        transition_capability: object | None = None,
    ) -> ValidationReport:
        """Atomically make a staged digest active after re-validating all gates."""
        denied = self._transition_denied(
            "activate", package_id, digest, transition_capability
        )
        if denied is not None:
            return denied
        try:
            with self._locked():
                return self._activate_locked(package_id, digest, now=now)
        except PackageValidationError as exc:
            return ValidationReport(False, "activate", "quarantined", package_id, digest, (str(exc),))

    def _activate_locked(
        self, package_id: str, digest: str, *, now: datetime | None = None
    ) -> ValidationReport:
        manifest = self._manifest()
        proposed, report = self._prepare_activation_locked(
            manifest, package_id, digest, now=now
        )
        self._write_manifest(proposed)
        return report

    def _prepare_activation_locked(
        self,
        manifest: dict[str, Any],
        package_id: str,
        digest: str,
        *,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], ValidationReport]:
        """Build a validated manifest transition without publishing it."""
        effective_signed = self._assert_manifest_policy(manifest, transition=True)
        manifest = deepcopy(manifest)
        versions = manifest["packages"].get(package_id, {})
        record = versions.get(digest)
        if not record or record.get("state") not in {"staged", "retired", "active"}:
            return manifest, ValidationReport(
                False, "activate", "quarantined", package_id, digest,
                ("digest is not staged or retained",),
            )
        try:
            package_path = self.packages / self._filename(digest)
            package = load_package(package_path, now=now)
            if package.package_id != package_id or package.document["digest"] != digest:
                raise PackageValidationError("package identity does not match registry request")
            trusted, signer = self._verify_signature(package_path, self._signature_path(digest))
            if trusted != bool(record.get("trusted")) or signer != record.get("signer"):
                raise PackageValidationError("publisher trust metadata changed")
            if effective_signed and not trusted:
                raise PackageValidationError("activation policy requires a trusted publisher signature")
        except Exception as exc:
            record["state"] = "quarantined"
            return manifest, ValidationReport(
                False, "activate", "quarantined", package_id, digest, (str(exc),)
            )
        prior = next((d for d, item in versions.items() if item.get("state") == "active" and d != digest), None)
        for other_digest, item in versions.items():
            if item.get("state") == "active" and other_digest != digest:
                item["state"] = "retired"
        record["state"] = "active"
        record["previous_digest"] = prior
        return manifest, ValidationReport(
            True, "activate", "active", package_id, digest,
            previous_digest=prior,
        )

    def rollback(
        self,
        package_id: str,
        *,
        now: datetime | None = None,
        transition_capability: object | None = None,
    ) -> ValidationReport:
        """Return atomically to the active version's recorded predecessor."""
        denied = self._transition_denied(
            "rollback", package_id, None, transition_capability
        )
        if denied is not None:
            return denied
        try:
            with self._locked():
                manifest = self._manifest()
                versions = manifest["packages"].get(package_id, {})
                active = next(((d, r) for d, r in versions.items() if r.get("state") == "active"), None)
                if not active or not active[1].get("previous_digest"):
                    return ValidationReport(False, "rollback", "quarantined", package_id, None,
                                            ("no rollback target is recorded",))
                return self._activate_locked(package_id, active[1]["previous_digest"], now=now)
        except PackageValidationError as exc:
            return ValidationReport(False, "rollback", "quarantined", package_id, None, (str(exc),))

    def retire(
        self,
        package_id: str,
        digest: str,
        *,
        transition_capability: object | None = None,
    ) -> ValidationReport:
        denied = self._transition_denied(
            "retire", package_id, digest, transition_capability
        )
        if denied is not None:
            return denied
        try:
            with self._locked():
                manifest = self._manifest()
                self._assert_manifest_policy(manifest, transition=True)
                record = manifest["packages"].get(package_id, {}).get(digest)
                if not record:
                    return ValidationReport(False, "retire", "quarantined", package_id, digest,
                                            ("unknown package digest",))
                record["state"] = "retired"
                self._write_manifest(manifest)
                return ValidationReport(True, "retire", "retired", package_id, digest)
        except PackageValidationError as exc:
            return ValidationReport(False, "retire", "quarantined", package_id, digest, (str(exc),))

    def _trusted_active_locked(
        self,
        manifest: dict[str, Any],
        package_id: str,
        digest: str,
        *,
        now: datetime | None = None,
        quarantine_on_failure: bool = True,
        effective_signed: bool | None = None,
        trust_snapshot: _TrustStoreSnapshot | None | object = _TRUST_SNAPSHOT_UNSET,
        artifact_stamps: list[tuple[_FileStamp, int]] | None = None,
    ) -> DetectionPackage | None:
        if effective_signed is None:
            effective_signed = self._assert_manifest_policy(
                manifest, transition=False
            )
        record = manifest["packages"].get(package_id, {}).get(digest)
        if not isinstance(record, dict) or record.get("state") != "active":
            return None
        try:
            package_path = self.packages / self._filename(digest)
            before = _regular_file_stamp(
                package_path, maximum=MAX_PACKAGE_BYTES
            )
            package = load_package(package_path, now=now)
            after = _regular_file_stamp(
                package_path, maximum=MAX_PACKAGE_BYTES
            )
            if after.metadata != before.metadata:
                raise PackageValidationError(
                    "active package changed while it was being loaded"
                )
            local_trust_snapshot = (
                self._read_trust_store_snapshot()
                if trust_snapshot is _TRUST_SNAPSHOT_UNSET
                else trust_snapshot
            )
            trusted, signer, package_proof, signature_proof = (
                self._verify_signature_artifacts(
                    package_path,
                    self._signature_path(digest),
                    trust_snapshot=local_trust_snapshot,
                    expected_document=package.document,
                )
            )
            package_stamp = after
            if package_proof is not None:
                if package_proof.stamp.metadata != after.metadata:
                    raise PackageValidationError(
                        "active package generation changed before signature verification"
                    )
                package_stamp = package_proof.stamp
            if (
                package.package_id != package_id
                or package.document["digest"] != digest
                or trusted != bool(record.get("trusted"))
                or signer != record.get("signer")
                or (effective_signed and not trusted)
            ):
                raise PackageValidationError("active package trust validation failed")
            if artifact_stamps is not None:
                artifact_stamps.append((package_stamp, MAX_PACKAGE_BYTES))
                if signature_proof is not None:
                    artifact_stamps.append(
                        (signature_proof.stamp, _MAX_SIGNATURE_BYTES)
                    )
            if trust_snapshot is _TRUST_SNAPSHOT_UNSET:
                self._assert_trust_store_stable(local_trust_snapshot)
            return package
        except Exception:
            if quarantine_on_failure:
                record["state"] = "quarantined"
                self._write_manifest(manifest)
            return None

    def active(self, package_id: str, *, now: datetime | None = None) -> DetectionPackage | None:
        """Return only a currently valid and currently trusted active package.

        Trust is re-evaluated on every read so key revocation, detached
        signature removal, package tampering, or expiry cannot leave a stale
        active object usable after activation.
        """
        try:
            with self._locked():
                manifest = self._manifest()
                for digest, record in manifest["packages"].get(
                    package_id, {}
                ).items():
                    if record.get("state") != "active":
                        continue
                    return self._trusted_active_locked(
                        manifest, package_id, digest, now=now
                    )
        except PackageValidationError:
            return None
        return None

    def active_set(
        self,
        expected_bindings: Mapping[str, str],
        *,
        now: datetime | None = None,
    ) -> tuple[DetectionPackage, ...]:
        """Trust-validate one exact active set under a single registry lock.

        Package contents, detached signatures, publisher trust, expiry, fixtures,
        and performance gates are still re-evaluated for every active package.
        The manifest is compared again after those reads so an out-of-band state
        replacement cannot yield a mixed runtime set.
        """
        if not isinstance(expected_bindings, Mapping):
            raise PackageValidationError("active bindings must be a mapping")
        expected = dict(sorted(expected_bindings.items()))
        if any(
            not isinstance(package_id, str)
            or not isinstance(digest, str)
            for package_id, digest in expected.items()
        ):
            raise PackageValidationError("active binding fields are invalid")
        with self._locked():
            manifest = self._manifest()
            effective_signed = self._assert_manifest_policy(
                manifest, transition=False
            )
            trust_snapshot = self._read_trust_store_snapshot()
            actual: dict[str, str] = {}
            for package_id, versions in manifest["packages"].items():
                if not isinstance(package_id, str) or not isinstance(versions, dict):
                    raise PackageValidationError("registry active inventory is invalid")
                active_digests = [
                    digest
                    for digest, record in versions.items()
                    if isinstance(digest, str)
                    and isinstance(record, dict)
                    and record.get("state") == "active"
                ]
                if len(active_digests) > 1:
                    raise PackageValidationError(
                        "registry contains multiple active digests for one package"
                    )
                if active_digests:
                    actual[package_id] = active_digests[0]
            if dict(sorted(actual.items())) != expected:
                raise PackageValidationError(
                    "registry active digest set does not match governed bindings"
                )

            packages: list[DetectionPackage] = []
            artifact_stamps: list[tuple[_FileStamp, int]] = []
            for package_id, digest in expected.items():
                package = self._trusted_active_locked(
                    manifest,
                    package_id,
                    digest,
                    now=now,
                    effective_signed=effective_signed,
                    trust_snapshot=trust_snapshot,
                    artifact_stamps=artifact_stamps,
                )
                if package is None:
                    raise PackageValidationError(
                        "registry did not return an exact trusted active package"
                    )
                packages.append(package)
            if self._manifest() != manifest:
                raise PackageValidationError(
                    "registry manifest changed during active-set validation"
                )
            if self._assert_manifest_policy(
                manifest, transition=False
            ) != effective_signed:
                raise PackageValidationError(
                    "registry signature policy changed during active-set validation"
                )
            for stamp, maximum in artifact_stamps:
                _assert_file_stamp_unchanged(stamp, maximum=maximum)
            self._assert_trust_store_stable(trust_snapshot)
            return tuple(packages)

    def inventory(self) -> dict[str, Any]:
        """Return a detached, structured view suitable for a local UI/report."""
        with self._locked():
            manifest = self._manifest()
            self._assert_manifest_policy(manifest, transition=False)
            return json.loads(json.dumps(manifest["packages"]))
