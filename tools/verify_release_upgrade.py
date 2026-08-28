"""Verify a portable Windows upgrade before the installer mutates its target.

The release workflow freezes this module as ``AngeronaReleaseVerifier.exe``.
The portable updater invokes only the already installed, ACL-protected copy;
candidate code is never executed to authorize itself.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any, Mapping

from angerona.core.update_authority import (
    ReleaseAuthorizationResult,
    ReleaseFloor,
    UpdateAuthorityPolicy,
    file_sha256,
    verify_release_authorization,
)


PORTABLE_FLOOR_SCHEMA = "angerona.portable-release-floor/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){2,3}$")
_REQUIRED = {
    "artifact": "Angerona.exe",
    "sbom": "Angerona-SBOM.json",
    "manifest": "release-payload-manifest.json",
    "catalog": "release-payload.cat",
    "provenance": "release-build-provenance.json",
    "authorization": "release-authorization.json",
    "trust": "release-trust.json",
}


def _version_tuple(value: str) -> tuple[int, int, int, int]:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise ValueError("portable release floor version is invalid")
    parts = [int(part) for part in value.split(".")]
    parts.extend([0] * (4 - len(parts)))
    if any(part > 65535 for part in parts):
        raise ValueError("portable release floor version is out of range")
    return parts[0], parts[1], parts[2], parts[3]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("portable release metadata contains a duplicate key")
        result[key] = value
    return result


def _regular(path: Path, label: str, maximum: int) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-link file")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= maximum:
        raise ValueError(f"{label} exceeds its byte budget")
    return path


def _root(path: Path, label: str) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{label} must be a regular non-link directory")
    if getattr(os.path, "isjunction", lambda _path: False)(path):
        raise ValueError(f"{label} must not be a junction")
    return path.resolve(strict=True)


def _paths(root: Path) -> dict[str, Path]:
    return {
        label: _regular(
            root / name,
            f"{label} release evidence",
            256 * 1024 * 1024 if label in {"artifact", "catalog"} else 8 * 1024 * 1024,
        )
        for label, name in _REQUIRED.items()
    }


def _load_trust(path: Path) -> dict[str, bytes]:
    path = _regular(path, "release trust store", 64 * 1024)
    try:
        document = json.loads(path.read_bytes(), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("release trust store is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict) or len(document) != 2:
        raise ValueError("release trust store must contain exactly two roots")
    trust: dict[str, bytes] = {}
    digests: set[str] = set()
    for signer_id, encoded in document.items():
        if not isinstance(signer_id, str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:@/-]{2,191}", signer_id
        ) or not isinstance(encoded, str):
            raise ValueError("release trust store entry is invalid")
        try:
            public = base64.b64decode(
                encoded + "=" * (-len(encoded) % 4),
                altchars=b"-_",
                validate=True,
            )
        except Exception as exc:
            raise ValueError("release trust-store key encoding is invalid") from exc
        if len(public) != 32:
            raise ValueError("release trust-store key length is invalid")
        digest = hashlib.sha256(public).hexdigest()
        if digest in digests:
            raise ValueError("release trust roots are not independent")
        trust[signer_id] = public
        digests.add(digest)
    return trust


def _verify(
    paths: Mapping[str, Path], trust: Mapping[str, bytes], *, now: float,
    installed_version: str, floor: ReleaseFloor | None,
) -> ReleaseAuthorizationResult:
    return verify_release_authorization(
        paths["authorization"].read_bytes(),
        trust,
        UpdateAuthorityPolicy(),
        now=now,
        expected_platform="windows-x64",
        expected_artifact_sha256=file_sha256(paths["artifact"]),
        expected_sbom_sha256=file_sha256(paths["sbom"]),
        expected_payload_manifest_sha256=file_sha256(paths["manifest"]),
        expected_payload_catalog_sha256=file_sha256(paths["catalog"]),
        expected_provenance_sha256=file_sha256(paths["provenance"]),
        installed_version=installed_version,
        highest_sequence=0 if floor is None else floor.highest_sequence,
        highest_version="0.0.0" if floor is None else floor.highest_version,
        floor_statement_sha256="" if floor is None else floor.statement_sha256,
    )


def _load_floor(path: Path) -> ReleaseFloor | None:
    if not path.exists():
        return None
    path = _regular(path, "portable release floor", 16 * 1024)
    try:
        document = json.loads(path.read_bytes(), object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("portable release floor is not valid UTF-8 JSON") from exc
    fields = {"schema", "highest_sequence", "highest_version", "statement_sha256"}
    if not isinstance(document, dict) or set(document) != fields:
        raise ValueError("portable release floor schema is invalid")
    if document["schema"] != PORTABLE_FLOOR_SCHEMA:
        raise ValueError("portable release floor identity is invalid")
    return ReleaseFloor(
        document["highest_sequence"],
        document["highest_version"],
        document["statement_sha256"],
    )


def _historical_installed_floor(
    paths: Mapping[str, Path], trust: Mapping[str, bytes],
) -> ReleaseFloor:
    probe = _verify(
        paths, trust, now=0.0, installed_version="0.0.0", floor=None,
    )
    if probe.statement is None:
        raise ValueError("installed release authorization cannot establish a floor")
    # Historical installed authorization may be expired. Verify it at its own
    # issuance instant; protected installation custody supplies current state.
    result = _verify(
        paths,
        trust,
        now=probe.statement.issued_at,
        installed_version="0.0.0",
        floor=None,
    )
    if not result.valid or result.statement is None:
        raise ValueError(
            "installed release authorization is not a valid rollback-floor anchor: "
            + "; ".join(result.errors)
        )
    return ReleaseFloor(
        result.statement.sequence,
        result.statement.version,
        result.statement_sha256,
    )


def _write_floor(path: Path, floor: ReleaseFloor) -> None:
    document = {
        "schema": PORTABLE_FLOOR_SCHEMA,
        "highest_sequence": floor.highest_sequence,
        "highest_version": floor.highest_version,
        "statement_sha256": floor.statement_sha256,
    }
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    try:
        with open(temporary, "xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def verify_portable_upgrade(
    *, candidate_root: Path, installed_root: Path, floor_output: Path, now: float,
) -> ReleaseFloor:
    candidate_root = _root(candidate_root, "candidate release root")
    installed_root = _root(installed_root, "installed release root")
    try:
        Path(floor_output).resolve(strict=False).relative_to(candidate_root)
    except ValueError as exc:
        raise ValueError("portable floor output must remain inside candidate staging") from exc
    candidate = _paths(candidate_root)
    installed = _paths(installed_root)
    if file_sha256(candidate["trust"]) != file_sha256(installed["trust"]):
        raise ValueError("candidate release attempts ordinary trust-root rotation")
    trust = _load_trust(installed["trust"])
    installed_floor = _historical_installed_floor(installed, trust)
    protected_floor = _load_floor(installed_root / "release-floor.json")
    if protected_floor is not None:
        if protected_floor.highest_sequence < installed_floor.highest_sequence:
            raise ValueError("protected release floor regressed below the installed release")
        if _version_tuple(protected_floor.highest_version) < _version_tuple(
            installed_floor.highest_version
        ):
            raise ValueError("protected release version regressed below the installed release")
        floor = protected_floor
    else:
        floor = installed_floor
    result = _verify(
        candidate,
        trust,
        now=now,
        installed_version=floor.highest_version,
        floor=floor,
    )
    if not result.valid or result.statement is None:
        raise ValueError(
            "candidate release authorization or rollback floor failed: "
            + "; ".join(result.errors)
        )
    next_floor = ReleaseFloor(
        result.statement.sequence,
        result.statement.version,
        result.statement_sha256,
    )
    _write_floor(floor_output, next_floor)
    return next_floor


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate-root", type=Path, required=True)
    parser.add_argument("--installed-root", type=Path, required=True)
    parser.add_argument("--floor-output", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    floor = verify_portable_upgrade(
        candidate_root=args.candidate_root,
        installed_root=args.installed_root,
        floor_output=args.floor_output,
        now=time.time(),
    )
    print(json.dumps({
        "verified": True,
        "highest_sequence": floor.highest_sequence,
        "highest_version": floor.highest_version,
        "statement_sha256": floor.statement_sha256,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
