"""Prepare, independently sign, and aggregate Angerona release authority.

The production CLI intentionally has no command that accepts two private
seeds. A builder prepares one canonical statement, each isolated witness job
signs that exact statement with its sole environment secret, and a secretless
finalizer verifies and combines the responses.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import stat
import time
from dataclasses import asdict
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from angerona.core.atomic_io import replace_with_retry
from angerona.core.update_authority import (
    PAYLOAD_MANIFEST_SCHEMA,
    ReleaseAuthorizationStatement,
    file_sha256,
    load_payload_manifest,
)


DEFAULT_BUILDER = (
    "https://github.com/Ag3nt47/AngeronaSuite/.github/workflows/release.yml"
)
SIGNATURE_SCHEMA = "angerona.release-signature/v1"
ROOT_POLICY_SCHEMA = "angerona.release-root-policy/v1"
MAX_SIGNATURE_RESPONSE_BYTES = 16 * 1024
MAX_ROOT_POLICY_BYTES = 64 * 1024
MAX_PAYLOAD_FILES = 4096
_SIGNER = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._:@-]{2,127})=([A-Z][A-Z0-9_]{2,127})$")
_SIGNER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{2,191}$")
_ENVIRONMENT_VARIABLE = re.compile(r"^[A-Z][A-Z0-9_]{2,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){2,3}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_RESERVED_PAYLOAD_NAMES = frozenset({
    "release-authorization.json",
    "release-build-provenance.json",
    "release-files.sha256",
    "release-payload.cat",
    "release-payload-manifest.json",
    "release-statement.json",
    "release-trust.json",
})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("release metadata contains a duplicate JSON key")
        result[key] = value
    return result


def _exact(value: Any, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise ValueError(f"{label} has an invalid schema")
    return value


def _write_atomic(path: Path, value: object) -> None:
    encoded = _canonical(value)
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    try:
        with open(temporary, "xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        replace_with_retry(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _regular(path: Path, label: str) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-link file")
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError(f"{label} must be a regular file")
    return path


def _read_bounded(path: Path, maximum: int, label: str) -> bytes:
    path = _regular(path, label)
    if path.stat().st_size > maximum:
        raise ValueError(f"{label} exceeds its byte budget")
    return path.read_bytes()


def _load_json(path: Path, maximum: int, label: str) -> tuple[bytes, Any]:
    raw = _read_bounded(path, maximum, label)
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    return raw, value


def version_sequence(value: str) -> int:
    if not isinstance(value, str) or not _VERSION.fullmatch(value):
        raise ValueError("release version must contain three or four numeric parts")
    parts = [int(item) for item in value.split(".")]
    parts += [0] * (4 - len(parts))
    if any(not 0 <= item <= 65535 for item in parts):
        raise ValueError("release version parts must fit unsigned 16-bit fields")
    return (parts[0] << 48) | (parts[1] << 32) | (parts[2] << 16) | parts[3]


def _private_seed(encoded: str) -> Ed25519PrivateKey:
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("release signer seed is missing")
    try:
        raw = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True,
        )
    except Exception as exc:
        raise ValueError("release signer seed encoding is invalid") from exc
    if len(raw) != 32:
        raise ValueError("release signer seed must contain exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def _decode_urlsafe(value: Any, length: int, label: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{label} encoding is invalid")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True,
        )
    except Exception as exc:
        raise ValueError(f"{label} encoding is invalid") from exc
    if len(raw) != length:
        raise ValueError(f"{label} length is invalid")
    return raw


def _public_text(public: bytes) -> str:
    return base64.urlsafe_b64encode(public).decode().rstrip("=")


def load_root_policy(
    path: Path, *, expected_sha256: str,
) -> tuple[int, dict[str, bytes]]:
    """Load one externally enrolled, exact-digest threshold root policy."""
    if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(
        expected_sha256
    ):
        raise ValueError("protected release root-policy SHA-256 is invalid")
    raw, value = _load_json(path, MAX_ROOT_POLICY_BYTES, "release root policy")
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256):
        raise ValueError("release root policy does not match its protected SHA-256")
    value = _exact(
        value,
        frozenset({"schema", "product", "version", "threshold", "keys"}),
        "release root policy",
    )
    if raw != _canonical(value):
        raise ValueError("release root policy is not canonical")
    if value["schema"] != ROOT_POLICY_SCHEMA or value["product"] != "Angerona":
        raise ValueError("release root policy identity is invalid")
    if type(value["version"]) is not int or not 1 <= value["version"] <= 2**31 - 1:
        raise ValueError("release root policy version is invalid")
    if type(value["threshold"]) is not int or value["threshold"] != 2:
        raise ValueError("release root policy must require exactly two witnesses")
    entries = value["keys"]
    if not isinstance(entries, list) or len(entries) != 2:
        raise ValueError("release root policy must enroll exactly two witnesses")
    keys: dict[str, bytes] = {}
    key_digests: set[str] = set()
    previous = ""
    for entry in entries:
        entry = _exact(
            entry,
            frozenset({"signer_id", "public_key"}),
            "release root-policy key",
        )
        signer_id = entry["signer_id"]
        if not isinstance(signer_id, str) or not _SIGNER_ID.fullmatch(signer_id):
            raise ValueError("release root-policy signer identity is invalid")
        if previous and signer_id <= previous:
            raise ValueError("release root-policy signer identities are not sorted")
        public = _decode_urlsafe(
            entry["public_key"], 32, "release root-policy public key"
        )
        digest = hashlib.sha256(public).hexdigest()
        if signer_id in keys or digest in key_digests:
            raise ValueError("release root-policy witnesses are not independent")
        keys[signer_id] = public
        key_digests.add(digest)
        previous = signer_id
    return value["version"], keys


def _canonical_relative(root: Path, path: Path) -> str:
    relative = path.relative_to(root)
    value = PurePosixPath(*relative.parts).as_posix()
    if (
        not value
        or len(value) > 240
        or "\\" in value
        or ":" in value
        or any(part in ("", ".", "..") for part in PurePosixPath(value).parts)
    ):
        raise ValueError("release payload path is not canonical")
    return value


def build_payload_manifest(
    *, payload_root: Path, output: Path,
) -> tuple[dict[str, Any], ...]:
    """Hash every pre-authorization payload file into one canonical manifest."""
    root = Path(payload_root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("release payload root must be a regular directory")
    if getattr(os.path, "isjunction", lambda _path: False)(root):
        raise ValueError("release payload root must not be a junction")
    root = root.resolve(strict=True)
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in tuple(names):
            child = directory_path / name
            if child.is_symlink() or getattr(
                os.path, "isjunction", lambda _path: False
            )(child):
                raise ValueError(
                    f"release payload contains a reparse directory: {name}"
                )
        for name in filenames:
            candidate = directory_path / name
            relative = _canonical_relative(root, candidate)
            if PurePosixPath(relative).name in _RESERVED_PAYLOAD_NAMES:
                continue
            candidate = _regular(candidate, f"release payload file {relative}")
            folded = relative.casefold()
            if folded in seen:
                raise ValueError("release payload contains a case-aliased path")
            seen.add(folded)
            entries.append({
                "path": relative,
                "sha256": file_sha256(candidate),
                "size": candidate.stat().st_size,
            })
            if len(entries) > MAX_PAYLOAD_FILES:
                raise ValueError("release payload exceeds its file-count budget")
    if not entries:
        raise ValueError("release payload is empty")
    entries.sort(key=lambda entry: entry["path"])
    document = {"schema": PAYLOAD_MANIFEST_SCHEMA, "files": entries}
    _write_atomic(output, document)
    loaded = load_payload_manifest(Path(output).read_bytes())
    return loaded


def prepare_release_statement(
    *,
    artifact: Path,
    sbom: Path,
    payload_manifest: Path,
    payload_catalog: Path,
    provenance_output: Path,
    statement_output: Path,
    version: str,
    platform: str,
    source_revision: str,
    invocation_id: str,
    builder_id: str = DEFAULT_BUILDER,
    issued_at: float | None = None,
    validity_seconds: int = 31 * 24 * 3600,
) -> ReleaseAuthorizationStatement:
    artifact = _regular(artifact, "release artifact")
    sbom = _regular(sbom, "release SBOM")
    payload_manifest = _regular(payload_manifest, "release payload manifest")
    payload_catalog = _regular(payload_catalog, "release payload catalog")
    load_payload_manifest(
        _read_bounded(
            payload_manifest, 2 * 1024 * 1024, "release payload manifest",
        )
    )
    if not _REVISION.fullmatch(source_revision):
        raise ValueError("source revision must be a full lowercase Git commit SHA")
    if not isinstance(invocation_id, str) or not 1 <= len(invocation_id) <= 190:
        raise ValueError("release invocation identity is invalid")
    if (
        not isinstance(validity_seconds, int)
        or not 300 <= validity_seconds <= 31 * 24 * 3600
    ):
        raise ValueError(
            "release authorization validity must be between five minutes and 31 days"
        )

    digests = {
        "artifact": file_sha256(artifact),
        "sbom": file_sha256(sbom),
        "payload_manifest": file_sha256(payload_manifest),
        "payload_catalog": file_sha256(payload_catalog),
    }
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": artifact.name, "digest": {"sha256": digests["artifact"]}},
            {"name": sbom.name, "digest": {"sha256": digests["sbom"]}},
            {
                "name": payload_manifest.name,
                "digest": {"sha256": digests["payload_manifest"]},
            },
            {
                "name": payload_catalog.name,
                "digest": {"sha256": digests["payload_catalog"]},
            },
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://angerona.local/release-build/v2",
                "externalParameters": {"version": version, "platform": platform},
                "internalParameters": {},
                "resolvedDependencies": [{
                    "uri": (
                        "git+https://github.com/Ag3nt47/AngeronaSuite.git@"
                        + source_revision
                    ),
                    "digest": {"gitCommit": source_revision},
                }],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": invocation_id},
            },
        },
    }
    _write_atomic(provenance_output, provenance)
    stamp = float(time.time() if issued_at is None else issued_at)
    statement = ReleaseAuthorizationStatement(
        schema="angerona.release-authorization/v2",
        product="Angerona",
        version=version,
        sequence=version_sequence(version),
        platform=platform,
        artifact_sha256=digests["artifact"],
        sbom_sha256=digests["sbom"],
        payload_manifest_sha256=digests["payload_manifest"],
        payload_catalog_sha256=digests["payload_catalog"],
        provenance_sha256=file_sha256(provenance_output),
        source_revision=source_revision,
        builder_id=builder_id,
        issued_at=stamp,
        expires_at=stamp + validity_seconds,
    )
    _write_atomic(statement_output, asdict(statement))
    return statement


def load_prepared_statement(path: Path) -> ReleaseAuthorizationStatement:
    raw, value = _load_json(path, 64 * 1024, "prepared release statement")
    value = _exact(
        value,
        frozenset(ReleaseAuthorizationStatement.__dataclass_fields__),
        "prepared release statement",
    )
    try:
        statement = ReleaseAuthorizationStatement(**value)
    except TypeError as exc:
        raise ValueError(
            "prepared release statement has invalid value types"
        ) from exc
    if raw != statement.canonical():
        raise ValueError("prepared release statement is not canonical")
    return statement


def sign_release_statement(
    *,
    statement_path: Path,
    signature_output: Path,
    signer: tuple[str, str],
    expected_public_key_variable: str,
    environment: Mapping[str, str],
) -> dict[str, str]:
    """Sign with one seed only after matching its separately enrolled root."""
    signer_id, variable = signer
    if not _SIGNER_ID.fullmatch(signer_id):
        raise ValueError("release signer identity is invalid")
    statement = load_prepared_statement(statement_path)
    key = _private_seed(environment.get(variable, ""))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    if not _ENVIRONMENT_VARIABLE.fullmatch(expected_public_key_variable):
        raise ValueError("release signer public-root environment name is invalid")
    expected_public = _decode_urlsafe(
        environment.get(expected_public_key_variable, ""),
        32,
        "enrolled release signer public key",
    )
    if not hmac.compare_digest(public, expected_public):
        raise ValueError("release signer seed does not match its enrolled public root")
    response = {
        "schema": SIGNATURE_SCHEMA,
        "signer_id": signer_id,
        "statement_sha256": statement.sha256,
        "signature": base64.urlsafe_b64encode(
            key.sign(statement.canonical())
        ).decode().rstrip("="),
    }
    _write_atomic(signature_output, response)
    return response


def finalize_release_authorization(
    *,
    statement_path: Path,
    signature_paths: Sequence[Path],
    authorization_output: Path,
    trust_output: Path,
    root_policy_path: Path,
    root_policy_sha256: str,
) -> ReleaseAuthorizationStatement:
    """Combine responses using only an exact, protected finalizer root policy."""
    statement = load_prepared_statement(statement_path)
    _policy_version, enrolled_keys = load_root_policy(
        root_policy_path, expected_sha256=root_policy_sha256,
    )
    expected = tuple(enrolled_keys)
    if len(signature_paths) != len(expected):
        raise ValueError("every expected release signer must provide one response")

    responses: dict[str, dict[str, str]] = {}
    fields = frozenset({
        "schema", "signer_id", "statement_sha256", "signature",
    })
    for path in signature_paths:
        _raw, value = _load_json(
            path, MAX_SIGNATURE_RESPONSE_BYTES, "release signature response",
        )
        value = _exact(value, fields, "release signature response")
        if value["schema"] != SIGNATURE_SCHEMA:
            raise ValueError("release signature response schema is invalid")
        signer_id = value["signer_id"]
        if not isinstance(signer_id, str) or signer_id not in expected:
            raise ValueError("release signature response has an unexpected signer")
        if signer_id in responses:
            raise ValueError("release signature response duplicates a signer")
        if value["statement_sha256"] != statement.sha256:
            raise ValueError("release signature response binds a different statement")
        public = enrolled_keys[signer_id]
        signature = _decode_urlsafe(value["signature"], 64, "release signature")
        try:
            Ed25519PublicKey.from_public_bytes(public).verify(
                signature, statement.canonical(),
            )
        except Exception as exc:
            raise ValueError(
                "release signature response failed verification"
            ) from exc
        responses[signer_id] = dict(value)
    if set(responses) != set(expected):
        raise ValueError("release signature response set is incomplete")

    signatures = [
        {"signer_id": identity, "signature": responses[identity]["signature"]}
        for identity in expected
    ]
    trust = {identity: _public_text(enrolled_keys[identity]) for identity in expected}
    _write_atomic(
        authorization_output,
        {"statement": asdict(statement), "signatures": signatures},
    )
    _write_atomic(trust_output, trust)
    return statement


def _signer(value: str) -> tuple[str, str]:
    match = _SIGNER.fullmatch(value)
    if not match:
        raise argparse.ArgumentTypeError(
            "signer must be SIGNER_ID=ENVIRONMENT_VARIABLE"
        )
    return match.group(1), match.group(2)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    manifest = commands.add_parser("manifest")
    manifest.add_argument("--payload-root", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)

    prepare = commands.add_parser("prepare")
    prepare.add_argument("--artifact", type=Path, required=True)
    prepare.add_argument("--sbom", type=Path, required=True)
    prepare.add_argument("--payload-manifest", type=Path, required=True)
    prepare.add_argument("--payload-catalog", type=Path, required=True)
    prepare.add_argument("--provenance-output", type=Path, required=True)
    prepare.add_argument("--statement-output", type=Path, required=True)
    prepare.add_argument("--version", required=True)
    prepare.add_argument("--platform", required=True)
    prepare.add_argument("--source-revision", required=True)
    prepare.add_argument("--invocation-id", required=True)
    prepare.add_argument("--builder-id", default=DEFAULT_BUILDER)

    sign = commands.add_parser("sign")
    sign.add_argument("--statement", type=Path, required=True)
    sign.add_argument("--signature-output", type=Path, required=True)
    sign.add_argument("--signer", type=_signer, required=True)
    sign.add_argument("--expected-public-key-env", required=True)

    finalize = commands.add_parser("finalize")
    finalize.add_argument("--statement", type=Path, required=True)
    finalize.add_argument(
        "--signature", action="append", type=Path, required=True,
    )
    finalize.add_argument("--authorization-output", type=Path, required=True)
    finalize.add_argument("--trust-output", type=Path, required=True)
    finalize.add_argument("--root-policy", type=Path, required=True)
    finalize.add_argument("--root-policy-sha256", required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "manifest":
        entries = build_payload_manifest(
            payload_root=args.payload_root, output=args.output,
        )
        summary = {
            "file_count": len(entries),
            "manifest_sha256": file_sha256(args.output),
        }
    elif args.command == "prepare":
        statement = prepare_release_statement(
            artifact=args.artifact,
            sbom=args.sbom,
            payload_manifest=args.payload_manifest,
            payload_catalog=args.payload_catalog,
            provenance_output=args.provenance_output,
            statement_output=args.statement_output,
            version=args.version,
            platform=args.platform,
            source_revision=args.source_revision,
            invocation_id=args.invocation_id,
            builder_id=args.builder_id,
        )
        summary = {
            "version": statement.version,
            "statement_sha256": statement.sha256,
        }
    elif args.command == "sign":
        response = sign_release_statement(
            statement_path=args.statement,
            signature_output=args.signature_output,
            signer=args.signer,
            expected_public_key_variable=args.expected_public_key_env,
            environment=os.environ,
        )
        summary = {
            "signer_id": response["signer_id"],
            "statement_sha256": response["statement_sha256"],
        }
    else:
        statement = finalize_release_authorization(
            statement_path=args.statement,
            signature_paths=args.signature,
            authorization_output=args.authorization_output,
            trust_output=args.trust_output,
            root_policy_path=args.root_policy,
            root_policy_sha256=args.root_policy_sha256,
        )
        summary = {
            "version": statement.version,
            "authorization_sha256": file_sha256(args.authorization_output),
            "signer_count": len(args.signature),
        }
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
