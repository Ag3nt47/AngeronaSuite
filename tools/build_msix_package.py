"""Render and validate Angerona's fail-closed full-trust MSIX inputs."""
from __future__ import annotations

import argparse
import html
import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


FOUNDATION = "http://schemas.microsoft.com/appx/manifest/foundation/windows10"
UAP = "http://schemas.microsoft.com/appx/manifest/uap/windows10"
RESCAP = (
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10/"
    "restrictedcapabilities"
)
CONTRACT_SCHEMA = "angerona.windows-install-contract/v2"
_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{2,49}$")
_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){3}$")
_TOKENS = ("__PACKAGE_NAME__", "__PUBLISHER_DN__", "__VERSION__")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Windows install contract contains a duplicate key")
        result[key] = value
    return result


def _regular(path: Path, label: str, maximum: int) -> bytes:
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-link file")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or not 1 <= metadata.st_size <= maximum:
        raise ValueError(f"{label} exceeds its byte budget")
    return path.read_bytes()


def four_part_version(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]+(?:\.[0-9]+){2,3}", value
    ):
        raise ValueError("MSIX version must have three or four numeric parts")
    parts = [int(part) for part in value.split(".")]
    parts.extend([0] * (4 - len(parts)))
    if any(part < 0 or part > 65535 for part in parts):
        raise ValueError("MSIX version parts must fit unsigned 16-bit fields")
    return ".".join(str(part) for part in parts)


def _validate_identity(package_name: str, publisher_dn: str, version: str) -> None:
    if not isinstance(package_name, str) or not _PACKAGE_NAME.fullmatch(package_name):
        raise ValueError("MSIX package Name is invalid")
    if (
        not isinstance(publisher_dn, str)
        or not 3 <= len(publisher_dn) <= 8192
        or not publisher_dn.startswith("CN=")
        or any(ord(character) < 32 for character in publisher_dn)
    ):
        raise ValueError("MSIX Publisher DN is invalid")
    if not _VERSION.fullmatch(version):
        raise ValueError("MSIX package version is not four-part numeric")


def validate_manifest(
    raw: bytes, *, package_name: str, publisher_dn: str, version: str,
) -> None:
    _validate_identity(package_name, publisher_dn, version)
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= 64 * 1024:
        raise ValueError("AppxManifest.xml exceeds its byte budget")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError("AppxManifest.xml is invalid XML") from exc
    if root.tag != f"{{{FOUNDATION}}}Package":
        raise ValueError("AppxManifest.xml package namespace is invalid")
    if set(root.attrib) != {"IgnorableNamespaces"} or root.attrib[
        "IgnorableNamespaces"
    ] != "uap rescap":
        raise ValueError("AppxManifest.xml namespace contract is invalid")
    identities = root.findall(f"{{{FOUNDATION}}}Identity")
    if len(identities) != 1 or identities[0].attrib != {
        "Name": package_name,
        "Publisher": publisher_dn,
        "Version": version,
        "ProcessorArchitecture": "x64",
    }:
        raise ValueError("AppxManifest.xml identity is not exact")
    applications = root.findall(
        f"{{{FOUNDATION}}}Applications/{{{FOUNDATION}}}Application"
    )
    if len(applications) != 1 or applications[0].attrib != {
        "Id": "Angerona",
        "Executable": "AngeronaStartup.exe",
        "EntryPoint": "Windows.FullTrustApplication",
    }:
        raise ValueError("AppxManifest.xml full-trust application is invalid")
    visuals = applications[0].find(f"{{{UAP}}}VisualElements")
    if visuals is None or visuals.attrib.get("Square44x44Logo") != (
        "Assets\\Square44x44Logo.png"
    ) or visuals.attrib.get("Square150x150Logo") != (
        "Assets\\Square150x150Logo.png"
    ):
        raise ValueError("AppxManifest.xml visual assets are invalid")
    capabilities = root.findall(
        f"{{{FOUNDATION}}}Capabilities/{{{RESCAP}}}Capability"
    )
    if len(capabilities) != 1 or capabilities[0].attrib != {"Name": "runFullTrust"}:
        raise ValueError("AppxManifest.xml capabilities are not fail-closed")


def render_manifest(
    *, template: Path, output: Path, package_name: str, publisher_dn: str,
    version: str,
) -> None:
    version = four_part_version(version)
    _validate_identity(package_name, publisher_dn, version)
    try:
        source = _regular(template, "AppxManifest template", 64 * 1024).decode(
            "utf-8"
        )
    except UnicodeDecodeError as exc:
        raise ValueError("AppxManifest template is not UTF-8") from exc
    for token in _TOKENS:
        if source.count(token) != 1:
            raise ValueError("AppxManifest template token set is invalid")
    replacements = {
        "__PACKAGE_NAME__": package_name,
        "__PUBLISHER_DN__": publisher_dn,
        "__VERSION__": version,
    }
    for token, value in replacements.items():
        source = source.replace(token, html.escape(value, quote=True))
    encoded = source.encode("utf-8")
    validate_manifest(
        encoded,
        package_name=package_name,
        publisher_dn=publisher_dn,
        version=version,
    )
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + f".{os.getpid()}.tmp")
    try:
        with open(temporary, "xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)


def build_assets(*, source: Path, output: Path) -> None:
    source = Path(source)
    _regular(source, "MSIX source logo", 16 * 1024 * 1024)
    try:
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QImage
    except Exception as exc:  # pragma: no cover - release environment gate
        raise RuntimeError("PySide6 is required to render deterministic MSIX assets") from exc
    image = QImage(str(source))
    if image.isNull() or image.width() < 150 or image.height() < 150:
        raise ValueError("MSIX source logo must decode at 150x150 or larger")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    for name, size in (
        ("Square44x44Logo.png", 44),
        ("StoreLogo.png", 50),
        ("Square150x150Logo.png", 150),
    ):
        rendered = image.scaled(
            size,
            size,
            Qt.AspectRatioMode.IgnoreAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        destination = output / name
        if not rendered.save(str(destination), "PNG"):
            raise RuntimeError(f"could not write deterministic MSIX asset {name}")


def validate_contract(path: Path) -> None:
    raw = _regular(path, "Windows install contract", 16 * 1024)
    try:
        document = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Windows install contract is not valid UTF-8 JSON") from exc
    canonical = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    if raw not in (canonical, canonical + b"\n"):
        raise ValueError("Windows install contract is not canonical")
    expected = {
        "schema": CONTRACT_SCHEMA,
        "product": "Angerona",
        "public_first_install": {
            "artifact": "signed-msix",
            "os_enforced_package_identity": True,
        },
        "public_windows_install_artifacts": [
            "signed-msix",
            "threshold-authorized-zip",
        ],
        "protected_portable_upgrade": {
            "artifact": "threshold-authorized-zip",
            "public_release_asset": True,
            "requires_installed_protected_authority": True,
            "rollback_floor_enforced": True,
        },
        "classic_installer": {
            "role": "approved-installation-migration-only",
            "public_trust_bootstrap": False,
            "public_release_asset": False,
            "requires_prior_approved_installation": True,
            "pre_elevation_custody_check": True,
            "delegates_elevation_and_mutation_to_installed_authority": True,
            "enterprise_clean_install": {
                "included": False,
                "same_public_asset": False,
                "requires_external_allow_policy": True,
                "separate_governed_artifact": True,
            },
        },
    }
    if document != expected:
        raise ValueError("Windows install contract is invalid")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    render = commands.add_parser("render-manifest")
    render.add_argument("--template", type=Path, required=True)
    render.add_argument("--output", type=Path, required=True)
    render.add_argument("--package-name", required=True)
    render.add_argument("--publisher-dn", required=True)
    render.add_argument("--version", required=True)
    assets = commands.add_parser("build-assets")
    assets.add_argument("--source", type=Path, required=True)
    assets.add_argument("--output", type=Path, required=True)
    contract = commands.add_parser("validate-contract")
    contract.add_argument("--contract", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.command == "render-manifest":
        render_manifest(
            template=args.template,
            output=args.output,
            package_name=args.package_name,
            publisher_dn=args.publisher_dn,
            version=args.version,
        )
    elif args.command == "build-assets":
        build_assets(source=args.source, output=args.output)
    else:
        validate_contract(args.contract)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
