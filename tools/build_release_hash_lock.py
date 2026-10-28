"""Build the Windows/Python 3.12 release hash lock from audited wheels.

The input wheelhouse must be populated with exactly the artifacts selected for
the release runner. This tool performs no network access and fails closed when a
constraint has no matching wheel or more than one matching artifact.
"""
from __future__ import annotations

import argparse
from collections import deque
from dataclasses import dataclass
from email.parser import BytesParser
import hashlib
import importlib.util
import re
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from zipfile import ZipFile

from packaging.requirements import Requirement
from packaging.specifiers import SpecifierSet
from packaging.tags import compatible_tags, cpython_tags, parse_tag
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version


_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s#]+)$")
TARGET = {
    "implementation_name": "cpython", "implementation_version": "3.12.0",
    "os_name": "nt", "platform_machine": "AMD64", "platform_release": "10",
    "platform_system": "Windows", "platform_version": "10.0",
    "platform_python_implementation": "CPython", "python_full_version": "3.12.0",
    "python_version": "3.12", "sys_platform": "win32",
}
_TAGS = frozenset(cpython_tags((3, 12), abis=("cp312",), platforms=("win_amd64",))) | frozenset(
    compatible_tags((3, 12), interpreter="cp312", platforms=("win_amd64",))
)


@dataclass(frozen=True)
class Wheel:
    path: Path
    name: str
    version: Version
    requirements: tuple[Requirement, ...]
    extras: frozenset[str]


def _metadata(path: Path) -> Wheel:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
        or getattr(info, "st_file_attributes", 0) & 0x400
        or not 1 <= info.st_size <= 512 * 1024**2
    ):
        raise ValueError(f"wheel is not a bounded plain single-link file: {path.name}")
    name, version, _build, tags = parse_wheel_filename(path.name)
    if not tags & _TAGS:
        raise ValueError(f"wheel is incompatible with CPython 3.12/Windows x86-64: {path.name}")
    with ZipFile(path) as archive:
        entries = archive.infolist()
        metadata = [item for item in entries if item.filename.count("/") == 1
                    and item.filename.endswith(".dist-info/METADATA")]
        if len(entries) > 32768 or len(metadata) != 1 or metadata[0].file_size > 2 * 1024**2:
            raise ValueError(f"wheel has missing, duplicate or oversized METADATA: {path.name}")
        prefix = metadata[0].filename.split("/", 1)[0]
        distribution, directory_version = prefix.removesuffix(".dist-info").rsplit("-", 1)
        if canonicalize_name(distribution) != name or Version(directory_version) != version:
            raise ValueError(f"wheel dist-info directory identity differs from its filename: {path.name}")
        wheel_headers = [item for item in entries if item.filename.count("/") == 1
                         and item.filename.endswith(".dist-info/WHEEL")]
        if (len(wheel_headers) != 1 or wheel_headers[0].filename != prefix + "/WHEEL"
                or wheel_headers[0].file_size > 64 * 1024):
            raise ValueError(f"wheel has missing, duplicate or oversized WHEEL headers: {path.name}")
        headers = BytesParser().parsebytes(archive.read(wheel_headers[0]), headersonly=True)
        declared = headers.get_all("Tag", [])
        if not 1 <= len(declared) <= 128 or frozenset(tag for row in declared for tag in parse_tag(row)) != tags:
            raise ValueError(f"wheel WHEEL tags differ from its filename: {path.name}")
        document = BytesParser().parsebytes(archive.read(metadata[0]), headersonly=True)
    if (
        len(document.get_all("Name", [])) != 1 or len(document.get_all("Version", [])) != 1
        or canonicalize_name(document["Name"]) != name or Version(document["Version"]) != version
    ):
        raise ValueError(f"wheel METADATA identity does not match its filename: {path.name}")
    python = document.get_all("Requires-Python", [])
    if len(python) > 1 or (python and not SpecifierSet(python[0]).contains(TARGET["python_full_version"])):
        raise ValueError(f"wheel Requires-Python excludes the target: {path.name}")
    requirements = document.get_all("Requires-Dist", [])
    extras = frozenset(canonicalize_name(extra) for extra in document.get_all("Provides-Extra", []))
    if len(requirements) > 4096 or len(extras) > 128:
        raise ValueError(f"wheel dependency metadata exceeds its bounds: {path.name}")
    return Wheel(path, name, version, tuple(Requirement(row) for row in requirements), extras)


def validate_closure(selected: list[Wheel], provided: list[Wheel]) -> None:
    """Prove the exact selected graph for the declared target, never the host.

    Explicit local build wheels may satisfy edges without entering the external
    hash lock. They must be supplied as reviewed artifacts, not installed extras.
    """
    wheels: dict[str, Wheel] = {}
    for artifact in [*selected, *provided]:
        if artifact.name in wheels:
            raise ValueError(f"duplicate selected/provided dependency: {artifact.name}")
        wheels[artifact.name] = artifact
    extras: dict[str, set[str]] = {name: set() for name in wheels}
    pending = deque(wheels)
    while pending:
        name = pending.popleft()
        artifact = wheels[name]
        contexts = {"", *extras[name]}
        for requirement in artifact.requirements:
            if requirement.marker and not any(
                requirement.marker.evaluate({**TARGET, "extra": extra}) for extra in contexts
            ):
                continue
            dependency = canonicalize_name(requirement.name)
            if requirement.url:
                raise ValueError(f"{name}: active direct-URL dependency is not an audited wheel pin: {requirement}")
            if dependency not in wheels:
                raise ValueError(f"{name}: missing target dependency {requirement} (CPython 3.12/win_amd64)")
            target = wheels[dependency]
            if not requirement.specifier.contains(target.version, prereleases=True):
                raise ValueError(f"{name}: pinned {dependency}=={target.version} does not satisfy {requirement}")
            requested = {canonicalize_name(extra) for extra in requirement.extras}
            if not requested <= target.extras:
                raise ValueError(f"{name}: {dependency} does not declare requested extras {sorted(requested-target.extras)}")
            added = requested - extras[dependency]
            if added:
                extras[dependency].update(added)
                pending.append(dependency)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_lock(constraints: Path, wheelhouse: Path, *, provided_wheels: tuple[Path, ...] = ()) -> str:
    wheels: dict[tuple[str, str], list[Path]] = {}
    for path in sorted(wheelhouse.glob("*.whl")):
        name, version, _build, _tags = parse_wheel_filename(path.name)
        wheels.setdefault((canonicalize_name(name), str(version)), []).append(path)

    pins = []
    selected = []
    seen = set()
    for raw in constraints.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIN.fullmatch(line)
        if match is None:
            raise ValueError(f"constraint is not an exact pin: {raw!r}")
        name, version = match.groups()
        normalized = canonicalize_name(name)
        if normalized in seen or len(seen) >= 512:
            raise ValueError(f"duplicate or excessive constraint: {name}")
        seen.add(normalized)
        matches = wheels.get((normalized, str(Version(version))), [])
        if len(matches) != 1:
            raise ValueError(
                f"{name}=={version}: expected exactly one selected wheel, found {len(matches)}"
            )
        pins.append((name, version))
        selected.append(_metadata(matches[0]))
    validate_closure(selected, [_metadata(path) for path in provided_wheels])
    output = [
        "# Generated by tools/build_release_hash_lock.py.",
        "# Target: CPython 3.12, Windows x86-64. Refresh only after review.",
        "--only-binary=:all:",
        "",
    ]
    for (name, version), artifact in zip(pins, selected):
        digest = _sha256(artifact.path)
        output.extend((f"{name}=={version} \\", f"    --hash=sha256:{digest}", ""))
    return "\n".join(output).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--constraints", type=Path, default=Path("constraints-release.txt"))
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("requirements-release-hashed.txt"))
    parser.add_argument("--provided-wheel", type=Path, action="append", default=[],
                        help="Reviewed local build wheel installed separately (for example Angerona's SRT shim).")
    parser.add_argument("--check", action="store_true", help="Validate closure and require the committed lock to match without rewriting it.")
    args = parser.parse_args()
    with TemporaryDirectory(prefix="angerona-release-lock-") as scratch:
        provided = tuple(args.provided_wheel)
        if not provided:
            # This is reviewed repository source, not an installed distribution
            # or dependency resolver. Match the release/runtime SRT build.
            helper = Path(__file__).absolute().with_name("build_srt_compat_wheel.py")
            spec = importlib.util.spec_from_file_location("_angerona_lock_srt_builder", helper)
            if spec is None or spec.loader is None:
                raise ValueError("the reviewed local SRT builder is unavailable")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            provided = (module.build(Path(scratch)),)
        rendered = build_lock(args.constraints, args.wheelhouse, provided_wheels=provided)
    if args.check:
        if args.output.read_text(encoding="utf-8") != rendered:
            raise ValueError("committed Windows lock differs from the validated target dependency closure")
    else:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
