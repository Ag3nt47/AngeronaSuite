"""Deterministic, offline checks for high-value README claims.

This intentionally uses static parsing only. It does not import Angerona
modules, start services, inspect the host, or use the network.
"""
from __future__ import annotations

import ast
import re
import subprocess
import sys
import zlib
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


STATUS_RE = re.compile(
    r"<!--\s*ANGERONA_DOC_STATUS\s+tests=(\d+)\s+skips=(\d+)\s+modules=(\d+)\s*-->"
)
FINAL_RE = re.compile(
    r"Final Cycle \d+ verification\.\*\*.*?"
    r"passes\s+\*\*(\d+) tests with\s+(\d+) intentional platform skips\*\*",
    re.DOTALL,
)
IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*(?P<target><[^>]+>|[^)\s]+)")
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
MAX_PUBLIC_IMAGE_BYTES = 16 * 1024 * 1024
MAX_VERSION_METADATA_BYTES = 2 * 1024 * 1024
STABLE_VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")

ACRONYMS = {
    "EDR": "Endpoint Detection and Response",
    "NDR": "Network Detection and Response",
    "SOAR": "Security Orchestration, Automation, and Response",
    "WFP": "Windows Filtering Platform",
    "HMAC": "Hash-based Message Authentication Code",
    "RBAC": "Role-Based Access Control",
}


def _version_text(root: Path, relative: str, errors: list[str]) -> str | None:
    try:
        with (root / relative).open("rb") as stream:
            raw = stream.read(MAX_VERSION_METADATA_BYTES + 1)
        if len(raw) > MAX_VERSION_METADATA_BYTES:
            raise ValueError("metadata exceeds its byte limit")
        return raw.decode("utf-8-sig").replace("\r\n", "\n")
    except (OSError, UnicodeError, ValueError):
        errors.append(f"{relative}: current-version metadata is unreadable or oversized")
        return None


def _project_version(source: str) -> str | None:
    # Require one explicit scalar in the project table. This deliberately
    # avoids executing the package or depending on tomllib (Python 3.11+).
    tables = list(re.finditer(r"(?m)^[ \t]*\[([^\]\r\n]+)\][ \t]*(?:#.*)?$", source))
    indexes = [index for index, table in enumerate(tables) if table.group(1) == "project"]
    if len(indexes) != 1:
        return None
    index = indexes[0]
    end = tables[index + 1].start() if index + 1 < len(tables) else len(source)
    project = source[tables[index].end():end]
    assignments = [line for line in project.splitlines() if re.match(
        r'''^[ \t]*(?:version|"version"|'version')[ \t]*=''', line,
    )]
    if len(assignments) != 1:
        return None
    match = re.fullmatch(r'''[ \t]*version[ \t]*=[ \t]*(["'])([^"'\r\n]+)\1[ \t]*(?:#.*)?''', assignments[0])
    return match.group(2) if match else None


def _package_version(source: str) -> str | None:
    try:
        tree = ast.parse(source, filename="src/angerona/__init__.py")
    except (SyntaxError, ValueError, RecursionError):
        return None
    values = []
    accepted_targets = set()
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else (
            [node.target] if isinstance(node, ast.AnnAssign) else []
        )
        for target in targets:
            if isinstance(target, ast.Name) and target.id == "__version__":
                accepted_targets.add(id(target))
                values.append(node.value)
    # Conditional/reassigned/computed versions cannot be proved statically.
    if any(isinstance(node, ast.Name) and node.id == "__version__"
           and isinstance(node.ctx, ast.Store) and id(node) not in accepted_targets
           for node in ast.walk(tree)):
        return None
    if len(values) != 1 or not isinstance(values[0], ast.Constant) or type(values[0].value) is not str:
        return None
    return values[0].value


def validate_current_versions(root: Path, *, readme: str | None = None) -> list[str]:
    """Compare current release labels; older review/component versions are history."""
    errors: list[str] = []
    project = _version_text(root, "pyproject.toml", errors)
    package = _version_text(root, "src/angerona/__init__.py", errors)
    expected = _project_version(project) if project is not None else None
    actual = _package_version(package) if package is not None else None
    if project is not None and (expected is None or not STABLE_VERSION_RE.fullmatch(expected)):
        errors.append("pyproject.toml: require one explicit stable three-part project.version")
    if package is not None and (actual is None or not STABLE_VERSION_RE.fullmatch(actual)):
        errors.append("src/angerona/__init__.py: require one literal stable three-part __version__")
    if expected is None or not STABLE_VERSION_RE.fullmatch(expected):
        return errors
    if actual is not None and actual != expected:
        errors.append(f"src/angerona/__init__.py: __version__ disagrees with project.version {expected}")

    if readme is None:
        readme = _version_text(root, "README.md", errors)
    documents = [
        ("README.md", readme, r"(?m)^##[ \t]+Current development:[ \t]+v([^\s]+)[ \t]*$", "current-development heading"),
        ("ANGERONA_CAPABILITIES.md", _version_text(root, "ANGERONA_CAPABILITIES.md", errors),
         r"(?m)^Current development version:[ \t]+\*\*v([^\s*]+)\*\*", "current-development header"),
    ]
    for relative, text, pattern, label in documents:
        if text is None:
            continue
        matches = re.findall(pattern, text)
        if len(matches) != 1 or matches[0] != expected:
            errors.append(f"{relative}: {label} must name project.version {expected} exactly once")

    llms = _version_text(root, "llms.txt", errors)
    if llms is not None:
        first_section = re.search(r"(?m)^##[ \t]", llms)
        frontmatter = llms[:first_section.start()] if first_section else llms
        versions = re.findall(r"(?m)^Version:[ \t]*([^\s]+)[ \t]*$", frontmatter)
        latest = re.search(r"(?m)^##[ \t]+LATEST[ \t]+\(v([^\s)]+)", llms)
        if len(versions) != 1 or versions[0] != expected:
            errors.append(f"llms.txt: current Version header must name project.version {expected} exactly once")
        if latest is None or latest.group(1) != expected:
            errors.append(f"llms.txt: first LATEST heading must name project.version {expected}")

    changelog = _version_text(root, "CHANGELOG.md", errors)
    if changelog is not None:
        newest = re.search(r"(?m)^##[ \t]+v?([^\s]+)", changelog)
        if newest is None or newest.group(1) != expected:
            errors.append(f"CHANGELOG.md: newest entry must name project.version {expected}")
    shell_name = "tools/Show-AngeronaStartupRecovery.ps1"
    shell = _version_text(root, shell_name, errors)
    if shell is not None:
        labels = (
            (r"\$form\.Text\s*=\s*'Angerona ([^ '\r\n]+) - Safe Startup'", "window title"),
            (r'\$brand\.Text\s*=\s*"ANGERONA[ \t]+([^ \t`"\r\n]+)`r`nSafe Startup dashboard"', "dashboard brand"),
        )
        for pattern, label in labels:
            matches = re.findall(pattern, shell)
            if matches != [expected]:
                errors.append(f"{shell_name}: {label} must name project.version {expected} exactly once")
    return errors


def _module_count(root: Path) -> int:
    count = 0
    for path in sorted((root / "src" / "angerona" / "modules").glob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (OSError, SyntaxError):
            continue
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            for base in node.bases:
                name = base.id if isinstance(base, ast.Name) else (
                    base.attr if isinstance(base, ast.Attribute) else ""
                )
                if name == "BaseModule":
                    count += 1
                    break
    return count


def _normalized_prose(text: str) -> str:
    text = re.sub(r"```.*?```", " ", text, flags=re.DOTALL)
    text = re.sub(r"!\[[^\]]*\]\([^)]+\)", " ", text)
    text = re.sub(r"`[^`]*`", " ", text)
    return re.sub(r"\s+", " ", text)


def local_readme_image_targets(readme: str) -> tuple[list[str], list[str]]:
    """Return unique, repository-relative README image targets."""

    targets: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()
    for match in IMAGE_RE.finditer(readme):
        raw = match.group("target").strip("<>")
        parsed = urlsplit(raw)
        if parsed.scheme or parsed.netloc:
            continue
        if parsed.query or parsed.fragment:
            errors.append(f"README.md: local image target has query/fragment: {raw}")
            continue
        decoded = unquote(parsed.path)
        if "\\" in decoded:
            errors.append(f"README.md: local image target uses backslashes: {raw}")
            continue
        relative = PurePosixPath(decoded)
        if (
            not decoded
            or relative.is_absolute()
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            errors.append(f"README.md: unsafe local image target: {raw}")
            continue
        canonical = relative.as_posix()
        if canonical not in seen:
            seen.add(canonical)
            targets.append(canonical)
    return targets, errors


def _git_tracks(root: Path, relative: str) -> bool | None:
    """Return tracking state, or None when *root* is not a Git worktree."""

    probe = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        return None
    try:
        if Path(probe.stdout.strip()).resolve() != root.resolve():
            return None
    except OSError:
        return None
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", relative],
        capture_output=True,
        text=True,
        check=False,
    )
    return tracked.returncode == 0


def validate_png_payload(payload: bytes) -> tuple[int, int]:
    """Validate bounded PNG chunk framing, CRCs, and required chunks."""

    if len(payload) <= 24 or payload[:8] != PNG_SIGNATURE:
        raise ValueError("invalid PNG signature or length")
    offset = len(PNG_SIGNATURE)
    width = 0
    height = 0
    color_type = -1
    saw_header = False
    saw_palette = False
    saw_data = False
    saw_end = False
    data_ended = False
    while offset < len(payload):
        if len(payload) - offset < 12:
            raise ValueError("truncated PNG chunk")
        length = int.from_bytes(payload[offset : offset + 4], "big")
        chunk_type = payload[offset + 4 : offset + 8]
        chunk_end = offset + 12 + length
        if length > MAX_PUBLIC_IMAGE_BYTES or chunk_end > len(payload):
            raise ValueError("PNG chunk exceeds the bounded payload")
        if len(chunk_type) != 4 or not all(
            65 <= byte <= 90 or 97 <= byte <= 122 for byte in chunk_type
        ):
            raise ValueError("PNG chunk type is invalid")
        data_start = offset + 8
        data_end = data_start + length
        data = payload[data_start:data_end]
        expected_crc = int.from_bytes(payload[data_end : data_end + 4], "big")
        actual_crc = zlib.crc32(chunk_type)
        actual_crc = zlib.crc32(data, actual_crc) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise ValueError("PNG chunk CRC is invalid")

        if not saw_header:
            if chunk_type != b"IHDR" or length != 13:
                raise ValueError("PNG must begin with one 13-byte IHDR")
            width = int.from_bytes(data[0:4], "big")
            height = int.from_bytes(data[4:8], "big")
            bit_depth = data[8]
            color_type = data[9]
            allowed_depths = {
                0: {1, 2, 4, 8, 16},
                2: {8, 16},
                3: {1, 2, 4, 8},
                4: {8, 16},
                6: {8, 16},
            }
            if (
                not (0 < width <= 16384 and 0 < height <= 16384)
                or color_type not in allowed_depths
                or bit_depth not in allowed_depths[color_type]
                or data[10] != 0
                or data[11] != 0
                or data[12] not in {0, 1}
            ):
                raise ValueError("PNG IHDR fields are invalid")
            saw_header = True
        elif chunk_type == b"IHDR":
            raise ValueError("PNG contains a duplicate IHDR")
        elif chunk_type == b"PLTE":
            if saw_data or length == 0 or length % 3 or length > 768:
                raise ValueError("PNG palette is invalid or misplaced")
            saw_palette = True
        elif chunk_type == b"IDAT":
            if data_ended:
                raise ValueError("PNG IDAT chunks are not consecutive")
            if color_type == 3 and not saw_palette:
                raise ValueError("indexed PNG is missing a palette")
            saw_data = True
        elif chunk_type == b"IEND":
            if length != 0 or not saw_data:
                raise ValueError("PNG IEND is invalid or precedes image data")
            saw_end = True
            offset = chunk_end
            if offset != len(payload):
                raise ValueError("PNG has trailing bytes after IEND")
            break
        else:
            if saw_data:
                data_ended = True
            if 65 <= chunk_type[0] <= 90:
                raise ValueError("PNG contains an unknown critical chunk")
        offset = chunk_end

    if not saw_header or not saw_data or not saw_end:
        raise ValueError("PNG is missing IHDR, IDAT, or IEND")
    return width, height


def _validate_local_readme_images(root: Path, readme: str) -> list[str]:
    targets, errors = local_readme_image_targets(readme)
    if not targets:
        errors.append("README.md: require at least one local public image")
        return errors

    resolved_root = root.resolve()
    for relative in targets:
        candidate = root.joinpath(*PurePosixPath(relative).parts)
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            errors.append(f"README.md: image is unavailable: {relative}: {exc}")
            continue
        if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
            errors.append(f"README.md: image escapes repository or is not a file: {relative}")
            continue
        tracked = _git_tracks(root, relative)
        if tracked is False:
            errors.append(f"README.md: image is not tracked by Git: {relative}")
        try:
            size = resolved.stat().st_size
            payload = resolved.read_bytes()
        except OSError as exc:
            errors.append(f"README.md: cannot inspect image: {relative}: {exc}")
            continue
        if size <= 24 or size > MAX_PUBLIC_IMAGE_BYTES:
            errors.append(
                f"README.md: image size is outside the public bound: {relative}"
            )
            continue
        if resolved.suffix.lower() != ".png":
            errors.append(f"README.md: local public image must be PNG: {relative}")
            continue
        try:
            validate_png_payload(payload)
        except ValueError as exc:
            errors.append(f"README.md: image has invalid PNG structure: {relative}: {exc}")
    return errors


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    readme_path = root / "README.md"
    try:
        readme = readme_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"README.md: cannot read: {exc}"]

    errors.extend(validate_current_versions(root, readme=readme))

    markers = list(STATUS_RE.finditer(readme))
    if len(markers) != 1:
        errors.append("README.md: require exactly one ANGERONA_DOC_STATUS marker")
        marker = None
    else:
        marker = markers[0]
        if readme[marker.end():].strip():
            errors.append("README.md: ANGERONA_DOC_STATUS must be the final content")

    finals = list(FINAL_RE.finditer(readme))
    if not finals:
        errors.append("README.md: Final Cycle verification statement is missing")
    if marker is not None and finals:
        tests, skips, modules = map(int, marker.groups())
        final_tests, final_skips = map(int, finals[-1].groups())
        if (tests, skips) != (final_tests, final_skips):
            errors.append(
                "README.md: final verification count disagrees with "
                "ANGERONA_DOC_STATUS"
            )
        static_modules = _module_count(root)
        if modules != static_modules:
            errors.append(
                f"README.md: marker modules={modules}, static discovery={static_modules}"
            )
        module_claim = re.compile(
            rf"\b(?:discovery|auto-discovery)\b[^\n]{{0,80}}\b{modules}\s+modules\b",
            re.IGNORECASE,
        )
        if not module_claim.search(readme):
            errors.append(
                f"README.md: no discovery claim matches marker modules={modules}"
            )

    required_claims = {
        "source runtime path": r"sibling `AngeronaData` directory",
        "packaged D-drive data root": r"D:\\AngeronaData",
        "protected fallback data root": r"%ProgramData%\\Angerona",
        "optional cloud boundary": r"Cloud\s+integrations are optional and off by default",
        "synthetic public screenshot": r"all displayed telemetry.*synthetic",
        "user-mode limitation": r"Angerona is user-mode",
        "no production kernel driver": r"ships no production kernel driver",
    }
    for label, pattern in required_claims.items():
        if not re.search(pattern, readme, re.IGNORECASE | re.DOTALL):
            errors.append(f"README.md: missing {label} claim")

    errors.extend(_validate_local_readme_images(root, readme))

    prose = _normalized_prose(readme)
    for acronym, expansion in ACRONYMS.items():
        first = re.search(rf"\b{re.escape(acronym)}\b", prose)
        expanded = re.search(
            rf"{re.escape(expansion)}\s*\(\s*{re.escape(acronym)}\s*\)",
            prose,
            re.IGNORECASE,
        )
        if first and (not expanded or expanded.start() > first.start()):
            errors.append(
                f"README.md: {acronym} must be expanded on first prose use"
            )
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate(root)
    for error in errors:
        print(error)
    if not errors:
        print("documentation drift check: PASS")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
