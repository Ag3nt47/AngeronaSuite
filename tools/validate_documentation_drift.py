"""Deterministic, offline checks for high-value README claims.

This intentionally uses static parsing only. It does not import Angerona
modules, start services, inspect the host, or use the network.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path


STATUS_RE = re.compile(
    r"<!--\s*ANGERONA_DOC_STATUS\s+tests=(\d+)\s+skips=(\d+)\s+modules=(\d+)\s*-->"
)
FINAL_RE = re.compile(
    r"Final Cycle \d+ verification\.\*\*.*?"
    r"passes\s+\*\*(\d+) tests with\s+(\d+) intentional platform skips\*\*",
    re.DOTALL,
)

ACRONYMS = {
    "EDR": "Endpoint Detection and Response",
    "NDR": "Network Detection and Response",
    "SOAR": "Security Orchestration, Automation, and Response",
    "WFP": "Windows Filtering Platform",
    "HMAC": "Hash-based Message Authentication Code",
    "RBAC": "Role-Based Access Control",
}


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


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    readme_path = root / "README.md"
    try:
        readme = readme_path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"README.md: cannot read: {exc}"]

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
