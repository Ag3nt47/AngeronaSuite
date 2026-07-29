"""Deterministic static policy checks for repository GitHub Actions workflows."""
from __future__ import annotations

import re
import sys
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$")


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    workflow_dir = root / ".github" / "workflows"
    for path in sorted((*workflow_dir.glob("*.yml"), *workflow_dir.glob("*.yaml"))):
        text = path.read_text(encoding="utf-8")
        label = path.relative_to(root).as_posix()
        if re.search(r"(?m)^\s*pull_request_target\s*:", text):
            errors.append(f"{label}: pull_request_target is forbidden")
        if not re.search(r"(?m)^permissions:\s*\n(?:[ \t]+.+\n)*?[ \t]+contents:\s*read\s*$", text):
            errors.append(f"{label}: top-level contents: read permission required")
        if "concurrency:" not in text:
            errors.append(f"{label}: concurrency policy required")
        jobs = re.split(r"(?m)^  (?=[A-Za-z0-9_-]+:\s*$)", text.split("jobs:", 1)[-1])
        for block in jobs:
            match = re.match(r"([A-Za-z0-9_-]+):", block)
            if match and "runs-on:" in block and "timeout-minutes:" not in block:
                errors.append(f"{label}: job {match.group(1)} lacks timeout")
        for line_no, match in enumerate(
            re.finditer(r"(?m)^\s*-\s+uses:\s*([^@\s]+)@([^\s#]+)", text), 1
        ):
            action, ref = match.groups()
            if not SHA.fullmatch(ref):
                errors.append(
                    f"{label}: action {action}@{ref} is not SHA-pinned"
                )
        if re.search(r"(?m)^\s+(?:contents|packages|actions):\s*write\s*$", text):
            if "pull_request:" in text and "if: startsWith(github.ref, 'refs/tags/v')" not in text:
                errors.append(f"{label}: write token may be exposed to pull request code")
    return errors


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    errors = validate(root)
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
