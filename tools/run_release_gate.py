"""Run Angerona's fixed local quality gate and emit content-addressed evidence."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

from angerona.core.release_evidence import (
    QualityCheckEvidence, build_evidence_pack, write_evidence_pack,
)

ROOT = Path(__file__).resolve().parents[1]
PYTHON = Path(sys.executable).resolve()
CHECKS = {
    "bytecode": (str(PYTHON), "-m", "compileall", "-q", "src"),
    "dependency-audit": (
        str(PYTHON), "-m", "pip_audit", "--progress-spinner", "off",
    ),
    "documentation-drift": (
        str(PYTHON), "tools/validate_documentation_drift.py",
    ),
    "lint": (str(PYTHON), "-m", "ruff", "check", "src", "tests", "tools"),
    "unit-tests": (str(PYTHON), "-m", "pytest", "-q"),
}
MAX_CAPTURE = 4 * 1024 * 1024


def _git(*arguments: str) -> str:
    return subprocess.run(
        ("git", *arguments), cwd=ROOT, check=True, capture_output=True,
        text=True, timeout=30,
    ).stdout.strip()


def _project_version() -> str:
    in_project = False
    for line in (ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_project = stripped == "[project]"
            continue
        if in_project and stripped.startswith("version"):
            _key, separator, value = stripped.partition("=")
            version = value.strip().strip("\"'")
            if separator and version:
                return version
    raise ValueError("pyproject.toml has no project version")


def _run(check_id: str, command: tuple[str, ...], timeout: int) -> QualityCheckEvidence:
    started = time.monotonic()
    timed_out = False
    try:
        result = subprocess.run(
            command, cwd=ROOT, capture_output=True, timeout=timeout,
            stdin=subprocess.DEVNULL, shell=False,
        )
        output = (result.stdout or b"") + b"\n" + (result.stderr or b"")
        exit_code = int(result.returncode)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        output = (exc.stdout or b"") + b"\n" + (exc.stderr or b"")
        exit_code = 124
    output = output[-MAX_CAPTURE:]
    return QualityCheckEvidence.from_output(
        check_id, command=command, exit_code=exit_code,
        duration_seconds=time.monotonic() - started, output=output,
        timed_out=timed_out,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path,
        default=ROOT / "analysis" / "release-evidence-local.json",
    )
    parser.add_argument("--timeout-seconds", type=int, default=1800)
    args = parser.parse_args()
    timeout = max(60, min(int(args.timeout_seconds), 3600))
    checks = tuple(
        _run(check_id, command, timeout)
        for check_id, command in sorted(CHECKS.items())
    )
    source_epoch = int(os.environ.get(
        "SOURCE_DATE_EPOCH", _git("show", "-s", "--format=%ct", "HEAD"),
    ))
    pack = build_evidence_pack(
        version=_project_version(),
        commit_sha=_git("rev-parse", "HEAD"),
        source_date_epoch=source_epoch,
        checks=checks,
        limitations=(
            "Local gate evidence is content-addressed but not a publisher signature.",
            "Long-duration physical-host soak and external penetration tests are separate gates.",
        ),
    )
    write_evidence_pack(args.output.resolve(), pack)
    print(f"{pack.manifest.gate_status}: {args.output.resolve()}")
    return 0 if pack.manifest.gate_status == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
