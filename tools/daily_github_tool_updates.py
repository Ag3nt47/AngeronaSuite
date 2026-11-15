#!/usr/bin/env python3
"""Run Angerona's cross-platform GitHub-tool check outside the GUI."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from angerona.core.data_paths import data_dir  # noqa: E402
from angerona.updater.github_tool_updates import check_and_apply_github_tools  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=None)
    parser.add_argument("--check-only", action="store_true", help="Do not prepare or test managed scanners.")
    parser.add_argument("--no-download", action="store_true", help="Use only already bundled scanner files.")
    options = parser.parse_args(argv)
    report = check_and_apply_github_tools(
        options.data_dir or data_dir(),
        allow_download=not options.no_download,
        apply_managed=not options.check_only,
    )
    print(json.dumps({
        "status": report.status,
        "checked_at": report.checked_at,
        "summary": report.summary(),
        "record_path": report.record_path,
        "tools": report.tools,
    }, indent=2, sort_keys=True))
    return 0 if report.status == "checked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
