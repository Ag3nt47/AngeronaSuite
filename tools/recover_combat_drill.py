"""Inspect or finish a proven unapplied inert-drill quarantine checkpoint.

Inspection is read-only. Apply requires the reviewed token and a stopped app;
it preserves private backups and never moves a target or rearms Combat itself.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from angerona.core.combat_checkpoint_recovery import (  # noqa: E402
    existing_installation, inspect_drill_checkpoint, recover_drill_checkpoint,
)
from tools.recover_combat_startup import _require_stopped  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-token", default="")
    args = parser.parse_args()
    try:
        module = existing_installation(args.data_root)
        if args.apply:
            if not args.expected_token:
                raise ValueError("Apply requires the reviewed inspection token")
            _require_stopped()
            report = recover_drill_checkpoint(
                module, expected_token=args.expected_token, before_commit=_require_stopped,
            )
        else:
            report = inspect_drill_checkpoint(module)
        print(json.dumps(report, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"eligible": False, "error": str(exc), "rearmed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
