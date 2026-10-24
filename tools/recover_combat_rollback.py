"""Inspect a completed firewall rollback checkpoint; explicit apply needs a stopped app.

Only one exact authenticated failure terminal after a successful recovery undo
is eligible. No journal history, signing key or host firewall rule is changed.
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
    existing_installation, inspect_rollback_checkpoint, recover_rollback_checkpoint,
)
from tools.recover_combat_startup import _require_stopped  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-token", default="")
    args = parser.parse_args()
    try:
        if args.apply:
            _require_stopped()
        module = existing_installation(args.data_root)
        report = (recover_rollback_checkpoint(
            module, expected_token=args.expected_token, before_commit=_require_stopped,
        ) if args.apply else inspect_rollback_checkpoint(module))
        print(json.dumps(report, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"eligible": False, "error": str(exc), "rearmed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
