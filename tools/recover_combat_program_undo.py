"""Explicit stopped-only closure of a proven no-effect interrupted program undo.

Default inspection is read-only. Applying adds authenticated accounting only;
it never removes a firewall rule, executes a process action, resets authority,
or rearms response. Both terminal phases are durable before checkpoint advance.
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
    existing_installation, inspect_program_undo_checkpoint, recover_program_undo_checkpoint,
)
from tools.recover_combat_host_undo import _require_stopped  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-token", default="")
    args = parser.parse_args()
    try:
        _require_stopped()
        module = existing_installation(args.data_root)
        report = (recover_program_undo_checkpoint(module, expected_token=args.expected_token,
                                                  before_commit=_require_stopped) if args.apply
                  else inspect_program_undo_checkpoint(module))
        print(json.dumps(report, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"eligible": False, "error": str(exc), "rearmed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
