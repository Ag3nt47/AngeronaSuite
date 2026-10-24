"""Explicit stopped-only closure of a proven no-effect interrupted host undo.

No host action is executed. Existing journal history/key remain intact; apply
requires a freshly reviewed inspection token and creates verified private backups.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from angerona.core.combat_checkpoint_recovery import (  # noqa: E402
    existing_installation, inspect_host_undo_checkpoint, recover_host_undo_checkpoint,
)
from tools.recover_combat_startup import _require_stopped as _require_core_stopped  # noqa: E402


def _require_stopped() -> None:
    """Also refuse standalone Black Box and its Python launcher wrappers."""
    import psutil

    _require_core_stopped()
    for process in psutil.process_iter(["pid", "name"]):
        if process.pid == os.getpid():
            continue
        name = str(process.info.get("name") or "").casefold()
        if not name.startswith("python"):
            continue
        try:
            arguments = process.cmdline()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as exc:
            raise ValueError("Cannot verify that every Black Box process is stopped") from exc
        if any(arg.replace("\\", "/").rsplit("/", 1)[-1].casefold()
               == "blackbox_recorder.py" for arg in arguments):
            raise ValueError("Stop Black Box before applying checkpoint recovery")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-root", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--expected-token", default="")
    args = parser.parse_args()
    try:
        _require_stopped()
        module = existing_installation(args.data_root)
        report = (recover_host_undo_checkpoint(module, expected_token=args.expected_token,
                                               before_commit=_require_stopped) if args.apply
                  else inspect_host_undo_checkpoint(module))
        print(json.dumps(report, indent=2))
        return 0
    except Exception as exc:
        print(json.dumps({"eligible": False, "error": str(exc), "rearmed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
