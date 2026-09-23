"""Explicit ordinary-user service provisioning; never invokes sudo or UAC."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Install/remove Angerona's native per-user protection service. "
        "Protection survives GUI closure; Windows/macOS require the user session."))
    parser.add_argument("command", choices=("install-user", "remove-user"))
    args = parser.parse_args()
    from angerona.core.engine_service import install_user_service, remove_user_service
    if args.command == "install-user":
        result = install_user_service()
        print(f"Installed per-user protection: {result}")
    else:
        remove_user_service()
        print("Removed per-user protection startup")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
