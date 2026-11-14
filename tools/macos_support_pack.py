#!/usr/bin/env python3
"""Manage the optional Angerona macOS support pack.

    python3.12 tools/macos_support_pack.py status
    python3.12 tools/macos_support_pack.py install [--from-directory DIR]
    python3.12 tools/macos_support_pack.py enable | disable | uninstall
    python3.12 tools/macos_support_pack.py decline

``install`` downloads the reviewed revision pinned in
``release/macos-support-pack.json`` and verifies every byte before anything is
written. ``should-ask`` is used by the guided macOS setup: it exits 0 only when
the pack is not yet current and the user has not declined it.

Standard library only; it runs before Angerona's runtime exists.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from angerona.platforms.macos import support_pack as pack  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=(
        "status", "install", "enable", "disable", "uninstall", "decline", "should-ask",
    ))
    parser.add_argument("--from-directory", type=Path,
                        help="install from a local copy of the pack (still hash-verified)")
    parser.add_argument("--data", type=Path, help="Angerona data folder (default: per-user)")
    parser.add_argument("--json", action="store_true", help="print status as JSON")
    args = parser.parse_args(argv)
    data = args.data or pack.default_data_dir()

    if args.action == "should-ask":
        return 0 if pack.status(ROOT, data)["should_ask"] else 1
    if args.action == "status":
        state = pack.status(ROOT, data)
        if args.json:
            print(json.dumps(state, indent=2, sort_keys=True))
        else:
            print(f"Reviewed pack version : {state['pinned_version'] or 'none'}"
                  + (f" ({state['pin_problem']})" if state["pin_problem"] else ""))
            print(f"Installed             : {state['installed_version'] or 'no'}")
            print(f"Matches reviewed pin  : {'yes' if state['current'] else 'no'}")
            print(f"Verified              : {'yes' if state['verified'] else 'no'} ({state['detail']})")
            print(f"Enabled at launch     : {'yes' if state['enabled'] else 'no'}")
            if state["declined"]:
                print("Setup prompt          : declined (run install to add it later)")
        return 0
    if sys.platform != "darwin":
        print("The macOS support pack is only for macOS.", file=sys.stderr)
        return 1
    try:
        if args.action == "install":
            fetch = pack.directory_fetcher(args.from_directory) if args.from_directory else None
            print("Verifying the reviewed Angerona macOS support pack"
                  + (" from a local folder..." if args.from_directory else " from GitHub..."))
            receipt = pack.install(ROOT, data, fetch=fetch)
            print(f"Installed and verified support pack {receipt['version']} "
                  f"({len(receipt['modules']) // 2} modules).")
            print(f"Scripts: {data / 'macos-support' / 'current' / 'scripts'}")
            print("WARNING: the support modules are unsigned. While enabled, Angerona starts "
                  "with its reduced-security development override and says so at every start.")
            print("Turn them off at any time with: tools/macos_support_pack.py disable")
        elif args.action == "enable":
            pack.set_enabled(data, True)
            print("Support modules will load at the next Angerona start (reduced-security mode).")
        elif args.action == "disable":
            pack.set_enabled(data, False)
            print("Support modules are disabled; Angerona starts in its normal mode.")
        elif args.action == "uninstall":
            removed = pack.uninstall(data)
            print("Support pack removed." if removed else "The support pack was not installed.")
        elif args.action == "decline":
            pack.decline(data)
            print("Setup will not offer the support pack again. Install it later with: "
                  "tools/macos_support_pack.py install")
    except pack.SupportPackError as exc:
        print(f"Support pack: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
