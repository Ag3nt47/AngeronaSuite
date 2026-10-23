"""Check GitHub daily and offer an explicitly approved verified-release upgrade.

Noninteractive use only checks. A source-main push or unsigned asset can never
activate an Angerona update. No scheduler or service is created.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

# Bind the tool to its own checked-out source, including isolated worktrees.
# An editable environment for a different checkout must not select old code.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-now", action="store_true", help="Check metadata now, retaining the shared 60-second retry floor")
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check-only", action="store_true", help="Never prompt, download or install")
    action.add_argument("--download", action="store_true", help="Offer download only, with explicit interactive approval")
    action.add_argument("--install", action="store_true", help="Offer download and protected installation, with explicit interactive approval")
    parser.add_argument("--json", action="store_true", help="Print structured check results; implies check-only")
    parser.add_argument("--installed-version", help="Explicit installed vMAJOR.MINOR.PATCH comparison value; otherwise read protected installed metadata")
    args = parser.parse_args(argv)

    from angerona.core.data_paths import data_dir, project_root
    from angerona.updater.release_update import (
        approve_release, check_release_updates, download_release, installed_release_version, install_download,
    )
    from angerona import __version__
    from angerona.updater.github_updater import version_tuple

    version_origin = "protected installed metadata"
    version_known = True
    if args.installed_version is not None:
        try:
            version_tuple(args.installed_version)
        except ValueError:
            parser.error("--installed-version must be vMAJOR.MINOR.PATCH")
        version = args.installed_version.removeprefix("v")
        version_origin = "explicit operator comparison value; protected installer independently verifies rollback policy"
    else:
        try:
            version = installed_release_version()
        except Exception:
            version, version_known = __version__, False
            version_origin = "helper source version only; installed version is unknown"

    state = data_dir() / "github-updates"
    check = check_release_updates(state, project_root(), force=args.check_now, version=version)
    payload = {"report": asdict(check.report), "cached": check.cached, "hold": check.hold,
               "candidate": asdict(check.candidate) if check.candidate else None,
               "candidate_identity": check.candidate.identity if check.candidate else None,
               "installation": "requires exact approval and protected signed-release verification",
               "comparison_version": version, "comparison_version_origin": version_origin}
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(check.report.summary())
        print(f"Comparison version: v{version} ({version_origin}).")
        if check.cached:
            print("Using the previous shared daily check; no metadata request was repeated.")
        if check.hold:
            print("Held: " + check.hold)
    if check.report.status in {"failed", "clock_rollback", "busy"}:
        return 1
    if args.check_only or args.json or not sys.stdin.isatty() or not check.candidate:
        return 0
    candidate = check.candidate
    requested = "download" if args.download else "install"
    if requested == "install" and not version_known:
        print("Installation held: installed version is unknown. Use the signed MSIX for first install, or supply --installed-version for an existing protected installation.")
        return 1
    print(f"\nRelease {candidate.tag}; {candidate.archive.name}; {candidate.archive.size} bytes")
    print(f"Release ID {candidate.release_id}; asset IDs {candidate.archive.id}/{candidate.checksum.id}")
    print(f"Reviewed identity: {candidate.identity}")
    print("GitHub/checksums are transport checks. Installation still requires the independently trusted protected installer.")
    try:
        answer = input(f"Approve {requested} of this exact release? [y/N] ").strip().casefold()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    approval = approve_release(candidate, action=requested, accepted=answer in {"y", "yes"})
    if approval is None:
        print("Declined; no release payload downloaded or installation changed.")
        return 0
    try:
        download = download_release(candidate, approval, state / "releases", version=version)
        print(f"Downloaded original ZIP and checksum: {download.directory}")
        if requested == "install":
            result = install_download(download, approval)
            print(result["message"])
        else:
            print("Download complete; install trust remains unverified. The protected installer is required.")
        return 0
    except Exception as exc:
        print(f"Update held: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    import multiprocessing

    multiprocessing.freeze_support()
    raise SystemExit(main())
