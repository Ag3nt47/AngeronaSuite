"""Check once per day, or prepare an isolated source update without installing it.

Schedule this installed helper externally if checks are needed while the suite
is closed. No task, listener, service, or automatic installation is registered.
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-now", action="store_true", help="Bypass the daily interval, retaining a 60-second retry floor")
    parser.add_argument("--json", action="store_true", help="Print a structured report")
    parser.add_argument("--source-root", type=Path, help="Canonical source checkout to inspect; packaged installs may omit it")
    parser.add_argument("--stage", metavar="FULL_SHA", help="Download and preserve a source candidate; never changes the installation")
    parser.add_argument("--base", metavar="FULL_SHA", help="Known canonical ancestor; defaults to origin/main only when it is a local ancestor")
    parser.add_argument("--stage-id", help="Previously prepared source-<32 hexadecimal digits> stage")
    parser.add_argument("--manifest-sha256", help="Exact digest printed by preparation; required for later review actions")
    review = parser.add_mutually_exclusive_group()
    review.add_argument("--validate", action="store_true", help="Verify candidate hashes and syntax without executing downloaded code")
    review.add_argument("--resolve", metavar="RELATIVE_PATH", help="Explicitly resolve one conflict inside the isolated candidate")
    parser.add_argument("--choose", choices=("user", "upstream", "base", "delete"), help="Retained conflict side to use")
    args = parser.parse_args(argv)

    reviewing = args.validate or args.resolve is not None
    staging = args.stage is not None
    if staging and reviewing:
        parser.error("--stage cannot be combined with a review action")
    if args.check_now and (staging or reviewing):
        parser.error("--check-now applies only to metadata checks")
    if args.base is not None and not staging:
        parser.error("--base requires --stage")
    if args.choose is not None and args.resolve is None:
        parser.error("--choose requires --resolve")
    if not reviewing and (args.stage_id is not None or args.manifest_sha256 is not None):
        parser.error("--stage-id and --manifest-sha256 require --validate or --resolve")
    if staging and not re.fullmatch(r"[0-9a-f]{40}", args.stage):
        parser.error("--stage requires a full canonical revision")
    if args.base is not None and not re.fullmatch(r"[0-9a-f]{40}", args.base):
        parser.error("--base requires a full canonical revision")
    if reviewing and (not re.fullmatch(r"source-[0-9a-f]{32}", args.stage_id or "")
                      or not re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256 or "")):
        parser.error("review actions require a valid --stage-id and --manifest-sha256")
    if args.resolve is not None and (not args.resolve or not args.choose):
        parser.error("--resolve requires a nonempty relative path and --choose")

    from angerona.core.data_paths import data_dir, project_root
    from angerona.updater.github_updater import check_installed_updates

    source = args.source_root if args.source_root is not None else project_root()
    state = data_dir() / "github-updates"
    if reviewing:
        from angerona.updater.source_stage import resolve_source_conflict, validate_source_candidate

        try:
            stage = state / "stages" / args.stage_id
            if args.resolve is not None:
                result = resolve_source_conflict(stage, args.manifest_sha256, args.resolve, args.choose)
            else:
                result = validate_source_candidate(stage, args.manifest_sha256)
        except Exception as exc:
            print(json.dumps({"status": "failed", "error_type": type(exc).__name__, "message": str(exc)}) if args.json else str(exc))
            return 1
        print(json.dumps(result, sort_keys=True))
        return 1 if result.get("static_checks") == "failed" else 0
    if staging:
        from angerona.updater.source_stage import prepare_source_update

        try:
            result = prepare_source_update(source, state / "stages", args.stage, base_revision=args.base or "")
        except Exception as exc:
            report = {"status": "failed", "error_type": type(exc).__name__,
                      "message": str(exc), "original_installation_changed": False}
            print(json.dumps(report) if args.json else report["message"])
            return 1
        report = asdict(result)
        report["stage_directory"] = str(state / "stages" / result.stage_id)
        print(json.dumps(report, sort_keys=True) if args.json else f"{result.status}: {report['stage_directory']}\n{result.message}")
        return 2 if result.conflicts else 0
    report = check_installed_updates(state, source, force=args.check_now)
    payload = asdict(report)
    payload.update({"available": report.available, "summary": report.summary(),
                    "source_url": report.source_url, "release_url": report.release_url})
    print(json.dumps(payload, sort_keys=True) if args.json else report.summary())
    return 1 if report.status in {"failed", "partial", "clock_rollback"} else 0


if __name__ == "__main__":
    raise SystemExit(main())
