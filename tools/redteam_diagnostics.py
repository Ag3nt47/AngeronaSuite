"""Read current authenticated Red Team/Shark findings without starting sensors."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))


def main(argv=None, *, reader=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, help="Active verification profile's existing report directory")
    parser.add_argument("--kind", choices=("red_team", "shark"), default="red_team")
    parser.add_argument("--expect-run")
    parser.add_argument("--expect-report-sha256")
    parser.add_argument("--expect-head-sha256")
    parser.add_argument("--expect-sequence", type=int)
    parser.add_argument("--summary", action="store_true", help="Bounded digest/count/reason summary for a read-only harness")
    args = parser.parse_args(argv)
    from angerona.core.simulation_diagnostics import load_report_diagnostics, live_debug_summary
    try:
        if args.data_dir is None:
            from angerona.core.data_paths import resolve_data_dir
            args.data_dir = resolve_data_dir()
        result = (reader or load_report_diagnostics)(args.data_dir, report_kind=args.kind,
            expected_run_id=args.expect_run, expected_report_sha256=args.expect_report_sha256,
            expected_head_sha256=args.expect_head_sha256, expected_sequence=args.expect_sequence)
        output = live_debug_summary(result) if args.summary else json.dumps(result, ensure_ascii=True, allow_nan=False, indent=2)
    except (ValueError, OSError, TypeError, KeyError, RuntimeError, RecursionError):
        print(json.dumps({"state": "unavailable", "response_authorized": False,
            "reason": "The current report could not be authenticated within the diagnostic bounds; review its preserved originals and expected binding."}))
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
