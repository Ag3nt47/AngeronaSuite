"""Prepare and verify the fixed offline analysis appliance, or analyze local source."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from angerona.core import tool_analysis_jobs as jobs  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, help='Separate analysis runtime directory')
    parser.add_argument('--prepare', action='store_true', help='Acquire only catalog-pinned artifacts')
    parser.add_argument('--check', action='store_true', help='Verify VMware with inert fixtures for both analyzers')
    parser.add_argument('--input', type=Path, help='Local source folder to copy and analyze')
    parser.add_argument('--tool', choices=sorted(jobs.TOOLS), default='bandit')
    args = parser.parse_args()
    root = args.root or jobs.default_root()
    try:
        if args.prepare:
            print(jobs.prepare_runtime(root, jobs.AnalysisOperation(), lambda text: print(text, flush=True)))
        if args.check:
            print(jobs.check_runtime(root, jobs.AnalysisOperation())[1])
        if args.input:
            report = jobs.run_analysis(root, args.input, args.tool, jobs.AnalysisOperation())
            print(json.dumps(report, indent=2, ensure_ascii=True))
        else:
            ready, reason = jobs.readiness(root)
            print(reason)
            if not ready:
                return 1
    except KeyboardInterrupt:
        print('Interrupted. Any supervised VM is stopped by its Windows Job Object.', file=sys.stderr)
        return 130
    except Exception as exc:
        print(str(exc) if isinstance(exc, (ValueError, PermissionError)) else type(exc).__name__, file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
