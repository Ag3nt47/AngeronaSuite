"""Explicit file recovery drills using the existing encrypted backup provider."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Create and hash-verify an encrypted backup restored into a new private directory. "
        "This local drill does not prove offline/offsite recovery. Keys stay in this user's "
        "OS credential store; losing that account or store can prevent recovery. Plaintext "
        "test copies remain in the private output directory for later verification."))
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--fixture", action="store_true", help="Use three small inert test files")
    mode.add_argument("--source", type=Path, help="Read selected files under this directory")
    mode.add_argument("--verify", type=Path, help="Reread an existing drill's archive and restored files")
    parser.add_argument("--file", action="append", default=[], help="Explicit relative file selection; repeat up to 64 times")
    parser.add_argument("--output-parent", type=Path, help="Existing directory for a new private drill; default: Angerona data")
    args = parser.parse_args()
    if (args.source is not None) != bool(args.file):
        parser.error("--source requires explicit --file selections; --file is only valid with --source")
    from angerona.core.recovery_drill import fixture_drill, protected_keys, run_drill, verify_drill
    try:
        encryption, audit = protected_keys(create=args.verify is None)
        if args.verify is not None:
            result = verify_drill(args.verify, encryption_key=encryption, audit_key=audit)
        else:
            from angerona.core.data_paths import data_dir
            parent = args.output_parent or data_dir()
            if args.fixture:
                result = fixture_drill(parent, encryption_key=encryption, audit_key=audit)
            else:
                result = run_drill(args.source, args.file, parent,
                                   encryption_key=encryption, audit_key=audit)
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0
    except Exception as exc:
        print("Recovery drill failed: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
