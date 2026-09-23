"""Review and explicitly enroll local AI instruction/memory/tool-definition files.

Examples:
  python tools/manage_agent_integrity.py observe C:\\Agents\\AGENTS.md --kind instruction
  python tools/manage_agent_integrity.py enroll C:\\Agents\\AGENTS.md --kind instruction \
      --sha256 <digest-from-observe> --approve
  python tools/manage_agent_integrity.py check

Default scope is every Angerona ARIA/broker tool. Use --tool NAME to scope it to
specific registered tools, or --monitor-only for detection without action gating.
Changing an accepted file requires observe + accept-change with its NEW digest.
No file contents are executed or displayed. This does not police other agents.
Mapped mutations require Windows handle custody; macOS/Linux provide read-only
point-in-time drift monitoring and withhold mapped mutating tool actions.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from angerona.core.agent_integrity import (
    AgentIntegrityError, AgentIntegrityStore, KINDS, observe_agent_file,
)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("observe", "enroll", "accept-change", "list", "check"))
    parser.add_argument("path", nargs="?")
    parser.add_argument("--kind", choices=sorted(KINDS), default="instruction")
    parser.add_argument("--tool", action="append", default=None)
    parser.add_argument("--monitor-only", action="store_true")
    parser.add_argument("--sha256", default="")
    parser.add_argument("--approve", action="store_true", help="Explicitly accept exactly the supplied digest")
    args = parser.parse_args(argv)
    try:
        store = AgentIntegrityStore.current()
        if args.action in {"list", "check"}:
            result = store.enrolled() if args.action == "list" else store.verify()
        else:
            if not args.path or (args.tool and args.monitor_only):
                parser.error("Provide a file path and choose --tool or --monitor-only")
            tools = () if args.monitor_only else tuple(args.tool or ["*"])
            observation = observe_agent_file(str(Path(args.path).absolute()), args.kind, tools)
            if args.action == "observe":
                result = dataclasses.asdict(observation)
            else:
                if not args.approve or args.sha256 != observation.sha256:
                    raise AgentIntegrityError("Observe first, then pass its exact --sha256 and --approve")
                # Authority creation occurs only during explicitly approved enrollment.
                from angerona.core.eventbus import BusAuthority
                BusAuthority.load()
                action = store.enroll if args.action == "enroll" else store.accept_change
                identifier = action(observation, approved=True)
                result = {"status": "accepted", "target_id": identifier, "sha256": observation.sha256}
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 1 if isinstance(result, dict) and result.get("status") == "drift" else 0
    except (AgentIntegrityError, ValueError, OSError) as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
