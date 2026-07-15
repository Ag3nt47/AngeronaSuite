"""run_aria_selftests.py — run every ARIA module's self_test() at once.

From the repo root:

    python run_aria_selftests.py

Imports the ARIA modules from the installed ``angerona`` package (or the
``src/`` layout) and runs each self_test. Exits 0 only if all pass. No external
dependencies; PySide6 is optional (the HUD's pure core is tested regardless).
"""
from __future__ import annotations

import os
import sys

# Windows terminals may still expose a legacy CP1252 stream.  ARIA self-test
# details contain Unicode status arrows, so make the standalone runner as
# robust as the main self-check harness.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

# Allow running straight from a source checkout without installing.
_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)


def main() -> int:
    from angerona.core.perf_governor import PerfGovernor
    from angerona.core.posture_history import PostureHistory
    from angerona.core.runbook_rag import RunbookRAG
    from angerona.core.assistant import Assistant
    from angerona.core.aria_routines import Routines
    from angerona.core.aria_dispatch import Dispatch
    from angerona.gui import aria_hud
    from angerona.connectors.voice import Voice
    from angerona.connectors.channel_push import ChannelPush
    from angerona.connectors.inbox_triage import InboxTriage
    from angerona.connectors.research import Research
    from angerona.connectors import research_fetchers
    from angerona.connectors.inbox_watcher import InboxWatcher

    checks = [
        ("perf_governor  (ARIA Overdrive)", PerfGovernor().self_test),
        ("assistant      (agentic engine)", Assistant().self_test),
        ("runbook_rag", RunbookRAG().self_test),
        ("posture_history", PostureHistory().self_test),
        ("aria_routines  (scheduled)", Routines().self_test),
        ("aria_dispatch  (6-agent loop)", Dispatch(lambda a, t: f"{a}:ok").self_test),
        ("aria_hud       (orb/status core)", aria_hud.self_test),
        ("voice          (opt-in I/O)", Voice().self_test),
        ("channel_push   (auto-brief)", ChannelPush().self_test),
        ("inbox_triage   (phishing)", InboxTriage().self_test),
        ("research       (on-command)", Research().self_test),
        ("research_fetchers (Chrome bridge)", research_fetchers.self_test),
        ("inbox_watcher  (email scanning)", InboxWatcher().self_test),
    ]

    all_ok = True
    for label, fn in checks:
        ok, detail = fn()
        all_ok &= ok
        print(f"[{'PASS' if ok else 'FAIL'}] {label}\n       {detail}\n")
    print("=" * 60)
    print("ALL PASS" if all_ok else "SOME FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
