"""Run Extreme Red Team campaigns until every actionable step is closed.

This is a local defensive validation harness. The companion batch file first
runs deterministic response-safety negative controls, then this script starts
the real detector, recorder, Adversary Combat, and Red Team components, runs an
Extreme chained campaign, evaluates the normal AAR, and loops until all four
effectiveness scorecard rates are 100%. Reversible combat changes are undone
after each report is secured. Safety and effectiveness remain separate gates.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import time
from pathlib import Path
from types import SimpleNamespace


_TECHNIQUES = (
    ("T1566.001", "Initial Access"),
    ("T1003", "Credential Access"),
    ("T1548.002", "Privilege Escalation"),
    ("T1070", "Defense Evasion"),
    ("T1547.001", "Registry Run Key"),
    ("T1053.005", "Scheduled Task"),
    ("T1546.003", "WMI Persistence"),
    ("T1021.002", "Lateral Movement"),
    ("T1071", "Command and Control"),
    ("T1074", "Exfil Staging"),
    ("T1486", "Ransomware Impact"),
    ("T1485", "Data Destruction"),
    ("T1059", "Tagged Process Execution"),
)


def _score(report: str) -> dict[str, int | bool]:
    def percent(label: str) -> int:
        match = re.search(
            rf"{re.escape(label)}\s*:\s*\d+/\d+.*?\((\d+)%\)",
            report,
            re.I,
        )
        return int(match.group(1)) if match else -1

    return {
        "detection": percent("Detection coverage"),
        "response": percent("Response success"),
        "contracts": percent("Action contracts"),
        "closure": percent("Verified closure"),
        "resilience": "Resilience check   : PASS" in report,
        "missed": "[MISSED " in report,
        "false_positive": "[FALSE-POS]" in report,
    }


def _complete(score: dict[str, int | bool]) -> bool:
    return (
        all(score[key] == 100 for key in (
            "detection", "response", "contracts", "closure",
        ))
        and score["resilience"] is True
        and score["missed"] is False
        and score["false_positive"] is False
    )


def _wait_ready(modules: list[object], timeout: float = 60.0) -> None:
    deadline = time.monotonic() + timeout
    for module in modules:
        remaining = max(0.1, deadline - time.monotonic())
        waiter = getattr(module, "wait_for_first_cycle", None)
        if callable(waiter) and not waiter(timeout=remaining):
            raise RuntimeError(f"{module.name} did not reach its first detector cycle")
        if getattr(module, "status", "") == "error":
            raise RuntimeError(f"{module.name} failed: {module.last_error}")


def _run_round(root: Path, round_number: int) -> tuple[bool, str, dict]:
    from angerona.core import drill_resolution
    from angerona.core.config import Config
    from angerona.core.eventbus import EventBus
    from angerona.core.storage import FlightRecorder
    from angerona.modules.adversary_combat import AdversaryCombat
    from angerona.modules.file_integrity import FileIntegrityModule
    from angerona.modules.process_monitor import ProcessMonitorModule
    from angerona.modules.purple_guard import PurpleGuard, install_policies
    from angerona.shark.aar_report import generate_aar
    from angerona.shark.red_team import REDTEAM_STAGE_CATEGORY, RedTeamEngine

    root.mkdir(parents=True, exist_ok=True)
    sandbox = root / "drill-sandbox"
    sandbox.mkdir(parents=True, exist_ok=True)
    config = Config(data_dir=root)
    config.adversary_combat_enabled = True
    config.adversary_combat_mode = "maximum"
    config.adversary_combat_min_severity = "LOW"
    config.adversary_combat_block_network = True
    config.adversary_combat_quarantine_files = True
    config.adversary_combat_process_action = "terminate"
    config.adversary_combat_isolate_host = True
    config.adversary_combat_activate_honeypots = False
    config.adversary_combat_isolation_threshold = 3
    config.save()
    manager = SimpleNamespace(config=config, modules={})

    recorder = FlightRecorder(config.db_path)
    bus = EventBus(ring_size=5000, priority_ring_size=5000)
    bus.arm(recorder.authority)
    bus.subscribe(recorder.record_bus)

    findings = [{"mitre": mitre, "name": name} for mitre, name in _TECHNIQUES]
    installed = [mitre for mitre, _name in _TECHNIQUES]
    install_policies(findings, f"validation-seed-{round_number}", root)
    drill_resolution.apply_contracts(
        findings,
        f"validation-seed-{round_number}",
        root,
        installed=installed,
    )

    combat = AdversaryCombat(root)
    fim = FileIntegrityModule()
    process = ProcessMonitorModule()
    purple = PurpleGuard(root)
    modules = [combat, fim, process, purple]
    for module in modules:
        module.bind(bus)
        if hasattr(module, "bind_manager"):
            module.bind_manager(manager)
        manager.modules[module.name] = module

    engine = RedTeamEngine(root, documents_dir=sandbox, on_event=print)
    engine.hold_evidence_for_aar()
    report = ""
    try:
        for module in modules:
            module.start()
        _wait_ready(modules)
        if not engine.start(intensity="Extreme", campaign=True, target_dir=sandbox):
            raise RuntimeError("Extreme Red Team campaign refused to start")
        deadline = time.monotonic() + 15 * 60
        while engine.is_running:
            if time.monotonic() >= deadline:
                raise TimeoutError("Extreme Red Team campaign exceeded 15 minutes")
            time.sleep(0.25)
        # Maximum-mode sensor cadences are <=2s. This also lets the combat queue
        # drain before the recorder-backed AAR snapshot is taken.
        settle_deadline = time.monotonic() + 20.0
        while combat._queue.unfinished_tasks and time.monotonic() < settle_deadline:
            time.sleep(0.1)
        report = generate_aar(
            root,
            settle_seconds=4.0,
            history_name="redteam_history.json",
            stage_category=REDTEAM_STAGE_CATEGORY,
            title="RED TEAM ATTACK",
            report_basename="redteam_aar",
        )
        score = _score(report)
        return _complete(score), report, score
    finally:
        # Freeze every producer and the Combat consumer before rollback. If FIM
        # remains live while quarantined drill files are restored, it can see
        # those restorations as fresh changes and create a second generation of
        # actions after undo_all took its snapshot.
        for module in reversed(modules):
            module.stop()
        undo_result = combat.undo_all()
        still_applied = [
            item for item in combat.list_actions(limit=5000)
            if item.get("reversible") is True and not item.get("undone")
        ]
        try:
            engine.release_evidence_after_aar(engine.evidence_cleanup_scope())
        except Exception:
            engine.stop_and_clean()
        recorder.close()
        # Preserve proof receipts, but never report a passing campaign while a
        # reversible firewall, suspension, quarantine, isolation, or honeypot
        # mutation remains applied.
        if not undo_result.get("ok") or still_applied:
            raise RuntimeError(
                "validation cleanup left reversible Combat state applied: "
                f"undo={undo_result}, active={len(still_applied)}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--data-root",
        type=Path,
        default=Path.cwd() / ".tmp" / "adversary-combat-validation",
    )
    parser.add_argument(
        "--max-rounds",
        type=int,
        default=0,
        help="0 means keep running until a 100%% report is produced",
    )
    args = parser.parse_args(argv)
    session = args.data_root.resolve() / time.strftime("%Y%m%d_%H%M%S")
    os.environ["ANGERONA_DATA"] = str(session)
    os.environ["ANGERONA_ADVERSARY_COMBAT_ENABLED"] = "1"
    os.environ["ANGERONA_ADVERSARY_COMBAT_MODE"] = "maximum"
    os.environ["ANGERONA_ADVERSARY_COMBAT_MIN_SEVERITY"] = "LOW"
    os.environ["ANGERONA_ADVERSARY_COMBAT_ACTIVATE_HONEYPOTS"] = "0"
    os.environ["ANGERONA_FIM_WATCH_ONLY"] = str(session / "drill-sandbox")

    round_number = 0
    while args.max_rounds <= 0 or round_number < args.max_rounds:
        round_number += 1
        # Keep the active Config, recorder, detector watch roots, and AAR in one
        # canonical runtime root. Timestamped AAR history still preserves rounds.
        round_root = session
        print(f"\n=== EXTREME ADVERSARY COMBAT VALIDATION ROUND {round_number} ===")
        try:
            complete, report, score = _run_round(round_root, round_number)
        except Exception as exc:
            print(f"ROUND {round_number} ERROR: {type(exc).__name__}: {exc}")
            complete, report, score = False, "", {}
        print(f"ROUND {round_number} SCORE: {score}")
        if complete:
            report_path = round_root / "redteam_aar.txt"
            print(report)
            print(f"\n100% VALIDATION PASSED. Report: {report_path}")
            return 0
        print("Coverage is not 100%; automatically starting another Extreme round.")
    print("Maximum requested rounds exhausted before 100% validation.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
