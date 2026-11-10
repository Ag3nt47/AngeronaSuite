"""Capture real Qt widgets with inert fixtures, then encode a bounded public GIF.

Capture uses the repository Qt runtime. Encode uses the managed Python/Pillow
runtime, without importing Angerona or Qt. Every frame retains a visible DEMO
banner. No scan, response button, model, external service or cloud API is used.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


ROOT = Path(__file__).resolve().parents[1]
SCRATCH = ROOT / ".tmp" / "public-demo-scan-progress-20261029"
MAX_GIF = 12 * 1024 * 1024
CHAPTERS = 14
FRAMES_PER_CHAPTER = 10
FRAME_DURATION_MS = 500
FRAME_COUNT = CHAPTERS * FRAMES_PER_CHAPTER
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_CAPTURE_BYTES = 96 * 1024 * 1024
SCREENSHOTS = (
    "github-tools-demo", "zero-breach-demo", "spyware-scan-demo",
    "breach-lockdown-demo", "after-action-demo",
    "github-tools-settings-demo", "github-tools-credits-demo", "auto-adapt-demo",
    "red-team-progress-demo", "red-team-passing-demo", "red-team-diagnostics-demo",
    "component-heartbeats-demo", "heartbeat-details-demo",
)
CAPTURE_SOURCES = (
    "tools/create_public_demo.py", "tools/capture_public_dashboard.py",
    "tools/capture_spywareguard.py", "src/angerona/__init__.py",
    "src/angerona/gui/main_window.py", "src/angerona/gui/curated_tools.py",
    "src/angerona/gui/spyware_guard_page.py", "src/angerona/gui/breach_display.py",
    "src/angerona/gui/header_controls.py", "src/angerona/gui/pages.py",
    "src/angerona/gui/display_recovery.py", "src/angerona/gui/holographic_orb.py",
    "src/angerona/gui/attack_heatmap.py",
    "src/angerona/gui/theme.py", "src/angerona/gui/dashboard_sections.py",
    "src/angerona/gui/dashboard_footer.py", "src/angerona/gui/window_fit.py",
    "src/angerona/core/curated_tools.py", "src/angerona/core/curated_tool_worker.py",
    "src/angerona/core/curated_tool_progress.py", "src/angerona/modules/spyware_guard.py",
    "src/angerona/gui/adaptation_workbench.py", "src/angerona/core/host_adaptation.py",
    "src/angerona/gui/window_controls.py", "src/angerona/gui/recovery_panel.py",
    "src/angerona/gui/prevention_panel.py", "src/angerona/core/windows_prevention.py",
    "src/angerona/gui/red_team_console.py", "src/angerona/gui/simulation_diagnostics.py",
    "src/angerona/gui/progress_ring.py", "src/angerona/gui/animations.py",
    "src/angerona/gui/action_progress.py", "src/angerona/gui/action_worker.py",
    "src/angerona/gui/async_snapshot.py", "src/angerona/gui/presentation_timer.py",
    "src/angerona/gui/component_heartbeat.py", "src/angerona/gui/github_tools.py",
    "src/angerona/gui/context_info.py", "src/angerona/shark/simulation_session.py",
    "src/angerona/shark/run_manifest.py",
    "src/angerona/gui/notification_inbox.py", "src/angerona/core/spyware_news.py",
    "src/angerona/core/spyware_scan_schedule.py", "src/angerona/core/spyware_artifact_scan.py",
    "src/angerona/core/spyware_native_windows.py", "src/angerona/core/threat.py",
)


def source_fingerprints() -> dict[str, str]:
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in CAPTURE_SOURCES}


def plain(path: Path, *, scratch: bool = False) -> Path:
    if not path.is_absolute():
        raise ValueError("demo paths must be absolute")
    path = Path(os.path.abspath(path))
    if scratch and (not path.is_relative_to(SCRATCH) or path == SCRATCH):
        raise ValueError("demo scratch must remain inside its explicit task directory")
    for item in (*reversed(path.parents), path):
        if item.exists():
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("demo refuses redirected paths")
            if item == path and not stat.S_ISDIR(info.st_mode) and info.st_nlink != 1:
                raise ValueError("demo refuses multiply linked files")
    return path


def identity() -> dict:
    class FileTime(ctypes.Structure):
        _fields_ = [("value", ctypes.c_ulonglong)]
    created, exited, kernel, user = FileTime(), FileTime(), FileTime(), FileTime()
    if not ctypes.windll.kernel32.GetProcessTimes(ctypes.c_void_p(-1), ctypes.byref(created),
            ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
        raise ctypes.WinError()
    return {"pid": os.getpid(), "creation_filetime": str(created.value)}


def publish_media(staged: Path, destination: Path, *, replace: bool) -> None:
    """Replace only the explicit reviewed demo asset, preserving raced edits."""
    staged, destination = plain(staged), plain(destination)
    prior = None
    if destination.exists():
        if not replace:
            raise ValueError("updating an existing public demo requires --replace-existing-demo")
        if destination.stat().st_size > MAX_GIF:
            raise ValueError("existing demo asset exceeds its bounded replacement read")
        prior = hashlib.sha256(destination.read_bytes()).digest()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if prior is None or hashlib.sha256(destination.read_bytes()).digest() != prior:
            raise ValueError("public demo asset changed during publication")
    elif prior is not None:
        raise ValueError("public demo asset disappeared during publication")
    os.replace(staged, destination)


def _settings_fixture(config, forbidden):
    """Install inert readers before constructing the real Settings dialog."""
    from angerona.connectors import hand_controls, voice
    from angerona.core import autostart, process_allowlist, provider_credentials, secure_store, usb_policy
    from angerona.gui.pages import SettingsDialog
    from types import SimpleNamespace

    autostart.is_enabled = lambda: False
    autostart.enable_autostart = autostart.disable_autostart = forbidden
    secure_store.read_secret_values = lambda *_args, **_kwargs: {}
    secure_store.read_secret_map = lambda *_args, **_kwargs: {}
    provider_credentials.provider_form_values = lambda: {
        provider.provider_id: "" for provider in provider_credentials.PROVIDER_CREDENTIALS}
    usb_policy.usb_pin_configured = lambda: False
    process_allowlist.entries = lambda *_args, **_kwargs: []
    voice.Voice.list_input_devices = staticmethod(lambda: [])
    voice.offline_model_status = lambda: (False, "DEMO - speech service and microphone not opened")
    hand_controls.HandControls = lambda *_args, **_kwargs: SimpleNamespace(
        status=lambda: "DEMO - camera and hand controls not opened")
    config.save = forbidden
    settings = SettingsDialog(config, forbidden, forbidden, initial_tab="General")
    if any(field.text() for field in settings._key_fields.values()):
        raise RuntimeError("the Settings fixture unexpectedly contains a provider credential")
    if settings._aria_imap_pass.text() or settings._teams_pw.text():
        raise RuntimeError("the Settings fixture unexpectedly contains a connector credential")
    return settings


def _attack_fixture(parent, forbidden):
    """Real MITRE widget, fixed technique samples, explicitly unavailable proof."""
    from types import SimpleNamespace
    from angerona.core import attack_coverage
    from angerona.gui import attack_heatmap

    matrix = {}
    for index, tid in enumerate(("T1059", "T1071", "T1547", "T1055", "T1003", "T1021")):
        meta = attack_heatmap._TID_TO_META.get(tid)
        if meta is None:
            continue
        matrix[tid] = {"label": meta[0], "fullname": meta[2], "tactic": meta[1],
                       "heat": .85 - index * .1, "count": 12 - index,
                       "last_seen": "DEMO fixed replay", "event_ids": [f"DEMO-{index:03d}"]}
    snapshot = {"generated": "DEMO - fixed synthetic replay", "matrix": matrix,
                "summary": {"techniques_active": len(matrix),
                            "tactics_active": len({row["tactic"] for row in matrix.values()}),
                            "highest_heat_tid": "T1059", "highest_heat_label": "Synthetic execution sample"}}
    attack_heatmap.get_tracker = lambda: SimpleNamespace(snapshot=lambda: snapshot, reset=forbidden)
    attack_coverage.readiness_snapshot = lambda *_args, **_kwargs: {
        "available": False, "reason": "DEMO - live detection/response readiness is not measured",
        "techniques": [{"tid": item.tid, "collecting": False, "stage": "declared",
                        "gaps": ["DEMO - no live readiness proof was produced"]}
                       for item in attack_coverage.COVERAGE]}
    dialog = attack_heatmap.AttackHeatmapWindow(parent)
    dialog._timer.stop()
    dialog._on_cell_clicked("T1059")
    return dialog


def _curated_fixture(manager, forbidden):
    """Copy-only publications for the production widgets; no service exists."""
    import copy
    from PySide6.QtCore import QObject, Signal
    from angerona.core.curated_tools import credits
    from angerona.gui import curated_tools

    class MemoryController(QObject):
        status_changed = Signal(dict)
        credits_ready = Signal(object)
        settings_saved = Signal()

        def __init__(self):
            super().__init__()
            self.manager = manager
            self._closed = False
            self.state = dict(
                state="references", installed=True, verified=True, version="0.1.10", busy=False,
                execution_available=True, message="DEMO - fixed synthetic evidence; no scanner was executed.",
                coverage={"checked": ["Synthetic process, browser and desktop evidence"],
                          "not_checked": ["Encrypted phone evidence", "Live device acquisition"],
                          "note": "DEMO - coverage labels illustrate report structure, not host coverage."},
                findings=[{"state": "reference", "title": "Synthetic historical indicator reference",
                           "note": "DEMO - a reference is not a confirmed active infection."}],
                admin_state={"verified": True, "elevated": False,
                             "integrity": "DEMO synthetic ordinary-user observation"},
                resource_usage={"cpu_percent": 0.0, "rss_mib": 32.0,
                                "read_bytes": 0, "write_bytes": 0, "process_alive": False},
                provenance={"synthetic": True, "host_actions": False, "live_scan": False},
            )

        def snapshot(self):
            return copy.deepcopy(self.state)

        def update(self, **values):
            self.state.update(values)
            self.status_changed.emit(self.snapshot())

        def load_credits(self):
            self.credits_ready.emit(list(credits()))
            return True

        def shutdown(self):
            self._closed = True

        def wait_for_shutdown(self, _timeout=0):
            return True

        prepare = scan = priority_scan = cancel = self_test = open_tool = revert = forbidden
        save_options = clear_reports = refresh = auto_prepare = forbidden
        show_storage_review = show_after_action = forbidden
        review_reports = export_report = allow_next_report = forbidden
        open_retained_scan_report = forbidden

    controller = MemoryController()
    manager._curated_tools_controller = controller
    curated_tools.get_curated_tools_controller = lambda _manager: controller
    return controller


def _scan_progress_fixture(step):
    """Fixed copied observations; no scanner, clock estimate or host file exists."""
    if type(step) is not int or not 0 <= step < FRAMES_PER_CHAPTER:
        raise ValueError("the synthetic progress slot is outside its explicit plan")
    elapsed = (0, 1, 5, 10, 15, 25, 300, 301, 302, 302)[step]
    stopping, ended = step in (6, 7), step >= 8

    def row(key, label, *, state="pending", completed=0, total=None, unit="items", **values):
        result = dict(id=key, label=label, state=state, completed=completed, total=total, unit=unit,
                      percent=completed * 100 / total if total else None,
                      checked=completed, skipped=0, elapsed_s=0.0, remaining_s=None)
        result.update(values)
        return result

    native_steps = [row(key, label) for key, label in (
        ("persistence", "Persistence sources"), ("processes", "Process inventory"),
        ("hashes", "Bounded file hashes"), ("memory", "Bounded process memory"),
        ("connections", "Connections"))]
    toolkit_steps = [row(key, label, state="queued", unit="checks") for key, label in (
        ("browser", "Browser and application traces"), ("hash", "File fingerprints"),
        ("host", "Host configuration and DNS"), ("traces", "Windows activity traces"),
        ("windows-execution", "Windows execution records"), ("report", "Writing scanner reports"))]
    native = dict(schema=1, request_id="ab" * 16, operation_id="ab" * 16, sequence=step + 1,
                  state="queued" if step == 0 else "cancelling" if stopping else "cancelled" if ended else "running",
                  current_step="", current_task="DEMO - waiting for native checks", current_file="",
                  elapsed_s=elapsed, remaining_s=None, steps=native_steps,
                  item_completed=None, item_total=None, item_unit="", item_remaining_s=None)
    toolkit = dict(schema=1, operation_id="ab" * 16, sequence=step + 1,
                   state="queued" if step == 0 else "timed-out" if step >= 6 else "running",
                   current_step="", current_task="DEMO - waiting for the pinned toolkit", current_file="",
                   elapsed_s=elapsed, remaining_s=None, steps=toolkit_steps,
                   item_completed=None, item_total=None, item_unit="", item_remaining_s=None)
    if step == 1:
        native_steps[0] = row("persistence", "Persistence sources", state="running", completed=1,
                              total=3, unit="collectors", elapsed_s=1.0)
        native.update(current_step="persistence", current_task="DEMO - checking supported persistence collectors")
    if step >= 2:
        native_steps[0] = row("persistence", "Persistence sources", state="completed", completed=3, total=3, unit="collectors", elapsed_s=2.0)
        native_steps[1] = row("processes", "Process inventory", state="completed", completed=24, total=24, unit="process records", elapsed_s=3.0)
        byte_count = (256, 512, 768)[min(step - 2, 2)]
        native_steps[2] = row("hashes", "Bounded file hashes",
                              state="cancelling" if stopping else "cancelled" if ended else "running",
                              completed=1, total=4, unit="candidate records", elapsed_s=max(1, elapsed - 5),
                              percent=(1 + byte_count / 1024) * 100 / 4,
                              percent_basis="completed candidate slots plus current file byte fraction",
                              item_completed=byte_count, item_total=1024, item_unit="bytes",
                              item_remaining_s=None if step >= 6 else 2.0,
                              remaining_s=None if step >= 6 else 15.0)
        native.update(current_step="hashes", current_task="DEMO - hashing a bounded candidate file",
                      current_file="D:/DEMO/evidence/sample-application.exe", item_completed=byte_count,
                      item_total=1024, item_unit="bytes", item_remaining_s=None if step >= 6 else 2.0)
    if 1 <= step < 5:
        # Existing fetched SQLite rows describe only this query. They do not
        # provide a measured denominator for the entire browser reader.
        query_rows = (0, 0, 100, 200, 300)[step]
        toolkit_steps[0] = row("browser", "Browser and application traces", state="running", unit="checks",
                               checked=query_rows, elapsed_s=elapsed)
        toolkit.update(current_step="browser", current_task="DEMO - comparing fetched browser database rows",
                       current_file="D:/DEMO/evidence/browser-history.sqlite",
                       item_completed=query_rows, item_total=400, item_unit="database rows processed",
                       item_remaining_s=2.0 if query_rows else None)
    if step >= 5:
        toolkit_steps[0] = row("browser", "Browser and application traces", state="incomplete",
                               completed=1, total=1, unit="reader", checked=400, skipped=2, elapsed_s=15.0)
        toolkit_steps[1] = row("hash", "File fingerprints", state="running", completed=1, total=4,
                               unit="candidate files", elapsed_s=10.0,
                               remaining_s=None if step >= 6 else 18.0)
        toolkit.update(current_step="hash", current_task="DEMO - reading the current file for fingerprints",
                       current_file="D:/DEMO/evidence/second-application.exe",
                       item_completed=512, item_total=1024, item_unit="bytes read",
                       item_remaining_s=None if step >= 6 else 4.0)
    for reader in (native, toolkit):
        settled = {"completed", "incomplete", "skipped", "failed"}
        reader["completed_steps"] = sum(item["state"] in settled for item in reader["steps"])
        reader["total_steps"] = len(reader["steps"])
        fraction = sum(1.0 if item["state"] in settled else (item["percent"] or 0) / 100
                       if item["state"] in {"running", "cancelling", "cancelled"} else 0
                       for item in reader["steps"])
        reader["overall_percent"] = round(100 * fraction / reader["total_steps"], 1)
        reader["item_percent"] = (reader["item_completed"] * 100 / reader["item_total"]
                                  if reader["item_total"] else None)
    done = () if step == 0 else ("preflight",)
    progress = dict(request_id="ab" * 16, unit="workflow_stages",
                    stage="preflight" if step == 0 else "cancelling" if stopping else "finished" if ended else "toolkit",
                    finished=len(done), total=4, planned_stages=("preflight", "native", "toolkit", "aggregation"),
                    finished_stages=done, state="finished" if ended else "running")
    fraction = (len(done) + native["overall_percent"] / 100 + toolkit["overall_percent"] / 100) / 4
    native_completion = None
    partial_result = None
    if ended:
        native_completion = dict(request_id=progress["request_id"], lifecycle_generation=1,
                                 request_finished=True, collector_finished=True,
                                 finding_counts=dict(advisory=2, omitted=0), coverage_incomplete=True)
        partial_result = dict(match_counts=dict(total=2, tool_findings=1, references=1,
                                               withdrawn=0, displayed=2, omitted=0),
                              coverage_incomplete=True)
    return dict(state="timed-out" if ended else "stopping" if stopping else "running",
                busy=not ended, lifecycle="terminal" if ended else "draining" if stopping else "running",
                message=("DEMO - the synthetic time budget expired; partial evidence is retained. Native work is still stopping."
                         if stopping else "DEMO - time budget reached; owned work has ended and partial results are retained. No clean-host verdict."
                         if ended else "DEMO - fixed synthetic reader and current-item observations; no scanner or host file exists."),
                elapsed_seconds=elapsed, timeout_seconds=300, scan_progress=progress,
                scanner_progress={"native": native, "toolkit": toolkit},
                native_scan_completion=native_completion, partial_result=partial_result,
                review_available=ended,
                review_gap="DEMO · partial report ready for review. No host scan ran." if ended else "",
                resource_usage=dict(cpu_percent=round(18.0 + (step % 4) * 7.5, 1) if step < 6 else 0.0,
                                    rss_mib=42.0 + step if step < 6 else 0.0,
                                    read_bytes=(step + 1) * 1048576, write_bytes=(step + 1) * 4096,
                                    process_alive=step < 6,
                                    native={"state": native["state"], "request_id": "ab" * 16}),
                demo_expected_overall=int(int(fraction * 1_000_000) * 100 // 1_000_000))


def _breach_fixture(manager, forbidden):
    """Typed synthetic presentation only; action dispatch remains forbidden."""
    from types import SimpleNamespace
    from angerona.core.breach_state import BreachActionAvailability, BreachDisplaySnapshot
    snapshot = BreachDisplaySnapshot(
        active=True, state="breached", case_id="de" * 16, sequence=1,
        summary="DEMO - synthetic confirmed case and lockdown receipt; no host or network action",
        containment_state="locked-down",
        details=(
            ("SIMULATION", "No live breach, scanner, native evidence or response exists in this replay."),
            ("Detection", "Synthetic first-party evidence case; external toolkit references alone do not confirm compromise."),
            ("Network scope", "DEMO - modeled Ethernet, Wi-Fi and other outbound connections held by case-owned rules."),
            ("Receipt", "DEMO - synthetic rule receipt only; no firewall rule was created or changed."),
            ("Operator control", "Lift Lockdown restores only the case-owned controls in an authorized installed runtime."),
            ("After lifting", "The breach remains visible until separately reviewed and resolved."),
            ("Coverage", "Source Observe does not gain response authority from this synthetic projection."),
        ),
        actions=(
            BreachActionAvailability("investigate", True, "Read the synthetic case evidence", False),
            BreachActionAvailability("trace", True, "Inspect synthetic provenance; no remote contact", False),
            BreachActionAvailability("isolate", False, "DEMO - modeled case already locked down"),
            BreachActionAvailability("patch", False, "Advisory only; a reviewed patch is not supplied by a finding"),
            BreachActionAvailability("kill", False, "DEMO - there is no validated live process target"),
            BreachActionAvailability("lift_lockdown", True, "DEMO - modeled case-owned receipt; button is not activated"),
            BreachActionAvailability("review_resolved", True, "DEMO - separate operator review; button is not activated"),
        ),
    )
    manager._breach_state_controller = SimpleNamespace(snapshot=lambda: snapshot, request_action=forbidden)
    return snapshot


def _adaptation_demo_payload():
    """Fresh fixed publications only; no host, clock, secret or storage source."""
    effects = []
    for name in ("Domain", "Private", "Public"):
        before = {"name": name, "enabled": name != "Public", "inbound": "Block", "outbound": "Allow"}
        after = {"name": name, "enabled": True, "inbound": "Block", "outbound": "Block"}
        effects.append({"profile": name, "before": before, "after": after, "changed": True,
            "reason": "DEMO - illustrative emergency-containment preset; no host policy was inspected or changed.",
            "reversibility": "DEMO reference only - real rollback requires an authenticated complete firewall snapshot.",
            "verification": "DEMO projection only - no native postcondition or protection result exists."})
    return {"synthetic": True, "host_actions": False, "authority": "held", "effects": effects,
        "state": {"automation_enabled": False, "auto_apply": False, "triggers": [],
                  "exceptions": [], "feedback_weights": {}},
        "report": {"baseline_exists": False, "risk_score_complete": False,
            "findings": [], "active_findings": 0, "excluded_findings": 0,
            "incomplete_collectors": ["DEMO - no host audit"],
            "current": {"collector_status": {}, "firewall": {"supported": False,
                "complete": False, "reason": "DEMO - no host audit", "profiles": []}}},
        "snapshots": [{"snapshot_id": "DEMO-NOT-A-REAL-RESTORE-POINT",
            "captured_at": "DEMO fixed reference", "status": "not restorable",
            "plan": {"profile_id": "lockdown"}}],
        "transactions": [{"transaction_id": "DEMO-NO-AUTHENTICATED-TRANSACTION",
            "updated_at": "DEMO fixed reference", "kind": "DEMO review",
            "status": "DEMO - no host mutation", "profile_id": "lockdown",
            "snapshot_id": "DEMO-NOT-A-REAL-RESTORE-POINT", "projected_effects": effects}],
        "activity": [{"ts": "DEMO fixed reference", "action": "DEMO preview",
            "result": "host untouched", "detail": "Synthetic before/after and history examples; no audit, apply or rollback ran."}]}


def _adaptation_fixture(forbidden):
    """Actual workbench, strictly inert service, no host manager or workers."""
    import copy
    from PySide6.QtCore import Qt
    from PySide6.QtGui import QAction
    from PySide6.QtWidgets import QCheckBox, QLabel, QPushButton, QWidget
    from angerona.core.host_adaptation import AdaptationPlan, PROFILES
    from angerona.gui import prevention_panel, recovery_panel
    from angerona.gui.adaptation_workbench import AdaptationWorkbench

    payload = _adaptation_demo_payload()
    real_recovery_panel, real_prevention_panel = recovery_panel.RecoveryPanel, prevention_panel.PreventionPanel

    class DemoRecoveryPanel(real_recovery_panel):
        def __init__(self, _manager=None, parent=None):
            super().__init__(None, parent)

        def _module(self):
            return None

        def refresh(self):
            for button in self._buttons:
                button.setEnabled(False)
            self.status.setText("DEMO - no independent recovery provider is connected.")
            self.latest.setText("DEMO - no archive, key, ledger or measured restore was read.")
            self.details.setPlainText("DEMO - synthetic workbench only. Independent recovery is unavailable; no host provider runs.")

        def _queue(self, *_args, **_kwargs):
            return forbidden()

        def showEvent(self, event):  # noqa: N802 - Qt signature
            QWidget.showEvent(self, event)
            self.refresh()

    class DemoPreventionPanel(real_prevention_panel):
        def __init__(self, _manager=None, parent=None):
            super().__init__(None, parent, inspector=forbidden, client=None)
            self.status.setText("DEMO - native policy has not been inspected; no installed client exists.")

        def _start(self, *_args, **_kwargs):
            return forbidden()

        def _open_reference(self, *_args, **_kwargs):
            return forbidden()

        def _buttons(self):
            for button in (self.inspect_button, self.prepare_button, self.apply_button,
                           self.copy_button, self.restore_button):
                button.setEnabled(False)

    class MemoryAdaptationService:
        __slots__ = ()

        def profiles(self):
            return tuple(PROFILES.values())

        def state(self):
            return copy.deepcopy(payload["state"])

        def list_exceptions(self):
            return []

        def list_snapshots(self):
            return copy.deepcopy(payload["snapshots"])

        def activity(self):
            return copy.deepcopy(payload["activity"])

        def load_baseline(self):
            return None

        def security_baseline_status(self):
            return {"available": False, "supported": True,
                    "detail": "DEMO - no recovery artifact exists and no authority is granted."}

        def breaker_status(self):
            return {"locked": True, "reason": "DEMO - host effects are forbidden", "events": []}

        def transactions(self):
            return copy.deepcopy(payload["transactions"])

        def command_stack(self, _plan):
            return ("DEMO ONLY (not executed): Set-NetFirewallProfile -Profile Domain,Private,Public "
                    "-Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block",)

        audit = capture_snapshot = build_plan = prepare_review = sandbox = simulate_plan = forbidden
        apply_plan = rollback = capture_security_baseline = restore_security_baseline = forbidden
        save_baseline = add_exception = remove_exception = export_report = forbidden
        set_automation = add_trigger = remove_trigger = evaluate_context = reset_breaker = forbidden

        def __getattr__(self, name):
            raise AttributeError("DEMO service has no live provider: " + name)

    class DemoAdaptationWorkbench(AdaptationWorkbench):
        def _refresh_status(self):
            # Synchronous copied publications: no status thread is started.
            service = self.service
            values = {name: {"value": operation()} for name, operation in (
                ("baseline", service.load_baseline), ("recovery", service.security_baseline_status),
                ("breaker", service.breaker_status), ("transactions", service.transactions),
                ("state", service.state), ("exceptions", service.list_exceptions),
                ("activity", service.activity))}
            values["snapshots"] = {"value": tuple((
                str(snapshot.get("snapshot_id") or ""),
                f"{snapshot.get('captured_at', '')} · "
                f"{snapshot.get('plan', {}).get('profile_id', 'unknown')} · "
                f"{snapshot.get('status', 'ready')}",
            ) for snapshot in service.list_snapshots())}
            self._on_status_finished(values)

        def _run_task(self, *_args, **_kwargs):
            return forbidden()

    # The workbench imports these two constructors locally. Replace them only
    # for this synchronous construction, restoring before any event pumping.
    # Both subclasses retain the real panel UI and explicitly remove providers.
    try:
        recovery_panel.RecoveryPanel, prevention_panel.PreventionPanel = DemoRecoveryPanel, DemoPreventionPanel
        dialog = DemoAdaptationWorkbench(MemoryAdaptationService())
    finally:
        recovery_panel.RecoveryPanel, prevention_panel.PreventionPanel = real_recovery_panel, real_prevention_panel
    dialog.setWindowTitle("Auto Adapt - DEMO ONLY - authority held")
    dialog.profile_combo.setCurrentIndex(dialog.profile_combo.findData("lockdown"))
    plan = AdaptationPlan(
        plan_id="DEMO-NOT-AN-APPROVED-PLAN", profile_id="lockdown",
        created_at="DEMO fixed reference", expires_at="DEMO - no execution approval",
        host_id="DEMO-NOT-A-HOST", precondition_digest="DEMO-NO-HOST-SAMPLE",
        actions=PROFILES["lockdown"].actions, drastic=True,
        warnings=("DEMO - synthetic projection only; no host policy is read or changed.",),
        digest="DEMO-INVALID-NO-AUTHORITY")
    dialog._display_audit(copy.deepcopy(payload["report"]))
    dialog._display_plan(plan)
    dialog._display_effects(copy.deepcopy(payload["effects"]))
    dialog.change_table.selectRow(0)
    dialog.review_summary.setText("DEMO - projected changes only. Authority held; no native audit, apply, rollback or authenticated transaction exists.")
    dialog.footer_detail.setText("DEMO - read-only navigation. Real changes require an exact approved plan, authenticated recovery and fresh native verification.")
    dialog.baseline_status.setText("Baseline: DEMO only")
    dialog.recovery_status.setText("Recovery: DEMO reference, not restorable")
    dialog.risk_status.setText("Risk: not measured in DEMO")
    authority = QLabel("DEMO - AUTHORITY HELD - NO HOST POLICY WAS READ OR CHANGED")
    authority.setTextFormat(Qt.PlainText)
    authority.setWordWrap(True)
    authority.setStyleSheet("color:#fbbf24;background:#172033;font-weight:700;padding:8px;")
    dialog._workbench_scroll.widget().layout().insertWidget(0, authority)
    for button in dialog.findChildren(QPushButton):
        button.setEnabled(False)
    for checkbox in dialog.findChildren(QCheckBox):
        checkbox.setEnabled(False)
    for action in dialog.findChildren(QAction):
        action.setEnabled(False)
    if (dialog.apply_button.isEnabled() or dialog._task_thread is not None
            or dialog._status_thread is not None or dialog._latest_review is not None
            or dialog.prevention_panel._job is not None or dialog.prevention_panel._client is not None
            or dialog.prevention_panel._inspect is not forbidden
            or dialog.recovery_panel.manager is not None
            or any(timer.isActive() for timer in (dialog._result_timer,
                dialog.recovery_panel._timer, dialog.prevention_panel._poll_timer))):
        raise RuntimeError("the inert Auto Adapt fixture unexpectedly admitted work or authority")
    return dialog



def _red_team_fixture(parent, forbidden):
    """Actual presenters with inert providers and explicitly synthetic DTOs.

    No session, engine, authenticated handoff, history reader, device service,
    source loader or patch provider is connected to these public-demo views.
    """
    from PySide6.QtWidgets import QDialog
    from angerona.gui.red_team_console import RedTeamConsole
    from angerona.gui.simulation_diagnostics import (
        SimulationDiagnosticsPanel, _prepare_snapshot,
    )

    class DemoRedTeamConsole(RedTeamConsole):
        def _load_history(self):
            self._hist_list.clear()
            self._hist_view.setPlainText(
                "DEMO - no saved report, key or signed history was read.")

        def _refresh_device_enrollments(self, _select_id=""):
            self.device_enrollments.clear()
            self.device_lab_log.setPlainText(
                "DEMO - no device enrollment, inspection or service exists.")

        def _refresh_response_readiness(self, *_unused):
            self.response_readiness.setText(
                "DEMO - synthetic presentation only. No host response provider "
                "or readiness inspection is connected.")
            self.response_readiness.setStyleSheet("color:#fbbf24;")

        def _on_tab_changed(self, index):
            if index != 0:
                forbidden()

        def _launch(self):
            forbidden()

        def _stop(self):
            forbidden()

        def _cancel_preparing_launch(self, *_unused):
            return None  # No real launch owner exists in this fixture.

    console = DemoRedTeamConsole(parent, default_target="D:/DEMO/not-created")
    console.loc_edit.setText("DEMO - no marker directory is created or scanned")
    console.cb_shark.setChecked(False)
    console.cb_comprehensive.setChecked(False)
    console.github_tools._loaded = True
    console.github_tools.analysis_lab._loaded = True
    console.github_tools.status.setText("DEMO - no source library or worker loaded.")
    console.github_tools.analysis_lab.status.setText(
        "DEMO - no analysis runtime or process loaded.")
    console._run_splitter.setSizes([230, 430])
    console.log.setPlainText(
        "DEMO - fixed modeled outcomes; no simulation, detector or response ran. "
        "The two illustrated runs are independent synthetic presentations. "
        "A green example is not a host result or an efficacy benchmark.")
    if (console._hist_listing or console._hist_reading
            or console._history_pool.activeThreadCount()
            or console._editor_reader.thread is not None
            or console.github_tools._worker is not None
            or console.github_tools._busy):
        raise RuntimeError("a Red Team demo provider unexpectedly started work")

    class DemoDiagnosticsPanel(SimulationDiagnosticsPanel):
        def _update_buttons(self):
            super()._update_buttons()
            for button in (self.copy_button, self.export_button,
                           self.refresh_button, self.patch_button):
                button.setEnabled(False)
                button.setToolTip(
                    "DEMO - synthetic projection; no authentication, export or "
                    "patch provider is connected.")

        def refresh_diagnostics(self):
            return forbidden()

        def copy_json(self):
            return forbidden()

        def export_json(self):
            return forbidden()

        def review_selected_fix(self):
            return forbidden()

    rows = []
    samples = (
        ("Initial Access", "T1204", "pass", "pass", "pass", "illustrated-match",
         "DEMO - modeled analytic match and containment postcondition.",
         "none", []),
        ("Discovery", "T1046", "fail", "unscored", "fail", "illustrated-miss",
         "DEMO - expected telemetry did not arrive in this modeled case.",
         "sensor-review", ["DEMO - inspect the exact provider's availability.",
                           "DEMO - repair the collector and rerun its regression."]),
        ("Defense Evasion", "T1562", "inconclusive", "unscored", "inconclusive",
         "illustrated-unavailable",
         "DEMO - required kernel telemetry is unavailable; coverage is held.",
         "deployment-review", ["DEMO - review the platform and installed authority.",
                               "DEMO - preserve the gap until a fresh canary returns."]),
    )
    for index, (stage, technique, detected, response, status, reason_code,
                reason, fix_kind, next_steps) in enumerate(samples):
        rows.append(dict(index=index, stage=stage, technique=technique,
            category="synthetic-demo", detection_status=detected,
            response_status=response, status=status, reason_code=reason_code,
            reason=reason, evidence=["DEMO - fixed display example; no host event."],
            next_steps=next_steps,
            source_areas=["DEMO - relevant collector and regression tests"]
                         if next_steps else [],
            fix_kind=fix_kind, fix_status="not-applied" if next_steps else "none"))
    diagnostics = DemoDiagnosticsPanel(parent, config=getattr(parent, "config", None),
                                      auto_load=False)
    diagnostics._snapshot = _prepare_snapshot(dict(
        schema="angerona.simulation-diagnostics.v1",
        run_id="DEMO-NOT-AN-AUTHENTICATED-RUN", report_kind="red_team",
        report_sha256="1" * 64, head_sha256="2" * 64, sequence=0,
        report_state="complete", coverage_score_eligible=True,
        overall_status="failing", omitted_rows=0, omitted_text_characters=0,
        synthetic=True, host_actions=False, rows=rows))
    diagnostics._snapshot_version = diagnostics._source_version
    diagnostics._render_summary()
    diagnostics._apply_filter()
    diagnostics.table.selectRow(0)
    diagnostics.message.setText(
        "DEMO - synthetic report projection, not authenticated evidence. "
        "Filters and next-step explanations are real UI; no patch or export runs.")
    if (not isinstance(console, QDialog) or diagnostics._jobs
            or diagnostics._worker is not None or diagnostics._source is not None):
        raise RuntimeError("the Red Team demo unexpectedly connected a provider")
    return console, diagnostics


def _red_team_progress_fixture(console, step):
    """Feed real count/badge presenters; never execute or authenticate a run."""
    from angerona.gui.red_team_console import SessionLifecycleProjection
    from angerona.shark.simulation_session import RunPerformanceSnapshot

    clean = step >= 4
    run_id = "DEMO-CLEAN-ILLUSTRATION" if clean else "DEMO-GAP-ILLUSTRATION"
    session_id = "DEMO-SESSION-CLEAN" if clean else "DEMO-SESSION-GAP"
    digest = ("b" if clean else "a") * 64
    if step in (0, 4):
        console.set_launch_status(dict(status="accepted", runs={"red_team": run_id}),
                                  {"auto_remediate": True})
        if not console.bind_performance_session(session_id, 1, {run_id: digest}):
            raise RuntimeError("the synthetic current-session presentation was refused")
    finished = (1, 4, 7, 8, 7, 8)[step]
    final = step in (3, 5)
    if not final:
        evaluated, detected, contained, gaps = (
            (0, 0, 0, 0) if step == 0 else
            (4, 4, 4, 0) if step == 1 else
            (7, 6, 5, 2) if step == 2 else
            (7, 7, 7, 0))
        publication = RunPerformanceSnapshot(
            session_id=session_id, session_generation=1, run_id=run_id,
            plan_sha256=digest, state="provisional", eligible_planned=8,
            evaluated_steps=evaluated, detection_verified_steps=detected,
            native_verified_steps=min(detected, 4),
            simulation_verified_steps=max(0, detected - 4),
            containment_verified_steps=contained, provisional_failures=gaps,
            containment_required=True, unsettled_steps=8 - evaluated,
            unavailable_steps=0,
            verification_scope="DEMO - fixed synthetic presentation; no verification ran")
        if not console.record_performance_snapshot(publication):
            raise RuntimeError("the typed synthetic performance publication was refused")
    lifecycle = SessionLifecycleProjection(session_id=session_id, generation=1,
        plans_by_run=((run_id, digest),), phase="DEMO-retired" if final else "DEMO-running",
        source_available=True, owner_finished=final, workers_retired=final,
        custody_released=final)
    if not console.record_session_lifecycle(lifecycle):
        raise RuntimeError("the synthetic lifecycle publication was refused")
    console.update_execution_progress({"red_team": dict(schema=1, run_id=run_id,
        state="completed" if final else "running", finished=finished, total=8,
        failed_units=0, current_task="DEMO - modeled step and evidence review")})
    if final:
        caught = 8 if clean else 6
        console.record_verified_report("red_team", run_id, dict(
            run_id=run_id, outcome="verified" if clean else "partial",
            coverage_score_eligible=True, detection_steps=8, detection_caught=caught,
            epistemic_metrics={"verified_containment": dict(count=caught, eligible=8)},
            evidence_taxonomy={"denominator": 8,
                "compatible_analytic_union": {"count": caught},
                "native_analytic_detection": {"count": min(caught, 4)},
                "native_analytic_opportunity": dict(file_marker_steps=4,
                    process_observation_only_steps=4, unclassified_steps=0,
                    total_expected_positive_steps=8)},
            synthetic=True, host_actions=False))
    # Only the cosmetic arc angle is replayed; it never advances a work count.
    console.overall_progress._angle = step * 45
    console.overall_progress.update()
    console.log.append(
        f"DEMO frame {step + 1}: {console.performance_badge.text()} · "
        "fixed modeled outcomes; no detector or host action.")
    return dict(synthetic=True, host_actions=False, run_id=run_id,
        expected_percent=100 if final else finished * 100 // 9,
        displayed_percent=console.overall_progress.percent,
        badge_state=console.performance_badge.property("performanceState"),
        badge_text=console.performance_badge.text(),
        caught=console.catch_comparison._caught, missed=console.catch_comparison._missed,
        provisional=console.catch_comparison._provisional,
        provider_started=bool(console._hist_listing or console._hist_reading
            or console._history_pool.activeThreadCount()
            or console._editor_reader.thread is not None
            or console.github_tools._worker is not None))


def _help_fixture(window):
    """Retain the actual owner's modeless Help window without changing Qt APIs."""
    from PySide6.QtWidgets import QDialog
    dialog = window._open_help()
    if not isinstance(dialog, QDialog) or dialog.isModal() or dialog.parent() is not window:
        raise RuntimeError("the actual modeless Help dialog was not constructed by its owner")
    return dialog


def capture(runtime_root: Path, frames_root: Path, poster: Path, *, replace: bool = False) -> None:
    runtime_root, frames_root = plain(runtime_root, scratch=True), plain(frames_root, scratch=True)
    if (runtime_root.exists() or runtime_root.is_relative_to(frames_root)
            or frames_root.is_relative_to(runtime_root)):
        raise ValueError("capture requires a fresh, separate, task-owned runtime directory")
    poster = plain(poster)
    captured_sources = source_fingerprints()
    if poster != ROOT / "assets" / "screenshots" / "dashboard-demo.png" or (poster.exists() and not replace):
        raise ValueError("capture requires its explicit poster path and permission to replace an existing demo")
    frames_root.mkdir(parents=True, exist_ok=False)
    import faulthandler
    traceback_stream = (frames_root / "capture-stacks.log").open("x", encoding="utf-8")
    faulthandler.dump_traceback_later(45, file=traceback_stream)
    # Publication frames use physical 1600x1060 pixels. Keep the diagnostic
    # owner's enlarged-font/DPI test settings out of this disposable renderer.
    os.environ.update(ANGERONA_PUBLIC_DEMO_ROOT=str(runtime_root), QT_QPA_PLATFORM="offscreen",
                      QT_SCALE_FACTOR="1", QT_SCREEN_SCALE_FACTORS="", QT_FONT_DPI="96",
                      QT_OPENGL="software", QT_QUICK_BACKEND="software",
                      TEMP=str(frames_root), TMP=str(frames_root), ANGERONA_STORAGE_AUTOMIGRATE="0")
    if str(ROOT / "tools") not in sys.path:
        sys.path.insert(0, str(ROOT / "tools"))
    # Explicitly prohibit accidental network or executable dispatch in this
    # disposable demo process, including any deferred UI callback.
    import socket
    import subprocess
    forbidden_attempts = []

    def forbidden(*_args, **_kwargs):
        forbidden_attempts.append("network/process dispatch refused")
        raise RuntimeError("external effects are forbidden in the public demo")

    socket.create_connection = forbidden
    socket.socket.connect = forbidden
    socket.socket.connect_ex = forbidden
    subprocess.Popen = forbidden
    import capture_public_dashboard as demo
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QDialog, QHeaderView, QLabel, QLineEdit, QPlainTextEdit, QProgressBar, QStackedWidget, QTextEdit, QVBoxLayout, QWidget
    from angerona import __version__
    from angerona.core.config import Config
    from angerona.core.eventbus import Event, Severity
    from angerona.gui.pages import AlertDetailDialog

    (frames_root / "capture-identity.json").write_text(json.dumps(identity()), encoding="ascii")
    app, window, storage = demo._build_demo_window()
    curated = _curated_fixture(window.manager, forbidden)
    wrapper = QWidget()
    wrapper.setWindowTitle("Angerona public demonstration - synthetic fixtures only")
    wrapper.setStyleSheet(window.styleSheet())
    layout = QVBoxLayout(wrapper)
    layout.setContentsMargins(14, 12, 14, 12)
    layout.setSpacing(8)
    banner = QLabel(f"DEMO  |  ANGERONA {__version__}  |  REAL APPLICATION UI  |  SYNTHETIC DATA  |  NO HOST ACTIONS")
    banner.setStyleSheet("color:#fbbf24;background:#172033;font:700 16px 'Segoe UI';padding:10px;")
    layout.addWidget(banner)
    title = QLabel()
    title.setStyleSheet("font:700 23px 'Segoe UI';color:#f8fafc;")
    subtitle = QLabel()
    subtitle.setWordWrap(True)
    subtitle.setStyleSheet("font:14px 'Segoe UI';color:#cbd5e1;")
    layout.addWidget(title)
    layout.addWidget(subtitle)
    progress = QProgressBar()
    progress.setRange(0, FRAME_COUNT)
    progress.setTextVisible(False)
    progress.setFixedHeight(5)
    layout.addWidget(progress)
    stack = QStackedWidget()
    window.setParent(stack)
    window.setWindowFlags(Qt.Widget)
    stack.addWidget(window)
    layout.addWidget(stack, 1)
    wrapper.resize(1600, 1060)
    wrapper.show()
    demo._settle(app)
    # All scores and PASS strings in the existing fixture are illustrative.
    window.posture_lbl.setText("DEMO POSTURE 96 - synthetic illustration")
    window.console.out.setPlainText(
        "PUBLIC DEMO - fixed synthetic records, no host scan or response.\n"
        "Module health and posture below are illustrations, not test results.\n"
        "Evidence must satisfy separate policy and exact-target checks before response.\n"
        "Source Observe and signed installed Windows authority remain distinct.")
    window.system_pulse.shutdown()
    # The compact EKG consumes copied synthetic publications only. Its clock
    # advances by the GIF slot duration, never by a real host heartbeat.
    fixture_clock = [2000.0]
    fixture_missing_blackbox = [False]
    heartbeat_strip = window.component_heartbeat_strip
    heartbeat_strip._clock = lambda: fixture_clock[0]
    def heartbeat_publication():
        return tuple({"role": role, "generation_id": f"DEMO-{role}-001-synthetic",
                      "pid": 41001 + index, "deadline_seconds": 3.0,
                      "last_heartbeat_monotonic": None if role == "blackbox" and fixture_missing_blackbox[0] else fixture_clock[0] - .2,
                      "state": "unavailable" if role == "blackbox" and fixture_missing_blackbox[0] else "running",
                      "reason": "DEMO - synthetic missing heartbeat; no real process inspected" if role == "blackbox" and fixture_missing_blackbox[0]
                                else "DEMO - fixed synthetic heartbeat publication; no real process inspected"}
                     for index, role in enumerate(("core", "watchdog", "scanner", "blackbox")))
    window.set_component_heartbeat_source(heartbeat_publication)
    # The published capture replays one fixed demo day. Freeze the normal
    # wall-clock readers and use the same replay rows shown in Live Alerts.
    window.cards._count_reader.close()
    window.cards._threat_reader.close()
    window.cards._apply_count(storage.revision(), window.alerts_panel.table.rowCount())
    window.cards._apply_threat_snapshot((0, ("Secure", "#2fe38a")))
    # Both dashboard coverage summaries read these same inert module objects.
    for name in ("Telemetry Canary Drills", "YARA Scanner"):
        module = window.manager.modules[name]
        module.health = 65
        module.health_note = "DEMO - modeled coverage gap. No sensor ran."
    window.status_strip.refresh()
    window.modules_panel.refresh()
    window.live_defense_activity.refresh()
    window._update_module_ribbon_summary()
    window._last_posture["factors"]["degraded_modules"] = window._assessment_coverage[1]
    window._notifications.upsert(
        "public-demo-review", "DEMO · Review the sample evidence",
        "This pending notification is a fixed demonstration record.", forbidden)
    if (window._assessment_coverage != (0, 2)
            or not window.live_defense_activity.summary.text().endswith(" · 2 degraded")
            or window.cards.c_alerts.value.text() != str(len(demo.SYNTHETIC_EVENTS))
            or window.cards.c_threat.value.text() != "None detected"):
        raise RuntimeError("the synthetic dashboard summaries disagree with their source records")
    # Scan Center starts with the user's Downloads path even before any scan.
    # Replace that default input before inspecting/capturing any scene, including
    # scenes where the real Scan Center tab is currently hidden.
    window.scan_center.path_edit.setText("DEMO - synthetic findings; no path was scanned")
    frames = []
    frame_sha256 = {}
    staged_screenshots = {}
    chapter_names = []
    interactions = {"dashboard_panels_collapsed": {"console": [], "activity": [], "pulse": []},
                    "alerts": {"row_count": 0, "positions": []},
                    "settings_tabs": [], "attack_tabs": [], "attack_horizontal_positions": [],
                    "heartbeats": [], "heartbeat_details_steps": [],
                    "curated_views": [], "priority_resources": [], "priority_progress": [], "breach_colors": [],
                    "after_action_scroll": [], "auto_adapt": [],
                    "red_team_progress": [], "red_team_diagnostics": [],
                    "current_assessment": [], "research_wire": [], "compact_scan": [],
                    "reader_waypoints": []}
    captured_bytes = 0
    detail = None
    settings = spyware = spyware_host = attack = None
    heartbeat_details = None
    hub = credits_dialog = after_action = adaptation = None
    help_dialog = red_team = red_team_diagnostics = None

    def chapter(number, heading, description, widget, navigate=None, screenshot_at=None):
        nonlocal captured_bytes
        chapter_names.append(heading)
        title.setText(f"{number}/{CHAPTERS}  {heading}")
        subtitle.setText(description)
        stack.setCurrentWidget(widget)
        demo._settle(app, .2)
        for step in range(FRAMES_PER_CHAPTER):
            fixture_clock[0] = 2000.0 + len(frames) * FRAME_DURATION_MS / 1000
            if navigate is not None:
                navigate(step)
                # Disclosure resize and tab/scroll layout are queued by Qt.
                # Capture their settled widgets rather than an in-flight paint.
                demo._settle(app, .35)
            progress.setValue((number - 1) * FRAMES_PER_CHAPTER + step + 1)
            app.processEvents()
            texts = [label.text() for label in wrapper.findChildren(QLabel)]
            texts += [field.text() for field in wrapper.findChildren(QLineEdit)]
            texts += [view.toPlainText() for view in wrapper.findChildren(QPlainTextEdit)]
            texts += [view.toPlainText() for view in wrapper.findChildren(QTextEdit)]
            visible = "\n".join(texts).casefold()
            for private in (str(Path.home()), os.environ.get("USERNAME", ""), os.environ.get("COMPUTERNAME", "")):
                if private and private.casefold() in visible:
                    raise RuntimeError("private host identity appeared in demo labels")
            destination = frames_root / f"frame-{len(frames):03d}.png"
            demo._save_widget(wrapper, destination)
            size = destination.stat().st_size
            captured_bytes += size
            if size > MAX_FRAME_BYTES or captured_bytes > MAX_CAPTURE_BYTES:
                raise RuntimeError("public demo capture reached its explicit frame/disk byte budget")
            frames.append(destination.name)
            frame_sha256[destination.name] = hashlib.sha256(destination.read_bytes()).hexdigest()
            name = (screenshot_at or {}).get(step)
            if name is not None:
                if name not in SCREENSHOTS or name in staged_screenshots:
                    raise RuntimeError("demo screenshot name or multiplicity differs from its explicit plan")
                staged = frames_root / f"{name}.png"
                with destination.open("rb") as source, staged.open("xb") as target:
                    target.write(source.read())
                staged_screenshots[name] = staged
            if len(frames) == 1:
                print(json.dumps({"outcome": "first-dashboard-frame", "path": str(destination),
                                  "app_version": __version__, "capture": identity()}), flush=True)
    try:
        panel_controls = {"console": window._console_collapse, "activity": window._activity_collapse,
                          "pulse": window._pulse_collapse}
        ribbons = window._module_ribbons_disclosure
        if any(control.is_collapsed() for control in panel_controls.values()) or ribbons.is_expanded():
            raise RuntimeError("the demo requires panels open by default with only module health folded")

        def scroll_top(widget, scroll):
            return widget.mapTo(scroll.viewport(), widget.rect().topLeft()).y()

        def in_scroll_view(widget, scroll):
            top = scroll_top(widget, scroll)
            return widget.isVisible() and top >= 0 and top + widget.height() <= scroll.viewport().height()

        def browse_dashboard(step):
            nonlocal heartbeat_details
            if step == 0:
                window._refresh_current_assessment()
            elif step in (2, 4):
                # Exercise the production dwell rule without waiting nine wall-clock
                # seconds or enabling motion for any processed Qt event.
                window._assessment_banner.clearFocus()
                previous_motion = window.config.ui_motion_enabled
                window.config.ui_motion_enabled = True
                try:
                    window._refresh_current_assessment(
                        now=window._assessment_since + window._ASSESSMENT_DWELL_SECONDS + .1)
                finally:
                    window.config.ui_motion_enabled = previous_motion
            if step in (0, 2, 4):
                interactions["current_assessment"].append(
                    (window._assessment_key, window._assessment_banner.accessibleDescription()))
            fixture_missing_blackbox[0] = step >= 4
            heartbeat_strip.refresh_snapshot()
            interactions["heartbeats"].append([
                {"role": row.role, "state": row.state, "fresh": row.fresh}
                for row in heartbeat_strip.snapshot()])
            # Exercise the real Console heading button, never the internal
            # grouping adapter. Other panels retain their open startup state.
            console = panel_controls["console"]
            if console.is_collapsed() != (step in (2, 3)):
                console._minimize_button.click()
            for name, control in panel_controls.items():
                interactions["dashboard_panels_collapsed"][name].append(control.is_collapsed())
            if step == 6:
                heartbeat_strip.click()
                heartbeat_details = heartbeat_strip._details_dialog
                for label in heartbeat_details.findChildren(QLabel):
                    label.setText("DEMO - synthetic heartbeat publications. No real process or sensor is being monitored; liveness does not establish protection.")
                heartbeat_details.setParent(stack)
                heartbeat_details.setWindowFlags(Qt.Widget)
                stack.addWidget(heartbeat_details)
            if 6 <= step <= 8:
                stack.setCurrentWidget(heartbeat_details)
                interactions["heartbeat_details_steps"].append(step)
            else:
                stack.setCurrentWidget(window)

        chapter(1, "One workbench for local security evidence",
                "Current assessment rotates between simulated coverage gaps and a pending notification. Heartbeat details explain a red EKG when a synthetic publication is missing.",
                window, browse_dashboard,
                screenshot_at={1: "component-heartbeats-demo", 7: "heartbeat-details-demo"})
        selected = next(event for event in window.bus.recent(12) if event.module == "C2 Beacon Detector")

        # Extra rows are fixed inert observations, not simulated host collection.
        for index in range(72):
            window.bus.publish(Event(module="File Integrity Monitor" if index % 2 else "C2 Beacon Detector",
                severity=Severity.INFO if index % 3 else Severity.LOW, ts=1_785_240_300 + index,
                message=f"DEMO replay row {index + 1:02d} - synthetic evidence retained for analyst review",
                details={"public_demo": True, "synthetic": True, "training_only": True}))
        alerts = window.alerts_panel
        alerts._events = []
        alerts._newest_ts = 0.0
        alerts._accept_async_results = True
        alerts._apply_loaded_events(2, list(window.bus.recent(120)))
        alerts._accept_async_results = False
        if alerts.table.rowCount() < 72:
            raise RuntimeError("synthetic live-alert rows did not reach their bounded replay count")
        window.cards._apply_count(storage.revision(), alerts.table.rowCount())
        interactions["alerts"]["row_count"] = alerts.table.rowCount()
        alerts.setParent(stack)
        alerts.setWindowFlags(Qt.Widget)
        stack.addWidget(alerts)
        def scroll_alerts(step):
            bar = alerts.table.verticalScrollBar()
            if step and bar.maximum() <= 0:
                raise RuntimeError("the real alerts table did not expose a scrolling range")
            bar.setValue(round(bar.maximum() * step / (FRAMES_PER_CHAPTER - 1)))
            interactions["alerts"]["positions"].append({"value": bar.value(), "maximum": bar.maximum()})
        chapter(2, "Scroll the live-alert evidence stream",
                "The real alerts table scrolls through fixed synthetic rows. No host scan, allow/block action or alert dismissal is performed.",
                alerts, scroll_alerts)

        detail = AlertDetailDialog(selected, window, panel=window.alerts_panel)
        detail.setParent(stack)
        detail.setWindowFlags(Qt.Widget)
        stack.addWidget(detail)
        help_dialog = _help_fixture(window)
        help_dialog.setParent(stack)
        help_dialog.setWindowFlags(Qt.Widget)
        stack.addWidget(help_dialog)
        def browse_alert_and_help(step):
            stack.setCurrentWidget(help_dialog if step >= 7 else detail)
        chapter(3, "Read alert evidence and the operating guide",
                "Inspect original records, then Help & Info. An alert or AI explanation alone cannot authorize containment; the guide explains source Observe and Ring 3 limits.",
                detail, browse_alert_and_help)

        from types import SimpleNamespace
        from capture_spywareguard import DEMO_NOW, _SyntheticModule
        from angerona.gui import spyware_guard_page
        spyware_guard_page.time = SimpleNamespace(time=lambda: DEMO_NOW)

        class ResearchFixture(_SyntheticModule):
            queue_definition_import = None
            request_news_refresh = staticmethod(forbidden)

            def dashboard_snapshot(self):
                snapshot = super().dashboard_snapshot()
                snapshot["settings"]["spyware_network_enabled"] = False
                snapshot["news"][0].update(
                    title="DEMO · Spyware research brief and its evidence",
                    summary="Fixed cached preview. Read research context alongside local scan coverage.",
                )
                snapshot["news"].append({
                    "title": "DEMO · Emergency patching and exploit research",
                    "source": "project_zero",
                    "url": "https://projectzero.google/2026/10/emergency-patching.html",
                    "published": DEMO_NOW - 2 * 86400, "verified_at": DEMO_NOW - 120,
                    "summary": "Fixed cached preview. The source and publication date stay visible as the headline rotates.",
                })
                return snapshot

        spy_module = ResearchFixture()
        spy_config = SimpleNamespace(**spy_module.dashboard_snapshot()["settings"], ui_motion_enabled=False)
        # Use the production page's actual dialog-owned scrolling layout before
        # embedding that host as a fixed-viewport presentation widget.
        spyware_host = QDialog()
        spyware_layout = QVBoxLayout(spyware_host)
        spyware = spyware_guard_page.SpywareGuardPage(
            SimpleNamespace(modules={"SpywareGuard": spy_module}), spy_config, None, spyware_host)
        spyware.priority_scan.update_computer_specs({
            "cpu": 25.0, "ram": 43.75, "memory_total": 16 * 1024**3, "available": 9 * 1024**3,
        })
        spyware_layout.addWidget(spyware)
        spyware_host.setParent(stack)
        spyware_host.setWindowFlags(Qt.Widget)
        stack.addWidget(spyware_host)
        def browse_research_wire(step):
            if step == 0:
                spyware.refresh()
                spyware._timer.stop()
                spyware._news_rotation_timer.stop()
                spyware._news_scroll_timer.stop()
                spyware.hits_table.selectRow(0)
            elif step in (2, 7):
                # Use the timer's callback with fixed slots under reduced motion.
                spyware._rotate_news()
            if step in (4, 7):
                spyware.news_feed_details.click()
            if step in (5, 6):
                spyware.news_pause_button.click()
            if step in (0, 2, 4, 5, 6, 7):
                demo._settle(app, .05)
                scroll = spyware._window_fit.scroll_area
                scroll.ensureWidgetVisible(spyware.news_strip, 0, 8)
                interactions["research_wire"].append({
                    "publisher": spyware.news_source_button.text(),
                    "headline": spyware.news_headline.accessibleName(),
                    "details": spyware.news_feed_details.isChecked(),
                    "paused": spyware.news_pause_button.isChecked(),
                    "visible": in_scroll_view(spyware.news_strip, scroll),
                    "refresh_enabled": spyware.news_refresh_button.isEnabled(),
                })

        chapter(4, "Inspect SpywareGuard's dedicated workspace",
                "The Research Wire rotates through fixed cached examples with publisher dates, pause and feed details. No research fetch, scan or containment runs.",
                spyware_host, browse_research_wire)

        settings_config = Config(data_dir=runtime_root, autostart_enabled=False,
                                 aria_enabled=False, aria_voice_enabled=False, ui_motion_enabled=False)
        settings = _settings_fixture(settings_config, forbidden)
        settings.setParent(stack)
        settings.setWindowFlags(Qt.Widget)
        stack.addWidget(settings)
        def browse_settings(step):
            if step < 5:
                settings._select_tab("General")
                area = settings.tabs.currentWidget()
                area.ensureWidgetVisible(settings._startup_recovery_enabled, 0, 60)
            else:
                settings._select_tab("System")
                area = settings.tabs.currentWidget()
                area.ensureWidgetVisible(settings._storage_controls, 0, 40)
            interactions["settings_tabs"].append(settings.tabs.tabText(settings.tabs.currentIndex()))
        chapter(5, "Review recovery and drive-space settings",
                "Demo-only configuration: General owns startup recovery; System owns storage limits. No credentials are read and no setting is saved.",
                settings, browse_settings)

        attack = _attack_fixture(window, forbidden)
        attack.setParent(stack)
        attack.setWindowFlags(Qt.Widget)
        stack.addWidget(attack)
        def browse_attack(step):
            if step < 6:
                attack._tabs.setCurrentIndex(0)
                bar = attack._view.horizontalScrollBar()
                bar.setValue(round(bar.maximum() * step / 5))
            else:
                attack._tabs.setCurrentIndex(1)
            interactions["attack_tabs"].append(attack._tabs.currentIndex())
            interactions["attack_horizontal_positions"].append(attack._view.horizontalScrollBar().value())
        chapter(6, "Explore the MITRE ATT&CK map and coverage limits",
                "Synthetic technique heat is shown separately from declared coverage. Live detection and response readiness are explicitly unavailable.",
                attack, browse_attack)

        window.soar_panel.table.clearSelection()
        window.soar_panel.table.setCurrentCell(-1, -1)
        window.soar_panel._sync_action_buttons()
        window.soar_panel.setParent(stack)
        window.soar_panel.setWindowFlags(Qt.Widget)
        stack.addWidget(window.soar_panel)
        header = window.soar_panel.table.horizontalHeader()
        for column in (0, 1, 2, 4):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.Stretch)
        chapter(7, "Review proposed actions before policy admits them",
                "These review-only SOAR records are inert training fixtures. No approval, response, Undo or host-control button is activated.", window.soar_panel)

        window.scan_center.path_edit.setText("DEMO - synthetic findings; no path was scanned")
        window.scan_center._apply_result({"status": "completed", "findings": list(demo.SYNTHETIC_SCAN_FINDINGS),
                                         "summary": {"public_demo": True, "synthetic": True}})
        window.scan_center.status.setText("DEMO - no scan executed; findings are fixed synthetic examples")
        window.scan_center.progress.setFormat("DEMO")
        window.scan_center.setParent(stack)
        window.scan_center.setWindowFlags(Qt.Widget)
        stack.addWidget(window.scan_center)
        chapter(8, "Investigate findings with clear provenance",
                "Scan Center displays sample findings only. Real collection depends on platform, permissions and available providers.", window.scan_center)

        red_team, red_team_diagnostics = _red_team_fixture(window, forbidden)
        for view in (red_team, red_team_diagnostics):
            view.setParent(stack)
            view.setWindowFlags(Qt.Widget)
            stack.addWidget(view)

        def browse_red_team(step):
            if step < 6:
                stack.setCurrentWidget(red_team)
                interactions["red_team_progress"].append(
                    _red_team_progress_fixture(red_team, step))
            else:
                stack.setCurrentWidget(red_team_diagnostics)
                group = {6: 0, 7: 2, 8: 3, 9: 0}[step]
                red_team_diagnostics.filter.setCurrentIndex(group)
                red_team_diagnostics.table.selectRow(1 if step == 9 else 0)
                selected_row = red_team_diagnostics._selected_row()
                interactions["red_team_diagnostics"].append(dict(
                    filter=group, rows=red_team_diagnostics.model.rowCount(),
                    selected=selected_row["index"] if selected_row is not None else None,
                    has_detail=bool(red_team_diagnostics.detail.toPlainText()),
                    worker_started=bool(red_team_diagnostics._jobs
                        or red_team_diagnostics._worker is not None),
                    provider_connected=red_team_diagnostics._source is not None,
                    action_enabled=any(button.isEnabled() for button in (
                        red_team_diagnostics.copy_button, red_team_diagnostics.export_button,
                        red_team_diagnostics.refresh_button, red_team_diagnostics.patch_button))))
        chapter(9, "Track Red Team outcomes and inspect exact step diagnostics",
                "DEMO - two independent synthetic runs show progress, provisional gaps, final misses and a green passing illustration. Read-only step review separates facts, gaps and proposed fixes. No simulation, verification or patch runs.",
                red_team, browse_red_team,
                screenshot_at={2: "red-team-progress-demo", 5: "red-team-passing-demo",
                               7: "red-team-diagnostics-demo"})

        from angerona.gui.curated_tools import GitHubToolsDialog
        hub = GitHubToolsDialog(window.manager, window)
        # Select the inert curated page before showing the new Suggested default.
        if hub.tabs.tabText(0) != "Curated scanners":
            raise RuntimeError("the curated demo tab contract changed")
        hub.tabs.setCurrentIndex(0)
        # Reuse production views without constructing a catalog or lab worker.
        hub.source_library._loaded = True
        hub.source_library.analysis_lab._loaded = True
        hub.source_library.status.setText("DEMO - no repository download or source execution has occurred.")
        hub.source_library.analysis_lab.status.setText("DEMO - optional analysis runtime is not loaded or started.")
        hub.setParent(stack)
        hub.setWindowFlags(Qt.Widget)
        stack.addWidget(hub)

        def browse_curated(step):
            nonlocal credits_dialog
            if step < 4:
                stack.setCurrentWidget(hub)
                hub.tabs.setCurrentIndex(0)
                selected_view = "GitHub Tools - curated scanners"
            elif step < 7:
                # Present the actual selected tab as a close-up, using the same
                # temporary reparenting as the alerts and SOAR chapters. This
                # avoids a half-clipped outer card above the tab workspace.
                if step == 4:
                    spyware.layout().removeWidget(spyware.tabs)
                    spyware.tabs.setParent(stack)
                    stack.addWidget(spyware.tabs)
                stack.setCurrentWidget(spyware.tabs)
                spyware.tabs.setCurrentIndex(spyware.tabs.count() - 1)
                selected_view = "SpywareGuard - Zero-Breach tab close-up"
            elif step == 7:
                stack.removeWidget(spyware.tabs)
                spyware.tabs.setParent(spyware)
                spyware.layout().addWidget(spyware.tabs, 1)
                spyware.tabs.show()
                stack.setCurrentWidget(hub)
                hub.open_settings()
                if hub.tabs.currentWidget() is not hub.settings_scroll:
                    raise RuntimeError("the Settings demo did not open its actual settings widget")
                selected_view = "GitHub Tools - settings"
            elif step == 8:
                stack.setCurrentWidget(hub)
                hub.tabs.setCurrentIndex(0)
                demo._settle(app, .05)
                hub.scanner.credits_button.click()
                credits_dialog = hub.scanner._credits_dialog
                if credits_dialog is None:
                    raise RuntimeError("the production Credits action did not open its attribution view")
                credits_dialog.setParent(stack)
                credits_dialog.setWindowFlags(Qt.Widget)
                stack.addWidget(credits_dialog)
                stack.setCurrentWidget(credits_dialog)
                selected_view = "GitHub Tools - credits and license links"
            else:
                stack.setCurrentWidget(hub)
                hub.open_analysis()
                selected_view = "Source library - separate analysis sandbox"
            interactions["curated_views"].append(selected_view)

        chapter(10, "Add reviewed tools while keeping provenance visible",
                "DEMO - the GitHub hub and SpywareGuard share the pinned Zero-Breach adapter. Credits, license links and source analysis are visible; no tool or host scan runs.",
                hub, browse_curated, screenshot_at={1: "github-tools-demo", 5: "zero-breach-demo",
                                                  7: "github-tools-settings-demo", 8: "github-tools-credits-demo"})

        spyware.tabs.setCurrentIndex(0)
        scan = spyware.priority_scan
        scan_scroll = spyware._window_fit.scroll_area
        scan_scroll.verticalScrollBar().setValue(0)
        def replay_priority(step):
            publication = _scan_progress_fixture(step)
            expected = publication.pop("demo_expected_overall")
            prior_rows = dict(spyware.priority_scan.step_rows)
            curated.update(**publication)
            if any(spyware.priority_scan.step_rows.get(key) is not row for key, row in prior_rows.items()):
                raise RuntimeError("the real progress presenter replaced its stable reader widgets")
            scan.setup_toggle.setChecked(step in (6, 7))
            scan.toggle.setChecked(step in (6, 7))
            scan.explanation_toggle.setChecked(step == 7)
            if step == 7:
                demo._settle(app, .05)
                scan_scroll.ensureWidgetVisible(scan.options, 0, 8)
            elif step in (0, 3, 6, 8):
                scan_scroll.verticalScrollBar().setValue(0)
            # Purposeful navigation happens only at chapter waypoints; copied
            # status updates retain the current reader scroll position.
            target = {2: "native:hashes", 4: "toolkit:browser", 5: "toolkit:hash"}.get(step)
            if target is not None:
                row = scan.step_rows[target]
                demo._settle(app, .05)
                scan.steps_scroll.ensureWidgetVisible(row, 0, 0)
                scan_scroll.ensureWidgetVisible(scan.steps_scroll, 0, 8)
                interactions["reader_waypoints"].append({
                    "reader": target,
                    "visible": in_scroll_view(row, scan.steps_scroll) and in_scroll_view(row, scan_scroll),
                })
            interactions["priority_resources"].append(publication["resource_usage"])
            interactions["priority_progress"].append({"publication": publication["scan_progress"],
                "reader_publications": {source: {key: value.get(key) for key in (
                    "state", "overall_percent", "current_file", "item_completed", "item_total", "item_unit", "item_percent")}
                    for source, value in publication["scanner_progress"].items()},
                "expected_percent": expected,
                "displayed_percent": spyware.priority_scan.progress_ring.percent,
                "displayed_stage": spyware.priority_scan.progress_stage.text(),
                "displayed_current_task": spyware.priority_scan.activity.text(),
                "displayed_current_file": spyware.priority_scan.current_file.text(),
                "displayed_item_percent": spyware.priority_scan.item_progress.format(),
                "displayed_timing": spyware.priority_scan.timing.text(),
                "displayed_outcome": spyware.priority_scan.outcome.text(),
                "displayed_rows": {key: {"caption": row.caption.text(), "percent": row.bar.format(),
                                          "count": row.count.text()} for key, row in spyware.priority_scan.step_rows.items()
                                   if key in {"native:hashes", "toolkit:browser", "toolkit:hash", "toolkit:host"}},
                "stable_reader_widgets": True,
                "state": publication["state"], "busy": publication["busy"], "lifecycle": publication["lifecycle"],
                "scope": spyware.priority_scan._scope_mode,
                "resource_limits_open": spyware.priority_scan.toggle.isChecked(),
                "coverage_details_open": spyware.priority_scan.explanation_toggle.isChecked()})
            if step in (3, 7, 8):
                demo._settle(app, .05)
                overview = (spyware.news_strip, scan.progress_group, scan.explanation_group, scan.resource_group)
                tops = [scroll_top(widget, scan_scroll) for widget in overview]
                interactions["compact_scan"].append({
                    "setup_visible": scan.setup_body.isVisible(),
                    "resources_visible": scan.options.isVisible(),
                    "review_visible": scan.review_button.isVisible(),
                    "hits": scan.hits.text(),
                    "hits_before_setup": scan.layout().indexOf(scan.hits) < scan.layout().indexOf(scan.setup_toggle),
                    "overview_order": all(a < b for a, b in zip(tops, tops[1:])),
                    "overview_titles_in_view": all(0 <= y < scan_scroll.viewport().height() - 28 for y in tops),
                    "progress_and_hits_in_view": (in_scroll_view(scan.progress_group, scan_scroll)
                                                   and in_scroll_view(scan.hits, scan_scroll)),
                    "review_in_view": in_scroll_view(scan.review_button, scan_scroll),
                })
        chapter(11, "Follow measured reader and current-item progress",
                "DEMO · Research Wire, progress, current status and Computer specs precede setup. Reader close-ups show measured work. The modeled timeout retains partial hits for review.",
                spyware_host, replay_priority, screenshot_at={3: "spyware-scan-demo"})
        curated.update(message="DEMO - the modeled timeout and partial progress remain available; no host-clean verdict is claimed.")

        # Restore the production dashboard's evidence tabs after the earlier
        # close-up chapters, so the breach scene contains the full MainWindow.
        for index, (panel, label) in enumerate(((alerts, "Live Alerts"),
                                                (window.soar_panel, "SOAR Queue"),
                                                (window.scan_center, "Scan Center"))):
            stack.removeWidget(panel)
            window._right_tabs.insertTab(index, panel, label)
        window._right_tabs.setCurrentWidget(alerts)
        fixture_missing_blackbox[0] = False
        window.config.breach_alert_popup_enabled = False
        synthetic_breach = _breach_fixture(window.manager, forbidden)
        stack.setCurrentWidget(window)
        window.set_breach_visual_state(synthetic_breach)
        demo._settle(app, .1)
        breach_bridge = window._breach_view
        breach_bridge.poll_timer.stop()
        breach_bridge.flash_timer.stop()

        def replay_breach(step):
            # The real bridge paints its badge and outline; replay their slow
            # red/orange phases deterministically rather than using wall time.
            breach_bridge.poll_timer.stop()
            breach_bridge.flash_timer.stop()
            breach_bridge._orange = bool((step // 2) % 2)
            breach_bridge._paint_warning()
            window._refresh_current_assessment()
            if step == 0:
                interactions["current_assessment"].append(
                    (window._assessment_key, window._assessment_banner.accessibleDescription()))
            interactions["breach_colors"].append("orange" if breach_bridge._orange else "red")
            if window.posture_lbl.text() != "⚠️Breached⚠️":
                raise RuntimeError("the real dashboard did not retain its confirmed-breach badge")
        chapter(12, "Keep a confirmed breach visible until operator review",
                "DEMO SIMULATION - case status stays critical independently of the engine score. Modeled lockdown covers Ethernet, Wi-Fi and other outside connections; this capture changes no network rules.",
                window, replay_breach, screenshot_at={4: "breach-lockdown-demo"})

        after_action = breach_bridge.open_report()
        after_action.setParent(stack)
        after_action.setWindowFlags(Qt.Widget)
        stack.addWidget(after_action)
        if not after_action.actions["lift_lockdown"].isEnabled():
            raise RuntimeError("the synthetic case-owned Lift Lockdown availability was not presented")
        def browse_after_action(step):
            bar = after_action.text.verticalScrollBar()
            bar.setValue(round(bar.maximum() * step / (FRAMES_PER_CHAPTER - 1)))
            interactions["after_action_scroll"].append({"value": bar.value(), "maximum": bar.maximum()})
        chapter(13, "Review evidence, next steps and the explicit Lift Lockdown control",
                "DEMO SIMULATION - investigate and trace a detailed case, review held actions and Lift Lockdown availability. No response button is activated; lifting and resolving remain separate operator decisions.",
                after_action, browse_after_action, screenshot_at={1: "after-action-demo"})
        adaptation = _adaptation_fixture(forbidden)
        adaptation.setParent(stack)
        adaptation.setWindowFlags(Qt.Widget)
        stack.addWidget(adaptation)

        def browse_adaptation(step):
            if step in (5, 6):
                adaptation.tabs.setCurrentIndex(6)
                adaptation.transaction_table.selectRow(0)
                area = adaptation.tabs.currentWidget()
                area.ensureWidgetVisible(adaptation.transaction_table, 0, 20)
                selected_view = "DEMO history - no authenticated transaction"
            else:
                adaptation.tabs.setCurrentIndex(adaptation.adapt_tab_index)
                area = adaptation.tabs.currentWidget()
                if step >= 7:
                    area.ensureWidgetVisible(adaptation.snapshot_combo, 0, 35)
                    selected_view = "DEMO recovery reference - not restorable"
                else:
                    adaptation.change_table.selectRow(min(step, 2))
                    target = adaptation.change_details if step == 4 else adaptation.change_table
                    area.ensureWidgetVisible(target, 0, 20)
                    selected_view = "DEMO projected before/after changes"
            interactions["auto_adapt"].append({
                "view": selected_view, "synthetic": True, "host_actions": False,
                "authority_held": not adaptation.apply_button.isEnabled(),
                "changes": adaptation.change_table.rowCount(),
                "history_rows": adaptation.transaction_table.rowCount(),
                "snapshot_references": adaptation.snapshot_combo.count(),
                "worker_started": adaptation._task_thread is not None or adaptation._status_thread is not None
                                  or adaptation.prevention_panel._job is not None,
                "timer_active": any(timer.isActive() for timer in (adaptation._result_timer,
                    adaptation.recovery_panel._timer, adaptation.prevention_panel._poll_timer)),
                "provider_connected": adaptation.recovery_panel.manager is not None
                                      or adaptation.prevention_panel._client is not None
                                      or adaptation.prevention_panel._inspect is not forbidden})

        chapter(14, "Review Auto Adapt changes and rollback scope",
                "DEMO - the real workbench shows synthetic before/after changes, history and a non-restorable snapshot reference. Preset adjustments require a new exact preview; real rollback restores complete firewall policy. Authority is held and no action is run.",
                adaptation, browse_adaptation, screenshot_at={3: "auto-adapt-demo"})
        demo._privacy_guard()
        if (not all(row["fresh"] for row in interactions["heartbeats"][0])
                or not any(row["role"] == "blackbox" and not row["fresh"]
                           for row in interactions["heartbeats"][-1])
                or interactions["heartbeat_details_steps"] != [6, 7, 8]):
            raise RuntimeError("synthetic EKG beat, flatline or actual details interaction was not captured")
        if forbidden_attempts:
            raise RuntimeError("a demo callback attempted an external effect; inspect the private failure")
        assessment = interactions["current_assessment"]
        wire = interactions["research_wire"]
        compact, expanded, retained = interactions["compact_scan"]
        reader_waypoints = interactions["reader_waypoints"]
        if ([key for key, _ in assessment] != ["coverage", "inbox", "coverage", "case"]
                or "Open the case report." not in assessment[-1][1]
                or len(wire) != 6
                or len({row["headline"] for row in wire}) != 2
                or not wire[0]["publisher"].startswith("Citizen Lab · ")
                or not wire[1]["publisher"].startswith("Project Zero · ")
                or wire[-1]["publisher"] != wire[0]["publisher"]
                or [row["details"] for row in wire] != [False, False, True, True, True, False]
                or [row["paused"] for row in wire] != [False, False, False, True, False, False]
                or any(not row["visible"] or row["refresh_enabled"] for row in wire)
                or any(not row["hits_before_setup"] for row in (compact, expanded, retained))
                or not compact["overview_order"] or not compact["overview_titles_in_view"]
                or not compact["progress_and_hits_in_view"] or not retained["progress_and_hits_in_view"]
                or not retained["review_in_view"]
                or [row["reader"] for row in reader_waypoints] != ["native:hashes", "toolkit:browser", "toolkit:hash"]
                or any(not row["visible"] for row in reader_waypoints)
                or compact["setup_visible"] or compact["review_visible"]
                or not expanded["setup_visible"] or not expanded["resources_visible"]
                or retained["setup_visible"] or not retained["review_visible"]
                or "2 advisory hits" not in retained["hits"] or "1 tool finding" not in retained["hits"]):
            raise RuntimeError("the current assessment, Research Wire or compact scan views differ from the inert plan")
        red_progress, red_diagnostics = (interactions["red_team_progress"],
                                          interactions["red_team_diagnostics"])
        if (len(red_progress) != 6
                or [row["badge_state"] for row in red_progress]
                    != ["pending", "partial", "failing", "failing", "partial", "passing"]
                or any(row["displayed_percent"] != row["expected_percent"]
                       or row["provider_started"] or row["host_actions"] for row in red_progress)
                or (red_progress[3]["caught"], red_progress[3]["missed"]) != (6, 2)
                or (red_progress[5]["caught"], red_progress[5]["missed"]) != (8, 0)
                or [row["rows"] for row in red_diagnostics] != [3, 1, 1, 3]
                or [row["selected"] for row in red_diagnostics] != [0, 1, 2, 1]
                or any(not row["has_detail"] or row["worker_started"]
                       or row["provider_connected"] or row["action_enabled"] for row in red_diagnostics)):
            raise RuntimeError("real Red Team progress, badge or diagnostic controls differ from the inert plan")
        positions = interactions["alerts"]["positions"]
        if (positions[0]["value"] != 0 or positions[-1]["maximum"] <= 0
                or positions[-1]["value"] != positions[-1]["maximum"]
                or len({position["value"] for position in positions}) < 3):
            raise RuntimeError("the real alerts table did not complete its recorded scrolling demonstration")
        if (len(frames) != FRAME_COUNT or len(chapter_names) != CHAPTERS
                or set(staged_screenshots) != set(SCREENSHOTS)
                or set(interactions["breach_colors"]) != {"red", "orange"}
                or len({row["cpu_percent"] for row in interactions["priority_resources"]}) < 3
                or any(row["displayed_percent"] != row["expected_percent"] or not 0 <= row["displayed_percent"] < 100
                       for row in interactions["priority_progress"])
                or interactions["priority_progress"][3]["displayed_rows"]["native:hashes"]["percent"] != "37.5%"
                or "Stopping" not in interactions["priority_progress"][6]["displayed_stage"]
                or any(row["state"] != "timed-out" or row["busy"] for row in interactions["priority_progress"][-2:])
                or any(row["scope"] != "full" for row in interactions["priority_progress"])
                or len(interactions["auto_adapt"]) != FRAMES_PER_CHAPTER
                or len({row["view"] for row in interactions["auto_adapt"]}) != 3
                or any(not row["authority_held"] or row["worker_started"] or row["host_actions"]
                       or row["timer_active"] or row["provider_connected"]
                       or row["changes"] != 3 or row["history_rows"] != 1 or row["snapshot_references"] != 1
                       for row in interactions["auto_adapt"])
                or captured_sources != source_fingerprints()):
            raise RuntimeError("the capture plan, source revision or synthetic interaction coverage changed")
        report = {"schema": 2, "frames": frames, "frame_sha256": frame_sha256, "chapters": chapter_names,
                  "duration_ms": FRAME_DURATION_MS, "width": wrapper.width(),
                  "height": wrapper.height(), "synthetic": True, "host_actions": False,
                  "external_effect_attempts": 0, "app_version": __version__,
                  "interactions": interactions, "capture": identity(), "source_sha256": captured_sources,
                  "screenshots": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                  for name, path in staged_screenshots.items()}}
        serialized_report = json.dumps(report)
        if len(serialized_report.encode("ascii")) > 65536:
            raise RuntimeError("frame manifest exceeds its unchanged 64 KiB encode admission bound")
        (frames_root / "frames.json").write_text(serialized_report, encoding="ascii")
        staged_poster = frames_root / "poster.png"
        with (frames_root / frames[0]).open("rb") as source, staged_poster.open("xb") as target:
            target.write(source.read())
        publish_media(staged_poster, poster, replace=replace)
        for name, staged in staged_screenshots.items():
            publish_media(staged, ROOT / "assets" / "screenshots" / f"{name}.png", replace=replace)
        owned = []
        for name in (*frames, "frames.json", "capture-identity.json", "capture-stacks.log"):
            path = plain(frames_root / name, scratch=True)
            info = path.stat()
            owned.append(dict(path=str(path), device=info.st_dev, inode=info.st_ino,
                              bytes=info.st_size, modified_ns=info.st_mtime_ns,
                              sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
        (frames_root / "owned-files.json").write_text(json.dumps(
            dict(schema=1, capture=identity(), files=owned,
                 policy="Delete only an unchanged exact file after native process retirement and independent review; preserve unknown files.",
                 runtime_root=str(runtime_root),
                 runtime_policy="Synthetic runtime is separate; this frame manifest grants no recursive deletion authority."),
        ), encoding="ascii")
        print(json.dumps({"outcome": "captured", "frames": len(frames),
                          "seconds": FRAME_COUNT * FRAME_DURATION_MS / 1000,
                          "poster": str(poster), "capture": identity()}))
    finally:
        if detail is not None:
            detail.hide()
        for widget in (settings, spyware, spyware_host, attack, heartbeat_details, hub,
                       credits_dialog, after_action, adaptation, help_dialog,
                       red_team, red_team_diagnostics):
            if widget is not None:
                widget.close()
        wrapper.hide()
        window._breach_view.shutdown()
        curated.shutdown()
        demo._close_demo(app, window, storage)
        app.processEvents()
        faulthandler.cancel_dump_traceback_later()
        traceback_stream.close()


def encode(frames_root: Path, output: Path, *, replace: bool = False) -> None:
    from PIL import Image, ImageChops
    frames_root, output = plain(frames_root, scratch=True), plain(output)
    if output != ROOT / "assets" / "demo" / "angerona-demo.gif" or (output.exists() and not replace):
        raise ValueError("encode requires its explicit GIF path and permission to replace an existing demo")
    manifest_path = plain(frames_root / "frames.json", scratch=True)
    if manifest_path.stat().st_size > 65536:
        raise ValueError("frame manifest exceeds its bound")
    manifest = json.loads(manifest_path.read_text(encoding="ascii"))
    names = manifest.get("frames")
    if manifest.get("schema") != 2 or names != [f"frame-{index:03d}.png" for index in range(FRAME_COUNT)]:
        raise ValueError("frame manifest is invalid")
    if (manifest.get("duration_ms") != FRAME_DURATION_MS or not manifest.get("synthetic")
            or manifest.get("host_actions") is not False or len(manifest.get("chapters", [])) != CHAPTERS):
        raise ValueError("frame policy is invalid")
    frame_hashes = manifest.get("frame_sha256")
    if type(frame_hashes) is not dict or set(frame_hashes) != set(names):
        raise ValueError("frame fingerprint manifest is invalid")
    paths = []
    total_bytes = 0
    for name in names:
        if not isinstance(name, str) or not re.fullmatch(r"frame-\d{3}\.png", name):
            raise ValueError("invalid frame name")
        path = plain(frames_root / name, scratch=True)
        size = path.stat().st_size
        total_bytes += size
        if size > MAX_FRAME_BYTES or total_bytes > MAX_CAPTURE_BYTES:
            raise ValueError("frame exceeds its byte bound")
        if hashlib.sha256(path.read_bytes()).hexdigest() != frame_hashes[name]:
            raise ValueError("frame changed after capture")
        with Image.open(path) as image:
            if (image.format != "PNG" or image.width > 1920 or image.height > 1200
                    or image.size != (manifest.get("width"), manifest.get("height"))):
                raise ValueError("frame geometry or type is invalid")
            paths.append(path)
    palette_sample = Image.new("RGB", (800, 530 * CHAPTERS))
    for index in range(CHAPTERS):
        with Image.open(paths[index * FRAMES_PER_CHAPTER]) as original:
            sample = original.convert("RGB")
            sample.thumbnail((800, 530))
            palette_sample.paste(sample, (0, index * 530))
            sample.close()
    # Preserve the UI status colors when the sampled palette favors dashboard blues.
    # The last reserved color is the Red Team caught bar (#15803d).
    status_colors = [40, 223, 148, 255, 83, 99, 47, 227, 138, 251, 191, 36,
                     239, 68, 68, 251, 146, 60, 31, 156, 255, 248, 250, 252,
                     21, 128, 61]
    sampled_color_count = 256 - len(status_colors) // 3
    palette = palette_sample.quantize(colors=sampled_color_count)
    palette_sample.close()
    palette.putpalette(palette.getpalette()[:sampled_color_count * 3] + status_colors)
    quantized = []
    for path in paths:
        with Image.open(path) as original:
            image = original.convert("RGB")
            quantized.append(image.quantize(palette=palette, dither=Image.Dither.NONE))
            image.close()
    staged = frames_root / "encoded-demo.gif"
    with staged.open("xb") as target:
        quantized[0].save(target, format="GIF", save_all=True, append_images=quantized[1:],
                          duration=FRAME_DURATION_MS, loop=0, optimize=False, disposal=2)
    if staged.stat().st_size > MAX_GIF:
        staged.unlink()  # Only this invocation's new, exact output is eligible.
        raise ValueError("new GIF exceeded its explicit 12 MiB budget")
    with Image.open(staged) as image:
        count = image.n_frames
        duration = 0
        slot = 0
        for index in range(count):
            image.seek(index)
            frame_duration = image.info.get("duration", 0)
            if frame_duration <= 0 or frame_duration % FRAME_DURATION_MS:
                raise ValueError("encoded GIF contains an unexpected frame duration")
            decoded = image.convert("RGB")
            for _ in range(frame_duration // FRAME_DURATION_MS):
                if slot >= len(quantized) or ImageChops.difference(
                        decoded, quantized[slot].convert("RGB")).getbbox() is not None:
                    raise ValueError(f"encoded GIF changed the reviewed pixels in frame slot {slot}")
                slot += 1
            duration += frame_duration
    if duration != FRAME_COUNT * FRAME_DURATION_MS or slot != FRAME_COUNT:
        raise ValueError("encoded GIF duration differs from the reviewed chapter plan")
    publish_media(staged, output, replace=replace)
    print(json.dumps({"outcome": "encoded", "bytes": output.stat().st_size, "frames": count,
                      "duration_ms": duration, "encoder": identity()}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encode", action="store_true")
    parser.add_argument("--frames-root", type=Path, required=True)
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--replace-existing-demo", action="store_true",
                        help="Replace only the explicit planned demo asset leaves after successful validation.")
    parser.add_argument("--poster", type=Path, default=ROOT / "assets" / "screenshots" / "dashboard-demo.png")
    parser.add_argument("--gif", type=Path, default=ROOT / "assets" / "demo" / "angerona-demo.gif")
    args = parser.parse_args()
    if args.encode:
        encode(args.frames_root, args.gif, replace=args.replace_existing_demo)
    elif args.runtime_root is not None:
        capture(args.runtime_root, args.frames_root, args.poster, replace=args.replace_existing_demo)
    else:
        parser.error("capture requires --runtime-root")


if __name__ == "__main__":
    main()
