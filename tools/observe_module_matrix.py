"""Observe reviewed module workers in fresh ordinary-user profiles.

Default: discover and write a plan, without starting any module. --run starts
only explicitly audited sensor cases, serially, in isolated child processes.
This is a developer diagnostic, not a containment policy or security verdict.
Runtime coverage for other modules and full offline self-test are HELD pending
individual active-path review. No elevated launch or process killing is used.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
import datetime as dt
import itertools
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import threading
import time

SCHEMA = "angerona.module-observation-matrix.v1"
AUDITED = {
    "Process Monitor": "angerona.modules.process_monitor.ProcessMonitorModule",
    "Network Monitor": "angerona.modules.network_monitor.NetworkMonitorModule",
    "Sysmon Event Bridge": "angerona.modules.sysmon_listener.SysmonListenerModule",
    "Self-Integrity Monitor": "angerona.modules.self_integrity.SelfIntegrityMonitor",
    "SpywareGuard": "angerona.modules.spyware_guard.SpywareGuardModule",
    "C2 Beacon Detector": "angerona.modules.beacon_detector.BeaconDetectorModule",
    "Evidence Lattice Fusion": "angerona.modules.evidence_lattice.EvidenceLatticeModule",
    "Deterministic Fast-Path Interceptor": "angerona.modules.fast_path.FastPathModule",
    "In-Memory Flight Cache": "angerona.modules.flight_cache.FlightCacheModule",
    "Immutable Recovery Assurance Guard": "angerona.modules.immutable_recovery_guard.ImmutableRecoveryGuardModule",
    "Identity Session Guard": "angerona.modules.identity_session_guard.IdentitySessionGuardModule",
    "AegisPath Exposure Graph Guard": "angerona.modules.exposure_graph_guard.ExposureGraphGuardModule",
    "Fleet Health Monitor": "angerona.modules.fleet_health_monitor.FleetHealthMonitorModule",
    "LSASS Credential-Access Guard": "angerona.modules.lsass_guard.LsassGuardModule",
    "App Control Decision Evidence": "angerona.modules.app_control_monitor.AppControlDecisionSensor",
}
OFF = (
    "autostart_enabled", "blackbox_enabled", "alert_retention_enabled",
    "deception_user_folders", "process_baseline_enabled", "mobile_enabled",
    "ebpf_enabled", "mcp_enabled", "jarvis_control_enabled", "fleet_service_enabled",
    "aria_enabled", "perf_governor_enabled", "aria_voice_enabled",
    "aria_conversation_awareness", "aria_always_listen", "aria_hand_controls",
    "aria_voice_cloud_tts", "aria_cloud_fallback", "alert_analysis_cloud_fallback",
    "aria_push_enabled", "aria_inbox_enabled", "aria_research_egress",
    "teams_bot_enabled", "teams_bot_skip_auth", "siem_allow_plaintext", "siem_include_raw",
    "remote_bridge_allow_nonloopback", "spyware_auto_contain", "spyware_network_enabled",
    "spyware_memory_enabled", "spyware_beacon_enabled", "spyware_beacon_channel",
    "spyware_beacon_signal", "ugcap_enabled", "adversary_combat_enabled",
    "adversary_combat_block_network", "adversary_combat_quarantine_files",
    "adversary_combat_isolate_host", "adversary_combat_activate_honeypots",
    "identity_session_collection_enabled", "browser_extension_inventory_enabled", "ugcap_witness_enabled",
    "entropy_pool_enabled", "ui_motion_enabled", "holographic_orb_enabled",
)
BLANK = (
    "github_repo", "mobile_signal_cli", "mobile_signal_cli_sha256",
    "mobile_signal_cli_publisher", "mobile_host_number", "mobile_dest_number",
    "siem_host", "siem_ca_file", "remote_bridge_mode", "remote_bridge_peer",
    "remote_bridge_node_id", "ioc_feed_url", "ioc_feed_sha256", "aria_push_url",
    "aria_imap_host", "aria_imap_user", "aria_mic_device", "teams_app_id",
    "teams_allowed_users", "ugcap_vault_path",
)
ON = ("eco_mode", "live_debug_enabled", "require_signed_aar", "ugcap_lockdown")
FIXED = {
    "ollama_host": "http://127.0.0.1:65534", "ollama_keep_alive": "0",
    "ai_provider_order": [], "spyware_research_urls": [], "remote_bridge_bind": "127.0.0.1",
    "adversary_combat_mode": "contain", "adversary_combat_process_action": "suspend",
}
TCB = (
    "src/angerona/core/config.py", "src/angerona/core/module_manager.py",
    "src/angerona/core/module_base.py", "src/angerona/core/module_usage.py",
    "src/angerona/core/eventbus.py", "src/angerona/core/live_debug.py",
    "src/angerona/resilience/scanner.py", "src/angerona/resilience/ipc_ring.py",
    "src/angerona/core/exposure_graph.py", "src/angerona/core/recovery_assurance.py",
    "src/angerona/core/identity_session.py", "src/angerona/core/response_contract.py",
    "src/angerona/core/identity_collectors.py", "src/angerona/core/verified_readiness.py",
    "src/angerona/core/recovery_workflow.py", "src/angerona/core/recovery_drill.py",
    "src/angerona/telemetry/sensors.py", "src/angerona/core/spyware_sensors.py",
)
MAX_JSON = 512 * 1024
CAPTURE_BYTES = 8 * 1024 * 1024
STARTUP_SECONDS = 60.0
SHUTDOWN_SECONDS = 15.0


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("ascii")


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.casefold()).strip("-")[:70]


def validate_case(case):
    if not isinstance(case, dict) or case.get("disposition") != "ELIGIBLE":
        raise ValueError("Only an audited ELIGIBLE case may run")
    names = case.get("modules")
    if (not isinstance(names, list) or len(names) != len(set(names))
            or any(type(name) is not str or name not in AUDITED for name in names)):
        raise ValueError("Case contains an unaudited or duplicate module")
    if case.get("mode") == "scanner":
        if names or case.get("id") != "raw-scanner":
            raise ValueError("Scanner case must be independent of module workers")
    elif case.get("mode") == "modules":
        if not names and case.get("id") != "control":
            raise ValueError("Only control may have no module workers")
    else:
        raise ValueError("Unsupported case mode")
    return tuple(names)


def make_cases(rows):
    """Pure plan builder: metadata cannot grant startup authority."""
    names = [row["name"] for row in rows]
    if len(names) != 86 or len(set(names)) != 86 or not AUDITED.keys() <= set(names):
        raise ValueError("Expected the reviewed 86 built-ins and exact audited sensor identities")
    cases = [dict(id="control", mode="modules", modules=[], disposition="ELIGIBLE",
                  reason="Scheduling/export overhead control; no module runtime coverage")]
    for name in sorted(names):
        eligible = name in AUDITED
        cases.append(dict(id="solo-" + slug(name), mode="modules", modules=[name],
                          disposition="ELIGIBLE" if eligible else "HELD",
                          reason="Audited read-only sensor with explicit disabled response/egress"
                          if eligible else "Active start/stop and helper side effects not yet audited"))
    for pair in itertools.combinations(sorted(AUDITED), 2):
        cases.append(dict(id="pair-" + "--".join(map(slug, pair)), mode="modules",
                          modules=list(pair), disposition="ELIGIBLE",
                          reason="Pair of individually audited sensors; interaction observation remains pending"))
    cases.extend([
        dict(id="all-eligible", mode="modules", modules=sorted(AUDITED), disposition="ELIGIBLE",
             reason="Only audited sensors together; not all 86 capabilities"),
        dict(id="raw-scanner", mode="scanner", modules=[], disposition="ELIGIBLE",
             reason="Actual independent ScannerHost, fresh private ring/heartbeat, no supervisor"),
        dict(id="all-86-runtime", mode="modules", modules=sorted(names), disposition="HELD",
             reason="Includes host mutators, listeners, opt-in integrations and unaudited helpers"),
        dict(id="offline-all-selftests", mode="selftest", modules=sorted(names), disposition="HELD",
             reason="Existing offline self-check is separate validation; active callbacks need individual review"),
    ])
    identifiers = [case["id"] for case in cases]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("Case IDs collide")
    return cases


def select_cases(plan, requested, max_cases):
    by_id = {case["id"]: case for case in plan["cases"]}
    if requested:
        if len(set(requested)) != len(requested) or any(key not in by_id for key in requested):
            raise ValueError("Unknown or duplicate case selection")
        selected = [by_id[key] for key in requested]
        for case in selected:
            validate_case(case)
    else:
        selected = [case for case in plan["cases"] if case["disposition"] == "ELIGIBLE"]
    if len(selected) > max_cases:
        raise ValueError("Selection exceeds --max-cases; select fewer cases explicitly")
    return selected


def assert_config(config, names, selected):
    fields = config if isinstance(config, dict) else vars(config)
    for key, expected in [(key, False) for key in OFF] + [(key, True) for key in ON]:
        if fields.get(key) is not expected:
            raise ValueError("Unsafe or missing explicit boolean: " + key)
    if any(fields.get(key) != "" for key in BLANK):
        raise ValueError("A connector destination is not blank")
    if any(fields.get(key) != value for key, value in FIXED.items()):
        raise ValueError("An egress/response setting differs from the reviewed profile")
    states = fields.get("module_states")
    if (not isinstance(states, dict) or set(states) != set(names)
            or any(type(value) is not bool for value in states.values())
            or {key for key, value in states.items() if value} != set(selected)
            or not set(selected) <= AUDITED.keys()):
        raise ValueError("Exact complete module selection was not preserved")


def configure(profile, names, selected):
    from angerona.core.config import Config
    config = Config(data_dir=profile)  # Never load ambient settings or a golden baseline.
    for key in (*OFF, *ON, *BLANK, *FIXED):
        if not hasattr(config, key):
            raise ValueError("Reviewed Config field no longer exists: " + key)
    for key in OFF:
        setattr(config, key, False)
    for key in ON:
        setattr(config, key, True)
    for key in BLANK:
        setattr(config, key, "")
    for key, value in FIXED.items():
        setattr(config, key, list(value) if isinstance(value, list) else value)
    config.module_states = {name: name in selected for name in sorted(names)}
    assert_config(config, names, selected)
    config.save()
    return config


def plain(path, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
            or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
        raise ValueError("Linked, reparse or unexpected observation path")
    return info


def write_private(path, value, *, durable=True):
    """Keep custody and atomic replacement; only advisory progress may omit fsync."""
    from angerona.core.engine_transport import create_private_file, verify_private
    encoded = canonical(value) + b"\n"
    if len(encoded) > MAX_JSON:
        raise ValueError("Observation JSON exceeds its budget")
    temporary = path.with_name("." + path.name + "." + secrets.token_hex(6))
    descriptor = create_private_file(temporary)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            if durable:
                os.fsync(stream.fileno())
        if path.exists():
            verify_private(path)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_private(path):
    from angerona.core.engine_transport import verify_private
    verify_private(path)
    if plain(path).st_size > MAX_JSON:
        raise ValueError("Observation JSON exceeds its budget")
    raw = path.read_bytes()
    if len(raw) > MAX_JSON:
        raise ValueError("Observation JSON grew beyond its budget")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Observation record must be an object")
    return value


def exclusive_directory(path):
    from angerona.core.engine_transport import _windows_private_attributes, verify_private
    import win32file
    win32file.CreateDirectory(str(path), _windows_private_attributes(directory=True))
    verify_private(path, directory=True)


def environment(repo, profile):
    from angerona.core.privilege import sanitized_child_environment
    result = sanitized_child_environment(source={})
    result.update({
        "ANGERONA_HOME": str(repo), "ANGERONA_DATA": str(profile),
        "ANGERONA_DIAG_DIR": str(profile / "diagnostics"), "TEMP": str(profile / "tmp"),
        "TMP": str(profile / "tmp"), "EDR_DB_PATH": str(profile / "flight-recorder.db"),
        "EDR_LOG_DIR": str(profile / "logs"), "ANGERONA_RESILIENCE": "0",
        "ANGERONA_BLACKBOX_ENABLED": "0", "ANGERONA_DEBUG": "1",
        "OLLAMA_HOST": FIXED["ollama_host"], "PYTHON_DOTENV_DISABLED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    })
    return result


def install_environment(repo, profile):
    """Apply before importing Config, discovery or any module with import-time IO."""
    clean = environment(repo, profile)
    os.environ.clear()
    os.environ.update(clean)
    import tempfile
    tempfile.tempdir = str(profile / "tmp")


def source_snapshot(repo, modules):
    from angerona.core.process_allowlist import executable_sha256
    paths = set(TCB)
    # Include the complete first-party Python tree: an explicit helper list
    # alone silently misses transitive custody, identity and cancellation code.
    # This detects source drift, not hostile replacement of the verifier itself.
    source_root = repo / "src" / "angerona"
    source_bytes = 0
    for current, directories, filenames in os.walk(source_root, followlinks=False):
        current = Path(current)
        plain(current, directory=True)
        if len(current.relative_to(source_root).parts) > 16:
            raise ValueError("Reviewed source directory depth exceeded")
        directories[:] = sorted(name for name in directories if name != "__pycache__")
        for name in directories:
            plain(current / name, directory=True)
        for name in filenames:
            if name.endswith(".py"):
                path = current / name
                source_bytes += plain(path).st_size
                paths.add(path.relative_to(repo).as_posix())
                if len(paths) > 2048 or source_bytes > 64 * 1024 * 1024:
                    raise ValueError("Reviewed source tree budget exceeded")
    for module in modules.values():
        if module.name in AUDITED:
            paths.add("src/" + type(module).__module__.replace(".", "/") + ".py")
    paths.add(str(Path(__file__).resolve().relative_to(repo)).replace("\\", "/"))
    result = {}
    for relative in sorted(paths):
        path = repo / relative
        if plain(path).st_size > 16 * 1024 * 1024:
            raise ValueError("Unexpectedly large reviewed source")
        digest = executable_sha256(path)
        if not digest:
            raise ValueError("Reviewed source could not be read consistently")
        result[relative] = digest
    return result


def discover(profile, selected=()):
    from angerona.core.eventbus import BusAuthority, EventBus
    from angerona.core.module_manager import ModuleManager
    config = configure(profile, (), ())
    bus = EventBus()
    bus.arm(BusAuthority.generate())
    manager = ModuleManager(bus, config, target_platform="windows")
    manager.discover()
    if manager.discovery_errors or manager.external_rejections:
        raise ValueError("Built-in discovery has errors; inspect private diagnostic artifacts")
    names = set(manager.modules)
    if len(names) != 86 or not AUDITED.keys() <= names:
        raise ValueError("Built-in inventory changed")
    for name, identity in AUDITED.items():
        module = manager.modules[name]
        actual = type(module).__module__ + "." + type(module).__name__
        if actual != identity or manager.module_trust.get(name, {}).get("origin") != "builtin":
            raise ValueError("Audited sensor class identity or built-in provenance differs: " + name)
    if any(getattr(module, "_thread", None) is not None
           and module._thread.is_alive() for module in manager.modules.values()):
        raise ValueError("Discovery unexpectedly started a module worker")
    config.module_states = {name: name in selected for name in sorted(names)}
    assert_config(config, names, selected)
    config.save()
    return bus, manager, config


def rows_for(manager):
    from angerona.core.platforms import availability_for
    return [dict(name=name, identity=type(module).__module__ + "." + type(module).__name__,
                 platform_available=availability_for(module, manager.platform).available,
                 capability_id=manager.module_trust.get(name, {}).get("capability_id"))
            for name, module in sorted(manager.modules.items())]


def assert_runtime_defaults(manager, selected):
    """The audit covers default providers, not arbitrary injected integrations."""
    if "AegisPath Exposure Graph Guard" in selected:
        from angerona.modules.exposure_graph_guard import unavailable_snapshot_observer
        module = manager.modules["AegisPath Exposure Graph Guard"]
        if module._snapshot_observer is not unavailable_snapshot_observer:
            raise ValueError("Exposure provider must remain the audited unavailable default")
    if "Fleet Health Monitor" in selected:
        module = manager.modules["Fleet Health Monitor"]
        if module._fabric is not None or module._tenant_id != "":
            raise ValueError("Fleet monitor must remain unbound in this local observation")
    if "App Control Decision Evidence" in selected:
        from angerona.core.app_control_evidence import DecisionCorrelator
        module = manager.modules["App Control Decision Evidence"]
        if module._source is not None or module._owns_source is not True:
            raise ValueError("App Control must retain its unopened native provider")
        cursor, pending = module._cursor, module._pending
        if cursor._authority_key is not None:
            raise ValueError("App Control must use the selected profile bus-key authority")
        profile = Path(manager.config.data_dir)
        if (cursor.path != profile / "sensor-cursors" / "app-control.json"
                or pending.path != profile / "sensor-cursors" / "app-control.pending.json"
                or pending._cursor is not cursor):
            raise ValueError("App Control checkpoints must remain in the selected private profile")
        correlator = module._correlator
        if (type(correlator) is not DecisionCorrelator
                or (correlator.ttl_seconds, correlator.max_groups,
                    correlator.max_signatures, correlator.max_decisions) != (15.0, 256, 64, 8)
                or correlator._groups or correlator._seen_records
                or module._POLL_INTERVAL != 2.0):
            raise ValueError("App Control correlation and poll defaults changed")
    for name, module in manager.modules.items():
        if name not in selected and manager.is_enabled(name):
            raise ValueError("A non-selected module became enabled: " + name)
    assert_config(manager.config, manager.modules, selected)


class Capture:
    """Bounded stream sink; loss stays counted even after the byte budget fills."""
    def __init__(self, path, limit=CAPTURE_BYTES):
        from angerona.core.engine_transport import create_private_file
        self.stream = os.fdopen(create_private_file(path), "wb")
        self.limit, self.bytes, self.dropped = limit, 0, 0
        self.kinds, self.severities = Counter(), Counter()

    def put(self, record):
        self.kinds[str(record.get("kind", "unknown"))] += 1
        if record.get("kind") == "event":
            self.severities[str(record.get("severity", "UNKNOWN"))] += 1
        encoded = canonical(record) + b"\n"
        if len(encoded) > self.limit - self.bytes:
            self.dropped += 1
            return False
        self.stream.write(encoded)
        self.bytes += len(encoded)
        return True

    def close(self):
        self.stream.flush()
        self.stream.close()


def drain_views(service, capture, cursor):
    page = service.recent(cursor=cursor, limit=200)
    if page["gap"]:
        capture.put(dict(kind="gap", reason="retained-view-loss", lost=page["gap"]))
        cursor = max(cursor, page["first_seq"] - 1)
    for record in page["records"]:
        capture.put(record)
        cursor = record["seq"]
    return cursor, cursor >= page["last_seq"]


def stop_selected(manager, selected, timeout=SHUTDOWN_SECONDS):
    """Stop only started cases; never run arbitrary unstarted stop overrides."""
    deadline = time.monotonic() + timeout
    threads = []
    errors = []
    for name in selected:
        module = manager.modules[name]
        try:
            manager.set_enabled(name, False)
        except Exception as exc:
            errors.append(type(exc).__name__ + ": disabling " + name)
            # These exact identities use the reviewed BaseModule stop signal.
            # A failed profile save must not leave their worker running merely
            # because persistence of the disabled selection failed.
            try:
                module.stop()
            except Exception as stop_error:
                errors.append(type(stop_error).__name__ + ": stop signal " + name)
        # The allowlisted workers use BaseModule generations. SpywareGuard's
        # own finally retires research/beacon helpers; explicitly retain any
        # helper that unexpectedly exists rather than declaring it stopped.
        for attribute in ("_thread", "_restart_waiter", "_report_thread", "_beacon_thread", "_provider_thread"):
            thread = getattr(module, attribute, None)
            if isinstance(thread, threading.Thread) and thread not in threads:
                threads.append(thread)
    for thread in threads:
        if thread.ident is not None:
            thread.join(max(0.0, deadline - time.monotonic()))
    pending = [thread for thread in threads if thread.is_alive()]
    return pending, errors


def preserve_pending(threads):
    """A daemon worker still owning native resources must not vanish on exit."""
    def retain():
        for thread in threads:
            thread.join()
    if threads:
        threading.Thread(target=retain, name="MatrixPendingOwnership", daemon=False).start()


def record_module_interval_health(summary, active, elapsed):
    """Retain bounded sampled coverage evidence; never grant detector authority."""
    interval = summary.setdefault("module_interval_health", {})
    for name, state in active.items():
        row = interval.setdefault(name, dict(
            samples=0, warming_samples=0, completed_samples=0, gap_samples=0,
            incomplete_after_completion_samples=0,
            minimum_health=None, last_health=None, last_health_state="unknown",
            first_sample_elapsed_seconds=elapsed, last_sample_elapsed_seconds=elapsed,
            first_completed_elapsed_seconds=None, first_gap_elapsed_seconds=None,
            last_gap_elapsed_seconds=None, first_gap_note="", last_gap_note="",
            observed_incomplete=False, observed_not_running=False,
            observed_loss=False, observed_crash=False))
        seen_complete = row["completed_samples"] > 0
        completed = (state.get("first_cycle_complete") is True
                     and type(state.get("cycle_count")) is int and state["cycle_count"] > 0)
        health = state.get("health")
        if type(health) not in (int, float) or not math.isfinite(health) or not 0 <= health <= 100:
            health = None
        health_state = str(state.get("health_state", "unknown"))[:32]
        row["samples"] += 1
        row["last_sample_elapsed_seconds"] = elapsed
        row["last_health"], row["last_health_state"] = health, health_state
        if health is not None:
            row["minimum_health"] = health if row["minimum_health"] is None else min(row["minimum_health"], health)
        if completed:
            row["completed_samples"] += 1
            if row["first_completed_elapsed_seconds"] is None:
                row["first_completed_elapsed_seconds"] = elapsed
        elif not seen_complete:
            row["warming_samples"] += 1
        else:
            row["incomplete_after_completion_samples"] += 1
        incomplete = ((completed and (health_state != "ok" or health is None or health < 90))
                      or (seen_complete and not completed))
        not_running = state.get("thread_alive") is not True or state.get("status") != "running"
        loss = isinstance(state.get("event_overflow_count"), int) and state["event_overflow_count"] > 0
        crash = isinstance(state.get("crash_count"), int) and state["crash_count"] > 0
        for key, value in (("observed_incomplete", incomplete), ("observed_not_running", not_running),
                           ("observed_loss", loss), ("observed_crash", crash)):
            row[key] = row[key] or value
        if incomplete or not_running or loss or crash:
            note = str(state.get("health_note") or "Sampled coverage/liveness/loss evidence")[:200]
            row["gap_samples"] += 1
            if row["first_gap_elapsed_seconds"] is None:
                row["first_gap_elapsed_seconds"], row["first_gap_note"] = elapsed, note
            row["last_gap_elapsed_seconds"], row["last_gap_note"] = elapsed, note


def classification(active, summary, *, expected_modules, scanner=False):
    gaps = []
    if summary.get("shutdown_pending") or not summary.get("clean_shutdown"):
        return "SHUTDOWN_PENDING", ["Owned workers or exporter did not retire cleanly"]
    if summary.get("errors"):
        gaps.append("Worker/start/observation errors")
    if (summary.get("capture_dropped") or summary.get("export_dropped")
            or summary.get("gap_records") or summary.get("scanner_drops")):
        gaps.append("Telemetry or capture loss")
    if max(summary.get("max_heartbeat_gap_seconds", 0),
           summary.get("max_observation_gap_seconds", 0),
           summary.get("max_observer_work_seconds", 0)) > 2.0:
        gaps.append("Child observation-loop heartbeat exceeded two seconds; includes observer work and scheduling")
    if summary.get("observation_deadline_overrun_seconds", 0) > 2.0:
        gaps.append("Requested observation deadline exceeded by over two seconds; native calls are cooperative")
    for name in expected_modules:
        state = active.get(name, {})
        if not state.get("first_cycle_complete") or int(state.get("cycle_count", 0)) < 1:
            gaps.append(name + ": no completed sensor cycle")
        if not state.get("thread_alive") or state.get("status") != "running":
            gaps.append(name + ": worker not running at final observation")
        if state.get("health_state") != "ok":
            gaps.append(name + ": reported health is not fully available")
        if state.get("event_overflow_count") or state.get("crash_count"):
            gaps.append(name + ": module evidence loss or crash")
        interval = summary.get("module_interval_health", {}).get(name, {})
        if interval.get("gap_samples", 0):
            gaps.append(name + ": sampled interval includes coverage, liveness or evidence-loss gaps")
    if scanner and summary.get("scanner_heartbeat_count", 0) < 2:
        gaps.append("Independent scanner heartbeat was not observed")
    if scanner and summary.get("scanner_heartbeat_error"):
        gaps.append("Independent scanner heartbeat collection reported an error")
    if summary.get("source_changed"):
        gaps.append("Source changed after the reviewed plan")
    return ("OBSERVED_WITH_GAPS" if gaps else "OBSERVED"), gaps


def stop_requested(root, run_id, case_id):
    path = root / "stop.request.json"
    if not path.exists():
        return False
    return read_private(path) == dict(schema=SCHEMA, run_id=run_id, case_id=case_id, action="stop")


def record_step(summary, label, wall_started, cpu_started):
    """Attribute observer wall time without declaring a native blocking cause."""
    wall = max(0.0, time.perf_counter() - wall_started)
    cpu = max(0.0, time.thread_time() - cpu_started)
    maximum = summary.setdefault("observer_step_maxima", {})
    if wall > maximum.get(label, {}).get("wall_seconds", -1):
        maximum[label] = {"wall_seconds": wall, "thread_cpu_seconds": cpu}


@contextmanager
def observer_step(summary, label):
    """Retain measured work even when a native step raises or requests stop."""
    wall, cpu = time.perf_counter(), time.thread_time()
    try:
        yield
    finally:
        record_step(summary, label, wall, cpu)


@contextmanager
def observation_window(summary, duration):
    """Account the terminal interval before source validation and teardown."""
    started = time.monotonic()
    observation = dict(started=started, last_loop_start=started, wake_at=None)
    summary.update(max_observer_work_seconds=0.0, max_observer_work_thread_cpu_seconds=0.0,
                   max_wakeup_delay_seconds=0.0, requested_observation_seconds=duration,
                   heartbeat_persist_interval_seconds=1.0)
    try:
        yield observation
    finally:
        ended = time.monotonic()
        terminal = max(0.0, ended - observation["last_loop_start"])
        summary.update(observation_seconds=max(0.0, ended - started),
                       max_observation_gap_seconds=max(summary.get("max_heartbeat_gap_seconds", 0.0), terminal),
                       final_observer_silence_seconds=terminal,
                       observation_deadline_overrun_seconds=max(0.0, ended - started - duration))


@contextmanager
def observer_iteration(summary, observation):
    wall, cpu = time.perf_counter(), time.thread_time()
    now = time.monotonic()
    if observation["wake_at"] is not None:
        summary["max_wakeup_delay_seconds"] = max(
            summary["max_wakeup_delay_seconds"], max(0.0, now - observation["wake_at"]))
    summary["max_heartbeat_gap_seconds"] = max(
        summary.get("max_heartbeat_gap_seconds", 0.0), now - observation["last_loop_start"])
    summary["heartbeat_count"] = summary.get("heartbeat_count", 0) + 1
    observation["last_loop_start"] = now
    try:
        yield now
    finally:
        elapsed = max(0.0, time.perf_counter() - wall)
        if elapsed > summary["max_observer_work_seconds"]:
            summary["max_observer_work_seconds"] = elapsed
            summary["max_observer_work_thread_cpu_seconds"] = max(0.0, time.thread_time() - cpu)


def child(args, repo, run_root):
    from angerona.core.engine_transport import verify_private
    from angerona.core.privilege import is_admin
    if not args.run or is_admin():
        raise ValueError("Child runtime requires explicit --run and an ordinary user")
    root = run_root / args.child
    for path in (run_root, root, root / "data"):
        verify_private(path, directory=True)
    install_environment(repo, root / "data")
    plan = read_private(run_root / "plan.json")
    case = next((case for case in plan["cases"] if case["id"] == args.child), None)
    selected = validate_case(case)
    if plan.get("run_id") != args.run_id or plan.get("duration_seconds") != args.duration:
        raise ValueError("Child plan identity or duration differs")
    bus = manager = service = scanner = scanner_thread = scanner_reader = None
    scanner_counter = None
    capture = Capture(root / "views.jsonl")
    summary = dict(schema=SCHEMA, case_id=case["id"], run_id=args.run_id,
                   kind="case-result", errors=[], clean_shutdown=False,
                   shutdown_pending=False, max_heartbeat_gap_seconds=0.0,
                   heartbeat_count=0, scanner_heartbeat_count=0, normal_exit=False)
    active, cursor, pending = {}, 0, []
    started = time.monotonic()
    try:
        bus, manager, config = discover(root / "data", selected)
        if source_snapshot(repo, manager.modules) != plan["source_snapshot"]:
            raise ValueError("Reviewed source changed since plan creation; generate a new plan")
        assert_runtime_defaults(manager, selected)
        from angerona.core.live_debug import LiveDebugService, sanitize_text
        import psutil
        own = psutil.Process()
        birth = own.create_time()
        service = LiveDebugService(bus, root / "data", enabled=True)
        if not service.start():
            raise RuntimeError("Diagnostic exporter failed to start: " + service.status()["error"])
        for name in selected:
            if manager.start_if_enabled(manager.modules[name]) is not True:
                raise RuntimeError("Manager refused audited worker: " + name)
        if case["mode"] == "scanner":
            from angerona.resilience.scanner import ScannerHost
            from angerona.resilience.heartbeat import HeartbeatReader
            scanner = ScannerHost(interval=1.0, ring_name="matrix-telemetry")
            scanner_reader = HeartbeatReader("scanner")
            def run_scanner():
                try:
                    scanner.run()
                except BaseException as exc:
                    summary["errors"].append("ScannerHost: " + type(exc).__name__)
            scanner_thread = threading.Thread(target=run_scanner, name="MatrixRawScanner", daemon=False)
            scanner_thread.start()
        write_private(root / "ready.json", dict(schema=SCHEMA, run_id=args.run_id,
                      case_id=case["id"], pid=os.getpid(), birth=birth,
                      endpoint=service.status()["endpoint"], modules=list(selected)))
        last_heartbeat_write = float("-inf")
        cpu_start = own.cpu_times()
        with observation_window(summary, args.duration) as observation:
            observed_at = observation["started"]
            summary["startup_seconds"] = observed_at - started
            while time.monotonic() - observed_at < args.duration:
                with observer_iteration(summary, observation) as now:
                    with observer_step(summary, "cached_module_views"):
                        active = {name: manager.modules[name].operational_snapshot() for name in selected}
                        for state in active.values():
                            state["health_note"] = sanitize_text(state.get("health_note", ""), 500)
                            evidence = state.get("health_evidence")
                            if isinstance(evidence, dict) and isinstance(evidence.get("reason"), str):
                                evidence["reason"] = sanitize_text(evidence["reason"], 500)
                        record_module_interval_health(summary, active, now - observed_at)
                    with observer_step(summary, "scanner_receipt"):
                        if scanner is not None:
                            # Host ring counters are additive; never copy raw command lines.
                            summary["scanner_events"] = scanner._events
                            summary["scanner_drops"] = scanner._dropped
                            try:
                                beat = scanner_reader.read()
                                if (beat and scanner_reader.authentication_status(record=beat) == "authenticated"
                                        and beat["pid"] == os.getpid() and beat["flags"] == 1
                                        and beat["counter"] != scanner_counter):
                                    summary["scanner_heartbeat_count"] += 1
                                    scanner_counter = beat["counter"]
                            except Exception as exc:
                                if "scanner_heartbeat_error" not in summary:
                                    summary["scanner_heartbeat_error"] = type(exc).__name__
                    with observer_step(summary, "capture_drain"):
                        cursor, _ = drain_views(service, capture, cursor)
                    # Observe every 250 ms; private progress snapshots are
                    # advisory and volatile, unlike identity/result records.
                    if now - last_heartbeat_write >= 1.0:
                        with observer_step(summary, "heartbeat_persistence"):
                            write_private(root / "heartbeat.json", dict(schema=SCHEMA, pid=os.getpid(), birth=birth,
                                          elapsed_seconds=now - observed_at, modules=active,
                                          count=summary["heartbeat_count"],
                                          max_gap=summary["max_heartbeat_gap_seconds"]), durable=False)
                        last_heartbeat_write = time.monotonic()
                        summary.update(last_heartbeat_payload_elapsed_seconds=now - observed_at,
                                       last_heartbeat_persistence_completed_elapsed_seconds=last_heartbeat_write - observed_at)
                    with observer_step(summary, "owned_stop_check"):
                        if stop_requested(root, args.run_id, case["id"]):
                            summary["stop_reason"] = "owned-stop-request"
                            break
                observation["wake_at"] = time.monotonic() + 0.25
                time.sleep(0.25)
        summary.setdefault("stop_reason", "case-deadline")
        cpu_end = own.cpu_times()
        memory = own.memory_info()
        summary.update(observation_cpu_seconds=max(0, cpu_end.user + cpu_end.system - cpu_start.user - cpu_start.system),
                       total_process_cpu_seconds=cpu_end.user + cpu_end.system,
                       rss_bytes=memory.rss, peak_rss_bytes=getattr(memory, "peak_wset", memory.rss))
        summary["source_changed"] = source_snapshot(repo, manager.modules) != plan["source_snapshot"]
    except BaseException as exc:
        from angerona.core.live_debug import sanitize_text
        summary["errors"].append(type(exc).__name__ + ": " + sanitize_text(str(exc), 500))
    finally:
        if scanner is not None:
            scanner.stop()
        if manager is not None:
            pending, errors = stop_selected(manager, selected)
            summary["errors"].extend(errors)
        if scanner_thread is not None:
            scanner_thread.join(SHUTDOWN_SECONDS)
            if scanner_thread.is_alive():
                pending.append(scanner_thread)
            summary["scanner_events"] = scanner._events
            summary["scanner_drops"] = scanner._dropped
        if service is not None:
            clean_export = service.stop(timeout=3.0)
            for _ in range(15):  # Bounded final history snapshot, including stop gaps.
                cursor, done = drain_views(service, capture, cursor)
                if done:
                    break
            summary["export_dropped"] = service.status()["queue_dropped"]
            summary["export_status"] = service.status()
        else:
            clean_export = True
        summary.update(shutdown_pending=bool(pending) or not clean_export,
                       clean_shutdown=not pending and clean_export,
                       capture_dropped=capture.dropped, capture_bytes=capture.bytes,
                       gap_records=capture.kinds["gap"], event_severities=dict(capture.severities),
                       pending_threads=[thread.name for thread in pending], active_modules=active,
                       elapsed_seconds=time.monotonic() - started,
                       coverage_scope="Ordinary-user audited workers; no GUI/Qt responsiveness, no host security verdict")
        summary["state"], summary["coverage_gaps"] = classification(
            active, summary, expected_modules=selected, scanner=case["mode"] == "scanner")
        summary["normal_exit"] = summary["clean_shutdown"]  # Parent must still prove real exit code.
        write_private(root / "result.json", summary)
        capture.close()
        preserve_pending(pending)
        logging.shutdown()
    return 0 if summary["clean_shutdown"] and not summary["errors"] else 4


def prove_child(process, ready, args):
    import psutil
    pid, birth = ready.get("pid"), ready.get("birth")
    if type(pid) is not int or type(birth) not in (int, float) or not math.isfinite(birth):
        raise ValueError("Invalid owned child identity")
    own = psutil.Process(pid)
    ancestry = {ancestor.pid for ancestor in own.parents()}
    if pid != process.pid and process.pid not in ancestry:
        raise ValueError("Ready PID is not the owned launcher or a current descendant")
    if own.create_time() != birth:
        raise ValueError("Owned child birth time changed")
    command = own.cmdline()
    if str(Path(__file__).resolve()) not in command or args.run_id not in command or "--child" not in command:
        raise ValueError("Ready child does not match this exact source harness/run")
    from angerona.core.live_debug import LiveDebugClient
    client = LiveDebugClient(ready["endpoint"], expected_pid=pid, expected_birth=birth)
    try:
        client.connect(timeout=3.0)  # OS-owned pipe PID + creation-time proof, not a claimed PID.
    finally:
        client.close()
    return dict(pid=pid, birth=birth, launcher_pid=process.pid)


def owned_identity_exited(identity):
    """A reaped venv launcher alone does not prove its real core has exited."""
    if not isinstance(identity, dict):
        return False
    import psutil
    try:
        return psutil.Process(identity["pid"]).create_time() != identity["birth"]
    except psutil.NoSuchProcess:
        return True
    except (psutil.AccessDenied, KeyError, TypeError, ValueError):
        return False


def supervise_case(args, repo, run_root, case):
    from angerona.core.engine_transport import private_directory
    from angerona.core.live_debug import sanitize_text
    selected = validate_case(case)
    root = run_root / case["id"]
    exclusive_directory(root)
    for path in (root / "data", root / "data" / "tmp", root / "data" / "diagnostics", root / "data" / "logs"):
        private_directory(path)
    arguments = [str(args.python), "-I", "-B", str(Path(__file__).resolve()), "--repo", str(repo),
                 "--python", str(args.python), "--run-id", args.run_id, "--duration", str(args.duration),
                 "--run", "--child", case["id"]]
    process = subprocess.Popen(arguments, cwd=repo, env=environment(repo, root / "data"),
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    console = Capture(root / "console.jsonl", limit=512 * 1024)
    def drain_console():
        # Fixed byte reads: a newline-free child cannot create an unbounded line.
        while raw := process.stdout.read(4096):
            console.put(dict(kind="console", text=sanitize_text(raw.decode("utf-8", "replace"), 4096)))
    drain = threading.Thread(target=drain_console, name="MatrixConsole", daemon=True)
    drain.start()
    identity = None
    errors = []
    deadline = time.monotonic() + STARTUP_SECONDS + args.duration + SHUTDOWN_SECONDS + 8
    stop_sent = False
    try:
        while process.poll() is None and time.monotonic() < deadline:
            if identity is None and (root / "ready.json").exists():
                ready = read_private(root / "ready.json")
                if ready.get("run_id") != args.run_id or ready.get("case_id") != case["id"] or ready.get("modules") != list(selected):
                    raise ValueError("Owned child ready contract differs")
                identity = prove_child(process, ready, args)
                write_private(root / "owned-identity.json", identity)
            if (root / "result.json").exists():
                result = read_private(root / "result.json")
                if result.get("shutdown_pending"):
                    errors.append("Child reported native shutdown still pending")
                    break
            time.sleep(0.1)
    except (Exception, KeyboardInterrupt) as exc:
        errors.append(type(exc).__name__ + ": " + sanitize_text(str(exc), 240))
    finally:
        if process.poll() is None:
            write_private(root / "stop.request.json", dict(schema=SCHEMA, run_id=args.run_id,
                          case_id=case["id"], action="stop"))
            stop_sent = True
            try:
                process.wait(timeout=SHUTDOWN_SECONDS + 5)
            except subprocess.TimeoutExpired:
                errors.append("Owned process has not exited; matrix aborted, no forced termination")
        drain.join(timeout=1.0)
        if not drain.is_alive():
            process.stdout.close()
            console.close()
        else:
            errors.append("Owned console still open; child/descendant lifetime unresolved")
    result = read_private(root / "result.json") if (root / "result.json").exists() else {}
    exit_code = process.poll()
    if identity is None:
        errors.append("Actual child PID/birth/pipe ownership was not proven")
    core_exited = owned_identity_exited(identity)
    if identity is not None and not core_exited:
        errors.append("Real owned core lifetime remains unresolved after launcher observation")
    if (result.get("schema") != SCHEMA or result.get("run_id") != args.run_id
            or result.get("case_id") != case["id"]):
        errors.append("Final case evidence is absent or has a different identity")
    if exit_code is None or exit_code != 0 or errors:
        state = "UNRESOLVED" if exit_code is None else "FAILED"
    else:
        state = result.get("state", "UNKNOWN")
    report = dict(schema=SCHEMA, case_id=case["id"], state=state, identity=identity,
                  launcher_pid=process.pid, exit_code=exit_code, owned_stop_requested=stop_sent,
                  errors=errors, result=result, console_dropped=console.dropped,
                  actual_core_exit_proven=core_exited,
                  normal_exit=exit_code == 0 and result.get("normal_exit") is True
                  and core_exited and not errors and not drain.is_alive(),
                  next_case_allowed=exit_code is not None and core_exited and not drain.is_alive())
    write_private(root / "supervisor.json", report)
    return report


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--python", type=Path, required=True)
    parser.add_argument("--run-id", default=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + secrets.token_hex(3))
    parser.add_argument("--duration", type=int, default=15, help="Observation seconds per case, 5..3600")
    parser.add_argument("--case", action="append", default=[], help="Exact eligible plan case ID; repeat for selected cases")
    parser.add_argument("--max-cases", type=int, default=128, help="Maximum selected cases, 1..128")
    parser.add_argument("--run", action="store_true", help="Actually start reviewed runtime cases")
    parser.add_argument("--child", default="", help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    if os.name != "nt":
        raise ValueError("This harness currently supports Windows source observation only")
    if not args.repo.is_absolute() or not args.python.is_absolute():
        raise ValueError("--repo and --python must be explicit absolute paths")
    if args.child and (not args.run or not re.fullmatch(r"[a-z0-9-]{1,150}", args.child)):
        raise ValueError("Child mode requires explicit --run and a fixed case ID")
    repo = args.repo.resolve(strict=True)
    script = Path(__file__).resolve(strict=True)
    if (not script.is_relative_to(repo) or not (repo / "src" / "angerona").is_dir()
            or args.python.resolve(strict=True) != (repo / "venv" / "Scripts" / "python.exe").resolve(strict=True)
            or Path(sys.executable).resolve(strict=True) != args.python.resolve(strict=True)):
        raise ValueError("Harness/interpreter must belong to this actual source checkout")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", args.run_id):
        raise ValueError("Invalid bounded run ID")
    if not 5 <= args.duration <= 3600 or not 1 <= args.max_cases <= 128:
        raise ValueError("Duration/case count exceeds reviewed limits")
    sys.dont_write_bytecode = True
    sys.path[:0] = [str(repo / "src"), str(repo)]
    from angerona.core.privilege import is_admin
    if is_admin():
        raise ValueError("Refusing elevated mutable source observation, including plan-only discovery")
    parent = repo / ".tmp" / "module-observation-matrix"
    plain(repo, directory=True)
    plain(repo / ".tmp", directory=True)
    from angerona.core.engine_transport import private_directory
    if args.child:
        plain(parent, directory=True)
    else:
        private_directory(parent)
    run_root = parent / ("run-" + args.run_id)
    install_environment(repo, (run_root / args.child / "data") if args.child else run_root / "data")
    if args.child:
        return child(args, repo, run_root)
    exclusive_directory(run_root)  # Existing profiles are never reused or overwritten.
    for path in (run_root / "data", run_root / "data" / "tmp", run_root / "data" / "logs", run_root / "data" / "diagnostics"):
        private_directory(path)
    _bus, manager, _config = discover(run_root / "data")
    rows = rows_for(manager)
    plan = dict(schema=SCHEMA, run_id=args.run_id, duration_seconds=args.duration,
                repo=str(repo), python=str(args.python), cases=make_cases(rows), inventory=rows,
                source_snapshot=source_snapshot(repo, manager.modules),
                limitations=["Only individually audited default sensor paths; other runtime/self-test cases are HELD",
                             "No GUI/Qt responsiveness measurement, no host security verdict",
                             "Native calls and cooperative shutdown cannot be force-deadlined",
                             "Ordinary-user coverage and fresh unapproved integrity baseline may be degraded",
                             "LiveDebug free-text redaction is best effort; artifacts are private",
                             "Full first-party Python source hashes detect edits since this plan, not an independent trusted build or dependency/data attestation"])
    selected = select_cases(plan, args.case, args.max_cases)
    plan["selected_cases"] = [case["id"] for case in selected]
    write_private(run_root / "plan.json", plan)
    logging.shutdown()
    print(json.dumps(dict(plan=str(run_root / "plan.json"), run=args.run,
                          eligible=sum(case["disposition"] == "ELIGIBLE" for case in plan["cases"]),
                          held=sum(case["disposition"] == "HELD" for case in plan["cases"]),
                          selected_count=len(selected),
                          selected=plan["selected_cases"] if args.case else "all eligible"), ensure_ascii=True))
    if not args.run:
        return 0
    reports = []
    for case in selected:
        report = supervise_case(args, repo, run_root, case)
        reports.append(report)
        write_private(run_root / "matrix.json", dict(schema=SCHEMA, run_id=args.run_id,
                      reports=reports, complete=len(reports) == len(selected),
                      held_cases=[case["id"] for case in plan["cases"] if case["disposition"] == "HELD"],
                      note="Observation evidence only; no automatic fixes, approval or host security conclusion"))
        print(json.dumps(dict(case=case["id"], state=report["state"], exit_code=report["exit_code"])))
        if not report["next_case_allowed"]:
            return 5
    return 0 if all(report["normal_exit"] for report in reports) else 4


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt) as error:
        print(type(error).__name__ + ": " + str(error)[:400], file=sys.stderr)
        raise SystemExit(2) from None
