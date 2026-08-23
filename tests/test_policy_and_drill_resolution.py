from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from angerona.core import drill_resolution, process_allowlist, report_attest
from angerona.core.eventbus import Event, Severity
from angerona.modules.posture_hardening import PostureHardening
from angerona.modules.file_integrity import (
    register_runtime_watch, unregister_runtime_watch, watch_roots,
)
from angerona.shark.aar_report import _matches


class ProcessAllowlistTests(unittest.TestCase):
    def test_exact_path_and_name_policy(self):
        with tempfile.TemporaryDirectory() as td:
            data = Path(td)
            process_allowlist.add(path=r"C:\Program Files\Proton\ProtonVPN.Client.exe",
                                  data_dir=data)
            self.assertTrue(process_allowlist.is_allowed(
                "ProtonVPN.Client.exe",
                r"C:\Program Files\Proton\ProtonVPN.Client.exe", data))
            self.assertFalse(process_allowlist.is_allowed(
                "ProtonVPN.Client.exe", r"C:\Temp\ProtonVPN.Client.exe", data))
            process_allowlist.add(name="ProtonVPNService.exe", data_dir=data)
            self.assertTrue(process_allowlist.is_allowed("protonvpnservice.EXE", data_dir=data))
            self.assertFalse(process_allowlist.is_allowed(
                "ProtonVPNService.exe", r"C:\Temp\ProtonVPNService.exe", data))
            event = Event("Memory Injection Scanner", "test", Severity.HIGH,
                          details={"proc_name": "ProtonVPNService.exe"})
            self.assertTrue(process_allowlist.is_event_allowed(event, data))
            path_rich_event = Event(
                "Memory Injection Scanner", "test", Severity.HIGH,
                details={"proc_name": "ProtonVPNService.exe",
                         "exe": r"C:\Temp\ProtonVPNService.exe"})
            self.assertFalse(process_allowlist.is_event_allowed(path_rich_event, data))


class DrillResolutionTests(unittest.TestCase):
    def test_resolution_is_historical_and_run_scoped(self):
        with tempfile.TemporaryDirectory() as td:
            data = Path(td)
            (data / "bus.key").write_text(bytes(range(32)).hex(), encoding="ascii")
            now = time.time()
            drill_resolution.resolve(
                [{"mitre": "T1059", "name": "Benign Execution"}],
                run_id="run-one", data_dir=data, resolved_at=now)
            old = Event("Posture Hardening",
                        "NEW WEAKNESS (Red Team): Benign Execution (T1059) slipped past detection",
                        Severity.HIGH, ts=now - 1, details={"mitre": "T1059"})
            future = Event(old.module, old.message, old.severity, ts=now + 1,
                           details=old.details)
            self.assertTrue(drill_resolution.is_resolved_event(old, data))
            self.assertFalse(drill_resolution.is_resolved_event(future, data))
            self.assertTrue(drill_resolution.already_resolved("T1059", "run-one", data))
            self.assertFalse(drill_resolution.already_resolved("T1059", "run-two", data))

    def test_posture_uses_deterministic_drill_resolution(self):
        with tempfile.TemporaryDirectory() as td:
            data = Path(td)
            report_path = data / "redteam_aar.json"
            key_path = data / "bus.key"
            key_path.write_text(bytes(range(32)).hex(), encoding="ascii")
            original_key_path = report_attest._key_path
            report_attest._key_path = lambda: key_path
            self.addCleanup(setattr, report_attest, "_key_path", original_key_path)
            report_attest.write_signed_json(report_path, {
                "run_id": "run-one",
                "verdicts": [{
                    "stage": "Credential Access (simulated)",
                    "technique": "T1003 marker",
                    "description": "inert process marker",
                    "ts_start": time.time(),
                    "category": "detection",
                    "caught": False,
                }],
            })
            module = PostureHardening(data)
            self.assertEqual(len(module.ingest_redteam_report(report_path)), 1)
            weakness = module.weaknesses("VULNERABLE")[0]
            self.assertEqual(weakness["source"], "redteam")
            self.assertFalse(module.generate_remediation("T1003")["ok"])
            result = module.resolve_redteam_report(report_path)
            self.assertTrue(result["ok"])
            self.assertEqual(result["candidates"], 1)
            self.assertTrue(result["verification_required"])
            self.assertEqual(module.weaknesses()[0]["status"], "VULNERABLE")
            self.assertEqual(module.ingest_redteam_report(report_path), [])

            # Installing a candidate must not certify its own fix. A later run
            # carrying a real detector echo is the only PATCHED transition.
            lifecycle = drill_resolution.resolution_snapshot(data)["t1003"]
            proof = drill_resolution.verify_detector_evidence(
                "T1003",
                "run-two",
                detector="Purple Remediation Guard",
                event_ts=time.time() + 1,
                event_details={"mitre": "T1003", "artifact_path": "inert-marker",
                               "detector_policy": "reviewed-redteam-candidate"},
                data_dir=data,
                expected_contract_id=lifecycle["contract_id"],
                expected_contract_digest=lifecycle["contract_digest"],
            )
            self.assertTrue(proof["ok"])
            report_attest.write_signed_json(report_path, {
                "run_id": "run-two",
                "verdicts": [{
                    "stage": "Credential Access (simulated)",
                    "technique": "T1003 marker",
                    "description": "inert process marker",
                    "ts_start": time.time(),
                    "category": "detection",
                    "caught": True,
                    "detected_by": "Purple Remediation Guard",
                    "action_contract_id": lifecycle["contract_id"],
                    "action_contract_digest": lifecycle["contract_digest"],
                }],
            })
            self.assertEqual(module.ingest_redteam_report(report_path), [])
            self.assertEqual(module.weaknesses()[0]["status"], "PATCHED")

    def test_runtime_fim_target_and_process_pid_correlation(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "custom-drill-sandbox"
            self.assertTrue(register_runtime_watch(target))
            normalized = {str(Path(root)).casefold() for root in watch_roots()}
            self.assertIn(str(target).casefold(), normalized)
            unregister_runtime_watch(target)
            normalized = {str(Path(root)).casefold() for root in watch_roots()}
            self.assertNotIn(str(target).casefold(), normalized)

        event = Event("Telemetry Scanner", "process_creation: cmd.exe",
                      Severity.INFO, details={"pid": 4242,
                                              "proc_name": "cmd.exe"})
        step = {"artifact_paths": [], "pid": 4100, "pids": [4100, 4242],
                "correlation_tokens": ["ANGERONA_REDTEAM_abc123"]}
        self.assertFalse(_matches(step, event))
        tagged = Event("Telemetry Scanner", "process_creation: cmd.exe",
                       Severity.INFO, details={"pid": 4242,
                                               "proc_name": "cmd.exe",
                                               "cmdline": "cmd /c rem ANGERONA_REDTEAM_abc123"})
        self.assertTrue(_matches(step, tagged))


if __name__ == "__main__":
    unittest.main()
