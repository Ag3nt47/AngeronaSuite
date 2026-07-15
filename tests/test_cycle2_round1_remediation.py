from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from angerona.core.eventbus import Event, Severity
from angerona.core.storage import FlightRecorder
from angerona.shark.aar_report import _matches, evaluate


class AARCorrelationTests(unittest.TestCase):
    def test_basename_and_bare_pid_are_not_detection_evidence(self):
        step = {
            "artifact_paths": [r"D:\drill\unique-marker.txt"],
            "pid": 4242,
            "pids": [4242],
            "correlation_tokens": ["ANGERONA_REDTEAM_abcd1234"],
        }
        basename = Event("Scanner", "saw unique-marker.txt", Severity.HIGH,
                         details={"path": r"D:\other\unique-marker.txt"})
        bare_pid = Event("Telemetry", "ordinary process", Severity.HIGH,
                         details={"pid": 4242})
        tagged_pid = Event("Telemetry", "tagged process", Severity.HIGH,
                           details={"pid": 4242,
                                    "cmdline": "cmd /c rem ANGERONA_REDTEAM_abcd1234"})
        exact_path = Event("Scanner", "marker", Severity.HIGH,
                           details={"path": r"D:\drill\unique-marker.txt"})
        self.assertFalse(_matches(step, basename))
        self.assertFalse(_matches(step, bare_pid))
        self.assertTrue(_matches(step, tagged_pid))
        self.assertTrue(_matches(step, exact_path))

    def test_step_window_and_trigger_timestamp_are_bound(self):
        history = {"run_id": "run-1", "steps": [
            {"stage": "one", "technique": "T1", "description": "one",
             "ts_start": 100.0, "ts_end": 101.0,
             "artifact_paths": [r"D:\drill\one.txt"]},
            {"stage": "two", "technique": "T2", "description": "two",
             "ts_start": 110.0, "ts_end": 111.0,
             "artifact_paths": [r"D:\drill\two.txt"]},
        ]}
        catch = Event("FIM", "exact", Severity.HIGH, ts=102.0,
                      details={"path": r"D:\drill\one.txt"})
        unrelated = Event("FIM", "late repeated path", Severity.HIGH, ts=112.0,
                          details={"path": r"D:\drill\one.txt"})
        wrong_remediation = Event("Active Response SOAR", "other", Severity.HIGH,
                                  ts=103.0, details={"trigger_ts": 999.0})
        remediation = Event("Active Response SOAR", "rolled back", Severity.HIGH,
                            ts=104.0, details={"trigger_ts": 102.0})
        verdicts = evaluate(history, [catch, unrelated, wrong_remediation, remediation],
                            {"one": "detection", "two": "detection"})
        self.assertIs(verdicts[0].catch, catch)
        self.assertIs(verdicts[0].remediation, remediation)
        self.assertIsNone(verdicts[1].catch)


class SeverityRetentionTests(unittest.TestCase):
    def test_info_flood_does_not_evict_critical_and_bound_is_hard(self):
        with tempfile.TemporaryDirectory() as td:
            recorder = FlightRecorder(Path(td) / "events.db")
            recorder.MAX_ROWS = 10
            recorder.PRUNE_EVERY = 1
            try:
                recorder.record(Event("Detector", "critical-evidence", Severity.CRITICAL))
                for index in range(30):
                    recorder.record(Event("Telemetry", f"noise-{index}", Severity.INFO))
                events = recorder.recent(100)
                self.assertLessEqual(len(events), 10)
                self.assertIn("critical-evidence", {event.message for event in events})

                for index in range(12):
                    recorder.record(Event("Detector", f"critical-{index}", Severity.CRITICAL))
                self.assertLessEqual(len(recorder.recent(100)), 10)
            finally:
                recorder.close()


if __name__ == "__main__":
    unittest.main()
