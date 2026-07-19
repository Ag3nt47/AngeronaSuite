import time

from angerona.core.eventbus import Event, Severity
from angerona.shark.aar_report import evaluate, render


def test_fresh_purple_detection_and_correlated_soar_action_change_scorecard():
    started = time.time()
    path = r"C:\AngeronaTest\runtime-data\drill-sandbox\_redteam_lsass_dump_abcd.txt"
    history = {
        "run_id": "fresh-proof-run",
        "generated": "test",
        "steps": [{
            "stage": "Credential Access (simulated)",
            "technique": "T1003 marker",
            "description": "inert credential marker",
            "ts_start": started,
            "ts_end": started + 0.1,
            "ok": True,
            "artifact_paths": [path],
        }],
    }
    catch = Event(
        "Purple Remediation Guard", "exact candidate detected", Severity.HIGH,
        started + 0.2, {"path": path, "artifact_path": path, "mitre": "T1003"})
    action = Event(
        "Active Response SOAR", "artifact removed", Severity.HIGH,
        started + 0.3, {"path": path, "trigger_ts": catch.ts, "mitigated": True})

    verdicts = evaluate(history, [catch, action], {
        "Credential Access (simulated)": "detection"})

    assert verdicts[0].catch is catch
    assert verdicts[0].remediation is action
    report = render(history, verdicts, "RED TEAM ATTACK")
    assert "Response success   : 1/1" in report
    assert "Detector fixes proven by rerun: 1" in report
