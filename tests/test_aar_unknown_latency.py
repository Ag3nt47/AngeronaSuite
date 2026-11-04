from __future__ import annotations

import pytest

from angerona.core.eventbus import Event, Severity
from angerona.shark import aar_report


@pytest.mark.parametrize("latency", [None, float("nan"), float("inf"), -1.0, True, 10**1000])
@pytest.mark.parametrize("branch", ["native", "simulation", "observation", "observation-only", "response"])
def test_unknown_latency_is_displayed_without_mutating_evidence_or_scoring(latency, branch):
    catch = Event("fixture detector", "original event", Severity.MEDIUM)
    response = Event("Adversary Combat", "original response", Severity.INFO)
    verdict = aar_report.StepVerdict("Initial Access", "fixture", "rendering-only fixture", 1.0, True)
    if branch == "native":
        verdict.catch = verdict.native_catch = catch
        verdict.native_latency = latency
    elif branch == "simulation":
        verdict.catch = verdict.simulation_validation = catch
        verdict.simulation_validation_latency = latency
    elif branch == "observation":
        verdict.catch = catch
        verdict.observation = response
        verdict.observation_latency = latency
    elif branch == "observation-only":
        verdict.observation = catch
        verdict.observation_latency = latency
    else:
        verdict.catch = catch
        verdict.remediation = response
        verdict.remediation_latency = latency
    verdict.catch_latency = latency
    before = dict(verdict.__dict__)
    text = aar_report.render({"run_id": "render-fixture", "kind": "shark", "status": "completed",
                              "steps": [], "campaign": {}}, [verdict])
    assert "unknown latency" in text
    assert "nans" not in text.lower() and "infs" not in text.lower()
    assert verdict.__dict__ == before
    assert verdict.ok is True and not verdict.target_containment_verified
    assert not verdict.finding_resolved


def test_only_actual_finite_latency_measurements_enter_timing_summary():
    event = Event("fixture", "positive", Severity.MEDIUM)
    known = aar_report.StepVerdict("Initial Access", "known", "fixture", 1.0, True,
        catch=event, native_catch=event, native_latency=1.25, catch_latency=1.25)
    unknown = aar_report.StepVerdict("Initial Access", "unknown", "fixture", 1.0, True,
        catch=event, native_catch=event, native_latency=None, catch_latency=float("nan"))
    text = aar_report.render({"run_id": "render-fixture", "kind": "shark", "status": "completed",
                              "steps": [], "campaign": {}}, [known, unknown])
    assert "Avg detect time    : 1.25s" in text
    assert "unknown for 1 recorded verdict(s)" in text
