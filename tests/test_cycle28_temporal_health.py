from __future__ import annotations

from pathlib import Path

from angerona.core.temporal_tradecraft import TemporalAssessment
from angerona.modules.temporal_tradecraft_correlator import (
    TemporalTradecraftCorrelatorModule,
)


def _assessment(state: str, persistence: str = "authenticated") -> TemporalAssessment:
    return TemporalAssessment(
        state=state,
        reason=f"fixture-{state}",
        findings=(),
        missing_steps=(),
        retained_signals=2,
        dropped_signals=1 if state == "overflow" else 0,
        persistence_status=persistence,
        response_authorized=False,
    )


def test_live_temporal_assessment_drives_module_health(tmp_path: Path) -> None:
    module = TemporalTradecraftCorrelatorModule(
        data_root=tmp_path,
        master_key=b"T" * 32,
    )

    module._publish_assessment(_assessment("missing"))
    assert module.health == 55
    assert "state=missing" in module.health_note
    assert module.health_evidence["source_path"].endswith(
        "temporal_tradecraft_correlator.py"
    )

    module._publish_assessment(_assessment("overflow"))
    assert module.health == 35
    module._publish_assessment(_assessment("blind", "untrusted"))
    assert module.health == 20

    module._publish_assessment(_assessment("observing"))
    assert module.health == 100
    assert module.health_evidence is None


def test_unavailable_restart_custody_caps_otherwise_live_assessment(
    tmp_path: Path,
) -> None:
    module = TemporalTradecraftCorrelatorModule(
        data_root=tmp_path,
        master_key=b"T" * 32,
    )
    module._publish_assessment(_assessment("observing", "unavailable"))
    assert module.health == 35
    assert "persistence=unavailable" in module.health_note
