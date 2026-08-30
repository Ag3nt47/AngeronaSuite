from __future__ import annotations

from pathlib import Path

from angerona.modules import posture_hardening


def test_untrusted_technique_text_never_becomes_a_path_component(
    tmp_path: Path,
) -> None:
    module = posture_hardening.PostureHardening(data_dir=tmp_path)
    staged = Path(module._stage_placeholder("../../outside", "hostile id"))

    assert staged.parent == module.remediations.resolve()
    assert staged.name.startswith("RT-")
    assert staged.suffixes == [".advisory", ".md"]
    assert ".." not in staged.name
    assert not (tmp_path.parent / "outside.advisory.md").exists()


def test_invalid_technique_is_recorded_under_deterministic_safe_id(
    tmp_path: Path,
) -> None:
    module = posture_hardening.PostureHardening(data_dir=tmp_path)
    module.record_weakness("../T1003/escape", "unsafe", "High")
    first = module.weaknesses()[0]["mitre_id"]

    assert first.startswith("RT-")
    assert "/" not in first and "\\" not in first and ".." not in first
    assert posture_hardening._safe_technique_id("../T1003/escape") == first


def test_standard_attack_id_is_preserved() -> None:
    assert posture_hardening._safe_technique_id("t1546.003 marker") == "T1546.003"


def test_missing_posture_evidence_is_unknown_not_clean(tmp_path: Path) -> None:
    module = posture_hardening.PostureHardening(data_dir=tmp_path)

    snapshot = module.operational_snapshot()
    assert snapshot["health"] == 55
    assert "cannot be established from missing evidence" in str(snapshot["health_note"])
    assert snapshot["health_evidence"]["source_path"].endswith("posture_hardening.py")


def test_fresh_and_stale_trusted_posture_evidence_are_distinct(
    tmp_path: Path, monkeypatch
) -> None:
    module = posture_hardening.PostureHardening(data_dir=tmp_path)
    module._record_trusted_evidence("redteam", 13)
    module._recompute_health()
    assert module.health == 100
    assert "13 verdicts" in module.health_note

    current = posture_hardening.time.time()
    monkeypatch.setattr(posture_hardening.time, "time", lambda: current + 25 * 3600)
    module._recompute_health()
    assert module.health == 75
    assert "stale" in module.health_note
