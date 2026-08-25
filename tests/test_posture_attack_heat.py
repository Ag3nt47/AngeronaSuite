from __future__ import annotations

from types import SimpleNamespace

from angerona.core import attack_tracker, posture


def test_attack_penalty_reads_snapshot_matrix(monkeypatch) -> None:
    tracker = SimpleNamespace(snapshot=lambda: {
        "generated": "2026-08-25T00:00:00",
        "matrix": {
            "T1003": {"heat": 0.5},
            "T1055": {"heat": 0.16},
            "T1071": {"heat": 0.15},
        },
        "summary": {"techniques_active": 3},
    })
    monkeypatch.setattr(attack_tracker, "get_tracker", lambda: tracker)

    assert posture._attack_penalty() == 2


def test_attack_penalty_fails_closed_on_malformed_matrix(monkeypatch) -> None:
    tracker = SimpleNamespace(snapshot=lambda: {"matrix": ["not", "a", "mapping"]})
    monkeypatch.setattr(attack_tracker, "get_tracker", lambda: tracker)

    assert posture._attack_penalty() == 0
