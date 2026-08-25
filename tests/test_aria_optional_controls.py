from __future__ import annotations

import json
import inspect

from angerona.connectors.hand_controls import HandControls
from angerona.core.config import Config
from angerona.core.conversation_awareness import ConversationAwareness
from angerona.core.self_installer import CAPABILITIES
from angerona.gui.setup_wizard import SETUP_PROFILES, STEPS


OPTIONAL_ARIA_SWITCHES = (
    "aria_enabled",
    "perf_governor_enabled",
    "aria_voice_enabled",
    "aria_conversation_awareness",
    "aria_always_listen",
    "aria_hand_controls",
)


def test_every_aria_surface_and_sensor_is_off_by_default() -> None:
    config = Config()
    assert all(getattr(config, key) is False for key in OPTIONAL_ARIA_SWITCHES)
    assert config.aria_persona == "aria"
    assert config.aria_follow_up_seconds == 12
    assert config.aria_camera_index == 0

    for profile in SETUP_PROFILES.values():
        assert all(profile.get(key, False) is False for key in OPTIONAL_ARIA_SWITCHES)


def test_setup_exposes_persona_conversation_and_hand_navigation() -> None:
    mapped = {field.key for step in STEPS for field in step.fields}
    assert {
        "aria_persona",
        "aria_conversation_awareness",
        "aria_always_listen",
        "aria_follow_up_seconds",
        "aria_hand_controls",
        "aria_camera_index",
    } <= mapped
    controls = next(step for step in STEPS if "conversation and hand" in step.title.lower())
    copy = " ".join(
        [controls.intro]
        + [field.label + " " + field.note for field in controls.fields]
    ).lower()
    assert "off by default" in copy
    assert "never confirm" in copy
    assert "transient" in copy


def test_config_round_trips_explicit_aria_opt_ins(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("angerona.core.data_paths.data_dir", lambda: tmp_path)
    config = Config()
    config.aria_enabled = True
    config.aria_persona = "ultron"
    config.aria_voice_enabled = True
    config.aria_conversation_awareness = True
    config.aria_always_listen = True
    config.aria_follow_up_seconds = 18
    config.aria_hand_controls = True
    config.aria_camera_index = 2
    config.save()

    loaded = Config.load()
    assert loaded.aria_enabled is True
    assert loaded.aria_persona == "ultron"
    assert loaded.aria_voice_enabled is True
    assert loaded.aria_conversation_awareness is True
    assert loaded.aria_always_listen is True
    assert loaded.aria_follow_up_seconds == 18
    assert loaded.aria_hand_controls is True
    assert loaded.aria_camera_index == 2


def test_malformed_aria_control_settings_fail_closed(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("angerona.core.data_paths.data_dir", lambda: tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "settings.json").write_text(json.dumps({
        "aria_enabled": "yes",
        "aria_voice_enabled": 1,
        "aria_conversation_awareness": "true",
        "aria_always_listen": [],
        "aria_hand_controls": {},
        "aria_persona": "autonomous",
        "aria_follow_up_seconds": 999,
        "aria_camera_index": -4,
    }), encoding="utf-8")

    loaded = Config.load()
    assert all(getattr(loaded, key) is False for key in OPTIONAL_ARIA_SWITCHES)
    assert loaded.aria_persona == "aria"
    assert loaded.aria_follow_up_seconds == 60
    assert loaded.aria_camera_index == 0


def test_new_control_engines_pass_their_offline_contracts() -> None:
    assert ConversationAwareness().self_test()[0]
    assert HandControls().self_test()[0]
    assert CAPABILITIES["hand-controls"]["reqs"] == [
        ("cv2", "opencv-python"),
        ("mediapipe", "mediapipe"),
    ]


def test_gesture_dispatch_has_no_confirmation_path() -> None:
    from angerona.gui.main_window import MainWindow

    source = inspect.getsource(MainWindow._handle_aria_gesture)
    assert ".confirm(" not in source
    assert ".cancel(" in source
    assert "setCurrentIndex" in source
