from __future__ import annotations

from types import SimpleNamespace

from angerona.core.chill_mode import (
    CHILL_PAUSED_MODULES,
    CHILL_THROTTLE_FLOORS,
    ChillPolicy,
)
from angerona.core.module_base import BaseModule
from angerona.core.module_manager import ModuleManager
from angerona.core.ollama_lifecycle import effective_keep_alive
from angerona.core.posture import _health_penalty


class _Module(BaseModule):
    name = "test"

    def run(self) -> None:
        return


def test_chill_policy_escalates_extends_and_cools_without_flapping() -> None:
    now = [100.0]
    policy = ChillPolicy(quiet_seconds=10.0, clock=lambda: now[0])
    policy.enable()

    first = policy.observe_active([object()])
    assert first is not None and first.action == "escalate"
    now[0] = 108.0
    extension = policy.observe_active([object(), object()])
    assert extension is not None and extension.action == "extend"
    now[0] = 117.9
    assert policy.tick() is None
    now[0] = 118.1
    cooldown = policy.tick()
    assert cooldown is not None and cooldown.action == "cooldown"
    assert policy.tick() is None


def test_operator_practice_lease_wakes_without_claiming_hostile_event() -> None:
    now = [0.0]
    policy = ChillPolicy(quiet_seconds=5.0, clock=lambda: now[0])
    policy.enable()
    transition = policy.force_escalate("operator practice coverage")
    assert transition is not None
    assert transition.action == "escalate"
    assert transition.active_count == 0


def test_chill_policy_is_network_first_and_names_are_exact() -> None:
    assert "Network Monitor" not in CHILL_PAUSED_MODULES
    assert "ARP Watchdog" not in CHILL_PAUSED_MODULES
    assert "WLAN Monitor" not in CHILL_PAUSED_MODULES
    assert "Removable-Media / USB Monitor" not in CHILL_PAUSED_MODULES
    assert "File Integrity Monitor" in CHILL_PAUSED_MODULES
    assert "Shadow Shield" in CHILL_PAUSED_MODULES
    assert "Kernel-Boundary Posture Ledger" in CHILL_PAUSED_MODULES
    assert "Compliance Mapper" in CHILL_PAUSED_MODULES
    assert "AI Triage (Ollama)" in CHILL_PAUSED_MODULES
    assert "Kernel Posture Ledger" not in CHILL_PAUSED_MODULES
    assert "Self-Integrity Monitor" in CHILL_THROTTLE_FLOORS
    # Event-driven/live protection remains fully awake and unthrottled.  Chill
    # slows only auxiliary maintenance plus explicit polling fallbacks.
    for name in (
        "Network Monitor",
        "C2 Beacon Detector",
        "WFP Controller",
        "AMSI Bridge",
        "AV Telemetry Bridge",
        "ETW Core Listener",
        "ETW Real-Time Process Sensor",
        "Sysmon Event Bridge",
        "Removable-Media / USB Monitor",
        "Watchdog Monitor",
        "Active Response SOAR",
        "SOAR Automation",
        "Temporal Tradecraft Correlator",
        "Identity Session Guard",
        "Process Egress Lease Guard",
    ):
        assert name not in CHILL_PAUSED_MODULES
        assert name not in CHILL_THROTTLE_FLOORS

    assert {
        "Network Monitor",
        "C2 Beacon Detector",
        "WFP Controller",
        "ETW Core Listener",
        "AV Telemetry Bridge",
        "Removable-Media / USB Monitor",
        "Temporal Tradecraft Correlator",
        "Identity Session Guard",
        "Process Egress Lease Guard",
    }.issubset(ModuleManager._NO_STAGGER)


def test_chill_slows_only_auxiliary_idle_bookkeeping() -> None:
    assert CHILL_THROTTLE_FLOORS["Posture Hardening"] == 8.0
    assert CHILL_THROTTLE_FLOORS["HEAL"] == 6.0
    assert CHILL_THROTTLE_FLOORS["Storage Hygiene Enforcer"] == 8.0


def test_chill_throttle_floor_survives_governor_relaxation() -> None:
    module = _Module()
    module.set_throttle_floor(4.0)
    module.set_throttle(1.0)
    assert module._throttle == 4.0
    module.set_throttle_floor(1.0)
    module.set_throttle(1.0)
    assert module._throttle == 1.0


def test_policy_paused_modules_do_not_count_as_crashed() -> None:
    paused = SimpleNamespace(
        status="stopped", health=100, _chill_paused=True
    )
    manager = SimpleNamespace(
        modules={"deep": paused},
        is_enabled=lambda _name: True,
    )
    assert _health_penalty(manager) == (0, 0)


def test_chill_forces_ollama_immediate_release(monkeypatch) -> None:
    from angerona.modules.ai_triage import AITriageModule

    monkeypatch.setenv("ANGERONA_CHILL_ACTIVE", "1")
    assert effective_keep_alive("30m") == 0

    module = AITriageModule()
    monkeypatch.setenv("ANGERONA_MODEL", "environment-model:latest")
    module.bind_manager(SimpleNamespace(config=SimpleNamespace(
        ollama_host="http://127.0.0.1:11434/",
        ollama_model="operator-model:latest",
    )))
    assert module._host == "http://127.0.0.1:11434"
    assert module._model == "environment-model:latest"
    assert module._model_is_installed("llama3", ["llama3:8b"])
    assert module._model_is_installed("llama3:8b", ["llama3:8b"])
    assert not module._model_is_installed("llama3:70b", ["llama3:8b"])
    module._ask = lambda _prompt: (_ for _ in ()).throw(
        AssertionError("self-test must never run inference")
    )
    module._ping_ollama = lambda: (_ for _ in ()).throw(
        AssertionError("Chill self-test must not wake or probe local AI")
    )
    ok, detail = module.self_test()
    assert ok and "intentionally asleep" in detail

    monkeypatch.delenv("ANGERONA_CHILL_ACTIVE")
    monkeypatch.delenv("ANGERONA_MODEL")
    module._sync_config()
    assert module._model == "operator-model:latest"
    assert effective_keep_alive("30m") == "30m"
    module._ping_ollama = lambda: True
    ok, detail = module.self_test()
    assert ok and "operator-model:latest" in detail and "not loaded" in detail
    module._ping_ollama = lambda: False
    ok, detail = module.self_test()
    assert not ok and "not installed" in detail
    assert module.selftest_auto_repair is False

    # Preserve the legacy deployment variable when the Angerona-specific
    # override is absent, including before a manager/config is bound.
    monkeypatch.setenv("OLLAMA_MODEL", "deployment-model:latest")
    fresh_module = AITriageModule()
    assert fresh_module._model == "deployment-model:latest"


def test_reentering_chill_reclaims_stopped_and_restarting_wake_queue() -> None:
    """A rapid Full -> Chill click must not strand not-yet-started sensors."""
    from angerona.gui.main_window import MainWindow

    class Module:
        def __init__(self, status: str) -> None:
            self.status = status
            self._chill_paused = False
            self.stop_calls = 0

        def stop(self) -> None:
            self.stop_calls += 1
            self.status = "stopped"

    class Manager:
        def __init__(self) -> None:
            self.modules = {
                "running": Module("running"),
                "queued": Module("stopped"),
                "restarting": Module("restarting"),
                "disabled": Module("stopped"),
            }

        @staticmethod
        def is_enabled(name: str) -> bool:
            return name != "disabled"

    class Policy:
        enabled = False

        def enable(self) -> None:
            self.enabled = True

    class Button:
        def set_full_label(self, _text: str) -> None:
            pass

        def setStyleSheet(self, _style: str) -> None:
            pass

    harness = SimpleNamespace(
        _eco_worker=None,
        _eco_wake_epoch=0,
        _pending_chill_wake=None,
        _eco_paused=[],
        _ECO_HEAVY_MODULES=("running", "queued", "restarting", "disabled"),
        manager=Manager(),
        _apply_chill_throttles=lambda _enabled: None,
        _chill_policy=Policy(),
        _chill_auto_wake=True,
        _set_chill_runtime=lambda _quiet: None,
        eco_btn=Button(),
        console=SimpleNamespace(_append=lambda _text: None),
    )

    MainWindow._enter_eco(harness)

    for name in ("running", "queued", "restarting"):
        module = harness.manager.modules[name]
        assert module.stop_calls == 1
        assert module._chill_paused is True
    disabled = harness.manager.modules["disabled"]
    assert disabled.stop_calls == 0
    assert disabled._chill_paused is False
    assert harness._eco_paused == ["running", "queued", "restarting"]


def test_daily_briefing_separates_critical_evidence_from_active_attack() -> None:
    from angerona.core.eventbus import Event, Severity
    from angerona.modules.daily_briefing import _heuristic_briefing, _summarize_events

    summary = _summarize_events([
        Event("Red Team", "inert drill marker missed", Severity.CRITICAL),
        Event(
            "Vulnerability Assessment",
            "applicable CVE",
            Severity.CRITICAL,
            details={"finding_kind": "passive_vulnerability"},
        ),
    ])
    text = _heuristic_briefing(
        summary,
        {},
        [{
            "actor": "practice.exe",
            "pid": 7,
            "severity": "CRITICAL",
            "chain": "Practice -> Impact",
            "progress_pct": 100,
        }],
    )

    assert summary["by_severity"]["CRITICAL"] == 2
    assert summary["active_by_severity"].get("CRITICAL", 0) == 0
    assert "UNDER ATTACK" not in text
    assert "no active attack classified" in text
    assert "not classified as an active threat" in text


def test_chill_starts_resilience_backends_without_redundant_status_windows(
    monkeypatch,
) -> None:
    import angerona.app as app_module
    import angerona.resilience.manager as resilience_manager
    import angerona.resilience.shutdown_token as shutdown_token

    calls: list[dict] = []
    monkeypatch.setattr(app_module, "current_platform", lambda: "windows")
    monkeypatch.setattr(shutdown_token, "clear_standdown", lambda: None)
    monkeypatch.setattr(
        resilience_manager,
        "start_resilience",
        lambda _bus, **kwargs: calls.append(kwargs) or object(),
    )

    class Manager:
        modules = {}

        @staticmethod
        def discover() -> None:
            pass

        @staticmethod
        def start_enabled(*, deferred_names) -> None:
            assert isinstance(deferred_names, set)

    app = app_module.AngeronaApp.__new__(app_module.AngeronaApp)
    app.config = SimpleNamespace(
        runtime_chill_active=True,
        eco_mode=True,
        blackbox_enabled=False,
    )
    app.bus = object()
    app.manager = Manager()
    app.window = SimpleNamespace(
        _ECO_HEAVY_MODULES=(),
        startup_eco_requested=SimpleNamespace(emit=lambda: None),
    )
    app.reporter = SimpleNamespace(start=lambda: None)
    app._mcp = None
    app._record_startup_degradation = lambda *_args: None
    app._start_fleet_service = lambda: False

    app._load_modules()

    assert calls == [{"with_ui": False}]
