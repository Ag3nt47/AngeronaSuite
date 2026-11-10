from types import SimpleNamespace

import pytest

from angerona.app import AngeronaApp as App
from angerona.core import mobile_cli_custody as signal
from angerona.core import ollama_lifecycle as ollama


def outcome(**changes):
    return dict(schema=1, active_invocations=0, pending_external_trees=0,
                held_resources=0, launch_quiescent=True, **changes)


@pytest.mark.parametrize("field,value", [
    ("active_invocations", 1), ("pending_external_trees", 1),
    ("held_resources", -1), ("active_invocations", False),
    ("schema", True), ("launch_quiescent", 1), ("launch_quiescent", False),
])
def test_shutdown_never_claims_unknown_or_live_signal_custody_retired(field, value):
    facts = outcome()
    facts[field] = value
    assert App._signal_retirement_proven(facts) is False


def test_signal_file_close_hold_does_not_block_global_shutdown():
    facts = outcome()
    facts["held_resources"] = 1
    facts["capability_held"] = True
    assert App._signal_retirement_proven(facts) is True


def test_optional_drain_fences_signal_then_retains_unproven_tree(monkeypatch):
    calls = []
    facts = outcome()
    facts["pending_external_trees"] = 1
    monkeypatch.setattr(signal, "request_signal_stop", lambda: calls.append("fence"))
    monkeypatch.setattr(signal, "signal_cli_custody_snapshot", lambda: facts)
    app = App.__new__(App)
    app.manager = SimpleNamespace()
    assert app._drain_optional_owned(timeout=0) is False
    assert calls == ["fence"]
    assert app._signal_retirement_at_shutdown == facts


def test_terminal_signal_failure_runs_remaining_cleanup_before_reporting(monkeypatch):
    facts = outcome()
    facts["active_invocations"] = 1
    calls = []
    app = App.__new__(App)
    app._shutdown_critical_owned = lambda: calls.append("critical")
    app._drain_optional_owned = lambda: False
    app._shutdown_services_and_stores = lambda: calls.append("services-and-stores")
    monkeypatch.setattr(signal, "signal_cli_custody_snapshot", lambda: facts)
    monkeypatch.setattr(ollama, "owned_ollama_retirement_proven", lambda: True)
    with pytest.raises(signal.SignalCliRetirementIncomplete):
        app._shutdown_owned()
    assert calls == ["critical", "services-and-stores"]
    assert app._signal_retirement_at_shutdown == facts


def test_unavailable_signal_snapshot_is_not_a_retirement_receipt(monkeypatch):
    def unavailable():
        raise OSError("private diagnostic content")
    monkeypatch.setattr(signal, "signal_cli_custody_snapshot", unavailable)
    facts = App._signal_retirement_outcome()
    assert not App._signal_retirement_proven(facts)
    assert "private" not in str(facts)
