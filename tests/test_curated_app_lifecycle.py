"""Curated child entries and STOP fences never construct another security engine."""
from __future__ import annotations

import sys
import threading
from types import ModuleType, SimpleNamespace

import pytest


@pytest.mark.parametrize("frozen,administrator,trusted,expected,dispatched", [
    (False, False, True, 17, True),
    (False, True, True, 2, False),
    (True, False, True, 17, True),
    (True, True, True, 2, False),
    (True, False, False, 2, False),
])
def test_worker_entry_keeps_source_and_package_privilege_boundaries(
    monkeypatch, frozen, administrator, trusted, expected, dispatched,
):
    import angerona.__main__ as entry
    from angerona.core import privilege, windows_package_identity
    monkeypatch.setattr(sys, "argv", ["Angerona", "--curated-tool-worker", "private-request.json"])
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(privilege, "is_admin", lambda: administrator)
    monkeypatch.setattr(privilege, "ensure_admin", lambda: pytest.fail("Scanner entry requested UAC"))
    monkeypatch.setattr(windows_package_identity, "verify_current_msix_authority",
                        lambda: SimpleNamespace(trusted=trusted, reason="test authority"))
    calls = []
    worker = ModuleType("angerona.core.curated_tool_worker")
    worker.main = lambda arguments: calls.append(arguments) or 17
    monkeypatch.setitem(sys.modules, worker.__name__, worker)
    assert entry.main() == expected
    assert calls == ([["private-request.json"]] if dispatched else [])


def test_optional_scanner_failure_does_not_skip_ai_or_watchdog_stop_fences(monkeypatch):
    from angerona.app import AngeronaApp
    from angerona.core import ollama_lifecycle
    calls = []
    monkeypatch.setattr(ollama_lifecycle, "begin_ollama_shutdown", lambda: calls.append("ai-fence"))

    def broken_shutdown():
        calls.append("tool-cancel")
        raise RuntimeError("optional controller already retired")

    owner = SimpleNamespace(
        _shutdown_requested=threading.Event(),
        manager=SimpleNamespace(_curated_tools_controller=SimpleNamespace(shutdown=broken_shutdown)),
        _breach_state_controller=SimpleNamespace(request_stop=lambda: calls.append("breach-cancel")),
        _resilience=SimpleNamespace(request_stop=lambda: calls.append("watchdog-fence")),
    )
    AngeronaApp._cancel_owned_work(owner)
    assert owner._shutdown_requested.is_set()
    assert calls == ["tool-cancel", "breach-cancel", "ai-fence", "watchdog-fence"]


def test_shutdown_waits_for_scanner_thread_and_also_closes_breach_review():
    from angerona.app import AngeronaApp

    cancelled, retired = threading.Event(), threading.Event()
    calls = []

    def worker():
        assert cancelled.wait(2)
        calls.append("scanner-retired")
        retired.set()

    thread = threading.Thread(target=worker)
    thread.start()

    def wait_for_shutdown(timeout):
        thread.join(timeout)
        return not thread.is_alive()

    def close_breach(timeout):
        assert retired.is_set()
        assert 0 <= timeout <= 5
        calls.append("breach-retired")
        return True

    owner = SimpleNamespace(
        manager=SimpleNamespace(_curated_tools_controller=SimpleNamespace(
            shutdown=cancelled.set, wait_for_shutdown=wait_for_shutdown,
        )),
        _breach_state_controller=SimpleNamespace(close=close_breach),
    )
    try:
        assert AngeronaApp._drain_optional_owned(owner)
        assert calls == ["scanner-retired", "breach-retired"]
    finally:
        cancelled.set()
        thread.join(2)
        assert not thread.is_alive()


@pytest.mark.parametrize("failure", ["unretired", "exception"])
def test_unresolved_scanner_retirement_still_drains_breach_but_holds_store_close(failure):
    from angerona.app import AngeronaApp

    calls = []

    def scanner_wait(_timeout):
        if failure == "exception":
            raise RuntimeError("inert uncertain retirement")
        return False

    owner = SimpleNamespace(
        manager=SimpleNamespace(_curated_tools_controller=SimpleNamespace(
            shutdown=lambda: calls.append("scanner-cancel"), wait_for_shutdown=scanner_wait,
        )),
        _breach_state_controller=SimpleNamespace(
            close=lambda **_kwargs: calls.append("breach-retired") or True,
        ),
    )
    assert not AngeronaApp._drain_optional_owned(owner, timeout=0)
    assert calls == ["scanner-cancel", "breach-retired"]
