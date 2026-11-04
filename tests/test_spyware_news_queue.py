from __future__ import annotations

import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core import spyware_news
from test_spyware_guard import make_module


def wait_for(predicate, message, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(message)


@pytest.fixture
def worker(monkeypatch):
    """Actual module/research threads; deterministic inert command dispatch.

    This fixture exercises queue/lifecycle state only. It never claims sensor
    coverage or host authority and starts no real collector or network request.
    """
    module, bus = make_module()
    module._settings["spyware_network_enabled"] = True
    entered, dispatch = threading.Event(), threading.Event()

    def tick():
        entered.set()
        if dispatch.is_set():
            module._process_commands()
            module._ensure_report_worker()
        module._priority_scan_wake.clear()

    monkeypatch.setattr(module, "_tick", tick)
    sleep = module.sleep
    monkeypatch.setattr(module, "sleep", lambda seconds, **kwargs: sleep(min(seconds, 0.05), **kwargs))
    module.start()
    owners = [module._thread]
    assert entered.wait(5)
    ctx = SimpleNamespace(module=module, bus=bus, entered=entered, dispatch=dispatch, owners=owners)

    def release():
        dispatch.set()
        module._priority_scan_wake.set()

    ctx.release = release
    try:
        yield ctx
    finally:
        module.stop()
        for thread in owners:
            thread.join(3)
            assert not thread.is_alive(), "Owned module generation did not retire"
        if module._report_thread is not None:
            module._report_stop.set()
            module._report_thread.join(3)
            assert not module._report_thread.is_alive(), "Owned research worker did not retire"


def test_accepted_refresh_is_visible_while_dispatch_waits_and_requests_coalesce(worker, monkeypatch):
    module = worker.module
    calls = []
    monkeypatch.setattr(spyware_news, "fetch_news_source", lambda *_a, **_k: calls.append(1) or [])
    module._news_status["last_refresh"] = module._clock() - 3600
    for _ in range(12):
        assert module.request_news_refresh()
    assert module._commands.qsize() == 1
    snapshot = module.dashboard_snapshot()["news_status"]
    assert snapshot["state"] == "queued" and snapshot["refreshing"]
    assert "priority Spyware Scan" in snapshot["queued_reason"]
    assert snapshot["last_refresh"] == module._clock() - 3600
    assert "last_attempt" not in snapshot and not calls
    worker.release()
    wait_for(lambda: module._news_command_pending is None and not module._news_pending,
             "Admitted refresh did not settle")
    assert len(calls) == len(spyware_news.NEWS_SOURCES)
    assert module.dashboard_snapshot()["news_status"]["state"] == "empty"
    assert module._commands.unfinished_tasks == 0
    assert worker.bus.recent(10) == []


def test_full_command_queue_rejects_without_an_infinite_busy_state(worker, monkeypatch):
    module = worker.module
    monkeypatch.setattr(spyware_news, "fetch_news_source", lambda *_a, **_k: pytest.fail("Unexpected fetch"))
    for _ in range(module._commands.maxsize):
        assert module._enqueue("inert-no-op")
    assert not module.request_news_refresh()
    assert module._news_command_pending is None
    snapshot = module.dashboard_snapshot()["news_status"]
    assert snapshot["state"] == "retry-required" and not snapshot["refreshing"]
    assert snapshot["error"] == "QueueFull"


def test_worker_start_failure_retires_exact_news_tokens_and_preserves_success_date(worker, monkeypatch):
    module = worker.module
    module._news_status["last_refresh"] = module._clock() - 3600

    def failed_start(*_args):
        raise RuntimeError("Inert research-thread start failure")

    monkeypatch.setattr(module, "_schedule_report", failed_start)
    assert module.request_news_refresh()
    worker.release()
    wait_for(lambda: module._commands.unfinished_tasks == 0, "Failed command did not settle")
    snapshot = module.dashboard_snapshot()["news_status"]
    assert not module._news_pending and not module._news_jobs and module._news_command_pending is None
    assert snapshot["state"] == "failed" and not snapshot["refreshing"]
    assert snapshot["error"] == "RuntimeError"
    assert snapshot["last_refresh"] == module._clock() - 3600


def test_dispatch_error_clears_only_its_accepted_command(worker, monkeypatch):
    module = worker.module

    def failed_dispatch(**_kwargs):
        raise RuntimeError("Inert command dispatch failure")

    monkeypatch.setattr(module, "_schedule_news", failed_dispatch)
    assert module.request_news_refresh()
    worker.release()
    wait_for(lambda: module._commands.unfinished_tasks == 0, "Dispatch failure did not settle")
    assert module._news_command_pending is None
    snapshot = module.dashboard_snapshot()["news_status"]
    assert snapshot["state"] == "failed" and not snapshot["refreshing"]
    assert snapshot["error"] == "RuntimeError"
    assert all(event.details.get("response_authorized") is False for event in worker.bus.recent(10))


def test_opt_out_before_dispatch_holds_old_command_without_any_fetch(worker, monkeypatch):
    module = worker.module
    monkeypatch.setattr(spyware_news, "fetch_news_source", lambda *_a, **_k: pytest.fail("Opted-out fetch"))
    assert module.configure_settings(spyware_network_enabled=False)["queued"]
    assert module.request_news_refresh()
    worker.release()
    wait_for(lambda: module._commands.unfinished_tasks == 0, "Settings/refresh commands did not settle")
    assert not module._settings["spyware_network_enabled"]
    assert module._news_command_pending is None and not module._news_pending
    snapshot = module.dashboard_snapshot()["news_status"]
    assert snapshot["state"] == "disabled" and not snapshot["refreshing"]


def test_stop_retires_queued_display_and_rejects_requests_without_a_live_generation(worker):
    module = worker.module
    assert module.request_news_refresh()
    module.stop()
    worker.owners[0].join(3)
    assert not worker.owners[0].is_alive()
    assert not module.request_news_refresh()
    snapshot = module.dashboard_snapshot()["news_status"]
    assert module._news_command_pending is None and not snapshot["refreshing"]
    assert snapshot["state"] == "stopped"


def test_old_command_cannot_consume_a_new_generation_request(worker):
    module = worker.module
    assert module.request_news_refresh()
    old_request = module._news_command_pending
    old_generation = module.lifecycle_generation
    module.stop()
    worker.owners[0].join(3)
    assert not worker.owners[0].is_alive()
    worker.entered.clear()
    module.start()
    worker.owners.append(module._thread)
    assert worker.entered.wait(5)
    assert module.lifecycle_generation > old_generation
    assert module.request_news_refresh()
    new_request = module._news_command_pending
    assert new_request != old_request
    module._schedule_news(request=old_request)
    assert module._news_command_pending == new_request
    assert not module._news_pending and not module._news_jobs
    assert module.dashboard_snapshot()["news_status"]["state"] == "queued"


@pytest.mark.parametrize("transition", ["restart", "opt-out"])
def test_old_fetch_completion_does_not_overwrite_or_finish_a_replacement_job(worker, monkeypatch, transition):
    module = worker.module
    old_entered, old_release = threading.Event(), threading.Event()
    new_entered, new_release = threading.Event(), threading.Event()
    count, count_lock = [0], threading.Lock()

    def fetch(source, **_kwargs):
        with count_lock:
            count[0] += 1
            first = count[0] == 1
        if first:
            old_entered.set()
            assert old_release.wait(10), "Old owned fetch was not released"
        else:
            new_entered.set()
            assert new_release.wait(10), "New owned fetch was not released"
        return [{"source": source, "url": f"https://{source}.invalid/{'old' if first else 'new'}/",
                 "title": "Old result" if first else "New result", "published": module._clock() - 10,
                 "verified_at": module._clock(), "summary": "Inert research fixture", "advisory_only": True}]

    monkeypatch.setattr(spyware_news, "fetch_news_source", fetch)
    old_thread = None
    try:
        module._schedule_news()
        assert old_entered.wait(5)
        old_thread = module._report_thread
        if transition == "restart":
            module.stop()
            worker.owners[0].join(3)
            assert not worker.owners[0].is_alive()
            worker.entered.clear()
            module.start()
            worker.owners.append(module._thread)
            assert worker.entered.wait(5)
        else:
            assert module.configure_settings(spyware_network_enabled=False)["queued"]
            worker.release()
            wait_for(lambda: not module._settings["spyware_network_enabled"], "Opt-out did not settle")
            assert not module._news_jobs and not module._news_pending
            assert module.configure_settings(spyware_network_enabled=True)["queued"]
            wait_for(lambda: module._settings["spyware_network_enabled"], "Opt-in did not settle")
        assert module.request_news_refresh()
        worker.release()
        wait_for(lambda: "citizen_lab" in module._news_jobs,
                 "New generation did not admit its source batch")
        new_job = module._news_jobs["citizen_lab"]
        assert new_job[0] == module.lifecycle_generation
        old_release.set()
        if transition == "restart":
            old_thread.join(3)
            assert not old_thread.is_alive()
        else:
            assert new_entered.wait(5), "The same owned worker did not reach its new token"
        assert module._news_jobs.get("citizen_lab") == new_job
        assert "citizen_lab" in module._news_pending
        assert not any(row["title"] == "Old result" for row in module._news)
        module._priority_scan_wake.set()
        assert new_entered.wait(5)
        new_release.set()
        wait_for(lambda: not module._news_pending, "New generation source batch did not settle")
        assert module._news and all(row["title"] == "New result" for row in module._news)
    finally:
        old_release.set()
        new_release.set()
        if old_thread is not None and transition == "restart":
            old_thread.join(3)
            assert not old_thread.is_alive()
