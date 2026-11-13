"""Reload failures remain visible without flooding or skipping activation retries."""
from types import SimpleNamespace

from angerona.core.module_base import Severity
from angerona.modules import yara_scanner as yara


def _reporter(monkeypatch):
    module = yara.YaraScannerModule()
    clock = [0.0]
    events = []
    monkeypatch.setattr(yara, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    monkeypatch.setattr(module, "emit", lambda message, severity, **details:
                        events.append((message, severity, details)))
    return module, clock, events


def test_reload_failure_reminder_counts_repeats_at_exact_boundary(monkeypatch):
    module, clock, events = _reporter(monkeypatch)
    rules = object()
    for moment in (0.0, 1.0, 899.999, 900.0):
        clock[0] = moment
        module._report_reload_failure(rules, RuntimeError("inert activation refusal"))
    assert len(events) == 2
    assert events[0][2]["repeats_since_last_report"] == 0
    assert events[1][2]["repeats_since_last_report"] == 3
    assert all(level == Severity.HIGH for _, level, _ in events)
    assert all(details["disposition"] == "health" for _, _, details in events)
    assert all(details["response_authorized"] is False for _, _, details in events)
    clock[0] = 901.0
    module._report_reload_failure(rules, RuntimeError("inert activation refusal"))
    assert len(events) == 2


def test_new_rules_or_failure_reason_bypass_reload_cooldown(monkeypatch):
    module, _, events = _reporter(monkeypatch)
    first, second = object(), object()
    module._report_reload_failure(first, RuntimeError("first failure"))
    module._report_reload_failure(second, RuntimeError("first failure"))
    module._report_reload_failure(second, RuntimeError("different failure"))
    module._report_reload_failure(second, ValueError("different failure"))
    assert len(events) == 4
    assert all(details["repeats_since_last_report"] == 0 for _, _, details in events)
    # Only the current failure episode is retained, even after rule churn.
    assert module._reload_failure[0] is second


def test_run_retries_each_failure_and_reports_recurrence_after_recovery(monkeypatch):
    module, _, events = _reporter(monkeypatch)
    good, bad = object(), object()
    attempts, failures, cycles = [], [], []
    module._cursor_state_status = "ok"
    monkeypatch.setattr(module, "_find_rules", lambda: "inert-rules.yar")

    def activate(_path):
        module._compiled_rules = bad
        return good

    def scanner(rules):
        if rules is bad:
            attempts.append(rules)
            raise RuntimeError("inert activation refusal")
        return object()

    def wait(_seconds):
        if len(attempts) == 3:
            module._compiled_rules = good
        elif len(attempts) == 4:
            module._stop.set()

    def next_scan():
        cycles.append(True)
        module._compiled_rules = bad

    monkeypatch.setattr(module, "_activate", activate)
    monkeypatch.setattr(module, "_make_scanner", scanner)
    monkeypatch.setattr(module, "_load_cursor_state", lambda: "ok")
    monkeypatch.setattr(module, "_save_cursor_state", lambda: True)
    monkeypatch.setattr(module, "_optional_control_scanner", lambda: None)
    monkeypatch.setattr(module, "sleep", wait)
    monkeypatch.setattr(module, "_sleep_for_scan", next_scan)
    monkeypatch.setattr(module, "set_health", lambda pct, note:
                        failures.append(pct) if pct == 20 else None)
    monkeypatch.setattr(yara, "scan_roots", lambda: ())
    module.run()
    rejected = [row for row in events if "reload rejected" in row[0]]
    assert len(attempts) == 4 and failures == [20, 20, 20, 20]
    assert len(cycles) == 1
    assert len(rejected) == 2
    assert rejected[1][2]["repeats_since_last_report"] == 0
    recovered = [row for row in events if row[2].get("finding_code") == "yara.rules.reload-recovered"]
    assert len(recovered) == 1
    assert recovered[0][2]["repeats_since_last_report"] == 2
