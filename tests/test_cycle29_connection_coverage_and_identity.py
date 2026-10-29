from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.core import process_allowlist
from angerona.modules import beacon_detector, counter_agentic
from angerona.telemetry import sensors


@pytest.mark.parametrize("base,port,normalized", [
    ("127.0.0.1:23145", 23145, "http://127.0.0.1:23145"),
    ("localhost:23145", 23145, "http://localhost:23145"),
    ("[::1]:23145", 23145, "http://[::1]:23145"),
    ("https://localhost:23145", 23145, "https://localhost:23145"),
])
def test_counter_agentic_uses_configured_bare_port_without_mutating_settings(
    monkeypatch, base, port, normalized,
):
    from angerona.core.config import Config

    config = SimpleNamespace(ollama_host=base)
    monkeypatch.setattr(Config, "load", lambda: config)
    monkeypatch.setattr(counter_agentic, "list_connections",
                        lambda: pytest.fail("Parsing a configured endpoint must not collect connections"))
    assert counter_agentic._configured_inference_port() == (port, normalized, "")
    assert config.ollama_host == base


@pytest.mark.parametrize("base", [
    "0.0.0.0:11434", "localhost:0", "localhost:65536", "localhost:11434/path",
    "user:password@localhost:11434", "[::1%1]:11434", "::1:11434",
    "http://127.0.0.2:11434",  # Retain this module's narrower existing host policy.
])
def test_counter_agentic_invalid_base_remains_unavailable_without_default_port(monkeypatch, base):
    from angerona.core.config import Config

    monkeypatch.setattr(Config, "load", lambda: SimpleNamespace(ollama_host=base))
    port, endpoint, error = counter_agentic._configured_inference_port()
    assert port is None and endpoint == "" and error


def test_connection_enumeration_failure_is_not_an_empty_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psutil

    monkeypatch.setattr(
        psutil,
        "net_connections",
        lambda **_kwargs: (_ for _ in ()).throw(PermissionError("denied")),
    )
    monkeypatch.setattr(sensors, "_conn_cache", (0.0, None))

    rows = sensors.list_connections(max_age=0)
    assert rows == []
    assert rows.complete is False
    assert rows.receipt.enumerated == 0
    assert "denied" in rows.error


def test_connection_row_loss_is_counted_and_marks_snapshot_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import psutil

    good = SimpleNamespace(
        pid=7,
        status="ESTABLISHED",
        laddr=SimpleNamespace(ip="127.0.0.1", port=40000),
        raddr=SimpleNamespace(ip="127.0.0.1", port=11434),
    )
    bad = SimpleNamespace(
        pid=8,
        status="ESTABLISHED",
        laddr=object(),
        raddr=None,
    )
    monkeypatch.setattr(psutil, "net_connections", lambda **_kwargs: [good, bad])
    monkeypatch.setattr(sensors, "_conn_cache", (0.0, None))

    receipt = sensors.connection_snapshot(max_age=0)
    assert receipt.complete is False
    assert receipt.enumerated == 2
    assert receipt.skipped == 1
    assert len(receipt.connections) == 1


def test_beacon_detector_preserves_prior_state_across_incomplete_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = sensors.ConnectionSnapshot(
        (), 1000.0, False, 0, 0, "connection enumeration failed"
    )
    monkeypatch.setattr(
        beacon_detector,
        "list_connections",
        lambda: sensors.ConnectionList(receipt),
    )
    module = beacon_detector.BeaconDetectorModule()
    module._seen_last = {(77, "203.0.113.4")}

    coverage = module._poll_once()
    assert coverage.complete is False
    assert "enumeration failed" in coverage.error
    assert module._seen_last == {(77, "203.0.113.4")}


def test_inference_client_approval_requires_exact_path_and_current_digest(
    tmp_path: Path,
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"reviewed exact client")
    row = process_allowlist.add(
        path=str(executable),
        data_dir=tmp_path,
        source="manual",
    )
    policy = process_allowlist.policy_snapshot(tmp_path)

    assert row["sha256"]
    assert process_allowlist.is_digest_pinned_allowed(
        "python.exe", str(executable), policy=policy
    )
    assert not process_allowlist.is_digest_pinned_allowed(
        "python.exe", str(tmp_path / "renamed" / "python.exe"), policy=policy
    )

    executable.write_bytes(b"substituted client")
    assert not process_allowlist.is_digest_pinned_allowed(
        "python.exe", str(executable), policy=policy
    )


def test_counter_agentic_rejects_basename_only_and_reports_identity_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "python.exe"
    executable.write_bytes(b"unapproved renamed client")
    rows = [
        {
            "pid": 4242,
            "status": "ESTABLISHED",
            "laddr": "127.0.0.1:50000",
            "raddr": "127.0.0.1:11434",
        }
    ]

    class Process:
        def __init__(self, _pid: int):
            pass

        @staticmethod
        def name() -> str:
            return "python.exe"

        @staticmethod
        def exe() -> str:
            return str(executable)

        @staticmethod
        def create_time() -> float:
            return 1234.5

    monkeypatch.setattr(counter_agentic, "list_connections", lambda: rows)
    monkeypatch.setattr(counter_agentic.psutil, "Process", Process)
    monkeypatch.setattr(counter_agentic, "policy_snapshot", lambda: ())
    events: list[tuple[tuple, dict]] = []
    module = counter_agentic.CounterAgenticModule()
    module._inference_port = 11434
    module._inference_endpoint = "http://127.0.0.1:11434"
    module.emit = lambda *args, **kwargs: events.append((args, kwargs))

    coverage = module._watch_ollama_port()
    assert coverage.complete is True
    assert coverage.unexpected == 1
    assert events[0][1]["process"] == "python.exe"
    assert events[0][1]["process_create_time"] == 1234.5
    assert events[0][1]["process_path"] == str(executable)
    assert events[0][1]["authorization_policy"] == (
        "exact-path-sha256-operator-approval"
    )

    class Uninspectable(Process):
        @staticmethod
        def create_time() -> float:
            raise PermissionError("process denied")

    monkeypatch.setattr(counter_agentic.psutil, "Process", Uninspectable)
    second = counter_agentic.CounterAgenticModule()
    second._inference_port = 11434
    second._inference_endpoint = "http://127.0.0.1:11434"
    second.emit = lambda *args, **kwargs: events.append((args, kwargs))
    coverage = second._watch_ollama_port()
    assert coverage.complete is False
    assert coverage.identity_failures == 1
    assert coverage.unexpected == 1
    assert "process denied" in events[-1][1]["identity_error"]
