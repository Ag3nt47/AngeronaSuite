from __future__ import annotations

import http.client
import json
import threading
import time
from types import SimpleNamespace

import pytest

from angerona.core.security_scan_center import ScanResult
from angerona.engines.jarvis_control_server import (
    CONTROL_TOKEN_ENV,
    AngeronaJarvisControlServer,
    JarvisControlPlane,
    _ControlHTTPServer,
)


def _result(operation: str, status: str = "completed") -> ScanResult:
    return ScanResult(
        operation=operation,
        status=status,
        supported=True,
        executed=True,
        started_at=1.0,
        finished_at=2.0,
        summary="bounded test result",
    )


class _Manager:
    modules: dict[str, object] = {}


class _ScanCenter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def audit_listening_exposure(self, **kwargs: object) -> ScanResult:
        self.calls.append(("listener", kwargs))
        return _result("listening_exposure_audit")

    def summarize_network_posture(self, **kwargs: object) -> ScanResult:
        self.calls.append(("network", kwargs))
        return _result("network_posture_summary")

    def run_microsoft_defender_scan(self, **kwargs: object) -> ScanResult:
        self.calls.append(("defender", kwargs))
        return _result("microsoft_defender_scan")


def _wait_finished(plane: JarvisControlPlane) -> dict[str, object]:
    for _ in range(100):
        job = plane.status()["active_job"]
        if isinstance(job, dict) and job["state"] not in {"queued", "running", "cancelling"}:
            return job
        time.sleep(0.01)
    raise AssertionError("control-plane job did not finish")


def test_action_requires_single_use_confirmation_and_has_no_freeform_inputs() -> None:
    center = _ScanCenter()
    plane = JarvisControlPlane(_Manager(), scan_center=center)

    prepared = plane.prepare("defender_quick_scan")
    ticket = str(prepared["confirmation_id"])
    plane.execute(ticket)
    job = _wait_finished(plane)

    assert job["state"] == "completed"
    assert center.calls[0][0] == "defender"
    assert center.calls[0][1]["execute"] is True
    assert center.calls[0][1]["quick"] is True
    assert set(center.calls[0][1]) == {"execute", "quick", "cancellation"}
    with pytest.raises(PermissionError):
        plane.execute(ticket)


def test_unknown_actions_and_unowned_cancellation_fail_closed() -> None:
    plane = JarvisControlPlane(_Manager(), scan_center=_ScanCenter())
    with pytest.raises(ValueError):
        plane.prepare("run_command")
    with pytest.raises(KeyError):
        plane.cancel("not-a-job-owned-by-this-adapter")
    catalog = json.dumps(plane.action_catalog()).casefold()
    for prohibited in ("command", "remote host", "filesystem path", "disable protection"):
        assert prohibited not in catalog


def test_http_control_plane_rejects_missing_token_and_accepts_bearer() -> None:
    token = "t" * 48
    plane = JarvisControlPlane(_Manager(), scan_center=_ScanCenter())
    server = _ControlHTTPServer(("127.0.0.1", 0), plane, token)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.request("GET", "/v1/status")
        response = connection.getresponse()
        assert response.status == 401
        response.read()
        connection.close()

        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
        connection.request(
            "GET",
            "/v1/actions",
            headers={"Authorization": f"Bearer {token}"},
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        connection.close()
        assert response.status == 200
        assert {item["id"] for item in payload["actions"]} == {
            "listener_audit",
            "network_posture",
            "defender_quick_scan",
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_server_rejects_inherited_control_authority(monkeypatch, tmp_path) -> None:
    from angerona.core import secure_store

    monkeypatch.setenv(CONTROL_TOKEN_ENV, "inherited-parent-authority-" + "x" * 40)
    monkeypatch.setattr(secure_store, "read_secret_map", lambda *_a, **_k: {})

    with pytest.raises(ValueError, match="protected JARVIS control token"):
        AngeronaJarvisControlServer(
            _Manager(),
            SimpleNamespace(data_dir=tmp_path, jarvis_control_port=47925),
        )

    assert CONTROL_TOKEN_ENV not in __import__("os").environ


def test_server_uses_only_protected_enrolled_control_authority(
    monkeypatch, tmp_path
) -> None:
    from angerona.core import secure_store

    protected = "protected-store-authority-" + "p" * 40
    monkeypatch.setenv(CONTROL_TOKEN_ENV, "inherited-parent-authority-" + "x" * 40)
    monkeypatch.setattr(
        secure_store,
        "read_secret_map",
        lambda root, *, strict=False: {CONTROL_TOKEN_ENV: protected},
    )

    server = AngeronaJarvisControlServer(
        _Manager(),
        SimpleNamespace(data_dir=tmp_path, jarvis_control_port=47925),
    )

    assert server._token == protected
    assert CONTROL_TOKEN_ENV not in __import__("os").environ
