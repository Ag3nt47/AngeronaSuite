from __future__ import annotations

import http.client
import json
import os
import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from angerona.app import AngeronaApp
from angerona.core import flow_metrics
from angerona.gui.main_window import MainWindow
from tools import serve_canvas


def _metrics(*, generated_at: float | None = None, model: object = "local") -> dict:
    return {
        "schema_version": 1,
        "generated_at_epoch": time.time() if generated_at is None else generated_at,
        "generated": "2026-08-30T00:00:00Z",
        "live": True,
        "pipeline": {
            "cap_det": {"queue": 0, "latency_ms": 8.0},
            "det_tri": {"queue": 0, "latency_ms": 15.0},
            "dropped": 0,
        },
        "nodes": {
            "capture": {
                "state": "ok",
                "metrics": {"Events/sec": 0.0, "Queue depth": 0, "Sensors up": "1/1"},
            },
            "detect": {
                "state": "ok",
                "metrics": {"Detectors up": "1/1", "Queue depth": 0, "Modules total": 1},
            },
            "triage": {
                "state": "ok",
                "metrics": {"Audit events": 0, "Model": model, "GPU tier": "cpu"},
            },
            "respond": {
                "state": "ok",
                "metrics": {"SOAR port": 8000, "Redacts": "yes", "Gate": "review"},
            },
            "attack": {
                "state": "ok",
                "metrics": {"Red-team up": "standby", "Mode": "idle", "Trigger": "operator"},
            },
            "harden": {
                "state": "ok",
                "metrics": {"Threat level": "low", "Harden mods": "1/1", "Watchdog": "ok"},
            },
        },
    }


def _request(server, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection(
        serve_canvas.LOOPBACK_HOST, server.server_port, timeout=3
    )
    try:
        connection.request(
            "GET",
            path,
            headers={"Host": f"{serve_canvas.LOOPBACK_HOST}:{server.server_port}"},
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _start_server():
    server = serve_canvas.create_server(0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    return server, worker


def _stop_server(server, worker) -> None:
    server.shutdown()
    server.server_close()
    worker.join(timeout=3)


def test_canvas_uses_canonical_runtime_metrics_and_descriptor_read(
    tmp_path, monkeypatch,
) -> None:
    repository = tmp_path / "repository"
    runtime = tmp_path / "runtime"
    (repository / "diagnostics").mkdir(parents=True)
    (runtime / "diagnostics").mkdir(parents=True)
    (repository / "flow_canvas.html").write_text("safe-canvas", encoding="utf-8")
    (repository / "diagnostics" / "flow_metrics.json").write_text(
        json.dumps(_metrics(model="wrong-root")), encoding="utf-8"
    )
    (runtime / "diagnostics" / "flow_metrics.json").write_text(
        json.dumps(_metrics(model="canonical-runtime")), encoding="utf-8"
    )
    monkeypatch.setattr(serve_canvas, "_REPOSITORY_ROOT", repository)
    monkeypatch.setattr(serve_canvas, "_RUNTIME_DATA_ROOT", runtime)
    monkeypatch.setattr(Path, "open", lambda *_args, **_kwargs: pytest.fail("path reopened"))

    server, worker = _start_server()
    try:
        status, body = _request(server, "/diagnostics/flow_metrics.json")
        assert status == 200
        assert json.loads(body)["nodes"]["triage"]["metrics"]["Model"] == (
            "canonical-runtime"
        )
        assert _request(server, "/flow_canvas.html")[1] == b"safe-canvas"
    finally:
        _stop_server(server, worker)


def test_canvas_rejects_hardlinks_stale_or_out_of_contract_metrics(
    tmp_path, monkeypatch,
) -> None:
    repository = tmp_path / "repository"
    runtime = tmp_path / "runtime"
    repository.mkdir()
    (runtime / "diagnostics").mkdir(parents=True)
    source = tmp_path / "linked-canvas.html"
    source.write_text("not-authoritative", encoding="utf-8")
    try:
        os.link(source, repository / "flow_canvas.html")
    except OSError as exc:
        pytest.skip(f"hardlink creation is unavailable: {exc}")
    metrics_path = runtime / "diagnostics" / "flow_metrics.json"
    metrics_path.write_text(
        json.dumps(_metrics(generated_at=time.time() - 3600)), encoding="utf-8"
    )
    monkeypatch.setattr(serve_canvas, "_REPOSITORY_ROOT", repository)
    monkeypatch.setattr(serve_canvas, "_RUNTIME_DATA_ROOT", runtime)

    server, worker = _start_server()
    try:
        assert _request(server, "/flow_canvas.html")[0] == 404
        assert _request(server, "/diagnostics/flow_metrics.json")[0] == 422
        metrics_path.write_text(
            json.dumps(_metrics(model="x" * 129)), encoding="utf-8"
        )
        assert _request(server, "/diagnostics/flow_metrics.json")[0] == 422
        malformed = _metrics()
        malformed["unexpected"] = True
        metrics_path.write_text(json.dumps(malformed), encoding="utf-8")
        assert _request(server, "/diagnostics/flow_metrics.json")[0] == 422
    finally:
        _stop_server(server, worker)


def test_canvas_browser_open_follows_successful_os_selected_bind(monkeypatch) -> None:
    opened: list[str] = []
    monkeypatch.setattr(serve_canvas.webbrowser, "open", lambda url, **_kwargs: opened.append(url))
    monkeypatch.setattr(
        serve_canvas,
        "create_server",
        lambda _port: (_ for _ in ()).throw(OSError("occupied")),
    )
    assert serve_canvas.main([]) == 2
    assert opened == []

    class FakeServer:
        server_port = 49152

        @staticmethod
        def serve_forever() -> None:
            raise KeyboardInterrupt

        @staticmethod
        def server_close() -> None:
            pass

    monkeypatch.setattr(serve_canvas, "create_server", lambda port: FakeServer())
    assert serve_canvas.main([]) == 0
    assert opened == ["http://127.0.0.1:49152/flow_canvas.html"]


def test_canvas_rejects_descriptor_escape_and_parent_swap(
    tmp_path, monkeypatch,
) -> None:
    root = tmp_path / "root"
    (root / "diagnostics").mkdir(parents=True)
    target = root / "diagnostics" / "flow_metrics.json"
    target.write_bytes(b"trusted")
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside")
    monkeypatch.setattr(serve_canvas, "_descriptor_path", lambda _fd: outside)
    assert serve_canvas._read_stable_artifact(  # noqa: SLF001
        root, "diagnostics/flow_metrics.json", 100
    ) is None
    monkeypatch.undo()

    real_identity = serve_canvas._identity  # noqa: SLF001
    parent_identity = real_identity(os.lstat(root / "diagnostics"))
    parent_checks = 0

    def changed_parent_identity(metadata):
        nonlocal parent_checks
        identity = real_identity(metadata)
        if identity == parent_identity:
            parent_checks += 1
            if parent_checks > 1:
                return identity[0], identity[1] + 1
        return identity

    monkeypatch.setattr(serve_canvas, "_identity", changed_parent_identity)
    assert serve_canvas._read_stable_artifact(  # noqa: SLF001
        root, "diagnostics/flow_metrics.json", 100
    ) is None
    assert parent_checks == 2


def test_canvas_has_bounded_connection_and_header_budgets(monkeypatch) -> None:
    assert serve_canvas.HEADER_TIMEOUT_SECONDS <= 2.0
    monkeypatch.setattr(serve_canvas, "HEADER_TIMEOUT_SECONDS", 1.0)
    server = serve_canvas.create_server(0)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    partials: list[socket.socket] = []
    try:
        assert server.request_queue_size == serve_canvas.MAX_CONNECTIONS
        for _ in range(serve_canvas.MAX_CONNECTIONS):
            connection = socket.create_connection(server.server_address, timeout=2)
            connection.sendall(
                b"GET /flow_canvas.html HTTP/1.1\r\n"
                + f"Host: 127.0.0.1:{server.server_port}\r\nX-Wait: ".encode()
            )
            partials.append(connection)
        deadline = time.time() + 0.75
        while (
            server._connection_slots._value != 0  # noqa: SLF001
            and time.time() < deadline
        ):
            time.sleep(0.01)
        assert server._connection_slots._value == 0  # noqa: SLF001

        overflow = socket.create_connection(server.server_address, timeout=2)
        try:
            overflow.settimeout(0.75)
            overflow.sendall(b"GET /flow_canvas.html HTTP/1.1\r\n")
            try:
                assert overflow.recv(1) == b""
            except (ConnectionAbortedError, ConnectionResetError):
                pass
        finally:
            overflow.close()

        for connection in partials:
            connection.settimeout(2)
            try:
                assert connection.recv(1) == b""
            except (ConnectionAbortedError, ConnectionResetError):
                pass
    finally:
        for connection in partials:
            connection.close()
        _stop_server(server, worker)


def _operations_window() -> SimpleNamespace:
    return SimpleNamespace(
        config=SimpleNamespace(data_dir=Path("unused")),
        evidence_store=None,
        manager=object(),
        _operations_service=None,
        _operations_service_lock=threading.Lock(),
        _operations_service_shutdown=False,
        _operations_service_cancel=threading.Event(),
        _operations_service_state="idle",
        _operations_service_build_token=None,
        _operations_service_completion=threading.Event(),
        _operations_service_error="",
        _operations_modules_discovered=threading.Event(),
        _operations_modules_ready=threading.Event(),
    )


def test_operations_construction_is_nonblocking_and_cancelled_orphan_closes_once(
    monkeypatch,
) -> None:
    started = threading.Event()
    release = threading.Event()
    created = []

    class Service:
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1

    def factory(*_args, **_kwargs):
        started.set()
        assert release.wait(timeout=3)
        service = Service()
        created.append(service)
        return service

    monkeypatch.setattr("angerona.core.operations_center.LocalOperationsCenter", factory)
    window = _operations_window()
    window._operations_modules_discovered.set()
    errors: list[BaseException] = []

    def compose() -> None:
        try:
            MainWindow._ensure_operations_service(
                window, startup_owner=True, wait=True
            )
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=compose, daemon=True)
    worker.start()
    assert started.wait(timeout=3)
    before = time.perf_counter()
    with pytest.raises(RuntimeError, match="in progress"):
        MainWindow._ensure_operations_service(window)
    assert time.perf_counter() - before < 0.25

    before = time.perf_counter()
    MainWindow._close_operations_service(window)
    assert window._operations_service_cancel.is_set()
    assert time.perf_counter() - before < 0.25
    release.set()
    worker.join(timeout=3)

    assert errors and "cancelled" in str(errors[0])
    assert window._operations_service is None
    assert window._operations_service_state == "shutdown"
    assert len(created) == 1 and created[0].close_calls == 1
    MainWindow._close_operations_service(window)
    assert created[0].close_calls == 1


def test_shutdown_barrier_prevents_loader_resurrection(monkeypatch) -> None:
    entered_start = threading.Event()
    release_start = threading.Event()
    trace: list[str] = []

    class Manager:
        modules = {}

        @staticmethod
        def discover() -> None:
            trace.append("discover")

        @staticmethod
        def start_enabled(*, deferred_names) -> None:
            trace.append("start-enter")
            entered_start.set()
            assert release_start.wait(timeout=3)
            trace.append("start-exit")

    app = AngeronaApp.__new__(AngeronaApp)
    app._shutdown_requested = threading.Event()
    app._shutdown_gate = threading.Lock()
    app._startup_lifecycle_lock = threading.Lock()
    app.config = SimpleNamespace(eco_mode=False, blackbox_enabled=False)
    app.bus = object()
    app.manager = Manager()
    app.window = SimpleNamespace(
        _ECO_HEAVY_MODULES=(),
        startup_eco_requested=SimpleNamespace(emit=lambda: trace.append("eco")),
        _mark_operations_modules_discovered=lambda: trace.append(
            "operations-discovered"
        ),
        _ensure_operations_service=lambda **_kwargs: trace.append(
            "operations-ready"
        ) or object(),
    )
    app.reporter = SimpleNamespace(start=lambda: trace.append("reporter-start"))
    app._mcp = None
    app._resilience = None
    app._record_startup_degradation = lambda *_args: None
    app._start_fleet_service = lambda: trace.append("fleet-start")
    app._shutdown_owned = lambda: trace.append("cleanup")
    monkeypatch.setenv("ANGERONA_RESILIENCE", "0")

    loader = threading.Thread(target=app._load_modules_guarded, daemon=True)
    loader.start()
    assert entered_start.wait(timeout=3)
    shutdown = threading.Thread(target=app.shutdown, daemon=True)
    shutdown.start()
    assert app._shutdown_requested.wait(timeout=1)
    assert "cleanup" not in trace
    release_start.set()
    loader.join(timeout=3)
    shutdown.join(timeout=3)

    assert trace[-1] == "cleanup"
    assert "reporter-start" not in trace
    assert "fleet-start" not in trace


def test_flow_metrics_emits_versioned_fresh_contract(monkeypatch) -> None:
    monkeypatch.setattr(flow_metrics, "_hw_cache", {"tier": "cpu", "model": "local"})
    manager = SimpleNamespace(modules={})
    bus = SimpleNamespace(recent=lambda _limit: [])
    document = flow_metrics.build_metrics(
        manager, bus, SimpleNamespace(ollama_model="local")
    )
    assert document["schema_version"] == 1
    assert time.time() - document["generated_at_epoch"] < 2
    assert serve_canvas._valid_metrics(json.dumps(document).encode("utf-8"))  # noqa: SLF001


def test_canvas_metrics_rendering_has_no_html_execution_sink() -> None:
    canvas = Path("flow_canvas.html").read_text(encoding="utf-8")
    assert "innerHTML" not in canvas
    assert "textContent=String(value)" in canvas
    assert "validLiveFeed(data)" in canvas
    batch = Path("serve-canvas.bat").read_text(encoding="utf-8").casefold()
    assert "py -3" not in batch
    assert "start \"\" http" not in batch
