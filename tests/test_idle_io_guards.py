from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
from contextlib import nullcontext
from types import SimpleNamespace

from angerona.modules import frz_heartbeat
from angerona.resilience import diagnostics, heartbeat, scanner


def test_frz_beat_publishes_without_durable_flush(monkeypatch) -> None:
    class WriterSpy:
        beats = 0

        def beat(self) -> None:
            self.beats += 1

    module = frz_heartbeat.FrzHeartbeatModule()
    writer = WriterSpy()
    module._heartbeat_writer = writer

    module._write_beat()

    assert writer.beats == 1
    assert module._beats == 1


def test_unflushed_frz_mmap_is_visible_to_another_process(tmp_path) -> None:
    path = tmp_path / "frz.mmap"
    key = bytes(range(32))
    writer = heartbeat.HeartbeatWriter(
        frz_heartbeat._HEARTBEAT_COMPONENT,
        token_raw=key,
        path=path,
    )
    writer.beat()

    # Match the external watchdog's independent open/read behavior. No flush()
    # occurs before the child authenticates the new fixed v2 record, and the
    # child uses the shared protocol API rather than duplicating wire offsets.
    code = (
        "import pathlib,sys; "
        "from angerona.resilience.heartbeat import HeartbeatReader; "
        "r=HeartbeatReader(sys.argv[2], path=pathlib.Path(sys.argv[1]), "
        "key_raw=bytes.fromhex(sys.argv[3])); "
        "x=r.read(); print(r.authentication_status(record=x),x['pid'],x['flags'])"
    )
    env = dict(os.environ)
    src = str(pathlib.Path(__file__).resolve().parents[1] / "src")
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")
    raw = subprocess.check_output(
        [
            sys.executable,
            "-c",
            code,
            str(path),
            frz_heartbeat._HEARTBEAT_COMPONENT,
            key.hex(),
        ],
        text=True,
        timeout=10,
        env=env,
    ).strip()
    writer.close()

    assert raw == f"authenticated {os.getpid() & 0xFFFFFFFF} 1"


def test_component_status_does_not_overwrite_dashboard_aggregate(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setenv("ANGERONA_DIAG_DIR", str(tmp_path))
    dashboard = {"schema": "dashboard", "modules": {"running": 42}}
    aggregate = tmp_path / "status.json"
    aggregate.write_text(json.dumps(dashboard), encoding="utf-8")

    assert diagnostics.write_status("scanner", "running", {"marker": "test"})

    assert json.loads(aggregate.read_text(encoding="utf-8")) == dashboard
    component = json.loads(
        (tmp_path / "status_scanner.json").read_text(encoding="utf-8")
    )
    assert component["component"] == "scanner"
    assert component["marker"] == "test"


def test_process_sensor_fetches_expensive_fields_only_for_new_pids(
    monkeypatch,
) -> None:
    class NoSuchProcess(Exception):
        pass

    class AccessDenied(Exception):
        pass

    class FakeProcess:
        def __init__(self, pid: int, ppid: int, name: str) -> None:
            self.info = {"pid": pid}
            self._ppid = ppid
            self._name = name
            self.calls: list[str] = []

        def oneshot(self):
            return nullcontext()

        def ppid(self) -> int:
            self.calls.append("ppid")
            return self._ppid

        def name(self) -> str:
            self.calls.append("name")
            return self._name

        def exe(self) -> str:
            self.calls.append("exe")
            return f"C:/safe/{self._name}"

        def cmdline(self) -> list[str]:
            self.calls.append("cmdline")
            return [self._name, "--safe"]

    parent = FakeProcess(10, 1, "parent.exe")
    child = FakeProcess(11, 10, "child.exe")
    rows = [parent]
    requested_attrs: list[tuple[str, ...]] = []

    def process_iter(attrs, ad_value=None):
        requested_attrs.append(tuple(attrs))
        return list(rows)

    by_pid = {10: parent, 11: child}
    fake_psutil = SimpleNamespace(
        process_iter=process_iter,
        Process=lambda pid: by_pid[pid],
        NoSuchProcess=NoSuchProcess,
        AccessDenied=AccessDenied,
    )
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)

    sensor = scanner.RawProcessSensor()
    assert list(sensor.poll()) == []
    rows.append(child)
    frames = list(sensor.poll())

    assert requested_attrs == [("pid",), ("pid",)]
    assert "exe" not in parent.calls and "cmdline" not in parent.calls
    assert "exe" in child.calls and "cmdline" in child.calls
    record = json.loads(frames[0])
    assert record["pid"] == 11
    assert record["parent_name"] == "parent.exe"


def test_scanner_status_is_periodic_but_change_driven(monkeypatch) -> None:
    host = scanner.ScannerHost.__new__(scanner.ScannerHost)
    host.ring = SimpleNamespace(backpressure=False)
    host._last_status = 10.0
    host._last_ping_poll = 10.0
    host._last_ping = ""
    host._last_backpressure = False
    ping = {"value": ""}
    writes: list[tuple[float, str, bool]] = []
    clock = {"value": 0.0}

    monkeypatch.setattr(host, "_read_ping", lambda: ping["value"])
    monkeypatch.setattr(
        host,
        "_write_status",
        lambda: writes.append(
            (clock["value"], host._last_ping, bool(host.ring.backpressure))
        ),
    )

    clock["value"] = 11.0
    assert not host._maybe_write_status(clock["value"])

    ping["value"] = "nonce"
    clock["value"] = 12.0
    assert host._maybe_write_status(clock["value"])

    host.ring.backpressure = True
    clock["value"] = 13.0
    assert host._maybe_write_status(clock["value"])

    clock["value"] = 42.9
    assert not host._maybe_write_status(clock["value"])
    clock["value"] = 43.0
    assert host._maybe_write_status(clock["value"])

    assert writes == [
        (12.0, "nonce", False),
        (13.0, "nonce", True),
        (43.0, "nonce", True),
    ]
