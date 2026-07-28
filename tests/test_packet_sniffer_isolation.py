from __future__ import annotations

import json
import subprocess

from angerona.modules import packet_sniffer as module
from angerona.modules.packet_sniffer_worker import _token_kind


class _FakeWorker:
    def __init__(self, returncode: int, output: str = "") -> None:
        self.returncode = returncode
        self._output = output
        self.terminated = False

    def poll(self):
        return self.returncode

    def communicate(self, timeout=None):
        return self._output, ""

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


def test_worker_protocol_redacts_secret_values():
    secret = "password=do-not-log-this"
    assert _token_kind(secret.encode()) == "password"

    decoded = module._decode_records(
        json.dumps(
            {
                "type": "detection",
                "src": "10.0.0.4",
                "dst": "10.0.0.8",
                "token_kind": "password",
                "payload": secret,
            }
        )
    )

    assert decoded == (
        {
            "type": "detection",
            "src": "10.0.0.4",
            "dst": "10.0.0.8",
            "token_kind": "password",
        },
    )
    assert secret not in repr(decoded)


def test_native_worker_fault_is_returned_as_data(monkeypatch):
    native_access_violation = -1073741819
    worker = _FakeWorker(native_access_violation)
    sniffer = module.PacketSnifferModule()
    monkeypatch.setattr(sniffer, "_launch_worker", lambda: worker)

    result = sniffer._capture_once()

    assert result is not None
    assert result.returncode == native_access_violation
    assert module._returncode_label(result.returncode) == "0xC0000005"


def test_stop_terminates_capture_worker():
    worker = _FakeWorker(returncode=None)  # type: ignore[arg-type]
    sniffer = module.PacketSnifferModule()
    with sniffer._worker_lock:
        sniffer._worker = worker  # type: ignore[assignment]

    sniffer.stop()

    assert worker.terminated
    assert sniffer._worker is None


def test_decode_rejects_non_json_and_bounds_untrusted_fields():
    output = "\n".join(
        (
            "not-json",
            json.dumps(
                {
                    "type": "error",
                    "message": "x" * 500,
                }
            ),
        )
    )
    records = module._decode_records(output)
    assert len(records) == 1
    assert records[0]["type"] == "error"
    assert len(records[0]["message"]) == 240
