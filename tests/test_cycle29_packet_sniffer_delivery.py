from __future__ import annotations

import io
import json
import subprocess
import sys
import time

from angerona.modules import packet_sniffer as sniffer_module


class _BufferedWorker:
    def __init__(self, output: str, returncode: int = 0) -> None:
        self.stdout = io.StringIO(output)
        self.returncode = returncode

    def poll(self):
        return self.returncode

    def terminate(self):
        return None

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


def _line(record: dict) -> str:
    return json.dumps(record, separators=(",", ":")) + "\n"


def test_success_requires_consistent_loss_free_terminal_receipt(monkeypatch) -> None:
    detection = _line(
        {
            "type": "detection",
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "token_kind": "password",
        }
    )
    module = sniffer_module.PacketSnifferModule()
    monkeypatch.setattr(module, "_launch_worker", lambda: _BufferedWorker(detection))

    missing = module._capture_once()
    assert missing is not None
    assert missing.returncode == 126
    assert not missing.complete

    output = detection + _line({"type": "end", "emitted": 1, "dropped": 1})
    monkeypatch.setattr(module, "_launch_worker", lambda: _BufferedWorker(output))
    lossy = module._capture_once()
    assert lossy is not None
    assert lossy.returncode == 126
    assert not lossy.complete
    assert "dropped" in lossy.diagnostic


def test_parent_drains_pipe_while_worker_is_running(monkeypatch) -> None:
    # This output is larger than a normal Windows anonymous-pipe buffer. A
    # parent that waits for process exit before reading stdout deadlocks here.
    script = """
import json
for i in range(200):
    print(json.dumps({"type":"detection","src":f"10.0.0.{i % 250}","dst":"10.0.1.1","token_kind":"password"}), flush=True)
print(json.dumps({"type":"end","emitted":200,"dropped":0}), flush=True)
"""

    def launch():
        return subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )

    module = sniffer_module.PacketSnifferModule()
    monkeypatch.setattr(module, "_launch_worker", launch)

    result = module._capture_once()

    assert result is not None
    assert result.returncode == 0
    assert result.complete
    assert sum(record["type"] == "detection" for record in result.records) == 200


def test_hung_worker_is_killed_at_hard_deadline(monkeypatch) -> None:
    def launch():
        return subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )

    module = sniffer_module.PacketSnifferModule()
    monkeypatch.setattr(module, "_launch_worker", launch)
    monkeypatch.setattr(sniffer_module, "_WORKER_HARD_DEADLINE", 0.01)
    monkeypatch.setattr(sniffer_module, "_WORKER_POLL_SECONDS", 0.01)
    started = time.monotonic()

    result = module._capture_once()

    assert result is not None
    assert result.returncode == 124
    assert not result.complete
    assert time.monotonic() - started < 3.0
