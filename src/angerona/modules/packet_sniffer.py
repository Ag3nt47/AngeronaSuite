"""Crash-isolated deep-packet inspection.

Npcap/Scapy packet dissection is intentionally executed in a short-lived helper
process.  A malformed frame or a native capture-driver fault must never be able
to terminate the Angerona Core process (and therefore the dashboard).
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Any

from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import popen_hidden

_CAPTURE_WINDOW_SECONDS = 30.0
_WORKER_POLL_SECONDS = 0.20
_WORKER_STOP_TIMEOUT = 1.5
_MAX_FAILURE_BACKOFF = 60.0


@dataclass(frozen=True)
class _CaptureResult:
    returncode: int
    records: tuple[dict[str, Any], ...]
    diagnostic: str = ""


def _returncode_label(returncode: int) -> str:
    """Return a stable diagnostic label, including Windows NTSTATUS values."""
    if returncode >= 0:
        return str(returncode)
    return f"0x{(returncode & 0xFFFFFFFF):08X}"


def _decode_records(output: str) -> tuple[dict[str, Any], ...]:
    """Decode only the worker's bounded JSON objects.

    Payload contents are never accepted from the helper.  The protocol carries
    only endpoints and the *kind* of token found, so captured credentials cannot
    leak into alerts, logs, reports, or crash diagnostics.
    """
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            raw = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(raw, dict):
            continue
        kind = str(raw.get("type", ""))[:24]
        if kind == "detection":
            records.append(
                {
                    "type": "detection",
                    "src": str(raw.get("src", ""))[:64],
                    "dst": str(raw.get("dst", ""))[:64],
                    "token_kind": str(raw.get("token_kind", "credential"))[:32],
                }
            )
        elif kind == "error":
            records.append(
                {
                    "type": "error",
                    "message": str(raw.get("message", "capture worker error"))[:240],
                }
            )
        if len(records) >= 256:
            break
    return tuple(records)


class PacketSnifferModule(BaseModule):
    name = "Packet Sniffer"
    description = (
        "Inspects network packets for cleartext credentials in a crash-isolated "
        "capture worker."
    )
    category = "Network"
    enabled_by_default = False  # requires Scapy + Npcap

    def __init__(self) -> None:
        super().__init__()
        self._worker_lock = threading.Lock()
        self._worker: subprocess.Popen[str] | None = None
        self._worker_failures = 0

    def _launch_worker(self) -> subprocess.Popen[str]:
        return popen_hidden(
            [
                sys.executable,
                "-m",
                "angerona.modules.packet_sniffer_worker",
                "--timeout",
                str(_CAPTURE_WINDOW_SECONDS),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def _terminate_worker(self, worker: subprocess.Popen[str] | None = None) -> None:
        with self._worker_lock:
            target = worker if worker is not None else self._worker
        if target is None:
            return
        try:
            if target.poll() is None:
                target.terminate()
                try:
                    target.wait(timeout=_WORKER_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    target.kill()
                    target.wait(timeout=_WORKER_STOP_TIMEOUT)
        except Exception:
            pass
        finally:
            with self._worker_lock:
                if self._worker is target:
                    self._worker = None

    def _capture_once(self) -> _CaptureResult | None:
        """Run one bounded capture generation.

        ``None`` means the module was stopped. Any native failure is represented
        as data and contained inside the worker process.
        """
        worker = self._launch_worker()
        with self._worker_lock:
            self._worker = worker
        try:
            stop_event = self.generation_stop_event()
            while worker.poll() is None:
                if stop_event.wait(_WORKER_POLL_SECONDS):
                    self._terminate_worker(worker)
                    return None
            stdout, _ = worker.communicate(timeout=_WORKER_STOP_TIMEOUT)
            records = _decode_records(stdout or "")
            diagnostic = ""
            for record in records:
                if record.get("type") == "error":
                    diagnostic = str(record.get("message", ""))
                    break
            return _CaptureResult(
                returncode=int(worker.returncode or 0),
                records=records,
                diagnostic=diagnostic,
            )
        finally:
            self._terminate_worker(worker)

    def _publish_detections(self, records: tuple[dict[str, Any], ...]) -> None:
        for record in records:
            if record.get("type") != "detection":
                continue
            src = str(record.get("src") or "unknown")
            dst = str(record.get("dst") or "unknown")
            token_kind = str(record.get("token_kind") or "credential")
            self.emit(
                f"Possible cleartext {token_kind} {src}\N{RIGHTWARDS ARROW}{dst}; "
                "captured value redacted.",
                Severity.HIGH,
                src=src,
                dst=dst,
                token_kind=token_kind,
                payload_redacted=True,
                capture_isolation="subprocess",
            )

    def run(self) -> None:
        # Do not import Scapy into Core. Even import/probe stays inside the
        # subprocess boundary except for this non-loading package-presence check.
        try:
            scapy_present = importlib.util.find_spec("scapy") is not None
        except (ImportError, ValueError):
            scapy_present = False
        if not scapy_present:
            self.status = "error"
            self.set_health(0, "Scapy/Npcap is not installed")
            self.emit(
                "Packet sniffer disabled: Scapy/Npcap not installed.",
                Severity.MEDIUM,
            )
            return

        self.emit(
            "Packet sniffer active in a crash-isolated capture process.",
            Severity.INFO,
            capture_isolation="subprocess",
        )
        self.set_health(100, "")

        while not self.stopping:
            try:
                result = self._capture_once()
            except Exception as exc:
                if self.stopping:
                    break
                result = _CaptureResult(1, (), str(exc))
            if result is None:
                break

            self._publish_detections(result.records)
            if result.returncode == 0:
                self._worker_failures = 0
                self.last_error = ""
                self.set_health(100, "")
                self.mark_cycle_complete()
                continue

            self._worker_failures += 1
            code = _returncode_label(result.returncode)
            detail = result.diagnostic or f"worker exit {code}"
            self.last_error = detail
            self.set_health(
                45,
                "Capture worker fault contained; Core remained online",
            )
            # One alert per failed capture generation is useful. The exponential
            # restart delay prevents a broken Npcap installation from thrashing.
            self.emit(
                "Packet capture worker fault was contained; Angerona Core stayed "
                f"online (exit {code}). Retrying with backoff.",
                Severity.MEDIUM,
                worker_exit=code,
                failure_count=self._worker_failures,
                capture_isolation="subprocess",
            )
            delay = min(
                _MAX_FAILURE_BACKOFF,
                2.0 ** min(self._worker_failures, 6),
            )
            self.sleep(delay)

    def stop(self) -> None:
        super().stop()
        self._terminate_worker()

    def self_test(self) -> tuple[bool, str]:
        isolated = "subprocess"
        if self.status == "running" and self.health >= 40:
            return True, f"running, capture isolation={isolated}, health {self.health}%"
        if self.status == "stopped":
            return True, f"ready, capture isolation={isolated}"
        return False, (
            f"status={self.status}, capture isolation={isolated}, "
            f"health {self.health}%"
        )


def register() -> PacketSnifferModule:
    return PacketSnifferModule()
