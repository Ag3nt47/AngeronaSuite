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
import time
from dataclasses import dataclass
from typing import Any

from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import popen_hidden

_CAPTURE_WINDOW_SECONDS = 30.0
_WORKER_POLL_SECONDS = 0.20
_WORKER_STOP_TIMEOUT = 1.5
_WORKER_HARD_DEADLINE = _CAPTURE_WINDOW_SECONDS + 5.0
_MAX_WORKER_OUTPUT_CHARS = 256 * 1024
_MAX_FAILURE_BACKOFF = 60.0


@dataclass(frozen=True)
class _CaptureResult:
    returncode: int
    records: tuple[dict[str, Any], ...]
    diagnostic: str = ""
    complete: bool = False
    output_truncated: bool = False


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
        elif kind == "end":
            try:
                emitted = max(0, min(256, int(raw.get("emitted", 0))))
                dropped = max(0, int(raw.get("dropped", 0)))
            except (TypeError, ValueError, OverflowError):
                continue
            records.append(
                {
                    "type": "end",
                    "emitted": emitted,
                    "dropped": dropped,
                }
            )
        if len(records) >= 257:
            break
    return tuple(records)


class PacketSnifferModule(BaseModule):
    name = "Packet Sniffer"
    version = "1.13.0"
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
        output_parts: list[str] = []
        output_chars = 0
        output_truncated = False
        drain_error = ""
        stdout = getattr(worker, "stdout", None)

        def _drain_stdout() -> None:
            nonlocal output_chars, output_truncated, drain_error
            if stdout is None:
                return
            try:
                while True:
                    chunk = stdout.read(4096)
                    if not chunk:
                        break
                    if isinstance(chunk, bytes):
                        chunk = chunk.decode("utf-8", "replace")
                    remaining = _MAX_WORKER_OUTPUT_CHARS - output_chars
                    if remaining > 0:
                        output_parts.append(chunk[:remaining])
                        output_chars += min(len(chunk), remaining)
                    if len(chunk) > remaining:
                        output_truncated = True
            except Exception as exc:  # represented as a failed capture receipt
                drain_error = str(exc)[:240]

        drain_thread: threading.Thread | None = None
        if stdout is not None:
            drain_thread = threading.Thread(
                target=_drain_stdout,
                name="AngeronaPacketPipeDrain",
                daemon=True,
            )
            drain_thread.start()
        try:
            stop_event = self.generation_stop_event()
            deadline = time.monotonic() + _WORKER_HARD_DEADLINE
            while worker.poll() is None:
                if stop_event.wait(_WORKER_POLL_SECONDS):
                    self._terminate_worker(worker)
                    return None
                if time.monotonic() >= deadline:
                    self._terminate_worker(worker)
                    return _CaptureResult(
                        124,
                        (),
                        "capture worker exceeded its hard deadline",
                        complete=False,
                    )

            if drain_thread is None:
                captured, _ = worker.communicate(timeout=_WORKER_STOP_TIMEOUT)
                if isinstance(captured, bytes):
                    captured = captured.decode("utf-8", "replace")
                if len(captured or "") > _MAX_WORKER_OUTPUT_CHARS:
                    output_truncated = True
                output_parts.append((captured or "")[:_MAX_WORKER_OUTPUT_CHARS])
            else:
                drain_thread.join(timeout=_WORKER_STOP_TIMEOUT)
                if drain_thread.is_alive():
                    return _CaptureResult(
                        125,
                        (),
                        "capture worker pipe did not reach EOF",
                        complete=False,
                    )

            records = _decode_records("".join(output_parts))
            diagnostic = ""
            for record in records:
                if record.get("type") == "error":
                    diagnostic = str(record.get("message", ""))
                    break
            end_receipts = [record for record in records if record.get("type") == "end"]
            detection_count = sum(
                1 for record in records if record.get("type") == "detection"
            )
            terminal_counts_match = bool(
                len(end_receipts) == 1
                and int(end_receipts[0].get("dropped", 0)) == 0
                and int(end_receipts[0].get("emitted", -1)) == detection_count
            )
            complete = (
                int(worker.returncode or 0) == 0
                and terminal_counts_match
                and not output_truncated
                and not drain_error
            )
            returncode = int(worker.returncode or 0)
            if returncode == 0 and not complete:
                returncode = 126
                if not diagnostic:
                    if output_truncated:
                        diagnostic = "capture worker output exceeded its bounded pipe budget"
                    elif drain_error:
                        diagnostic = f"capture worker pipe failed: {drain_error}"
                    elif len(end_receipts) == 1 and int(
                        end_receipts[0].get("dropped", 0)
                    ):
                        diagnostic = (
                            "capture worker reported "
                            f"{int(end_receipts[0]['dropped'])} dropped detections"
                        )
                    else:
                        diagnostic = "capture worker terminal receipt was missing or inconsistent"
            return _CaptureResult(
                returncode=returncode,
                records=records,
                diagnostic=diagnostic,
                complete=complete,
                output_truncated=output_truncated,
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
            if result.returncode == 0 and result.complete:
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
                complete=result.complete,
                output_truncated=result.output_truncated,
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
