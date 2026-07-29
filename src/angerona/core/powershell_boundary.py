"""Review-gated boundary for a small fixed set of local PowerShell operations."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Mapping, Sequence

MAX_OUTPUT_BYTES = 64 * 1024
MAX_TIMEOUT_SECONDS = 120.0
_SAFE_SERVICE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SAFE_RULE = re.compile(r"^Angerona-[A-Za-z0-9_.-]{1,100}$")
_SAFE_PATH = re.compile(r"^[A-Za-z]:\\[^*\r\n]{1,500}$")


@dataclass(frozen=True)
class PowerShellRequest:
    operation_id: str
    arguments: tuple[tuple[str, str], ...] = ()
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        frozen_arguments = tuple((str(name), str(value)) for name, value in self.arguments)
        object.__setattr__(self, "arguments", frozen_arguments)
        if self.operation_id not in _OPERATIONS:
            raise ValueError("unsupported PowerShell operation")
        if not 0 < float(self.timeout_seconds) <= MAX_TIMEOUT_SECONDS:
            raise ValueError("timeout is outside the allowed range")
        names = [name for name, _ in self.arguments]
        if len(names) != len(set(names)):
            raise ValueError("duplicate argument")
        expected = set(_OPERATIONS[self.operation_id].arguments)
        if set(names) != expected:
            raise ValueError(f"arguments must be exactly {sorted(expected)}")
        for name, value in self.arguments:
            _OPERATIONS[self.operation_id].arguments[name](value)

    def canonical(self) -> bytes:
        return json.dumps({
            "operation_id": self.operation_id,
            "arguments": sorted(self.arguments),
            "timeout_seconds": float(self.timeout_seconds),
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def request_hash(self) -> str:
        return hashlib.sha256(self.canonical()).hexdigest()

    def argument_map(self) -> dict[str, str]:
        return dict(self.arguments)


@dataclass(frozen=True)
class ApprovalToken:
    request_hash: str
    expires_at: float
    signature: str


@dataclass(frozen=True)
class PowerShellResult:
    operation_id: str
    request_hash: str
    preview: bool
    approved: bool
    executed: bool
    success: bool
    exit_code: int | None
    stdout: str
    stderr: str
    started_at: float
    finished_at: float
    error: str = ""
    output_truncated: bool = False


@dataclass(frozen=True)
class _Operation:
    arguments: Mapping[str, Callable[[str], None]]
    render: Callable[[Mapping[str, str]], str]


def _validate_service(value: str) -> None:
    if not _SAFE_SERVICE.fullmatch(value):
        raise ValueError("invalid service name")


def _validate_rule(value: str) -> None:
    if not _SAFE_RULE.fullmatch(value):
        raise ValueError("invalid Angerona firewall rule name")


def _validate_path(value: str) -> None:
    if not _SAFE_PATH.fullmatch(value) or "'" in value:
        raise ValueError("invalid local Windows path")


def _quote(value: str) -> str:
    """PowerShell single-quote escaping; validation remains the primary gate."""
    return "'" + value.replace("'", "''") + "'"


_OPERATIONS: dict[str, _Operation] = {
    "service_restart": _Operation(
        {"service_name": _validate_service},
        lambda a: "Restart-Service -Name " + _quote(a["service_name"]) + " -ErrorAction Stop",
    ),
    "firewall_rule_remove": _Operation(
        {"rule_name": _validate_rule},
        lambda a: "Remove-NetFirewallRule -DisplayName "
        + _quote(a["rule_name"]) + " -ErrorAction Stop",
    ),
    "restore_point_create": _Operation(
        {},
        lambda _a: "Checkpoint-Computer -Description 'Angerona recovery point' "
        "-RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop",
    ),
    "defender_custom_scan": _Operation(
        {"path": _validate_path},
        lambda a: "Start-MpScan -ScanType CustomScan -ScanPath "
        + _quote(a["path"]) + " -ErrorAction Stop",
    ),
}


Runner = Callable[..., subprocess.CompletedProcess[str]]


class PowerShellBoundary:
    def __init__(
        self,
        approval_key: bytes,
        *,
        execution_enabled: bool = False,
        runner: Runner | None = None,
        executable: str = "powershell.exe",
    ) -> None:
        if len(approval_key) < 32:
            raise ValueError("approval key must be at least 32 bytes")
        self._key = bytes(approval_key)
        self.execution_enabled = bool(execution_enabled)
        self._runner = runner or subprocess.run
        self._executable = executable

    def preview(self, request: PowerShellRequest) -> tuple[str, ...]:
        script = _OPERATIONS[request.operation_id].render(request.argument_map())
        return (
            self._executable, "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "AllSigned", "-Command", script,
        )

    def issue_approval(
        self, request: PowerShellRequest, *, expires_at: float
    ) -> ApprovalToken:
        if expires_at <= time.time() or expires_at > time.time() + 3600:
            raise ValueError("approval expiry must be within the next hour")
        body = f"{request.request_hash}:{float(expires_at):.6f}".encode("ascii")
        return ApprovalToken(
            request.request_hash, float(expires_at),
            hmac.new(self._key, body, hashlib.sha256).hexdigest(),
        )

    def verify_approval(
        self, request: PowerShellRequest, token: ApprovalToken | None,
        *, now: float | None = None,
    ) -> bool:
        if token is None or token.request_hash != request.request_hash:
            return False
        stamp = time.time() if now is None else float(now)
        if token.expires_at < stamp:
            return False
        body = f"{token.request_hash}:{token.expires_at:.6f}".encode("ascii")
        expected = hmac.new(self._key, body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, token.signature)

    @staticmethod
    def _bound_output(value: str | bytes | None) -> tuple[str, bool]:
        if isinstance(value, bytes):
            raw = value
        else:
            raw = (value or "").encode("utf-8", errors="replace")
        truncated = len(raw) > MAX_OUTPUT_BYTES
        return raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"), truncated

    def run(
        self,
        request: PowerShellRequest,
        *,
        approval: ApprovalToken | None = None,
        execute: bool = False,
    ) -> PowerShellResult:
        started = time.time()
        approved = self.verify_approval(request, approval)
        if not execute:
            return PowerShellResult(
                request.operation_id, request.request_hash, True, approved,
                False, True, None, "", "", started, time.time(),
            )
        if not self.execution_enabled:
            return PowerShellResult(
                request.operation_id, request.request_hash, False, approved,
                False, False, None, "", "", started, time.time(),
                "PowerShell execution is disabled",
            )
        if not approved:
            return PowerShellResult(
                request.operation_id, request.request_hash, False, False,
                False, False, None, "", "", started, time.time(),
                "valid approval token required",
            )
        try:
            completed = self._runner(
                list(self.preview(request)), capture_output=True, text=True,
                timeout=float(request.timeout_seconds), check=False,
            )
            stdout, trunc_out = self._bound_output(completed.stdout)
            stderr, trunc_err = self._bound_output(completed.stderr)
            return PowerShellResult(
                request.operation_id, request.request_hash, False, True, True,
                completed.returncode == 0, int(completed.returncode), stdout,
                stderr, started, time.time(),
                output_truncated=trunc_out or trunc_err,
            )
        except subprocess.TimeoutExpired as exc:
            stdout, trunc_out = self._bound_output(exc.stdout)
            stderr, trunc_err = self._bound_output(exc.stderr)
            return PowerShellResult(
                request.operation_id, request.request_hash, False, True, True,
                False, None, stdout, stderr, started, time.time(),
                "execution timed out", trunc_out or trunc_err,
            )
        except Exception as exc:
            return PowerShellResult(
                request.operation_id, request.request_hash, False, True, True,
                False, None, "", "", started, time.time(),
                f"execution failed: {type(exc).__name__}",
            )
