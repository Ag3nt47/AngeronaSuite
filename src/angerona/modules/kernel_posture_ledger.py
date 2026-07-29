"""Read-only Windows kernel-boundary posture ledger.

This module does not claim kernel enforcement.  It raises the cost of reaching
the kernel unnoticed by continuously recording the host controls and transition
points an attacker commonly weakens first: Secure Boot, VBS/HVCI, boot debug and
test-signing flags, Code Integrity telemetry, and kernel-driver services.

Every observation is canonicalized into a bounded hash chain.  Unknown or
unreadable state is reported as degraded coverage, never as healthy.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from angerona.core.module_base import BaseModule, Severity
from angerona.core.win import run_hidden

LEDGER_VERSION = 1
GENESIS_HASH = "0" * 64
MAX_LEDGER_RECORDS = 256


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _bounded_text(value: object, limit: int = 240) -> str:
    return str(value or "").replace("\r", " ").replace("\n", " ")[:limit]


def _powershell_json(script: str, timeout: float = 8.0) -> object | None:
    if os.name != "nt":
        return None
    command = [
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-ExecutionPolicy", "Bypass", "-Command",
        f"$ErrorActionPreference='Stop'; {script} | ConvertTo-Json -Compress",
    ]
    try:
        result = run_hidden(
            command, capture_output=True, text=True, timeout=timeout,
            check=False,
        )
        if result.returncode != 0 or not (result.stdout or "").strip():
            return None
        return json.loads(result.stdout)
    except Exception:
        return None


def _secure_boot() -> bool | None:
    value = _powershell_json("[bool](Confirm-SecureBootUEFI)")
    return value if isinstance(value, bool) else None


def _device_guard() -> dict:
    value = _powershell_json(
        "$d=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard "
        "-ClassName Win32_DeviceGuard; "
        "[pscustomobject]@{vbs=[int]$d.VirtualizationBasedSecurityStatus;"
        "services=@($d.SecurityServicesRunning)}"
    )
    if not isinstance(value, dict):
        return {"vbs_status": None, "hvci": None}
    services = value.get("services")
    if not isinstance(services, list):
        services = [] if services is None else [services]
    vbs = value.get("vbs")
    return {
        "vbs_status": int(vbs) if isinstance(vbs, (int, float)) else None,
        # Win32_DeviceGuard SecurityServicesRunning value 2 is Memory Integrity.
        "hvci": 2 in services,
    }


def _boot_flags() -> dict:
    if os.name != "nt":
        return {"testsigning": None, "debug": None, "nointegritychecks": None}
    try:
        result = run_hidden(
            ["bcdedit.exe", "/enum", "{current}"],
            capture_output=True, text=True, timeout=6, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("bcdedit unavailable")
        text = (result.stdout or "").lower()

        def enabled(name: str) -> bool:
            return any(
                line.strip().startswith(name) and line.split()[-1] in {"yes", "on", "true", "1"}
                for line in text.splitlines()
            )

        return {
            "testsigning": enabled("testsigning"),
            "debug": enabled("debug"),
            "nointegritychecks": enabled("nointegritychecks"),
        }
    except Exception:
        return {"testsigning": None, "debug": None, "nointegritychecks": None}


def _code_integrity_log() -> bool | None:
    if os.name != "nt":
        return None
    try:
        result = run_hidden(
            ["wevtutil.exe", "gli", "Microsoft-Windows-CodeIntegrity/Operational"],
            capture_output=True, text=True, timeout=6, check=False,
        )
        return result.returncode == 0
    except Exception:
        return None


def _driver_services(limit: int = 2048) -> list[dict]:
    """Return bounded driver-service metadata without loading driver binaries."""
    if os.name != "nt":
        return []
    try:
        import winreg
        root = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services",
            0,
            winreg.KEY_READ,
        )
    except Exception:
        return []
    rows: list[dict] = []
    try:
        count = winreg.QueryInfoKey(root)[0]
        for index in range(min(count, limit)):
            try:
                name = winreg.EnumKey(root, index)
                key = winreg.OpenKey(root, name, 0, winreg.KEY_READ)
                try:
                    service_type = int(winreg.QueryValueEx(key, "Type")[0])
                    if not service_type & 0x3:  # kernel or filesystem driver
                        continue
                    try:
                        image = _bounded_text(winreg.QueryValueEx(key, "ImagePath")[0])
                    except OSError:
                        image = ""
                    try:
                        start = int(winreg.QueryValueEx(key, "Start")[0])
                    except OSError:
                        start = -1
                    rows.append({"name": name, "image": image, "start": start})
                finally:
                    winreg.CloseKey(key)
            except OSError:
                continue
    finally:
        winreg.CloseKey(root)
    return sorted(rows, key=lambda row: row["name"].casefold())


@dataclass(frozen=True)
class PostureAssessment:
    health: int
    risks: tuple[str, ...]
    unknown: tuple[str, ...]


def assess(snapshot: dict) -> PostureAssessment:
    risks: list[str] = []
    unknown: list[str] = []

    def check_bool(key: str, risk: str) -> None:
        value = snapshot.get(key)
        if value is False:
            risks.append(risk)
        elif value is None:
            unknown.append(key)

    check_bool("secure_boot", "Secure Boot is disabled")
    check_bool("hvci", "HVCI / Memory Integrity is not running")
    check_bool("code_integrity_log", "Code Integrity event channel is unavailable")
    for key, label in (
        ("testsigning", "boot test-signing is enabled"),
        ("debug", "boot debugging is enabled"),
        ("nointegritychecks", "boot integrity checks are disabled"),
    ):
        value = snapshot.get(key)
        if value is True:
            risks.append(label)
        elif value is None:
            unknown.append(key)
    if snapshot.get("vbs_status") is None:
        unknown.append("vbs_status")
    elif int(snapshot["vbs_status"]) < 2:
        risks.append("Virtualization-Based Security is not running")

    health = max(10, 100 - 18 * len(risks) - 6 * len(set(unknown)))
    return PostureAssessment(health, tuple(risks), tuple(sorted(set(unknown))))


class KernelPostureProvider:
    def snapshot(self) -> dict:
        guard = _device_guard()
        boot = _boot_flags()
        drivers = _driver_services()
        return {
            "secure_boot": _secure_boot(),
            "vbs_status": guard["vbs_status"],
            "hvci": guard["hvci"],
            "testsigning": boot["testsigning"],
            "debug": boot["debug"],
            "nointegritychecks": boot["nointegritychecks"],
            "code_integrity_log": _code_integrity_log(),
            "driver_count": len(drivers),
            "driver_set_sha256": _digest(drivers),
        }


class KernelPostureLedger:
    def __init__(
        self,
        path: Path,
        max_records: int = MAX_LEDGER_RECORDS,
        authority_key: bytes | None = None,
    ) -> None:
        self.path = Path(path)
        self.max_records = max(8, int(max_records))
        if authority_key is None:
            from angerona.core.eventbus import BusAuthority
            authority_key = BusAuthority.load()._key
        if not isinstance(authority_key, bytes) or len(authority_key) != 32:
            raise ValueError("kernel posture ledger requires a 32-byte authority")
        self._authority_key = authority_key
        self._initialized = self.path.exists()

    def _sign(self, body: dict) -> str:
        return hmac.new(self._authority_key, _canonical(body), hashlib.sha256).hexdigest()

    def _signed(self, body: dict) -> dict:
        return {**body, "record_hmac": self._sign(body)}

    def read(self) -> list[dict]:
        if not self.path.exists():
            if self._initialized:
                raise RuntimeError("kernel posture ledger disappeared after initialization")
            return []
        try:
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if not lines or any(not line.strip() for line in lines):
                raise ValueError("ledger is empty or contains blank records")
            rows = [json.loads(line) for line in lines]
            if any(not isinstance(row, dict) for row in rows):
                raise ValueError("ledger record is not an object")
            if len(rows) > self.max_records:
                raise ValueError("ledger exceeds its record bound")
            return rows
        except Exception as exc:
            raise RuntimeError(f"kernel posture ledger is corrupt: {exc}") from exc

    def append(self, snapshot: dict, ts: float | None = None) -> dict:
        rows = self.read()
        if rows:
            valid, reason = self._verify_rows(rows)
            if not valid:
                raise RuntimeError(f"refusing to overwrite invalid kernel ledger: {reason}")
        normal_rows = [row for row in rows if not row.get("anchor")]
        previous = normal_rows[-1].get("record_sha256", GENESIS_HASH) if normal_rows else GENESIS_HASH
        body = {
            "ledger_version": LEDGER_VERSION,
            "observed_at": float(time.time() if ts is None else ts),
            "previous_record_sha256": previous,
            "snapshot": snapshot,
            "snapshot_sha256": _digest(snapshot),
        }
        hashed = {**body, "record_sha256": _digest(body)}
        record = self._signed(hashed)
        normal_rows.append(record)
        if len(normal_rows) >= self.max_records:
            retained = normal_rows[-(self.max_records - 1):]
            anchor_body = {
                "ledger_version": LEDGER_VERSION,
                "anchor": True,
                "observed_at": float(time.time() if ts is None else ts),
                "previous_record_sha256": GENESIS_HASH,
                "anchor_hash": retained[0]["previous_record_sha256"],
            }
            anchor_hashed = {
                **anchor_body,
                "record_sha256": _digest(anchor_body),
            }
            rows = [self._signed(anchor_hashed), *retained]
        else:
            rows = normal_rows
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + f".tmp.{os.getpid()}")
        temp.write_text(
            "".join(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in rows),
            encoding="utf-8",
        )
        # Windows antivirus/indexing can briefly open a newly written file
        # without delete sharing, causing an otherwise atomic replace to fail
        # with ERROR_ACCESS_DENIED. Retry only that transient sharing class for
        # a short bounded window; persistent denial still fails closed.
        for attempt in range(6):
            try:
                os.replace(temp, self.path)
                break
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.02 * (attempt + 1))
        self._initialized = True
        return record

    def _verify_rows(self, rows: list[dict]) -> tuple[bool, str]:
        previous = GENESIS_HASH
        for index, record in enumerate(rows):
            signature = str(record.get("record_hmac", ""))
            signed_body = {key: value for key, value in record.items() if key != "record_hmac"}
            if not signature or not hmac.compare_digest(signature, self._sign(signed_body)):
                return False, f"record HMAC {index} does not match"
            body = {
                key: value for key, value in signed_body.items()
                if key != "record_sha256"
            }
            if record.get("previous_record_sha256") != previous:
                return False, f"chain link {index} does not match"
            if record.get("anchor"):
                if index != 0 or "anchor_hash" not in record:
                    return False, "anchor is malformed or misplaced"
                if record.get("record_sha256") != _digest(body):
                    return False, "anchor digest does not match"
                previous = str(record["anchor_hash"])
                continue
            if record.get("snapshot_sha256") != _digest(record.get("snapshot", {})):
                return False, f"snapshot digest {index} does not match"
            if record.get("record_sha256") != _digest(body):
                return False, f"record digest {index} does not match"
            previous = record["record_sha256"]
        return True, f"{len(rows)} record(s) verified"

    def verify(self) -> tuple[bool, str]:
        try:
            rows = self.read()
        except RuntimeError as exc:
            return False, str(exc)
        if not rows:
            return False, "kernel posture ledger is missing"
        return self._verify_rows(rows)


class KernelBoundaryPostureLedger(BaseModule):
    CODE = "KBPL"
    name = "Kernel-Boundary Posture Ledger"
    description = (
        "Read-only evidence for Secure Boot, VBS/HVCI, boot integrity flags, "
        "Code Integrity telemetry, and kernel-driver-service drift."
    )
    category = "Integrity"
    version = "1.0.0"
    enabled_by_default = True
    _INTERVAL = 300.0

    def __init__(
        self,
        provider: KernelPostureProvider | None = None,
        ledger_path: Path | None = None,
        authority_key: bytes | None = None,
    ) -> None:
        super().__init__()
        from angerona.core.data_paths import data_dir
        self._provider = provider or KernelPostureProvider()
        self._ledger = KernelPostureLedger(
            ledger_path or data_dir() / "evidence" / "kernel_boundary_ledger.jsonl",
            authority_key=authority_key,
        )
        self._last_snapshot: dict | None = None

    def observe_once(self) -> tuple[dict, PostureAssessment, list[str]]:
        snapshot = self._provider.snapshot()
        assessment = assess(snapshot)
        changes: list[str] = []
        if self._last_snapshot:
            for key in sorted(snapshot):
                if snapshot.get(key) != self._last_snapshot.get(key):
                    changes.append(key)
        self._ledger.append(snapshot)
        self._last_snapshot = dict(snapshot)
        return snapshot, assessment, changes

    def run(self) -> None:
        if not sys.platform.startswith("win"):
            self.set_health(60, "Windows-only posture evidence unavailable on this host")
            while not self.stopping:
                self.sleep(self._INTERVAL)
            return
        while not self.stopping:
            snapshot, result, changes = self.observe_once()
            note = (
                "; ".join(result.risks)
                or (f"unknown: {', '.join(result.unknown)}" if result.unknown else "posture verified")
            )
            self.set_health(result.health, note)
            if result.risks:
                self.emit(
                    "Kernel-boundary posture risk: " + "; ".join(result.risks),
                    Severity.HIGH,
                    risks=list(result.risks), unknown=list(result.unknown),
                    evidence_sha256=_digest(snapshot), user_mode_observation=True,
                )
            elif changes:
                severity = Severity.MEDIUM if "driver_set_sha256" in changes else Severity.INFO
                self.emit(
                    "Kernel-boundary posture changed: " + ", ".join(changes),
                    severity,
                    changed=changes, evidence_sha256=_digest(snapshot),
                    user_mode_observation=True,
                )
            self.sleep(self._INTERVAL)

    def self_test(self) -> tuple[bool, str]:
        # Verify the authenticated chain mechanism without mutating the live
        # evidence file. A first-run host legitimately has no observation yet;
        # that remains UNKNOWN in runtime health, but is not a broken module.
        import tempfile
        try:
            with tempfile.TemporaryDirectory(prefix="angerona-kbpl-") as root:
                probe = KernelPostureLedger(
                    Path(root) / "probe.jsonl",
                    max_records=8,
                    authority_key=self._ledger._authority_key,
                )
                probe.append(
                    {
                        "secure_boot": None,
                        "vbs_status": None,
                        "hvci": None,
                        "testsigning": None,
                        "debug": None,
                        "nointegritychecks": None,
                        "code_integrity_log": None,
                        "driver_count": 0,
                        "driver_set_sha256": _digest([]),
                    },
                    ts=0.0,
                )
                ok, detail = probe.verify()
            return ok, f"authenticated bounded ledger: {detail}; live posture starts unknown"
        except Exception as exc:
            return False, f"authenticated ledger self-test failed: {exc}"


def register() -> KernelBoundaryPostureLedger:
    return KernelBoundaryPostureLedger()
