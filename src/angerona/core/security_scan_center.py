"""Bounded, local-only defensive scanning services for the Angerona GUI.

The Scan Center intentionally has no remote-address input, packet capture,
credential testing, exploitation, quarantine, or automatic remediation.  It
produces privacy-minimized findings and guidance for an operator to review.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import platform
import re
import socket
import stat
import subprocess
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from angerona.core.data_paths import resource_root


MAX_SCAN_FILES = 10_000
MAX_SCAN_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_SCAN_SECONDS = 120.0
MAX_FINDINGS = 256
MAX_ERRORS = 32
MAX_CONNECTIONS = 2_048
MAX_INTERFACES = 64
MAX_INTERFACE_ADDRESSES = 256
_REPARSE_POINT = 0x400
_REMOTE_FILESYSTEMS = frozenset(
    {"9p", "afpfs", "cifs", "fuse.sshfs", "nfs", "nfs4", "smbfs", "sshfs"}
)
_EXECUTABLE_SUFFIXES = frozenset(
    {".bat", ".cmd", ".com", ".dll", ".exe", ".hta", ".js", ".jse", ".msi", ".ps1", ".scr", ".vbe", ".vbs", ".wsf"}
)
_DOCUMENT_SUFFIXES = frozenset(
    {".doc", ".docm", ".docx", ".jpeg", ".jpg", ".pdf", ".png", ".ppt", ".pptx", ".txt", ".xls", ".xlsx"}
)
_MACRO_SUFFIXES = frozenset({".docm", ".dotm", ".ppam", ".pptm", ".xlam", ".xlsm"})
_BIDI_CONTROLS = frozenset("\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_HIGH_RISK_PORTS = {
    135: "Windows RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "Remote Desktop",
    5985: "WinRM",
    5986: "WinRM TLS",
}
_DEVELOPMENT_PORTS = {3000, 5000, 8000, 8080, 8888}
_SAFE_PROCESS = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,79}$")


ProgressCallback = Callable[["ScanProgress"], None]


@dataclass(frozen=True)
class ScanFinding:
    """One bounded, presentation-ready defensive observation."""

    finding_id: str
    severity: str
    category: str
    title: str
    evidence: tuple[str, ...] = ()
    remediation: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.severity not in _SEVERITIES:
            raise ValueError("unsupported finding severity")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{2,63}", self.finding_id):
            raise ValueError("invalid finding id")
        for value, limit in ((self.category, 80), (self.title, 200)):
            if not value or len(value) > limit or any(ch in value for ch in "\r\n"):
                raise ValueError("finding text is invalid")
        if len(self.evidence) > 12 or len(self.remediation) > 12:
            raise ValueError("finding cardinality exceeds its bound")
        if any(len(item) > 500 or "\x00" in item for item in (*self.evidence, *self.remediation)):
            raise ValueError("finding detail exceeds its bound")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanProgress:
    """Small progress record safe to dispatch to a GUI thread."""

    phase: str
    completed: int
    total_limit: int
    detail: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    """Complete bounded result for one Scan Center operation."""

    operation: str
    status: str
    supported: bool
    executed: bool
    started_at: float
    finished_at: float
    summary: str
    findings: tuple[ScanFinding, ...] = ()
    metrics: Mapping[str, object] = field(default_factory=dict)
    errors: tuple[str, ...] = ()
    privacy: str = (
        "Local-only collection; no packets, credentials, usernames, full process paths, "
        "interface identifiers, MAC addresses, SSIDs, or IP addresses are returned."
    )

    def to_dict(self) -> dict[str, object]:
        return {
            "operation": self.operation,
            "status": self.status,
            "supported": self.supported,
            "executed": self.executed,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
            "metrics": dict(self.metrics),
            "errors": list(self.errors),
            "privacy": self.privacy,
        }


class ScanCancellationToken:
    """Thread-safe cooperative cancellation token."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()


def _bounded_int(value: int, ceiling: int, name: str) -> int:
    result = int(value)
    if result <= 0:
        raise ValueError(f"{name} must be positive")
    return min(result, ceiling)


def _is_reparse_or_link(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
        info = path.stat(follow_symlinks=False)
        return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
    except OSError:
        return True


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _private_location(relative_path: Path) -> str:
    """Return a useful but bounded location without exposing the selected root."""
    rendered = relative_path.as_posix().replace("\r", "_").replace("\n", "_")
    if len(rendered) <= 240:
        return rendered or "."
    digest = hashlib.sha256(rendered.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"<long-relative-path:{digest}>"


def _finding_id(prefix: str, *parts: object) -> str:
    body = "\x1f".join(str(part) for part in parts)
    return f"{prefix}.{hashlib.sha256(body.encode('utf-8')).hexdigest()[:16]}"


class SecurityScanCenter:
    """GUI-neutral local defensive scanner with strict resource limits."""

    def __init__(
        self,
        *,
        max_files: int = MAX_SCAN_FILES,
        max_total_bytes: int = MAX_SCAN_BYTES,
        max_file_bytes: int = MAX_FILE_BYTES,
        max_duration_seconds: float = MAX_SCAN_SECONDS,
        psutil_module: Any | None = None,
        yara_module: Any | None = None,
        defender_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
        trusted_defender_executable: Path | None = None,
        trusted_defender_roots: Sequence[Path] | None = None,
        platform_system: str | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self.max_files = _bounded_int(max_files, MAX_SCAN_FILES, "max_files")
        self.max_total_bytes = _bounded_int(max_total_bytes, MAX_SCAN_BYTES, "max_total_bytes")
        self.max_file_bytes = _bounded_int(max_file_bytes, MAX_FILE_BYTES, "max_file_bytes")
        duration = float(max_duration_seconds)
        if not 0 < duration <= MAX_SCAN_SECONDS:
            raise ValueError("max_duration_seconds is outside its allowed range")
        self.max_duration_seconds = duration
        self._psutil = psutil_module
        self._yara = yara_module
        self._runner = defender_runner or subprocess.run
        self._trusted_defender_executable = trusted_defender_executable
        self._trusted_defender_roots = (
            tuple(Path(item) for item in trusted_defender_roots)
            if trusted_defender_roots is not None else None
        )
        self._platform = platform_system or platform.system()
        self._monotonic = monotonic
        self._wall_clock = wall_clock

    @staticmethod
    def _notify(callback: ProgressCallback | None, progress: ScanProgress) -> None:
        if callback is None:
            return
        try:
            callback(progress)
        except Exception:
            # Presentation callbacks must never collapse a defensive scan.
            return

    @staticmethod
    def _cancelled(token: ScanCancellationToken | None) -> bool:
        return bool(token and token.cancelled)

    def _result(
        self,
        operation: str,
        started: float,
        *,
        status: str,
        supported: bool,
        executed: bool,
        summary: str,
        findings: Sequence[ScanFinding] = (),
        metrics: Mapping[str, object] | None = None,
        errors: Sequence[str] = (),
        privacy: str | None = None,
    ) -> ScanResult:
        kwargs: dict[str, object] = {}
        if privacy is not None:
            kwargs["privacy"] = privacy
        return ScanResult(
            operation=operation,
            status=status,
            supported=supported,
            executed=executed,
            started_at=started,
            finished_at=self._wall_clock(),
            summary=summary[:500],
            findings=tuple(findings[:MAX_FINDINGS]),
            metrics=dict(metrics or {}),
            errors=tuple(errors[:MAX_ERRORS]),
            **kwargs,
        )

    def _psutil_module(self):
        if self._psutil is not None:
            return self._psutil
        try:
            import psutil
        except ImportError:
            return None
        return psutil

    def _remote_mount(self, target: Path) -> bool:
        if str(target).startswith(("\\\\", "//")):
            return True
        psutil = self._psutil_module()
        if psutil is None:
            return False
        try:
            mounts = psutil.disk_partitions(all=True)
        except Exception:
            return False
        best: tuple[int, str, str] | None = None
        for mount in mounts[:256]:
            try:
                point = Path(str(mount.mountpoint)).resolve(strict=True)
                if _is_within(target, point):
                    candidate = (len(point.parts), str(mount.fstype).casefold(), str(mount.device))
                    if best is None or candidate[0] > best[0]:
                        best = candidate
            except (OSError, RuntimeError):
                continue
        return bool(
            best
            and (best[1] in _REMOTE_FILESYSTEMS or best[2].startswith(("//", "\\\\")))
        )

    def _validated_local_target(self, value: str | os.PathLike[str]) -> Path:
        raw = os.fspath(value)
        if not raw or "\x00" in raw or raw.startswith(("\\\\", "//")):
            raise ValueError("a local filesystem path is required")
        candidate = Path(raw).expanduser()
        if _is_reparse_or_link(candidate):
            raise ValueError("symlink and reparse-point scan roots are not allowed")
        try:
            target = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError("selected scan path does not exist") from exc
        try:
            mode = target.stat().st_mode
        except OSError as exc:
            raise ValueError("selected scan path is unavailable") from exc
        if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError("only a regular file or local directory can be scanned")
        if self._remote_mount(target):
            raise ValueError("remote and network-mounted scan paths are not allowed")
        return target

    @staticmethod
    def _iter_local_files(root: Path) -> Iterator[tuple[Path, Path]]:
        if root.is_file():
            yield root, Path(root.name)
            return
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        path = Path(entry.path)
                        try:
                            if entry.is_symlink() or _is_reparse_or_link(path):
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(path)
                            elif entry.is_file(follow_symlinks=False):
                                yield path, path.relative_to(root)
                        except (OSError, ValueError):
                            continue
            except OSError:
                continue

    def _make_yara_scanner(self) -> tuple[Any | None, str]:
        module = self._yara
        if module is None:
            try:
                import yara_x as module
            except ImportError:
                return None, "unavailable"
        rules = resource_root() / "rules.yar"
        try:
            if not rules.is_file() or rules.stat().st_size > 2 * 1024 * 1024:
                return None, "rules-unavailable"
            compiler = module.Compiler()
            compiler.add_include_dir(str(rules.parent.resolve()))
            compiler.add_source(
                rules.read_text(encoding="utf-8", errors="strict"), origin=str(rules.resolve())
            )
            scanner = module.Scanner(compiler.build())
            scanner.set_timeout(min(10, max(1, int(self.max_duration_seconds))))
            scanner.max_matches_per_pattern(64)
            scanner.fast_scan(True)
            return scanner, "active"
        except Exception:
            return None, "compile-error"

    @staticmethod
    def _metadata_findings(path: Path, relative: Path, mode: int, header: bytes) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        location = _private_location(relative)
        suffixes = [part.casefold() for part in path.suffixes]
        suffix = suffixes[-1] if suffixes else ""
        if any(ch in path.name for ch in _BIDI_CONTROLS):
            findings.append(ScanFinding(
                _finding_id("file.bidi-name", location), "medium", "File metadata",
                "Filename uses bidirectional text controls",
                (f"Selected-root relative location: {location}",),
                ("Verify the file source and rename or remove it if it is unexpected.",),
            ))
        if len(suffixes) >= 2 and suffix in _EXECUTABLE_SUFFIXES and suffixes[-2] in _DOCUMENT_SUFFIXES:
            findings.append(ScanFinding(
                _finding_id("file.double-extension", location), "medium", "File metadata",
                "Executable uses a document-style double extension",
                (f"Selected-root relative location: {location}",),
                ("Do not open it until its publisher and signature have been independently verified.",),
            ))
        if suffix in _MACRO_SUFFIXES:
            findings.append(ScanFinding(
                _finding_id("file.macro-enabled", location), "low", "File metadata",
                "Macro-enabled document requires review",
                (f"Selected-root relative location: {location}",),
                ("Keep Office macros disabled and validate the document source before use.",),
            ))
        if os.name != "nt" and suffix in _EXECUTABLE_SUFFIXES and mode & stat.S_IWOTH:
            findings.append(ScanFinding(
                _finding_id("file.world-writable", location), "medium", "File permissions",
                "Executable content is writable by every local account",
                (f"Selected-root relative location: {location}",),
                ("Remove world-write permission and verify ownership before execution.",),
            ))
        if header.startswith(b"MZ") and suffix not in {".com", ".dll", ".exe", ".scr"}:
            findings.append(ScanFinding(
                _finding_id("file.pe-mismatch", location), "medium", "File metadata",
                "Portable executable content has a misleading extension",
                (f"Selected-root relative location: {location}",),
                ("Treat the file as executable and verify its signature and source.",),
            ))
        return findings

    def scan_path(
        self,
        path: str | os.PathLike[str],
        *,
        cancellation: ScanCancellationToken | None = None,
        progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Scan one selected local path without following links or leaving its root."""
        operation = "local_path_scan"
        started = self._wall_clock()
        try:
            root = self._validated_local_target(path)
        except ValueError as exc:
            return self._result(
                operation, started, status="rejected", supported=True, executed=False,
                summary=str(exc), errors=("invalid-local-scope",),
            )
        scanner, yara_status = self._make_yara_scanner()
        deadline = self._monotonic() + self.max_duration_seconds
        findings: list[ScanFinding] = []
        errors: list[str] = []
        files = 0
        scanned_bytes = 0
        skipped_oversize = 0
        skipped_budget = 0
        timed_out = False
        for candidate, relative in self._iter_local_files(root):
            if self._cancelled(cancellation):
                break
            if self._monotonic() >= deadline:
                timed_out = True
                break
            if files >= self.max_files:
                break
            try:
                info = candidate.stat(follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    continue
                if info.st_size > self.max_file_bytes:
                    skipped_oversize += 1
                    continue
                if scanned_bytes + info.st_size > self.max_total_bytes:
                    skipped_budget += 1
                    break
                with candidate.open("rb") as stream:
                    header = stream.read(4096)
                files += 1
                scanned_bytes += info.st_size
                if len(findings) < MAX_FINDINGS:
                    findings.extend(
                        self._metadata_findings(candidate, relative, info.st_mode, header)[
                            : MAX_FINDINGS - len(findings)
                        ]
                    )
                if scanner is not None and len(findings) < MAX_FINDINGS:
                    try:
                        result = scanner.scan_file(str(candidate))
                        for match in tuple(getattr(result, "matching_rules", ()))[:32]:
                            rule = re.sub(r"[^A-Za-z0-9_.-]", "_", str(match.identifier))[:80]
                            findings.append(ScanFinding(
                                _finding_id("yara.match", _private_location(relative), rule),
                                "high", "Malware signatures", "YARA-X rule matched selected content",
                                (
                                    f"Rule: {rule or '<unnamed>'}",
                                    f"Selected-root relative location: {_private_location(relative)}",
                                ),
                                (
                                    "Do not execute the file.",
                                    "Validate the detection, file origin, and signature before a separately approved containment action.",
                                ),
                            ))
                            if len(findings) >= MAX_FINDINGS:
                                break
                    except Exception as exc:
                        if len(errors) < MAX_ERRORS:
                            errors.append(f"yara-file-scan:{type(exc).__name__}")
            except OSError as exc:
                if len(errors) < MAX_ERRORS:
                    errors.append(f"unreadable-file:{type(exc).__name__}")
            if files == 1 or files % 25 == 0:
                self._notify(
                    progress,
                    ScanProgress("scanning", files, self.max_files, "Selected local content"),
                )
        cancelled = self._cancelled(cancellation)
        limited = (
            files >= self.max_files or scanned_bytes >= self.max_total_bytes
            or skipped_budget > 0 or len(findings) >= MAX_FINDINGS or timed_out
        )
        status = "cancelled" if cancelled else "limited" if limited else "completed"
        self._notify(progress, ScanProgress(status, files, self.max_files, "Scan finished"))
        return self._result(
            operation, started, status=status, supported=True, executed=True,
            summary=(
                f"Scanned {files} local file(s); produced {len(findings)} review finding(s). "
                f"YARA-X status: {yara_status}. No containment or remediation was performed."
            ),
            findings=findings,
            metrics={
                "files_scanned": files,
                "bytes_scanned": scanned_bytes,
                "oversize_files_skipped": skipped_oversize,
                "budget_skips": skipped_budget,
                "file_limit": self.max_files,
                "byte_limit": self.max_total_bytes,
                "per_file_limit": self.max_file_bytes,
                "finding_limit": MAX_FINDINGS,
                "duration_limit_seconds": self.max_duration_seconds,
                "timed_out": timed_out,
                "yara_status": yara_status,
            },
            errors=errors,
            privacy=(
                "The operator-selected root stays local and is never returned; findings use only "
                "bounded relative locations. File contents are not retained or logged."
            ),
        )

    @staticmethod
    def _endpoint(endpoint: object) -> tuple[str, int]:
        if not endpoint:
            return "", 0
        if hasattr(endpoint, "ip") and hasattr(endpoint, "port"):
            return str(endpoint.ip), int(endpoint.port)
        try:
            return str(endpoint[0]), int(endpoint[1])  # type: ignore[index]
        except (IndexError, TypeError, ValueError):
            return "", 0

    @staticmethod
    def _bind_scope(host: str) -> str:
        value = host.strip("[]").casefold()
        # Passive classification only: this module never creates or binds a socket.
        if value in {"", "0.0.0.0", "::", "*"}:  # nosec B104
            return "all-interfaces"
        try:
            return "loopback" if ipaddress.ip_address(value).is_loopback else "one-interface"
        except ValueError:
            return "unknown"

    @staticmethod
    def _safe_process_name(value: object) -> str:
        text = str(value or "").strip()
        return text if _SAFE_PROCESS.fullmatch(text) else "<redacted-process>"

    def audit_listening_exposure(
        self,
        *,
        cancellation: ScanCancellationToken | None = None,
        progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Passively inventory this host's listening sockets; no packets are sent."""
        operation = "listening_exposure_audit"
        started = self._wall_clock()
        psutil = self._psutil_module()
        if psutil is None:
            return self._result(
                operation, started, status="unsupported", supported=False, executed=False,
                summary="Listening-port audit requires psutil; no network activity was attempted.",
            )
        try:
            connections = tuple(psutil.net_connections(kind="inet"))[:MAX_CONNECTIONS]
        except Exception as exc:
            return self._result(
                operation, started, status="error", supported=True, executed=True,
                summary="The operating system did not permit a passive listener inventory.",
                errors=(f"listener-inventory:{type(exc).__name__}",),
            )
        findings: list[ScanFinding] = []
        listeners = 0
        all_interfaces = 0
        deadline = self._monotonic() + self.max_duration_seconds
        timed_out = False
        process_cache: dict[int, str] = {}
        listen_constant = str(getattr(psutil, "CONN_LISTEN", "LISTEN")).casefold()
        for connection in connections:
            if self._cancelled(cancellation):
                break
            if self._monotonic() >= deadline:
                timed_out = True
                break
            if str(getattr(connection, "status", "")).casefold() not in {"listen", listen_constant}:
                continue
            host, port = self._endpoint(getattr(connection, "laddr", ()))
            if not 0 < port <= 65535:
                continue
            scope = self._bind_scope(host)
            listeners += 1
            if scope == "all-interfaces":
                all_interfaces += 1
            pid = getattr(connection, "pid", None)
            process_name = "unknown"
            if isinstance(pid, int) and pid > 0:
                if pid not in process_cache and len(process_cache) < 128:
                    try:
                        process_cache[pid] = self._safe_process_name(psutil.Process(pid).name())
                    except Exception:
                        process_cache[pid] = "unknown"
                process_name = process_cache.get(pid, "unknown")
            severity = "info"
            title = "Local-only listening service observed"
            if scope != "loopback":
                severity = "high" if port in _HIGH_RISK_PORTS else "medium"
                title = (
                    f"{_HIGH_RISK_PORTS[port]} is reachable beyond loopback"
                    if port in _HIGH_RISK_PORTS else "Listening service is reachable beyond loopback"
                )
            elif port in _DEVELOPMENT_PORTS:
                severity = "low"
                title = "Development-style service is listening locally"
            if severity != "info" and len(findings) < MAX_FINDINGS:
                findings.append(ScanFinding(
                    _finding_id("listener.exposure", port, scope, process_name), severity,
                    "Listening exposure", title,
                    (f"Port: {port}", f"Bind scope: {scope}", f"Process: {process_name}"),
                    (
                        "Confirm the service is expected and fully patched.",
                        "Restrict the bind address and host firewall scope to the minimum required.",
                        "Disable the service if it is unnecessary.",
                    ),
                ))
            if listeners == 1 or listeners % 25 == 0:
                self._notify(
                    progress,
                    ScanProgress("listeners", listeners, MAX_CONNECTIONS, "Passive local inventory"),
                )
        cancelled = self._cancelled(cancellation)
        status = (
            "cancelled" if cancelled else "limited"
            if len(connections) >= MAX_CONNECTIONS or timed_out else "completed"
        )
        return self._result(
            operation, started, status=status, supported=True, executed=True,
            summary=(
                f"Reviewed {listeners} listening socket(s); {all_interfaces} bind to all interfaces. "
                "No packets were captured or transmitted."
            ),
            findings=findings,
            metrics={
                "listeners_reviewed": listeners,
                "all_interface_listeners": all_interfaces,
                "connections_examined": len(connections),
                "connection_limit": MAX_CONNECTIONS,
                "finding_limit": MAX_FINDINGS,
                "duration_limit_seconds": self.max_duration_seconds,
                "timed_out": timed_out,
            },
        )

    def summarize_network_posture(
        self,
        *,
        cancellation: ScanCancellationToken | None = None,
        progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Summarize local interface posture without returning network identifiers."""
        operation = "network_posture_summary"
        started = self._wall_clock()
        psutil = self._psutil_module()
        if psutil is None:
            return self._result(
                operation, started, status="unsupported", supported=False, executed=False,
                summary="Network posture summary requires psutil; no network activity was attempted.",
            )
        try:
            stats = dict(psutil.net_if_stats())
            addresses = dict(psutil.net_if_addrs())
        except Exception as exc:
            return self._result(
                operation, started, status="error", supported=True, executed=True,
                summary="The operating system did not permit local interface inspection.",
                errors=(f"interface-inventory:{type(exc).__name__}",),
            )
        active = 0
        external = 0
        wireless = 0
        global_addresses = 0
        address_count = 0
        limited = len(stats) > MAX_INTERFACES
        deadline = self._monotonic() + self.max_duration_seconds
        timed_out = False
        for index, (name, state) in enumerate(tuple(stats.items())[:MAX_INTERFACES], start=1):
            if self._cancelled(cancellation):
                break
            if self._monotonic() >= deadline:
                timed_out = True
                break
            if not bool(getattr(state, "isup", False)):
                continue
            active += 1
            low_name = str(name).casefold()
            if any(token in low_name for token in ("wi-fi", "wifi", "wireless", "wlan", "airport")):
                wireless += 1
            interface_non_loopback = False
            for address in tuple(addresses.get(name, ()))[:16]:
                if address_count >= MAX_INTERFACE_ADDRESSES:
                    limited = True
                    break
                family = getattr(address, "family", None)
                if family not in {socket.AF_INET, socket.AF_INET6}:
                    continue
                address_count += 1
                raw = str(getattr(address, "address", "")).split("%", 1)[0]
                try:
                    parsed = ipaddress.ip_address(raw)
                except ValueError:
                    continue
                if not parsed.is_loopback:
                    interface_non_loopback = True
                if parsed.is_global:
                    global_addresses += 1
            if interface_non_loopback:
                external += 1
            self._notify(
                progress,
                ScanProgress("interfaces", index, min(len(stats), MAX_INTERFACES), "Aggregate posture"),
            )
        findings: list[ScanFinding] = []
        if active == 0:
            findings.append(ScanFinding(
                "network.no-active-interface", "low", "Network posture",
                "No active interface was observed",
                ("Active interface count: 0",),
                ("If connectivity is expected, verify adapter state and system network controls.",),
            ))
        if global_addresses:
            findings.append(ScanFinding(
                "network.global-address", "medium", "Network posture",
                "A globally routable local address is present",
                (f"Global address count: {global_addresses}",),
                (
                    "Confirm direct internet addressing is intended.",
                    "Keep the host firewall enabled and expose only required services.",
                ),
            ))
        if wireless:
            findings.append(ScanFinding(
                "network.wireless-limits", "info", "Network posture",
                "Wireless interface is active; encryption cannot be proven from this passive view",
                (f"Active wireless interface count: {wireless}",),
                ("Verify WPA2/WPA3, certificate validation, and router firmware in the trusted network UI.",),
            ))
        cancelled = self._cancelled(cancellation)
        status = "cancelled" if cancelled else "limited" if limited or timed_out else "completed"
        return self._result(
            operation, started, status=status, supported=True, executed=True,
            summary=(
                f"Observed {active} active interface(s), including {external} non-loopback interface(s). "
                "No SSID, MAC address, IP address, packet, or traffic content was retained."
            ),
            findings=findings,
            metrics={
                "interfaces_seen": min(len(stats), MAX_INTERFACES),
                "active_interfaces": active,
                "non_loopback_interfaces": external,
                "active_wireless_interfaces": wireless,
                "global_address_count": global_addresses,
                "interface_limit": MAX_INTERFACES,
                "address_limit": MAX_INTERFACE_ADDRESSES,
                "duration_limit_seconds": self.max_duration_seconds,
                "timed_out": timed_out,
            },
        )

    def _defender_roots(self) -> tuple[Path, ...]:
        if self._trusted_defender_roots is not None:
            return self._trusted_defender_roots
        system_drive = Path(os.environ.get("SystemRoot", r"C:\Windows")).anchor or "C:\\"
        return (
            Path(system_drive) / "Program Files" / "Windows Defender",
            Path(system_drive) / "ProgramData" / "Microsoft" / "Windows Defender",
        )

    def _find_defender_executable(self) -> Path | None:
        roots: list[Path] = []
        for raw_root in self._defender_roots():
            try:
                root = raw_root.resolve(strict=True)
                if not _is_reparse_or_link(root):
                    roots.append(root)
            except (OSError, RuntimeError):
                continue
        candidates: list[Path] = []
        if self._trusted_defender_executable is not None:
            candidates.append(self._trusted_defender_executable)
        for root in roots:
            candidates.append(root / "MpCmdRun.exe")
            platform_dir = root / "Platform"
            try:
                versions = sorted(
                    (
                        item for item in platform_dir.iterdir()
                        if item.is_dir() and not _is_reparse_or_link(item)
                    ),
                    key=lambda item: item.name,
                    reverse=True,
                )[:16]
                candidates.extend(item / "MpCmdRun.exe" for item in versions)
            except OSError:
                pass
        for candidate in candidates[:64]:
            try:
                if candidate.name.casefold() != "mpcmdrun.exe" or _is_reparse_or_link(candidate):
                    continue
                resolved = candidate.resolve(strict=True)
                if not resolved.is_file() or not any(_is_within(resolved, root) for root in roots):
                    continue
                return resolved
            except (OSError, RuntimeError):
                continue
        return None

    def run_microsoft_defender_scan(
        self,
        target: str | os.PathLike[str] | None = None,
        *,
        execute: bool = False,
        quick: bool = False,
        cancellation: ScanCancellationToken | None = None,
        progress: ProgressCallback | None = None,
    ) -> ScanResult:
        """Preview or explicitly run Defender; custom scans disable remediation.

        Microsoft Defender's command-line interface supports
        ``-DisableRemediation`` only for custom (ScanType 3) scans. Quick and
        full scans therefore follow the host's configured Defender threat
        actions, which is stated in both preview and completion results.
        """
        operation = "microsoft_defender_scan"
        started = self._wall_clock()
        if self._platform.casefold() != "windows":
            return self._result(
                operation, started, status="unsupported", supported=False, executed=False,
                summary="Microsoft Defender orchestration is available only on Windows.",
                privacy="No command was run and no data left this host.",
            )
        selected: Path | None = None
        if target is not None:
            try:
                selected = self._validated_local_target(target)
            except ValueError as exc:
                return self._result(
                    operation, started, status="rejected", supported=True, executed=False,
                    summary=str(exc), errors=("invalid-local-scope",),
                )
        executable = self._find_defender_executable()
        if executable is None:
            return self._result(
                operation, started, status="unsupported", supported=False, executed=False,
                summary="A trusted Microsoft Defender command-line executable was not found.",
            )
        scan_type = "3" if selected is not None else "1" if quick else "2"
        argv = [str(executable), "-Scan", "-ScanType", scan_type]
        preview = ["MpCmdRun.exe", "-Scan", "-ScanType", scan_type]
        remediation_disabled = selected is not None
        if remediation_disabled:
            argv.append("-DisableRemediation")
            preview.append("-DisableRemediation")
        if selected is not None:
            argv.extend(["-File", str(selected)])
            preview.extend(["-File", "<selected-local-target>"])
        metrics: dict[str, object] = {
            "mode": "custom" if selected is not None else "quick" if quick else "full",
            "remediation_disabled": remediation_disabled,
            "configured_threat_actions_possible": not remediation_disabled,
            "preview_argv": preview,
            "timeout_seconds": self.max_duration_seconds,
        }
        if not execute:
            return self._result(
                operation, started, status="preview", supported=True, executed=False,
                summary=(
                    "Microsoft Defender custom scan is ready. Execution requires an explicit "
                    "confirmation; remediation and quarantine are disabled for this scan."
                    if remediation_disabled else
                    "Microsoft Defender scan is ready. Execution requires an explicit confirmation. "
                    "Quick and full scans may apply the host's configured Defender threat actions."
                ),
                metrics=metrics,
                privacy="The preview contains no selected path, command output, or network data.",
            )
        if self._cancelled(cancellation):
            return self._result(
                operation, started, status="cancelled", supported=True, executed=False,
                summary="Microsoft Defender scan was cancelled before launch.", metrics=metrics,
            )
        self._notify(progress, ScanProgress("defender", 0, 1, "Microsoft Defender scan running"))
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            completed = self._runner(
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.max_duration_seconds,
                check=False,
                creationflags=creationflags,
            )
            metrics.update({
                "exit_code": int(completed.returncode),
                "output_capture": "disabled",
            })
            success = completed.returncode == 0
            findings = () if success else (
                ScanFinding(
                    "defender.scan-failed", "medium", "Microsoft Defender",
                    "Microsoft Defender did not complete the requested scan",
                    (f"Exit code: {int(completed.returncode)}",),
                    (
                        "Open Windows Security and review Protection history and service health.",
                        "Update Defender signatures, then retry the scan.",
                    ),
                ),
            )
            self._notify(progress, ScanProgress("completed", 1, 1, "Defender scan finished"))
            return self._result(
                operation, started, status="completed" if success else "error",
                supported=True, executed=True,
                summary=(
                    (
                        "Microsoft Defender completed the no-remediation custom scan."
                        if remediation_disabled else
                        "Microsoft Defender completed the scan; configured Defender threat actions "
                        "may have been applied."
                    )
                    if success else "Microsoft Defender returned an error; no remediation was requested."
                ),
                findings=findings, metrics=metrics,
                privacy=(
                    "Defender output capture is disabled; selected paths and command output are not "
                    "returned or retained."
                ),
            )
        except subprocess.TimeoutExpired:
            return self._result(
                operation, started, status="limited", supported=True, executed=True,
                summary="Microsoft Defender exceeded the Scan Center time limit.", metrics=metrics,
                errors=("defender-timeout",),
            )
        except Exception as exc:
            return self._result(
                operation, started, status="error", supported=True, executed=True,
                summary="Microsoft Defender could not be started through its trusted executable.",
                metrics=metrics, errors=(f"defender-start:{type(exc).__name__}",),
            )
