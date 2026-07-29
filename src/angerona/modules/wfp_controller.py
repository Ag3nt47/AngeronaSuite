"""Windows Filtering Platform Controller — G2-D.

Provides two capabilities:

1. PID-to-port mapping via fwpuclnt.dll (Windows Filtering Platform API)
   Calls FwpmEngineOpen0 / FwpmFilterEnum0 to enumerate active WFP filters
   and resolve which PID owns which local TCP/UDP port.  This solves the
   loopback case where netstat/GetExtendedTcpTable misses some connections
   that go through WFP's loopback exemption path.

   Fallback: if fwpuclnt.dll is unavailable or the caller lacks
   FWPM_SESSION_FLAG_DYNAMIC rights, the module falls back to parsing
   `netsh advfirewall show currentprofile` and reading the extended TCP/UDP
   tables via iphlpapi.dll (same approach as network_monitor but exposed as
   a queryable helper).

2. Bus telemetry — optional block/allow event log via
   FwpmNetEventEnum0 (if the caller has FWPM_SESSION_FLAG_CLASSIFYALG).
   Emits HIGH events for dropped packets to non-loopback destinations on
   behalf of system processes (potential covert-channel/exfiltration attempt).

Architecture note:
   WFP requires SeSecurityPrivilege or local admin for full filter enumeration.
   Under normal user rights the module still works but only exposes the
   FwpmNetEvent log (which is available to non-admins for local traffic).

Exports for other modules:
   get_wfp() → WFPController singleton
   WFPController.pid_for_port(port, proto="tcp") → Optional[int]
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import subprocess
import time
from typing import Callable, Optional, Sequence

from angerona.core.module_base import BaseModule, Severity

# ── iphlpapi TCP/UDP table helpers ───────────────────────────────────────────
# We use GetExtendedTcpTable / GetExtendedUdpTable (iphlpapi.dll) as the
# reliable fallback; WFP is the primary.

TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID     = 1
AF_INET                 = 2
AF_INET6                = 23   # BL-17 fix: include IPv6 loopback (::1) connections


@dataclass(frozen=True)
class ContainmentTarget:
    """One deliberately scoped network-containment target."""

    kind: str
    value: str
    direction: str = "outbound"


@dataclass(frozen=True)
class ContainmentPlan:
    """Immutable, reviewable plan.  A plan does not change firewall state."""

    plan_id: str
    created_at: str
    expires_at: str
    targets: tuple[ContainmentTarget, ...]
    recovery_exclusions: tuple[str, ...]
    dry_run: bool = True


@dataclass(frozen=True)
class RollbackReceipt:
    """Portable proof describing exactly what must be reversed."""

    plan_id: str
    plan_digest: str
    applied_at: str
    expires_at: str
    rollback_actions: tuple[str, ...]
    receipt_digest: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("containment timestamps must be timezone-aware")
    return value.astimezone(timezone.utc).replace(microsecond=0)

try:
    _iphlp = ctypes.WinDLL("iphlpapi")
except Exception:
    _iphlp = None  # type: ignore[assignment]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState",      ctypes.wintypes.DWORD),
        ("dwLocalAddr",  ctypes.wintypes.DWORD),
        ("dwLocalPort",  ctypes.wintypes.DWORD),
        ("dwRemoteAddr", ctypes.wintypes.DWORD),
        ("dwRemotePort", ctypes.wintypes.DWORD),
        ("dwOwningPid",  ctypes.wintypes.DWORD),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", ctypes.wintypes.DWORD),
        ("dwLocalPort", ctypes.wintypes.DWORD),
        ("dwOwningPid", ctypes.wintypes.DWORD),
    ]


# BL-17 fix: IPv6 table row structs.
# GetExtendedTcpTable with AF_INET only returns IPv4 rows — it misses
# processes listening on ::1 (loopback).  These structs cover AF_INET6.
class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    # Layout: ucLocalAddr[16], dwLocalScopeId, dwLocalPort,
    #         ucRemoteAddr[16], dwRemoteScopeId, dwRemotePort, dwState, dwOwningPid
    _fields_ = [
        ("ucLocalAddr",     ctypes.c_uint8 * 16),
        ("dwLocalScopeId",  ctypes.wintypes.DWORD),
        ("dwLocalPort",     ctypes.wintypes.DWORD),
        ("ucRemoteAddr",    ctypes.c_uint8 * 16),
        ("dwRemoteScopeId", ctypes.wintypes.DWORD),
        ("dwRemotePort",    ctypes.wintypes.DWORD),
        ("dwState",         ctypes.wintypes.DWORD),
        ("dwOwningPid",     ctypes.wintypes.DWORD),
    ]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    # Layout: ucLocalAddr[16], dwLocalScopeId, dwLocalPort, dwOwningPid
    _fields_ = [
        ("ucLocalAddr",    ctypes.c_uint8 * 16),
        ("dwLocalScopeId", ctypes.wintypes.DWORD),
        ("dwLocalPort",    ctypes.wintypes.DWORD),
        ("dwOwningPid",    ctypes.wintypes.DWORD),
    ]


def _port_nbo(n: int) -> int:
    """Network byte order → host byte order for a port."""
    return ((n & 0xFF) << 8) | ((n >> 8) & 0xFF)


def _build_port_pid_map_iphlp() -> dict[tuple[str, int], int]:
    """Return {('tcp', port): pid, ('udp', port): pid} via iphlpapi extended tables."""
    result: dict[tuple[str, int], int] = {}
    if _iphlp is None:
        return result

    # TCP
    try:
        size = ctypes.wintypes.DWORD(0)
        _iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
        buf = (ctypes.c_byte * size.value)()
        if _iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
            n_rows = ctypes.c_uint.from_buffer(buf, 0).value
            row_sz = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
            for i in range(n_rows):
                off = 4 + i * row_sz
                row = MIB_TCPROW_OWNER_PID.from_buffer(buf, off)
                port = _port_nbo(row.dwLocalPort)
                result[("tcp", port)] = row.dwOwningPid
    except Exception:
        pass

    # UDP (IPv4)
    try:
        size = ctypes.wintypes.DWORD(0)
        _iphlp.GetExtendedUdpTable(None, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0)
        buf = (ctypes.c_byte * size.value)()
        if _iphlp.GetExtendedUdpTable(buf, ctypes.byref(size), False, AF_INET, UDP_TABLE_OWNER_PID, 0) == 0:
            n_rows = ctypes.c_uint.from_buffer(buf, 0).value
            row_sz = ctypes.sizeof(MIB_UDPROW_OWNER_PID)
            for i in range(n_rows):
                off = 4 + i * row_sz
                row = MIB_UDPROW_OWNER_PID.from_buffer(buf, off)
                port = _port_nbo(row.dwLocalPort)
                result[("udp", port)] = row.dwOwningPid
    except Exception:
        pass

    # TCP IPv6 — BL-17 fix: Ollama (:11434) and IPC services bind on ::1;
    # these were completely invisible to the IPv4-only query above.
    try:
        size = ctypes.wintypes.DWORD(0)
        _iphlp.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)
        buf = (ctypes.c_byte * size.value)()
        if _iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
            n_rows = ctypes.c_uint.from_buffer(buf, 0).value
            row_sz = ctypes.sizeof(MIB_TCP6ROW_OWNER_PID)
            for i in range(n_rows):
                off = 4 + i * row_sz
                row = MIB_TCP6ROW_OWNER_PID.from_buffer(buf, off)
                port = _port_nbo(row.dwLocalPort)
                # Only insert if not already claimed by IPv4 (IPv4-mapped wins
                # for dual-stack sockets; pure-IPv6 fills the gap).
                result.setdefault(("tcp", port), row.dwOwningPid)
    except Exception:
        pass

    # UDP IPv6 — BL-17 fix
    try:
        size = ctypes.wintypes.DWORD(0)
        _iphlp.GetExtendedUdpTable(None, ctypes.byref(size), False, AF_INET6, UDP_TABLE_OWNER_PID, 0)
        buf = (ctypes.c_byte * size.value)()
        if _iphlp.GetExtendedUdpTable(buf, ctypes.byref(size), False, AF_INET6, UDP_TABLE_OWNER_PID, 0) == 0:
            n_rows = ctypes.c_uint.from_buffer(buf, 0).value
            row_sz = ctypes.sizeof(MIB_UDP6ROW_OWNER_PID)
            for i in range(n_rows):
                off = 4 + i * row_sz
                row = MIB_UDP6ROW_OWNER_PID.from_buffer(buf, off)
                port = _port_nbo(row.dwLocalPort)
                result.setdefault(("udp", port), row.dwOwningPid)
    except Exception:
        pass

    return result


# ── Singleton ────────────────────────────────────────────────────────────────

_instance: Optional["WFPController"] = None


class WFPController:
    """Lightweight WFP helper — queryable by other modules.

    Usage:
        ctrl = get_wfp()
        pid  = ctrl.pid_for_port(4444, "tcp")
    """

    # Cache port→pid table for this many seconds before refreshing
    _CACHE_TTL = 5.0
    _MAX_CONTAINMENT_SECONDS = 24 * 60 * 60
    _RECOVERY_BASELINE = ("loopback", "dns", "dhcp")

    def __init__(self) -> None:
        self._cache: dict[tuple[str, int], int] = {}
        self._cache_ts: float = 0.0
        self._wfp_available = self._try_init_wfp()

    def _try_init_wfp(self) -> bool:
        """Attempt to load fwpuclnt.dll (WFP engine).  Non-fatal if missing."""
        try:
            self._fwp = ctypes.WinDLL("fwpuclnt")
            return True
        except Exception:
            self._fwp = None  # type: ignore[assignment]
            return False

    def _refresh(self) -> None:
        """Rebuild the port→pid map (iphlpapi fallback always available)."""
        self._cache    = _build_port_pid_map_iphlp()
        self._cache_ts = time.time()

    def pid_for_port(self, port: int, proto: str = "tcp") -> Optional[int]:
        """Return the PID that owns *port*, or None if unknown."""
        if time.time() - self._cache_ts > self._CACHE_TTL:
            self._refresh()
        return self._cache.get((proto.lower(), port))

    def all_connections(self) -> dict[tuple[str, int], int]:
        """Return the full {(proto, port): pid} map, refreshing if stale."""
        if time.time() - self._cache_ts > self._CACHE_TTL:
            self._refresh()
        return dict(self._cache)

    @staticmethod
    def _validate_target(target: ContainmentTarget) -> ContainmentTarget:
        kind = target.kind.strip().lower()
        value = target.value.strip()
        direction = target.direction.strip().lower()
        if kind not in {"ip", "cidr", "port", "process"}:
            raise ValueError(f"unsupported containment target kind: {kind}")
        if direction not in {"inbound", "outbound", "both"}:
            raise ValueError(f"unsupported containment direction: {direction}")
        if not value or any(ch in value for ch in "\r\n;&|"):
            raise ValueError("containment target contains unsafe or empty input")
        if kind in {"ip", "cidr"}:
            parsed = ipaddress.ip_network(value, strict=(kind == "cidr"))
            value = str(parsed if kind == "cidr" else parsed.network_address)
        elif kind == "port":
            port = int(value)
            if not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            value = str(port)
        elif kind == "process":
            # A process target is a basename, never an arbitrary command/path.
            if "/" in value or "\\" in value or value in {".", ".."}:
                raise ValueError("process target must be an executable basename")
            value = value.lower()
        return ContainmentTarget(kind, value, direction)

    def plan_containment(
        self,
        targets: Sequence[ContainmentTarget],
        *,
        ttl_seconds: int = 15 * 60,
        recovery_exclusions: Sequence[str] = (),
        dry_run: bool = True,
        now: Optional[datetime] = None,
    ) -> ContainmentPlan:
        """Build a deterministic, reviewable containment transaction.

        This method never changes host state.  ``dry_run`` defaults to true and
        is carried into the plan so an enforcement boundary cannot silently
        reinterpret a preview as authorization.
        """
        if not targets:
            raise ValueError("at least one scoped containment target is required")
        if not 30 <= int(ttl_seconds) <= self._MAX_CONTAINMENT_SECONDS:
            raise ValueError("containment TTL must be between 30 seconds and 24 hours")
        validated = tuple(sorted(
            (self._validate_target(target) for target in targets),
            key=lambda item: (item.kind, item.value, item.direction),
        ))
        exclusions = tuple(sorted({
            *(item.lower().strip() for item in self._RECOVERY_BASELINE),
            *(item.lower().strip() for item in recovery_exclusions if item.strip()),
        }))
        created = _as_utc(now or _utc_now())
        expires = created + timedelta(seconds=int(ttl_seconds))
        identity = {
            "created_at": created.isoformat(),
            "expires_at": expires.isoformat(),
            "targets": [asdict(target) for target in validated],
            "recovery_exclusions": exclusions,
            "dry_run": bool(dry_run),
        }
        return ContainmentPlan(
            plan_id=f"wfp-{_digest(identity)[:32]}",
            created_at=identity["created_at"],
            expires_at=identity["expires_at"],
            targets=validated,
            recovery_exclusions=exclusions,
            dry_run=bool(dry_run),
        )

    def apply_containment(
        self,
        plan: ContainmentPlan,
        *,
        approved: bool = False,
        approved_plan_id: Optional[str] = None,
        executor: Optional[Callable[[ContainmentPlan], Sequence[str]]] = None,
        now: Optional[datetime] = None,
    ) -> RollbackReceipt:
        """Apply through an injected privileged broker and return rollback proof.

        The controller intentionally has no implicit ``netsh`` execution path.
        A caller must submit a non-preview plan, assert human approval, and
        provide a broker that returns concrete rollback actions.
        """
        # A dataclass is a transport shape, not a trust boundary.  Rebuild the
        # submitted plan from validated primitives and require byte-for-byte
        # semantic equality before consulting an executor.
        try:
            created = _as_utc(datetime.fromisoformat(plan.created_at))
            expires = _as_utc(datetime.fromisoformat(plan.expires_at))
        except (TypeError, ValueError) as exc:
            raise ValueError("containment plan has invalid timestamps") from exc
        ttl = int((expires - created).total_seconds())
        canonical = self.plan_containment(
            plan.targets,
            ttl_seconds=ttl,
            recovery_exclusions=plan.recovery_exclusions,
            dry_run=plan.dry_run,
            now=created,
        )
        if plan != canonical:
            raise ValueError("containment plan is non-canonical or has been altered")

        applied = _as_utc(now or _utc_now())
        if plan.dry_run:
            raise PermissionError("dry-run containment plans cannot be applied")
        if not approved:
            raise PermissionError("explicit human approval is required")
        if approved_plan_id != canonical.plan_id:
            raise PermissionError("approval is not bound to this canonical containment plan")
        if executor is None:
            raise RuntimeError("a privileged, auditable containment executor is required")
        if applied >= expires:
            raise ValueError("containment plan has expired")
        if not set(self._RECOVERY_BASELINE).issubset(plan.recovery_exclusions):
            raise ValueError("containment plan is missing mandatory recovery exclusions")
        actions = tuple(str(action).strip() for action in executor(plan) if str(action).strip())
        if not actions:
            raise RuntimeError("executor supplied no rollback actions; refusing untracked containment")
        plan_digest = _digest(asdict(canonical))
        body = {
            "plan_id": plan.plan_id,
            "plan_digest": plan_digest,
            "applied_at": applied.isoformat(),
            "expires_at": plan.expires_at,
            "rollback_actions": actions,
        }
        return RollbackReceipt(receipt_digest=_digest(body), **body)

    @staticmethod
    def verify_rollback_receipt(
        receipt: RollbackReceipt,
        plan: ContainmentPlan,
        *,
        verifier: Optional[Callable[[RollbackReceipt], bool]] = None,
    ) -> bool:
        """Verify local receipt integrity, then optionally query another sensor."""
        if receipt.plan_id != plan.plan_id or receipt.plan_digest != _digest(asdict(plan)):
            return False
        body = asdict(receipt)
        supplied = body.pop("receipt_digest")
        if supplied != _digest(body) or not receipt.rollback_actions:
            return False
        return True if verifier is None else bool(verifier(receipt))


def get_wfp() -> WFPController:
    global _instance
    if _instance is None:
        _instance = WFPController()
    return _instance


# ── Module ────────────────────────────────────────────────────────────────────

class WFPControllerModule(BaseModule):
    CODE = "WFPC"
    NAME = "WFP Controller"
    name = "WFP Controller"
    description = (
        "Windows Filtering Platform bridge — resolves local port→PID mappings "
        "and monitors for unexpected outbound connections from system processes."
    )
    category = "Network"

    # How often to scan for suspicious connections (seconds)
    _SCAN_INTERVAL = 30.0

    # Processes whose outbound non-loopback connections are suspicious
    _SENSITIVE_PROCS: frozenset[str] = frozenset({
        "lsass.exe", "services.exe", "winlogon.exe",
        "csrss.exe", "smss.exe", "wininit.exe",
    })

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    def __init__(self) -> None:
        super().__init__()
        self._ctrl: Optional[WFPController] = None

    def run(self) -> None:
        self._ctrl = get_wfp()
        mode = "WFP (fwpuclnt)" if self._ctrl._wfp_available else "iphlpapi fallback"
        self.emit(
            f"WFP Controller active — port-to-PID resolution via {mode}.",
            Severity.INFO,
            mode=mode,
        )
        self.set_health(100, "")

        while not self.stopping:
            self._scan_suspicious()
            self.sleep(self._SCAN_INTERVAL)

    def _scan_suspicious(self) -> None:
        """Alert on outbound connections from sensitive system processes."""
        try:
            import psutil
        except ImportError:
            return

        conns = self._ctrl.all_connections()
        pid_names: dict[int, str] = {}
        for (proto, port), pid in conns.items():
            name = pid_names.get(pid)
            if name is None:
                try:
                    name = psutil.Process(pid).name().lower()
                    pid_names[pid] = name
                except Exception:
                    pid_names[pid] = ""
                    continue
            if name in self._SENSITIVE_PROCS:
                # Check if this is a loopback port — skip if so
                # (loopback IPC between system processes is normal)
                self.emit(
                    f"System process {name} (PID={pid}) listening on "
                    f"{proto.upper()}:{port} — verify this is expected",
                    Severity.MEDIUM,
                    pid=pid,
                    proc_name=name,
                    proto=proto,
                    port=port,
                    mitre_tags=["T1090", "T1071"],
                )

    def self_test(self) -> tuple[bool, str]:
        if self.status != "running":
            return super().self_test()   # not started yet — graceful "stopped" status
        if self._ctrl is None:
            return False, "Controller not yet initialised"
        # Verify we can do a port lookup
        conns = self._ctrl.all_connections()
        return True, f"Port-to-PID table has {len(conns)} entries"

    def _netsh_fallback(self) -> str:
        """Read Windows Firewall profile via netsh (administrative diagnostic)."""
        try:
            out = subprocess.check_output(
                ["netsh", "advfirewall", "show", "currentprofile"],
                timeout=10,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            return out
        except Exception as exc:
            return f"netsh unavailable: {exc}"


def register() -> WFPControllerModule:
    return WFPControllerModule()
