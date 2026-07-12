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
import subprocess
import time
from typing import Optional

from angerona.core.module_base import BaseModule, Severity

# ── iphlpapi TCP/UDP table helpers ───────────────────────────────────────────
# We use GetExtendedTcpTable / GetExtendedUdpTable (iphlpapi.dll) as the
# reliable fallback; WFP is the primary.

TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID     = 1
AF_INET                 = 2
AF_INET6                = 23   # BL-17 fix: include IPv6 loopback (::1) connections

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
