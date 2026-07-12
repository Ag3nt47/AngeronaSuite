"""net_interfaces.py — VPN-adapter intelligence + split-tunnel detection.

Shared, dependency-light helper imported by three call sites:
  * NMON / WFPC — tag each NET event with an ``interface_type``.
  * ATRG (ai_triage) — pass ``interface_type`` into the Ollama prompt.
  * FPTH — the 18th deterministic IOC rule (split-tunnel abuse).

Design constraints (from the brief):
  * Standard library + psutil only. No third-party VPN/API libraries.
  * Non-blocking: classification is cached (adapters rarely change), and the
    per-PID connection scan is bounded and best-effort so the detection loop is
    never stalled.
  * We identify virtual adapters heuristically (name/description patterns, known
    TAP/TUN OUIs, point-to-point stats) rather than integrating any vendor API.
"""
from __future__ import annotations

import ipaddress
import threading
import time
from typing import Optional

import psutil


# ── Interface classification ──────────────────────────────────────────────────
PHYSICAL   = "Physical"
VIRTUAL_VPN = "Virtual_VPN"
LOOPBACK   = "Loopback"

# Substrings commonly found in virtual/VPN adapter names or descriptions.
_VPN_NAME_HINTS = (
    "tap", "tun", "wintun", "wireguard", "openvpn", "proton", "nordlynx",
    "mullvad", "tailscale", "zerotier", "vpn", "wg", "utun", "ppp",
)
# MAC OUI prefixes used by common virtual adapters (TAP-Windows, etc.).
_VPN_OUI_PREFIXES = ("00:ff:", "00:50:f2:", "00:1c:42:")  # TAP-Windows / MS / Parallels-style

_CACHE_TTL_S = 30.0
_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, dict]] = {}


def _macs_for(name: str, addrs) -> list[str]:
    out = []
    for a in addrs:
        # AF_LINK / AF_PACKET carries the MAC in .address (format varies by OS)
        if getattr(a, "family", None) in (getattr(psutil, "AF_LINK", -1),) and a.address:
            out.append(a.address.lower().replace("-", ":"))
    return out


def classify_interfaces() -> dict[str, str]:
    """Return {ifname: PHYSICAL|VIRTUAL_VPN|LOOPBACK}. Cached for _CACHE_TTL_S.

    Heuristics, in order: loopback flag → name/description hints → OUI match →
    point-to-point stat (many VPN tunnels report no broadcast + isup). Anything
    unmatched defaults to PHYSICAL (fail toward "external", never hide traffic).
    """
    now = time.time()
    with _cache_lock:
        hit = _cache.get("ifmap")
        if hit and (now - hit[0]) < _CACHE_TTL_S:
            return hit[1]

    result: dict[str, str] = {}
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
    except Exception:
        return {}

    for name, addrs in if_addrs.items():
        lname = name.lower()
        cls = PHYSICAL
        if "loopback" in lname or lname.startswith("lo"):
            cls = LOOPBACK
        elif any(h in lname for h in _VPN_NAME_HINTS):
            cls = VIRTUAL_VPN
        else:
            macs = _macs_for(name, addrs)
            if any(m.startswith(p) for m in macs for p in _VPN_OUI_PREFIXES):
                cls = VIRTUAL_VPN
            else:
                st = if_stats.get(name)
                # Point-to-point tunnels: up, but no L2 broadcast semantics.
                if st and st.isup and getattr(st, "duplex", 0) == 0 and st.speed == 0:
                    # weak signal — only tag VPN if it also owns a private /32-ish IP
                    for a in addrs:
                        if getattr(a, "netmask", None) in ("255.255.255.255", None):
                            cls = VIRTUAL_VPN
                            break
        result[name] = cls

    with _cache_lock:
        _cache["ifmap"] = (now, result)
    return result


def _local_ip_to_iface() -> dict[str, str]:
    """Map each local IP string → owning interface name (cached alongside ifmap)."""
    now = time.time()
    with _cache_lock:
        hit = _cache.get("ipmap")
        if hit and (now - hit[0]) < _CACHE_TTL_S:
            return hit[1]
    ipmap: dict[str, str] = {}
    try:
        for name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "address", None) and "." in str(a.address):
                    ipmap[a.address] = name
    except Exception:
        pass
    with _cache_lock:
        _cache["ipmap"] = (now, ipmap)
    return ipmap


def interface_type_for_local_ip(local_ip: str) -> str:
    """Classify the interface that owns a connection's local address."""
    if not local_ip:
        return PHYSICAL
    if local_ip.startswith("127.") or local_ip == "::1":
        return LOOPBACK
    iface = _local_ip_to_iface().get(local_ip)
    if not iface:
        return PHYSICAL
    return classify_interfaces().get(iface, PHYSICAL)


def tag_connection(conn) -> str:
    """interface_type for a psutil connection (uses its local address)."""
    try:
        return interface_type_for_local_ip(conn.laddr.ip) if conn.laddr else PHYSICAL
    except Exception:
        return PHYSICAL


def enrich_net_payload(payload: dict, local_ip: str) -> dict:
    """NMON helper: stamp interface_type onto an outgoing NET event payload."""
    payload = dict(payload or {})
    payload["interface_type"] = interface_type_for_local_ip(local_ip)
    return payload


# ── Untrusted-destination test ────────────────────────────────────────────────
def is_untrusted_external(ip: str) -> bool:
    """True if ip is a routable public address (not private/loopback/link-local).

    Deliberately conservative: anything we can't parse is treated as untrusted.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


# ── Split-tunnel detector (backs FPTH rule #18) ──────────────────────────────
def detect_split_tunnel(pid: int) -> Optional[dict]:
    """Stateless per-call check for one PID.

    Returns a finding dict if the PID holds concurrent ESTABLISHED connections
    over BOTH a Virtual_VPN interface AND a Physical interface to an untrusted
    external IP — the classic split-tunnel exfil/bypass pattern. Returns None
    otherwise. Never raises; on any error returns None (fail open).
    """
    try:
        conns = psutil.Process(pid).net_connections(kind="inet")
    except Exception:
        return None

    vpn_dsts: list[str] = []
    phys_ext_dsts: list[str] = []
    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        itype = interface_type_for_local_ip(c.laddr.ip if c.laddr else "")
        rip = c.raddr.ip
        if itype == VIRTUAL_VPN:
            vpn_dsts.append(rip)
        elif itype == PHYSICAL and is_untrusted_external(rip):
            phys_ext_dsts.append(rip)

    if vpn_dsts and phys_ext_dsts:
        return {
            "rule": "FPTH-18-SPLIT-TUNNEL",
            "pid": pid,
            "vpn_destinations": vpn_dsts[:10],
            "physical_external_destinations": phys_ext_dsts[:10],
            "reason": ("Process holds concurrent connections over a VPN interface "
                       "and a physical interface to an untrusted external host "
                       "(split-tunnel bypass / exfil pattern)."),
        }
    return None
