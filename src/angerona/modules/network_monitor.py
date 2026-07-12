"""Network connection monitor.

Tracks new outbound connections and flags three independent signals:

  1. Connection to a hardcoded suspicious port (illustrative C2/tooling
     ports) — HIGH, unchanged from before.
  2. First contact with an external HOST not seen (by ANY process) in the
     novelty window — MEDIUM. This is what actually catches exfil-style
     traffic over ordinary ports like 443/80, which a port-only heuristic
     structurally cannot.
  3. First contact with an already-known HOST, but from a PROCESS that
     hasn't talked to it before — LOW. This closes a real gap signal #2
     alone can't see: on a real machine, a handful of IP ranges (Google,
     Cloudflare's shared anycast edge, etc.) are essentially always
     "already known" because a browser or background service touched them
     recently — so a newly-launched process reaching one of those same
     addresses would otherwise generate no signal at all, even though "a
     process that's never talked to this host before just did" is exactly
     the kind of thing worth a quiet note. (This is also what makes a
     Shark Attack Exfiltration drill reliably testable: the test domains
     resolve into Cloudflare's shared IP space, which is near-guaranteed to
     already be "known" on any machine with a browser — signal #2 alone
     would almost never fire on a repeat run, not because detection is
     broken, but because that specific IP just isn't a fresh destination
     for anyone. Signal #3 doesn't care who else has visited it.)

To avoid drowning the alert feed, everything else (a process repeating a
connection it's already made itself) is NOT alerted individually — it's
counted and rolled up into one quiet INFO line per minute. Loopback and
private/local addresses are ignored entirely.
"""
from __future__ import annotations

import os
import time
from typing import Dict, Set, Tuple

from angerona.core.module_base import BaseModule, Severity
from angerona.core.net_interfaces import interface_type_for_local_ip
from angerona.telemetry.sensors import list_connections

# Ports commonly abused by malware C2 / tooling (illustrative, tune as needed).
SUSPICIOUS_PORTS = {4444, 1337, 6660, 6667, 31337, 12345, 9001, 5555}

# A host counts as "novel" again if we haven't seen it in this many minutes —
# a fresh destination is a meaningfully different signal than a long-running
# peer, but "seen once, forever trusted" would quietly stop watching after
# the first day of uptime.
NOVELTY_WINDOW_S = float(os.environ.get("ANGERONA_NETMON_NOVELTY_WINDOW_MIN", "60")) * 60


def _is_local(ip: str) -> bool:
    if not ip:
        return True
    if ip in ("127.0.0.1", "::1", "0.0.0.0"):
        return True
    if ip.startswith(("10.", "192.168.", "169.254.", "fe80", "fc", "fd", "::")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except Exception:
            pass
    return False


class NetworkMonitorModule(BaseModule):
    name = "Network Monitor"
    description = "Watches new outbound connections; alerts on suspicious ports and first-seen external hosts."
    category = "Network"

    def __init__(self) -> None:
        super().__init__()
        self._seen: Set[Tuple] = set()
        self._known_hosts: Dict[str, float] = {}  # ip -> last-seen ts (any process)
        self._known_pid_hosts: Set[Tuple[int, str]] = set()  # (pid, ip) this process has hit

    def run(self) -> None:
        now0 = time.time()
        for c in list_connections():
            self._seen.add((c["pid"], c["raddr"]))
            # Seed already-established peers as "known" so a pre-existing,
            # long-running connection doesn't get flagged as novel the
            # moment a second socket to the same host appears after startup.
            if c.get("raddr"):
                ip = c["raddr"].rsplit(":", 1)[0]
                if not _is_local(ip):
                    self._known_hosts[ip] = now0
                    self._known_pid_hosts.add((c["pid"], ip))
        self.set_health(100, "")
        self.emit("Network monitor active.", Severity.INFO)

        last_summary = time.time()
        new_external = 0
        while not self.stopping:
            self.sleep(4)
            for c in list_connections():
                if c["status"] != "ESTABLISHED" or not c["raddr"]:
                    continue
                ip = c["raddr"].rsplit(":", 1)[0]
                if _is_local(ip):
                    continue
                key = (c["pid"], c["raddr"])
                if key in self._seen:
                    continue
                self._seen.add(key)
                new_external += 1
                try:
                    rport = int(c["raddr"].rsplit(":", 1)[1])
                except Exception:
                    rport = -1

                # VPN awareness: tag the owning interface (Physical / Virtual_VPN /
                # Loopback) so downstream (AI triage, split-tunnel rule) has context.
                _laddr = c.get("laddr") or ""
                c["interface_type"] = interface_type_for_local_ip(
                    _laddr.rsplit(":", 1)[0] if _laddr else "")

                now = time.time()
                last_seen = self._known_hosts.get(ip)
                is_novel_host = last_seen is None or (now - last_seen) > NOVELTY_WINDOW_S
                is_novel_for_pid = (c["pid"], ip) not in self._known_pid_hosts
                self._known_hosts[ip] = now
                self._known_pid_hosts.add((c["pid"], ip))

                if rport in SUSPICIOUS_PORTS:
                    self.emit(f"Connection to suspicious port {rport}: {c['raddr']} "
                              f"(pid {c['pid']})", Severity.HIGH, **c)
                elif is_novel_host:
                    mins = int(NOVELTY_WINDOW_S // 60)
                    self.emit(f"First contact with external host {ip} in the last "
                              f"{mins}min (pid {c['pid']}, port {rport}) — novel-destination "
                              "signal.", Severity.MEDIUM, **c)
                elif is_novel_for_pid:
                    # The host itself is already known (some other process
                    # touched it recently — very common with shared-IP CDN
                    # ranges), but THIS process hasn't reached it before.
                    # Lower severity: much less alarming than a host nobody's
                    # ever seen, but still a real, distinct "new" signal.
                    self.emit(f"Process {c['pid']} made its first connection to already-known "
                              f"host {ip}:{rport} — new to this process, not to the machine.",
                              Severity.LOW, **c)

            # One quiet rollup per minute for everything else (repeat
            # connections to already-known hosts on ordinary ports).
            now = time.time()
            if now - last_summary >= 60:
                if new_external:
                    self.emit(f"{new_external} new external connection(s) in the last minute.",
                              Severity.INFO)
                new_external = 0
                last_summary = now
