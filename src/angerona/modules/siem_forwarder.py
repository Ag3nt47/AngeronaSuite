"""siem_forwarder.py — SIEM Forwarder (Code: SIEM).

Purpose
    Streams Angerona detections to a centralized SOC by translating EventBus
    events into ArcSight Common Event Format (CEF) and shipping them over
    verified TLS Syslog by default. Lets Angerona act as a sensor inside a larger SIEM/XDR estate
    (Splunk, Sentinel, QRadar, Elastic) without exposing any host internals
    beyond the alert text itself.

Opt-in by design
    This module sends data OFF the host, so it is DISABLED by default and does
    nothing until a destination is configured via environment:
        ANGERONA_SIEM_HOST   destination IP/hostname   (required to activate)
        ANGERONA_SIEM_PORT   default 6514
        ANGERONA_SIEM_PROTO  "tls" (default); plaintext tcp/udp require an
                             additional explicit risk acknowledgement
        ANGERONA_SIEM_MINSEV minimum severity to forward: INFO/LOW/MEDIUM/HIGH/CRITICAL
                             (default MEDIUM)
    With no host set it stays idle and reports so — it never blasts a default IP.

Resilience
    TLS/TCP reconnect on failure; opted-in UDP is fire-and-forget. If forwarding fails, the
    event is preserved locally (it already lives in the BlackBox/EventBus ring);
    SIEM forwarding is additive and never blocks or drops the local pipeline.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import os
import socket
import ssl
import threading
import time

from angerona.core.module_base import BaseModule, Severity

# Angerona Severity (0-4) → CEF severity (0-10).
_CEF_SEV = {0: 1, 1: 3, 2: 5, 3: 7, 4: 10}


class _CefFormatter:
    """Builds strictly-formatted CEF payloads. Pure/stateless — unit-testable."""

    def __init__(self, vendor="ProjectAngerona", product="AngeronaCore", version="1.3.1"):
        self.vendor = vendor
        self.product = product
        self.version = version

    @staticmethod
    def _esc_header(s: str) -> str:
        # In the CEF header, '|' and '\' must be escaped.
        return str(s).replace("\\", "\\\\").replace("|", "\\|")

    @staticmethod
    def _esc_ext(s: str) -> str:
        # In extensions, '=' and '\' must be escaped; newlines flattened.
        return (str(s).replace("\\", "\\\\").replace("=", "\\=")
                .replace("\n", " ").replace("\r", " "))

    def build(self, event_id: str, severity: int, name: str, msg: str,
              mitre_tag: str = "", extra: dict | None = None) -> str:
        cef_sev = _CEF_SEV.get(int(severity), 5)
        ext = f"msg={self._esc_ext(msg)}"
        if mitre_tag:
            ext += f" cs1={self._esc_ext(mitre_tag)} cs1Label=MITRE_Technique"
        for k, v in (extra or {}).items():
            ext += f" {k}={self._esc_ext(v)}"
        header = "|".join([
            "CEF:0", self._esc_header(self.vendor), self._esc_header(self.product),
            self._esc_header(self.version), self._esc_header(event_id),
            self._esc_header(name), str(cef_sev),
        ])
        return f"{header}|{ext}"


class SIEMForwarderModule(BaseModule):
    CODE = "SIEM"
    NAME = "SIEM Forwarder"
    name = "SIEM Forwarder"
    description = ("Forwards detections to a central SIEM as CEF over Syslog "
                   "(UDP/TCP). Opt-in: idle until ANGERONA_SIEM_HOST is set.")
    category = "Integration"
    version = "1.0.0"
    enabled_by_default = False        # off until a destination is configured

    _POLL = 3.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._fmt = _CefFormatter()
        self._last_ts = 0.0
        self._sent = 0
        self._fails = 0
        self._tcp: socket.socket | None = None
        self.host = ""
        self.port = 514
        self.proto = "tls"
        self.min_sev = Severity.MEDIUM
        self._config_refusal = ""

    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── config ───────────────────────────────────────────────────────────────
    def _load_config(self) -> bool:
        self.host = (os.environ.get("ANGERONA_SIEM_HOST") or "").strip()
        try:
            self.port = int(os.environ.get("ANGERONA_SIEM_PORT", "514"))
        except ValueError:
            self.port = 514
        self.proto = (os.environ.get("ANGERONA_SIEM_PROTO", "tls") or "tls").lower()
        if "ANGERONA_SIEM_PORT" not in os.environ and self.proto == "tls":
            self.port = 6514
        if self.proto not in {"tls", "tcp", "udp"}:
            self._config_refusal = f"unsupported SIEM protocol: {self.proto}"
            return False
        if self.proto != "tls" and os.environ.get(
                "ANGERONA_SIEM_ALLOW_PLAINTEXT", "").strip().lower() not in {
                    "1", "true", "yes"}:
            self._config_refusal = (
                "plaintext SIEM transport refused; use TLS or explicitly set "
                "ANGERONA_SIEM_ALLOW_PLAINTEXT=1")
            return False
        sev_name = (os.environ.get("ANGERONA_SIEM_MINSEV", "MEDIUM") or "MEDIUM").upper()
        self.min_sev = getattr(Severity, sev_name, Severity.MEDIUM)
        return bool(self.host)

    # ── transport ────────────────────────────────────────────────────────────
    def _send(self, payload: str) -> None:
        data = (payload + "\n").encode("utf-8", "replace")
        if self.proto in {"tcp", "tls"}:
            if self._tcp is None:
                raw = socket.create_connection((self.host, self.port), timeout=5)
                if self.proto == "tls":
                    ca_file = (os.environ.get("ANGERONA_SIEM_CA_FILE") or "").strip()
                    context = ssl.create_default_context(cafile=ca_file or None)
                    try:
                        self._tcp = context.wrap_socket(raw, server_hostname=self.host)
                    except Exception:
                        raw.close()
                        raise
                else:
                    self._tcp = raw
            try:
                self._tcp.sendall(data)
            except Exception:
                try:
                    self._tcp.close()
                except Exception:
                    pass
                self._tcp = None
                raise
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data, (self.host, self.port))

    def _forward_event(self, ev) -> None:
        details = getattr(ev, "details", {}) or {}
        mitre = str(details.get("mitre") or details.get("technique") or "")
        module = getattr(ev, "module", "Angerona")
        sev = int(getattr(ev, "severity", Severity.INFO))
        event_id = str(details.get("eid") or details.get("event_type") or module)
        message = getattr(ev, "message", "")
        if os.environ.get("ANGERONA_SIEM_INCLUDE_RAW", "").strip().lower() not in {
                "1", "true", "yes"}:
            from angerona.core.privacy import redact_text
            message = redact_text(message, limit=2000)
        payload = self._fmt.build(event_id=event_id, severity=sev, name=module,
                                  msg=message, mitre_tag=mitre,
                                  extra={"sev": getattr(getattr(ev, "severity", None), "label", str(sev))})
        self._send(payload)

    # ── lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        if not self._load_config():
            note = self._config_refusal or "no ANGERONA_SIEM_HOST configured"
            self.set_health(60, f"idle — {note}")
            self.emit(f"SIEM Forwarder idle — {note}.",
                      Severity.MEDIUM if self._config_refusal else Severity.LOW,
                      idle=True)
            while not self.stopping:
                self.sleep(30)
            return

        self.emit(f"SIEM Forwarder online — {self.proto.upper()} → {self.host}:{self.port} "
                  f"(min severity {self.min_sev.name}).", Severity.INFO)
        # Don't replay history on startup: baseline to the newest event.
        if self._bus is not None:
            recent = self._bus.recent(1)
            if recent:
                self._last_ts = recent[-1].ts

        while not self.stopping:
            try:
                if self._bus is not None:
                    for ev in self._bus.recent(100):
                        if ev.ts <= self._last_ts:
                            continue
                        self._last_ts = max(self._last_ts, ev.ts)
                        if int(getattr(ev, "severity", Severity.INFO)) < int(self.min_sev):
                            continue
                        if getattr(ev, "module", "") == self.NAME:
                            continue     # never forward our own status events
                        try:
                            self._forward_event(ev)
                            self._sent += 1
                        except Exception as exc:
                            self._fails += 1
                            self.last_error = str(exc)
                if self._fails and self._sent == 0:
                    self.set_health(40, f"forwarding failing ({self._fails}); check SIEM reachability")
                else:
                    self.set_health(100, f"{self._sent} events forwarded, {self._fails} failures")
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(50, f"forwarder error: {exc}")
            self.sleep(self._POLL)

        if self._tcp is not None:
            try:
                self._tcp.close()
            except Exception:
                pass

    def self_test(self) -> tuple[bool, str]:
        """Offline: verify CEF formatting + escaping without sending anything."""
        cef = self._fmt.build(event_id="4688", severity=int(Severity.HIGH),
                              name="ETW Real-Time Process Sensor",
                              msg="Process created: cmd.exe | pipe=x",
                              mitre_tag="T1059.001")
        ok = (cef.startswith("CEF:0|ProjectAngerona|AngeronaCore|")
              and "|7|" in cef                       # HIGH → CEF sev 7
              and "cs1=T1059.001" in cef
              and "pipe\\=x" in cef)                  # '=' in extension value escaped
        configured = "configured" if (os.environ.get("ANGERONA_SIEM_HOST") or "").strip() else "idle (no host set)"
        return ok, (f"CEF build + escaping verified ({configured})" if ok
                    else f"CEF format failed: {cef}")


def register() -> SIEMForwarderModule:
    return SIEMForwarderModule()
