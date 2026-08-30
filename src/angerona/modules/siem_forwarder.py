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
        ANGERONA_SIEM_PORT   defaults to 6514 for TLS, 443 for HTTPS
        ANGERONA_SIEM_MINSEV minimum severity to forward: INFO/LOW/MEDIUM/HIGH/CRITICAL
                             (default MEDIUM)
        ANGERONA_SIEM_PROTO  "tls" (default), "https" for exact application ACK;
                             plaintext tcp/udp require explicit risk acceptance
    With no host set it stays idle and reports so — it never blasts a default IP.

Resilience
    Selected events are committed to a bounded authenticated local outbox before
    their EventBus cursor advances. HTTPS requires an exact TLS-protected JSON
    acknowledgement before deleting a row. TLS/TCP reconnect on failure; opted-in
    UDP is fire-and-forget. Syslog socket success is explicitly transport-only
    and cannot produce end-to-end health 100. EventBus retention overflow is
    exported as an explicit durable gap receipt.

Drop-in contract: BaseModule subclass + CODE/NAME/state/health_pct/self_test +
module-level register().
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import socket
import ssl
import threading
import time
import uuid

from angerona import __version__
from angerona.core.durable_outbox import (
    DurableOutbox,
    OutboxFull,
    load_or_create_outbox_key,
)
from angerona.core.eventbus import Event
from angerona.core.module_base import BaseModule, Severity

# Angerona Severity (0-4) → CEF severity (0-10).
_CEF_SEV = {0: 1, 1: 3, 2: 5, 3: 7, 4: 10}


class _CefFormatter:
    """Builds strictly-formatted CEF payloads. Pure/stateless — unit-testable."""

    def __init__(self, vendor="ProjectAngerona", product="AngeronaCore", version=__version__):
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
    version = "1.13.0"
    supported_platforms = ("windows", "macos", "linux")
    capability_mode = "observe"
    capability_inputs = ("authenticated-eventbus-event",)
    capability_outputs = ("cef-syslog-envelope", "delivery-health")
    capability_permissions = ("configured-network-egress", "local-outbox-read-write")
    high_risk_permissions = ("configured-network-egress",)
    data_classes = ("security-finding", "redacted-event-summary")
    egress = "optional"
    retention = "bounded-authenticated-durable-outbox"
    response_authority = "none"
    restart_policy = "bounded-three-attempt-backoff-quarantine"
    loss_behavior = (
        "bounded-bus-ingress-with-durable-gap-receipt;"
        "retrying-transport-handoff-after-durable-enqueue"
    )
    resource_budget = {
        "worker_model": "single-lifecycle-thread",
        "event_delivery": (
            "durable-retry-until-exact-https-application-ack;"
            "syslog-is-transport-handoff-only"
        ),
        "startup_cycle_timeout_seconds": 30.0,
    }
    settings_schema = {
        "type": "object",
        "properties": {
            "host": {"type": "string", "maxLength": 253},
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "protocol": {
                "type": "string",
                "enum": ["https", "tls", "tcp", "udp"],
            },
            "minimum_severity": {
                "type": "string",
                "enum": ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            },
        },
        "additionalProperties": False,
    }
    enabled_by_default = False        # off until a destination is configured

    _POLL = 3.0

    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()
        self._fmt = _CefFormatter()
        self._sent = 0
        self._application_acks = 0
        self._fails = 0
        self._tcp: socket.socket | None = None
        self.host = ""
        self.port = 514
        self.proto = "tls"
        self.min_sev = Severity.MEDIUM
        self._config_refusal = ""
        self._outbox: DurableOutbox | None = None
        self._outbox_owner = f"siem-{uuid.uuid4().hex}"
        self._ingress_gaps = 0

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
        if "ANGERONA_SIEM_PORT" not in os.environ:
            if self.proto == "tls":
                self.port = 6514
            elif self.proto == "https":
                self.port = 443
        if self.proto not in {"https", "tls", "tcp", "udp"}:
            self._config_refusal = f"unsupported SIEM protocol: {self.proto}"
            return False
        if self.proto in {"tcp", "udp"} and os.environ.get(
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

    def _send_https(self, payload: str, item_id: str) -> None:
        """Require an exact TLS endpoint acknowledgement for one durable ID."""
        ack_id = str(item_id or "").strip()
        if not ack_id or len(ack_id) > 200:
            raise ValueError("durable SIEM item has an invalid acknowledgement ID")
        path = (os.environ.get("ANGERONA_SIEM_HTTPS_PATH") or "/api/events").strip()
        if (
            not path.startswith("/")
            or path.startswith("//")
            or len(path) > 2048
            or any(ord(char) < 0x20 for char in path)
        ):
            raise ValueError("ANGERONA_SIEM_HTTPS_PATH must be a bounded absolute path")
        ca_file = (os.environ.get("ANGERONA_SIEM_CA_FILE") or "").strip()
        context = ssl.create_default_context(cafile=ca_file or None)
        body = json.dumps(
            {"id": ack_id, "cef": payload},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        connection = http.client.HTTPSConnection(
            self.host,
            self.port,
            timeout=5.0,
            context=context,
        )
        try:
            connection.request(
                "POST",
                path,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Idempotency-Key": ack_id,
                },
            )
            response = connection.getresponse()
            response_body = response.read(64 * 1024 + 1)
            if len(response_body) > 64 * 1024:
                raise OSError("SIEM HTTPS acknowledgement exceeds 64 KiB")
            if not 200 <= int(response.status) < 300:
                raise OSError(f"SIEM HTTPS endpoint returned {response.status}")
            try:
                receipt = json.loads(response_body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as exc:
                raise OSError("SIEM HTTPS acknowledgement is not valid JSON") from exc
            if (
                not isinstance(receipt, dict)
                or receipt.get("accepted") is not True
                or not hmac.compare_digest(str(receipt.get("ack_id") or ""), ack_id)
            ):
                raise OSError(
                    "SIEM HTTPS acknowledgement does not match the durable ID"
                )
        finally:
            connection.close()

    def _format_event(self, ev) -> str:
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
        return self._fmt.build(
            event_id=event_id,
            severity=sev,
            name=module,
            msg=message,
            mitre_tag=mitre,
            extra={
                "sev": getattr(getattr(ev, "severity", None), "label", str(sev))
            },
        )

    @staticmethod
    def _stable_event_id(ev) -> str:
        signature = str(getattr(ev, "hmac_sig", "") or "").strip().casefold()
        if signature:
            return f"siem-{signature[:128]}"
        body = json.dumps(
            {
                "module": getattr(ev, "module", ""),
                "message": getattr(ev, "message", ""),
                "severity": int(getattr(ev, "severity", Severity.INFO)),
                "ts": float(getattr(ev, "ts", 0.0)),
                "details": getattr(ev, "details", {}) or {},
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
        return "siem-" + hashlib.sha256(body).hexdigest()

    def _open_outbox(self) -> DurableOutbox:
        from angerona.core.data_paths import data_dir

        root = data_dir() / "outbox"
        key = load_or_create_outbox_key(root / "siem.key")
        return DurableOutbox(
            root / "siem.sqlite3",
            key,
            max_items=20_000,
            max_bytes=128 * 1024 * 1024,
        )

    def _stage_bus_delta(self) -> int:
        if self._bus is None or self._outbox is None:
            return 0
        revision, events, overflow = self.read_bus_events()
        staged = 0
        for ev in events:
            if int(getattr(ev, "severity", Severity.INFO)) < int(self.min_sev):
                continue
            if getattr(ev, "module", "") == self.NAME:
                continue
            staged += int(self._outbox.enqueue(
                self._stable_event_id(ev),
                {"cef": self._format_event(ev)},
                now=float(getattr(ev, "ts", time.time())),
            ))
        if overflow:
            gap = Event(
                self.NAME,
                "EventBus retention overflow before SIEM durable staging; "
                "the exported evidence stream is incomplete.",
                Severity.HIGH,
                details={
                    "finding_code": "siem.eventbus.capacity_gap",
                    "event_revision": revision,
                    "response_authorized": False,
                },
            )
            staged += int(self._outbox.enqueue(
                f"siem-gap-{revision}",
                {"cef": self._format_event(gap), "ingress_gap": True},
                now=gap.ts,
            ))
            self._ingress_gaps += 1
            self.set_health(
                45,
                f"{self._ingress_gaps} EventBus capacity gap(s); "
                "a durable gap receipt was staged",
            )
        # The full selected delta is now either durably staged or deliberately
        # filtered. Any enqueue exception skips this commit and replays it.
        self.commit_bus_cursor(revision)
        return staged

    def _drain_outbox(self) -> None:
        if self._outbox is None:
            return
        for item in self._outbox.claim(
            self._outbox_owner, limit=100, lease_seconds=30.0
        ):
            try:
                payload = item.payload.get("cef")
                if not isinstance(payload, str) or not payload:
                    raise ValueError("durable SIEM item has no CEF payload")
                if self.proto == "https":
                    self._send_https(payload, item.item_id)
                    self._application_acks += 1
                else:
                    self._send(payload)
                self._outbox.acknowledge(item.item_id, self._outbox_owner)
                self._sent += 1
            except Exception as exc:
                self._fails += 1
                self.last_error = str(exc)
                self._outbox.retry(
                    item.item_id, self._outbox_owner, str(exc)
                )

    def _delivery_cycle(self) -> int:
        """Free capacity, durably stage the bus delta, then send new rows."""
        self._drain_outbox()
        staged = self._stage_bus_delta()
        self._drain_outbox()
        return staged

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
        try:
            self._outbox = self._open_outbox()
        except Exception as exc:
            self.last_error = str(exc)
            self.set_health(30, f"durable outbox unavailable: {exc}")
            self.emit(
                "SIEM Forwarder refused to start without its durable outbox.",
                Severity.HIGH,
                response_authorized=False,
            )
            while not self.stopping:
                self.sleep(30)
            return
        # Enroll once. A stop/start of this same instance must retain the cursor
        # so events published while stopped are staged on restart.
        self._enroll_cursor_once()

        while not self.stopping:
            try:
                self._delivery_cycle()
                stats = self._outbox.stats()
                if self._ingress_gaps:
                    self.set_health(
                        45,
                        f"{self._ingress_gaps} ingress gap(s), "
                        f"{stats.pending + stats.leased} queued; "
                        f"{self._sent} socket handoffs",
                    )
                elif stats.dead_letter:
                    self.set_health(
                        35,
                        f"{stats.dead_letter} dead-letter, {stats.pending} pending; "
                        f"{self._fails} delivery failures",
                    )
                elif stats.pending or stats.leased or self._fails:
                    self.set_health(
                        60,
                        f"{stats.pending + stats.leased} queued, {self._sent} socket handoffs, "
                        f"{self._fails} retries",
                    )
                else:
                    if self.proto == "https" and self._application_acks:
                        self.set_health(
                            100,
                            f"{self._application_acks} exact HTTPS application ACK(s)",
                        )
                    elif self.proto == "https":
                        self.set_health(
                            85,
                            "HTTPS endpoint ready; no application ACK observed yet",
                        )
                    else:
                        self.set_health(
                            75,
                            f"{self._sent} durable socket handoffs; collector "
                            "application ACK unavailable for Syslog transport",
                        )
            except OutboxFull as exc:
                self.last_error = str(exc)
                self.set_health(20, str(exc))
                self.emit(
                    "SIEM durable outbox is full; the EventBus cursor was not advanced.",
                    Severity.HIGH,
                    finding_code="siem.outbox.capacity_exhausted",
                    response_authorized=False,
                )
                try:
                    self._drain_outbox()
                except Exception as drain_exc:
                    self.last_error = f"{exc}; drain failed: {drain_exc}"
            except Exception as exc:
                self.last_error = str(exc)
                self.set_health(50, f"forwarder error: {exc}")
            self.sleep(self._POLL)

        if self._tcp is not None:
            try:
                self._tcp.close()
            except Exception:
                pass
        if self._outbox is not None:
            self._outbox.close()
            self._outbox = None

    def _enroll_cursor_once(self) -> int:
        """Seed only once so same-instance restarts capture stopped-time events."""
        if self._bus is not None and not self.bus_cursor_enrolled():
            return self.seed_bus_cursor()
        return self._bus_revision

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
