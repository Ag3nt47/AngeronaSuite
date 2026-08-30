"""Local-first threat-hunting normalization, anomaly reasoning, and graph views.

SentinelLens is deliberately a read-side control. It accepts bounded in-process
EventBus snapshots or explicit analyst imports of Syslog, Windows Event JSON,
and NetFlow JSON. It never opens a socket, executes a remediation, or sends
telemetry to a model provider. The GUI may hand its minimized narrative prompt
to Angerona's separately governed local-AI boundary after operator action.
"""
from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import math
import re
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import islice
from queue import Empty, Full, Queue
from types import SimpleNamespace
from typing import Any, Iterable

from angerona.core.causal_incident_graph import build_graph

MAX_IMPORT_BYTES = 64 * 1024
MAX_IMPORT_RECORDS = 5_000
MAX_BUNDLE_BYTES = 8 * 1024 * 1024
MAX_DETAIL_FIELDS = 64
MAX_DETAIL_BYTES = 32 * 1024
MAX_TEXT_CHARS = 4_096
MAX_JSON_DEPTH = 8
MAX_JSON_VALUES = MAX_IMPORT_RECORDS * (MAX_DETAIL_FIELDS + 2)
DEFAULT_SERVICE_QUEUE_CAPACITY = 1_024
MAX_SERVICE_QUEUE_CAPACITY = 16_384
DEFAULT_SERVICE_ANALYSIS_INTERVAL = 0.20

_SYSLOG = re.compile(
    r"^(?:<(?P<pri>[0-9]{1,3})>)?(?P<body>[^\r\n]+)$"
)
_WINDOWS_EVENT_IDS = {
    4624: "successful-logon",
    4625: "failed-logon",
    4688: "process-create",
    4697: "service-install",
    4720: "account-create",
    7045: "service-install",
}
_PROCESS_KEYS = ("Image", "NewProcessName", "ProcessName", "exe", "image")
_PARENT_KEYS = ("ParentImage", "ParentProcessName", "parent_image")
_PID_KEYS = ("ProcessId", "NewProcessId", "pid", "process_id")
_PPID_KEYS = ("ParentProcessId", "ppid", "parent_pid")


class SentinelLensInputError(ValueError):
    """A standardized log record was malformed or exceeded a safety bound."""


def _bounded_text(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    try:
        text = str(value or "")
    except Exception:
        text = f"<{type(value).__name__}>"
    text = text[:max(limit, limit * 4)]
    text = text.replace("\x00", "").replace("\r", " ").replace("\n", " ")
    return " ".join(text.split())[:limit]


def _first(mapping: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, ""):
            return value
    return None


def _positive_int(value: object) -> int | None:
    try:
        result = int(str(value), 0)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if 0 < result <= 2**31 - 1 else None


def _host_token(value: object) -> str:
    rendered = _bounded_text(value, 512).casefold()
    return hashlib.sha256(("sentinellens-host\0" + rendered).encode("utf-8")).hexdigest()


def _safe_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or len(value) > MAX_DETAIL_FIELDS:
        raise SentinelLensInputError("log detail object is invalid or too large")
    result: dict[str, Any] = {}
    for key, item in value.items():
        name = _bounded_text(key, 128)
        if not name:
            raise SentinelLensInputError("log detail key is empty")
        if name in result:
            raise SentinelLensInputError("log detail keys collide after normalization")
        if item is None or type(item) in (bool, int, float):
            if isinstance(item, float) and not math.isfinite(item):
                raise SentinelLensInputError("log detail contains a non-finite number")
            result[name] = item
        elif isinstance(item, str):
            result[name] = _bounded_text(item)
        elif isinstance(item, (list, tuple)):
            if len(item) > 32:
                raise SentinelLensInputError("log detail list is too large")
            result[name] = [_bounded_text(entry, 512) for entry in item]
        else:
            result[name] = _bounded_text(item)
    if len(json.dumps(
        result, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")) > MAX_DETAIL_BYTES:
        raise SentinelLensInputError("log detail object exceeds its byte bound")
    return result


@dataclass(frozen=True, slots=True)
class NormalizedHuntRecord:
    record_id: str
    source_format: str
    observed_at: float
    host_token: str
    kind: str
    severity: int
    message: str
    details: dict[str, Any]

    def as_event(self) -> SimpleNamespace:
        details = dict(self.details)
        details.update({
            "host_id": self.host_token,
            "sentinellens_record_id": self.record_id,
            "source_format": self.source_format,
        })
        return SimpleNamespace(
            module=f"SentinelLens/{self.source_format}",
            message=self.message,
            severity=self.severity,
            ts=self.observed_at,
            details=details,
            hmac_sig=self.record_id,
        )


def _record(
    source_format: str,
    observed_at: float,
    host: object,
    kind: str,
    severity: int,
    message: object,
    details: dict[str, Any],
) -> NormalizedHuntRecord:
    try:
        stamp = float(observed_at)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SentinelLensInputError("log observation time is invalid") from exc
    if not math.isfinite(stamp) or stamp <= 0:
        raise SentinelLensInputError("log observation time is invalid")
    bounded = _safe_mapping(details)
    token = _host_token(host)
    core = {
        "source_format": source_format,
        "observed_at": stamp,
        "host_token": token,
        "kind": kind,
        "severity": max(0, min(4, int(severity))),
        "message": _bounded_text(message),
        "details": bounded,
    }
    record_id = hashlib.sha256(json.dumps(
        core, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")).hexdigest()
    return NormalizedHuntRecord(record_id=record_id, **core)


def parse_syslog(payload: bytes, *, observed_at: float | None = None) -> NormalizedHuntRecord:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_IMPORT_BYTES:
        raise SentinelLensInputError("Syslog payload exceeds its byte bound")
    try:
        text = payload.decode("utf-8", "strict").strip()
    except UnicodeError as exc:
        raise SentinelLensInputError("Syslog payload is not UTF-8") from exc
    match = _SYSLOG.fullmatch(text)
    if not match:
        raise SentinelLensInputError("Syslog record is malformed or multiline")
    priority = int(match.group("pri") or 13)
    if not 0 <= priority <= 191:
        raise SentinelLensInputError("Syslog priority is invalid")
    body = match.group("body")
    # RFC 5424: VERSION TIMESTAMP HOST APP PROCID MSGID STRUCTURED-DATA MSG.
    fields = body.split(" ", 7)
    host = fields[2] if len(fields) >= 7 and fields[0].isdigit() else "unknown"
    app = fields[3] if len(fields) >= 7 and fields[0].isdigit() else "syslog"
    message = fields[7] if len(fields) == 8 else body
    severity = max(0, min(4, 4 - min(4, priority % 8 // 2)))
    return _record(
        "syslog",
        observed_at if observed_at is not None else time.time(),
        host,
        "log",
        severity,
        message,
        {"syslog_priority": priority, "source_app": app, "event_type": "syslog"},
    )


def parse_windows_event(
    payload: bytes, *, observed_at: float | None = None,
) -> NormalizedHuntRecord:
    value = _decode_json(payload, "Windows Event")
    system = value.get("System") or value.get("system") or {}
    if not isinstance(system, dict):
        system = {}
    raw_event_id = (
        value.get("EventID") or value.get("event_id") or value.get("eid")
        or system.get("EventID") or system.get("event_id")
    )
    if isinstance(raw_event_id, dict):
        raw_event_id = raw_event_id.get("#text") or raw_event_id.get("Value")
    event_id = _positive_int(raw_event_id)
    if event_id is None or event_id > 65_535:
        raise SentinelLensInputError("Windows Event ID is invalid")
    details = _windows_event_details(value.get("EventData") or value.get("details") or {})
    process = _bounded_text(_first(details, _PROCESS_KEYS), 1_024)
    parent = _bounded_text(_first(details, _PARENT_KEYS), 1_024)
    pid = _positive_int(_first(details, _PID_KEYS))
    ppid = _positive_int(_first(details, _PPID_KEYS))
    source_ip = _bounded_text(
        details.get("IpAddress") or details.get("SourceAddress")
        or details.get("source_ip"), 128
    )
    remote_ip = _bounded_text(
        details.get("DestinationIp") or details.get("DestAddress")
        or (source_ip if source_ip not in {"", "-", "::1", "127.0.0.1"} else ""),
        128,
    )
    standardized = {
        "eid": event_id,
        "event_type": _WINDOWS_EVENT_IDS.get(event_id, "windows-event"),
        "pid": pid,
        "ppid": ppid,
        "image": process,
        "parent_image": parent,
        "command_line": _bounded_text(
            details.get("CommandLine") or details.get("ProcessCommandLine"), 2_048
        ),
        "user": _bounded_text(
            details.get("TargetUserName") or details.get("SubjectUserName")
            or details.get("user"), 256
        ),
        "source_ip": source_ip,
        "remote_ip": remote_ip,
        "dest_port": _positive_int(
            details.get("DestinationPort") or details.get("DestPort")
        ),
        "path": _bounded_text(
            details.get("TargetFilename") or details.get("ObjectName")
            or details.get("TargetObject") or details.get("FileName"), 2_048
        ),
        "channel": _bounded_text(
            value.get("Channel") or value.get("channel") or system.get("Channel"), 256
        ),
    }
    normalized = {
        key: details[key]
        for key in sorted(details)
        if key not in standardized
    }
    normalized = dict(
        list(normalized.items())[:MAX_DETAIL_FIELDS - len(standardized)]
    )
    normalized.update(standardized)
    kind = "process" if event_id == 4688 else "auth" if event_id in {4624, 4625} else "log"
    severity = 3 if event_id in {4625, 4697, 4720, 7045} else 1
    return _record(
        "windows-event",
        observed_at if observed_at is not None else _timestamp(
            value.get("TimeCreated") or value.get("timestamp")
            or system.get("TimeCreated")
        ),
        value.get("Computer") or value.get("host") or system.get("Computer") or "unknown",
        kind,
        severity,
        value.get("Message") or f"Windows Event {event_id}: {normalized['event_type']}",
        normalized,
    )


def parse_netflow(payload: bytes, *, observed_at: float | None = None) -> NormalizedHuntRecord:
    value = _decode_json(payload, "NetFlow")
    source = _ip(value.get("src_ip") or value.get("source_ip"), "source")
    destination = _ip(value.get("dst_ip") or value.get("destination_ip"), "destination")
    src_port = _port(value.get("src_port") or value.get("source_port"), "source")
    dst_port = _port(value.get("dst_port") or value.get("destination_port"), "destination")
    protocol = _bounded_text(value.get("protocol") or "unknown", 16).lower()
    byte_count = _nonnegative_int(value.get("bytes"), "byte count")
    packet_count = _nonnegative_int(value.get("packets"), "packet count")
    details = {
        "event_type": "network_flow",
        "src_ip": source,
        "dest_ip": destination,
        "src_port": src_port,
        "dest_port": dst_port,
        "protocol": protocol,
        "bytes": byte_count,
        "packets": packet_count,
        "remote_ip": destination,
    }
    return _record(
        "netflow",
        observed_at if observed_at is not None else _timestamp(value.get("timestamp")),
        value.get("exporter") or value.get("host") or source,
        "network",
        2 if not ipaddress.ip_address(destination).is_private else 1,
        f"{protocol.upper()} flow {source}:{src_port} -> {destination}:{dst_port}",
        details,
    )


def _decode_json(payload: bytes, label: str) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_IMPORT_BYTES:
        raise SentinelLensInputError(f"{label} payload exceeds its byte bound")
    try:
        value = _json_loads(payload)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SentinelLensInputError(f"{label} payload is invalid JSON") from exc
    if not isinstance(value, dict) or len(value) > MAX_DETAIL_FIELDS:
        raise SentinelLensInputError(f"{label} document is invalid or too large")
    return value


def _json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    if len(pairs) > MAX_DETAIL_FIELDS:
        raise SentinelLensInputError("JSON object exceeds its field bound")
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SentinelLensInputError(f"JSON object contains duplicate key {key!r}")
        result[key] = value
    return result


def _json_loads(payload: bytes) -> Any:
    text = payload.decode("utf-8", "strict")

    def reject_constant(value: str) -> None:
        raise SentinelLensInputError(f"JSON contains non-finite constant {value}")

    value = json.loads(
        text,
        object_pairs_hook=_json_object,
        parse_constant=reject_constant,
    )
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen = 0
    while stack:
        item, depth = stack.pop()
        seen += 1
        if seen > MAX_JSON_VALUES or depth > MAX_JSON_DEPTH:
            raise SentinelLensInputError("JSON document exceeds its structure bound")
        if isinstance(item, dict):
            stack.extend((entry, depth + 1) for entry in item.values())
        elif isinstance(item, list):
            if depth and len(item) > MAX_DETAIL_FIELDS:
                raise SentinelLensInputError("nested JSON list exceeds its item bound")
            stack.extend((entry, depth + 1) for entry in item)
        elif isinstance(item, float) and not math.isfinite(item):
            raise SentinelLensInputError("JSON contains a non-finite number")
    return value


def _windows_event_details(value: object) -> dict[str, Any]:
    """Flatten common XML-to-JSON EventData without accepting an open-ended tree."""
    if not isinstance(value, dict):
        raise SentinelLensInputError("Windows EventData must be an object")
    flattened = {key: item for key, item in value.items() if key != "Data"}
    rows = value.get("Data")
    if rows is not None:
        if not isinstance(rows, list) or len(rows) > MAX_DETAIL_FIELDS:
            raise SentinelLensInputError("Windows EventData rows exceed their bound")
        for row in rows:
            if not isinstance(row, dict) or len(row) > 4:
                raise SentinelLensInputError("Windows EventData row is invalid")
            key = row.get("@Name") or row.get("Name") or row.get("name")
            item = row.get("#text") if "#text" in row else row.get("Value")
            name = _bounded_text(key, 128)
            if not name or name in flattened:
                raise SentinelLensInputError(
                    "Windows EventData row name is missing or duplicated"
                )
            flattened[name] = item
    return _safe_mapping(flattened)


def _timestamp(value: object) -> float:
    if isinstance(value, dict):
        value = value.get("SystemTime") or value.get("system_time") or value.get("#text")
    try:
        parsed = float(value)
    except (TypeError, ValueError, OverflowError):
        text = _bounded_text(value, 128)
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            moment = datetime.fromisoformat(text)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            parsed = moment.timestamp()
        except (ValueError, OverflowError, OSError):
            return time.time()
    return parsed if math.isfinite(parsed) and parsed > 0 else time.time()


def _ip(value: object, label: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError as exc:
        raise SentinelLensInputError(f"NetFlow {label} address is invalid") from exc


def _port(value: object, label: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SentinelLensInputError(f"NetFlow {label} port is invalid") from exc
    if not 0 <= result <= 65_535:
        raise SentinelLensInputError(f"NetFlow {label} port is invalid")
    return result


def _nonnegative_int(value: object, label: str) -> int:
    if value in (None, ""):
        return 0
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise SentinelLensInputError(f"NetFlow {label} is invalid") from exc
    if not 0 <= result <= 2**63 - 1:
        raise SentinelLensInputError(f"NetFlow {label} is invalid")
    return result


def _detect_json_format(value: dict[str, Any]) -> str:
    system = value.get("System") or value.get("system")
    if any(key in value for key in ("EventID", "event_id", "eid")) or (
        isinstance(system, dict)
        and any(key in system for key in ("EventID", "event_id"))
    ):
        return "windows-event"
    if (
        any(key in value for key in ("src_ip", "source_ip"))
        and any(key in value for key in ("dst_ip", "destination_ip"))
    ):
        return "netflow"
    raise SentinelLensInputError("JSON record is neither Windows Event nor NetFlow")


def parse_log_bundle(
    payload: bytes, *, source_format: str = "auto", suffix: str = ""
) -> tuple[NormalizedHuntRecord, ...]:
    """Parse one bounded, memory-only Syslog/Windows Event/NetFlow import.

    JSON may be one pretty-printed object, a bounded array, or JSON Lines. Auto
    detection is per record so a file cannot silently change a later record's
    parser contract.
    """
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_BUNDLE_BYTES:
        raise SentinelLensInputError("log bundle is empty or exceeds its byte bound")
    requested = _bounded_text(source_format, 32).casefold()
    if requested not in {"auto", "syslog", "windows-event", "netflow"}:
        raise SentinelLensInputError("unsupported import format")
    suffix = _bounded_text(suffix, 16).casefold()
    if requested == "auto" and suffix in {".log", ".txt"}:
        requested = "syslog"

    if requested == "syslog" or (
        requested == "auto" and payload.lstrip()[:1] not in {b"{", b"["}
    ):
        lines = [line for line in payload.splitlines() if line.strip()]
        if not lines or len(lines) > MAX_IMPORT_RECORDS:
            raise SentinelLensInputError("Syslog import record count is invalid")
        return tuple(parse_syslog(bytes(line)) for line in lines)

    documents: list[dict[str, Any]] = []
    try:
        decoded = _json_loads(payload)
    except (UnicodeError, ValueError, RecursionError):
        decoded = None
    if isinstance(decoded, dict):
        documents = [decoded]
    elif isinstance(decoded, list):
        if not decoded or len(decoded) > MAX_IMPORT_RECORDS:
            raise SentinelLensInputError("JSON import record count is invalid")
        if not all(isinstance(item, dict) for item in decoded):
            raise SentinelLensInputError("JSON import array must contain only objects")
        documents = decoded
    elif decoded is not None:
        raise SentinelLensInputError("JSON import must contain an object or object array")
    else:
        lines = [line for line in payload.splitlines() if line.strip()]
        if not lines or len(lines) > MAX_IMPORT_RECORDS:
            raise SentinelLensInputError("JSON Lines record count is invalid")
        for line in lines:
            if len(line) > MAX_IMPORT_BYTES:
                raise SentinelLensInputError("one import record exceeds its byte bound")
            documents.append(_decode_json(bytes(line), "log bundle"))

    records: list[NormalizedHuntRecord] = []
    parsers = {"windows-event": parse_windows_event, "netflow": parse_netflow}
    for value in documents:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        if len(encoded) > MAX_IMPORT_BYTES:
            raise SentinelLensInputError("one import record exceeds its byte bound")
        selected = _detect_json_format(value) if requested == "auto" else requested
        parser = parsers.get(selected)
        if parser is None:
            raise SentinelLensInputError("JSON cannot be parsed as Syslog")
        records.append(parser(encoded))
    if not records:
        raise SentinelLensInputError("import contains no records")
    return tuple(records)


@dataclass(frozen=True, slots=True)
class AnomalyFinding:
    finding_id: str
    rule_id: str
    score: int
    title: str
    reason: str
    event_id: str
    evidence: tuple[str, ...]
    remediation_proposals: tuple[str, ...]


def _event_value(event: Any) -> tuple[str, str, int, float, dict[str, Any], str]:
    details = getattr(event, "details", {})
    details = _safe_mapping(details) if isinstance(details, dict) else {}
    module = _bounded_text(getattr(event, "module", "Unknown"), 160)
    message = _bounded_text(getattr(event, "message", ""), 512)
    try:
        severity = max(0, min(4, int(getattr(event, "severity", 0))))
    except (TypeError, ValueError):
        severity = 0
    try:
        stamp = float(getattr(event, "ts", 0.0) or 0.0)
    except (TypeError, ValueError):
        stamp = 0.0
    if not math.isfinite(stamp) or stamp < 0:
        stamp = 0.0
    identity = _bounded_text(getattr(event, "hmac_sig", ""), 128).casefold()
    if not re.fullmatch(r"[0-9a-f]{64}", identity):
        identity = hashlib.sha256(json.dumps(
            [module, message, severity, stamp, details],
            sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")).hexdigest()
    return module, message, severity, stamp, details, identity


def analyze_events(events: Iterable[Any]) -> tuple[AnomalyFinding, ...]:
    findings: list[AnomalyFinding] = []
    auth_failures: dict[str, list[tuple[float, str]]] = {}
    office = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
    script = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
    lateral = {"wmiprvse.exe", "wsmprovhost.exe", "psexesvc.exe"}
    for event in events:
        module, message, severity, stamp, details, identity = _event_value(event)
        graph_event_id = f"EV:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"
        image = _bounded_text(_first(details, _PROCESS_KEYS), 1_024).replace("/", "\\").split("\\")[-1].casefold()
        parent = _bounded_text(_first(details, _PARENT_KEYS), 1_024).replace("/", "\\").split("\\")[-1].casefold()
        event_type = _bounded_text(details.get("event_type"), 80).casefold()
        candidates: list[tuple[str, int, str, str, tuple[str, ...]]] = []
        if image in script and parent in office:
            candidates.append((
                "SL-OFFICE-SCRIPT", 92, "Office application spawned a script host",
                f"{parent or 'office process'} created {image}; this uncommon parent/child relation can begin a multi-step execution chain.",
                (
                    "Capture the exact process tree and command line for analyst review.",
                    "If the process identity is still live, stage an exact-object suspend proposal in Adversary Combat.",
                    "Inspect related file and network nodes before considering containment.",
                ),
            ))
        if image in lateral or any(name in message.casefold() for name in lateral):
            candidates.append((
                "SL-LATERAL-TOOL", 84, "Possible remote-management/lateral-movement activity",
                f"Observed {image or 'a lateral-management marker'} in a process or log relationship; context is required before calling it malicious.",
                (
                    "Trace parent, authentication, and remote-endpoint evidence in this graph.",
                    "Review the account and source-host activity in the same time window.",
                    "Use a typed, review-gated network or process containment proposal only if identities corroborate.",
                ),
            ))
        remote = details.get("remote_ip") or details.get("dest_ip")
        if remote:
            try:
                public_remote = ipaddress.ip_address(str(remote)).is_global
            except ValueError:
                public_remote = False
            destination_port = _positive_int(details.get("dest_port") or details.get("remote_port"))
            if public_remote and destination_port not in {53, 80, 123, 443}:
                candidates.append((
                    "SL-UNCOMMON-EGRESS", 72, "Public outbound flow on an uncommon port",
                    f"A process or flow reached global address {remote} on port {destination_port or 'unknown'}; novelty is an anomaly, not proof of compromise.",
                    (
                        "Resolve the exact process birth identity and executable digest owning the flow.",
                        "Compare the endpoint with the approved network baseline and threat intelligence.",
                        "If corroborated, stage an exact remote-address block for review.",
                    ),
                ))
        if event_type in {"failed-logon", "authentication_failure"} or details.get("eid") == 4625:
            key = _bounded_text(details.get("user") or details.get("target_user") or module, 160)
            if stamp > 0:
                auth_failures.setdefault(key, []).append((stamp, graph_event_id))
        if severity >= 4 and not candidates:
            candidates.append((
                "SL-CRITICAL-SIGNAL", 65, "Critical sensor signal requires correlation",
                f"{module} emitted a critical signal. SentinelLens preserves it as a hunt lead without treating severity alone as causal proof.",
                (
                    "Open the source event and verify its exact evidence and health receipt.",
                    "Trace connected process, file, network, and technique nodes.",
                    "Stage remediation only through the typed response review workflow.",
                ),
            ))
        for rule, score, title, reason, proposals in candidates:
            finding_id = "SLF-" + hashlib.sha256(
                f"{rule}\0{identity}".encode("utf-8")
            ).hexdigest()[:20].upper()
            findings.append(AnomalyFinding(
                finding_id,
                rule,
                score,
                title,
                reason,
                graph_event_id,
                (graph_event_id,),
                proposals,
            ))
    for subject, rows in auth_failures.items():
        rows.sort()
        left = 0
        best: tuple[int, int] | None = None
        for right, (stamp, _event_id) in enumerate(rows):
            while stamp - rows[left][0] > 300.0:
                left += 1
            if right - left + 1 >= 5 and (
                best is None or right - left > best[1] - best[0]
            ):
                best = (left, right)
        if best is not None:
            window = rows[best[0]:best[1] + 1]
            evidence = tuple(row[1] for row in window[-32:])
            finding_id = "SLF-" + hashlib.sha256(
                ("SL-AUTH-BURST\0" + subject + "\0" + "".join(evidence)).encode("utf-8")
            ).hexdigest()[:20].upper()
            findings.append(AnomalyFinding(
                finding_id,
                "SL-AUTH-BURST",
                min(95, 60 + len(window) * 3),
                "Burst of failed authentication events",
                f"{len(window)} failures for the same bounded subject occurred within five minutes.",
                evidence[0],
                evidence,
                (
                    "Review source addresses, account state, and successful logons in the same window.",
                    "Confirm whether the pattern matches an approved scanner or user error.",
                    "Use the identity-aware account/network response workflow if corroborated.",
                ),
            ))
    unique = {finding.finding_id: finding for finding in findings}
    return tuple(sorted(unique.values(), key=lambda row: (-row.score, row.finding_id)))


def build_sentinel_snapshot(
    events: Iterable[Any], *, max_events: int = 2_000,
) -> dict[str, Any]:
    try:
        limit = max(1, min(MAX_IMPORT_RECORDS, int(max_events)))
    except (TypeError, ValueError, OverflowError) as exc:
        raise SentinelLensInputError("snapshot event bound is invalid") from exc
    sampled = list(islice(iter(events), limit + 1))
    source_truncated = len(sampled) > limit
    bounded: list[SimpleNamespace] = []
    rejected = 0
    for event in sampled[:limit]:
        try:
            module, message, severity, stamp, details, identity = _event_value(event)
            bounded.append(SimpleNamespace(
                module=module,
                message=message,
                severity=severity,
                ts=stamp,
                details=details,
                hmac_sig=identity,
            ))
        except (SentinelLensInputError, TypeError, ValueError, RecursionError):
            rejected += 1
    graph = build_graph(
        bounded,
        max_events=limit,
        max_nodes=limit * 3,
        max_edges=limit * 6,
    )
    anomalies = analyze_events(bounded)
    event_evidence: dict[str, dict[str, Any]] = {}
    for event in bounded:
        module = str(event.module)
        details = event.details
        identity = str(event.hmac_sig)
        event_id = f"EV:{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"
        event_evidence[event_id] = {
            "source_module": module,
            "source_format": details.get("source_format", "eventbus"),
            "evidence_identity_sha256": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
            "details": details,
        }
    for node in graph.get("nodes", ()):
        evidence = event_evidence.get(str(node.get("id")))
        if evidence:
            node["exact_evidence"] = evidence
    graph["sentinellens_schema"] = "angerona.sentinellens-snapshot.v1"
    graph["anomalies"] = [
        {
            "finding_id": item.finding_id,
            "rule_id": item.rule_id,
            "score": item.score,
            "title": item.title,
            "reason": item.reason,
            "event_id": item.event_id,
            "evidence": list(item.evidence),
            "remediation_proposals": list(item.remediation_proposals),
        }
        for item in anomalies
    ]
    graph["privacy"] = {
        "mode": "local-only",
        "external_model_calls": 0,
        "raw_telemetry_exported": False,
        "remediation_execution": False,
    }
    graph["stats"].update({
        "source_records_examined": min(len(sampled), limit),
        "source_truncated": source_truncated,
        "rejected_records": rejected,
    })
    return graph


class SentinelLensService:
    """App-owned, bounded background read model for local security telemetry.

    ``EventBus`` invokes subscribers inline.  Consequently, :meth:`submit_event`
    performs only a state check and ``Queue.put_nowait`` plus bounded accounting.
    Parsing, normalization, graph construction, and anomaly analysis stay on this
    service's dedicated Python thread.  Queue pressure drops only this additive
    read-model copy and is reported explicitly; it never delays a sensor or
    authorizes remediation.

    The standardized payload methods are deliberately in-process.  SentinelLens
    owns no socket, listener, subprocess, or cloud client.  Invalid record content
    is rejected by the worker and counted without killing the analysis loop.
    """

    def __init__(
        self,
        bus: Any = None,
        *,
        queue_capacity: int = DEFAULT_SERVICE_QUEUE_CAPACITY,
        max_events: int = 2_000,
        analysis_interval: float = DEFAULT_SERVICE_ANALYSIS_INTERVAL,
        batch_size: int = 128,
    ) -> None:
        try:
            capacity = int(queue_capacity)
            event_limit = int(max_events)
            interval = float(analysis_interval)
            bounded_batch = int(batch_size)
        except (TypeError, ValueError, OverflowError) as exc:
            raise SentinelLensInputError("service bounds are invalid") from exc
        if not 1 <= capacity <= MAX_SERVICE_QUEUE_CAPACITY:
            raise SentinelLensInputError("service queue capacity is invalid")
        if not 1 <= event_limit <= MAX_IMPORT_RECORDS:
            raise SentinelLensInputError("service event capacity is invalid")
        if not 0.01 <= interval <= 10.0:
            raise SentinelLensInputError("service analysis interval is invalid")
        if not 1 <= bounded_batch <= 1_024:
            raise SentinelLensInputError("service batch size is invalid")

        self._bus = bus
        self._queue: Queue[tuple[str, object]] = Queue(maxsize=capacity)
        self._queue_capacity = capacity
        self._max_events = event_limit
        self._analysis_interval = interval
        self._batch_size = bounded_batch
        self._records: deque[SimpleNamespace] = deque(maxlen=event_limit)
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._stop_requested = threading.Event()
        self._thread: threading.Thread | None = None
        self._subscribed = False
        self._accepting = False
        self._state = "created"
        self._snapshot = build_sentinel_snapshot((), max_events=event_limit)
        self._snapshot_revision = 0
        self._submitted = 0
        self._accepted = 0
        self._queue_dropped = 0
        self._stopped_rejections = 0
        self._admission_rejections = 0
        self._analysis_rejections = 0
        self._processed_records = 0
        self._analyses_completed = 0
        self._analysis_failures = 0
        self._last_analysis_at = 0.0
        self._last_error_type = ""
        self._clean_shutdown = False
        self._accepted_by_source = {
            "eventbus": 0,
            "syslog": 0,
            "windows-event": 0,
            "netflow": 0,
            "normalized": 0,
        }

    def start(self) -> bool:
        """Start once and subscribe the non-blocking handoff to ``EventBus``."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            if self._state in {"stopping", "stopped"}:
                raise RuntimeError("a stopped SentinelLens service cannot be restarted")
            self._accepting = True
            self._state = "running"
            worker = threading.Thread(
                target=self._run,
                name="angerona-sentinellens",
                daemon=True,
            )
            self._thread = worker
            bus = self._bus
            if bus is not None and not self._subscribed:
                subscribe = getattr(bus, "subscribe", None)
                if not callable(subscribe):
                    self._accepting = False
                    self._state = "created"
                    self._thread = None
                    raise TypeError("SentinelLens EventBus does not support subscriptions")
                subscribe(self.submit_event, delivery_budget_ms=2.0)
                self._subscribed = True
            worker.start()
            return True

    def _admission_error(self, message: str) -> SentinelLensInputError:
        with self._lock:
            self._admission_rejections += 1
        return SentinelLensInputError(message)

    def _bounded_payload(self, payload: bytes, label: str) -> bytes:
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_IMPORT_BYTES:
            raise self._admission_error(f"{label} payload exceeds its byte bound")
        return payload

    def _enqueue(self, source: str, payload: object) -> bool:
        # Do not acquire a condition, wait for capacity, parse, copy an open-ended
        # object, or perform I/O here.  This method is the EventBus hot-path gate.
        if not self._accepting:
            with self._lock:
                self._submitted += 1
                self._stopped_rejections += 1
            return False
        try:
            self._queue.put_nowait((source, payload))
        except Full:
            with self._lock:
                self._submitted += 1
                self._queue_dropped += 1
            return False
        with self._lock:
            self._submitted += 1
            self._accepted += 1
            self._accepted_by_source[source] += 1
        return True

    def submit_event(self, event: object) -> bool:
        """Offer one EventBus event without parsing or blocking its publisher."""
        return self._enqueue("eventbus", event)

    def submit_syslog(self, payload: bytes) -> bool:
        """Offer one bounded Syslog record from an in-process integration."""
        return self._enqueue("syslog", self._bounded_payload(payload, "Syslog"))

    def submit_windows_event(self, payload: bytes) -> bool:
        """Offer one bounded Windows Event JSON record in-process."""
        return self._enqueue(
            "windows-event", self._bounded_payload(payload, "Windows Event")
        )

    def submit_netflow(self, payload: bytes) -> bool:
        """Offer one bounded NetFlow JSON record in-process."""
        return self._enqueue("netflow", self._bounded_payload(payload, "NetFlow"))

    def submit_record(self, record: NormalizedHuntRecord) -> bool:
        """Offer one already-normalized record without granting response authority."""
        if not isinstance(record, NormalizedHuntRecord):
            raise self._admission_error("normalized SentinelLens record is invalid")
        return self._enqueue("normalized", record)

    @staticmethod
    def _normalize_queued(source: str, payload: object) -> SimpleNamespace:
        if source == "syslog":
            event = parse_syslog(payload).as_event()  # type: ignore[arg-type]
        elif source == "windows-event":
            event = parse_windows_event(payload).as_event()  # type: ignore[arg-type]
        elif source == "netflow":
            event = parse_netflow(payload).as_event()  # type: ignore[arg-type]
        elif source == "normalized":
            if not isinstance(payload, NormalizedHuntRecord):
                raise SentinelLensInputError("normalized SentinelLens record is invalid")
            event = payload.as_event()
        elif source == "eventbus":
            event = payload
        else:
            raise SentinelLensInputError("SentinelLens queue source is invalid")
        module, message, severity, stamp, details, identity = _event_value(event)
        return SimpleNamespace(
            module=module,
            message=message,
            severity=severity,
            ts=stamp,
            details=details,
            hmac_sig=identity,
        )

    def _consume(self, source: str, payload: object) -> bool:
        try:
            event = self._normalize_queued(source, payload)
        except (SentinelLensInputError, TypeError, ValueError, RecursionError) as exc:
            with self._lock:
                self._analysis_rejections += 1
                self._last_error_type = type(exc).__name__[:120]
            return False
        with self._lock:
            self._records.append(event)
            self._processed_records += 1
        return True

    def _analyze(self) -> None:
        with self._lock:
            # Mirror EventBus.recent(): newest evidence first.  The graph builder
            # independently sorts facts by timestamp and identity.
            events = list(reversed(self._records))
        try:
            snapshot = build_sentinel_snapshot(events, max_events=self._max_events)
        except Exception as exc:
            with self._changed:
                self._analysis_failures += 1
                self._last_error_type = type(exc).__name__[:120]
                self._state = "degraded" if self._accepting else self._state
                self._changed.notify_all()
            return
        with self._changed:
            self._snapshot = snapshot
            self._snapshot_revision += 1
            self._analyses_completed += 1
            self._last_analysis_at = time.time()
            self._last_error_type = ""
            if self._accepting:
                self._state = "running"
            self._changed.notify_all()

    def _run(self) -> None:
        dirty = False
        last_analysis = time.monotonic()
        try:
            while True:
                if self._stop_requested.is_set() and self._queue.empty():
                    break
                try:
                    source, payload = self._queue.get(timeout=0.05)
                except Empty:
                    if dirty and time.monotonic() - last_analysis >= self._analysis_interval:
                        self._analyze()
                        dirty = False
                        last_analysis = time.monotonic()
                    continue

                processed = 0
                while True:
                    try:
                        dirty = self._consume(source, payload) or dirty
                    finally:
                        self._queue.task_done()
                    processed += 1
                    if processed >= self._batch_size:
                        break
                    try:
                        source, payload = self._queue.get_nowait()
                    except Empty:
                        break

                if dirty and (
                    self._queue.empty()
                    or time.monotonic() - last_analysis >= self._analysis_interval
                    or self._stop_requested.is_set()
                ):
                    self._analyze()
                    dirty = False
                    last_analysis = time.monotonic()
            if dirty:
                self._analyze()
        finally:
            with self._changed:
                self._accepting = False
                self._clean_shutdown = self._queue.empty()
                self._state = "stopped"
                self._changed.notify_all()

    def revision(self) -> int:
        """Return the monotonic completed-analysis revision."""
        with self._lock:
            return self._snapshot_revision

    def wait_for_revision(self, revision: int = 0, timeout: float = 2.0) -> bool:
        """Wait only for tests/controllers that explicitly need analysis freshness."""
        try:
            target = int(revision)
            bounded_timeout = max(0.0, min(30.0, float(timeout)))
        except (TypeError, ValueError, OverflowError) as exc:
            raise SentinelLensInputError("service wait bound is invalid") from exc
        with self._changed:
            return self._changed.wait_for(
                lambda: self._snapshot_revision > target
                or self._state == "stopped",
                timeout=bounded_timeout,
            ) and self._snapshot_revision > target

    def recent_events(self, limit: int = 2_000) -> list[SimpleNamespace]:
        """Return a bounded defensive copy for mixed live/import UI snapshots."""
        try:
            bounded = max(0, min(self._max_events, int(limit)))
        except (TypeError, ValueError, OverflowError) as exc:
            raise SentinelLensInputError("service recent-event bound is invalid") from exc
        with self._lock:
            rows = list(islice(reversed(self._records), bounded))
        return [SimpleNamespace(
            module=row.module,
            message=row.message,
            severity=row.severity,
            ts=row.ts,
            details=copy.deepcopy(row.details),
            hmac_sig=row.hmac_sig,
        ) for row in rows]

    def health(self) -> dict[str, Any]:
        """Return bounded queue, loss, analysis, and lifecycle evidence."""
        with self._lock:
            state = self._state
            return {
                "state": state,
                "accepting": self._accepting,
                "callback_contract": "bounded-put_nowait-only",
                "queue_depth": min(self._queue.qsize(), self._queue_capacity),
                "queue_capacity": self._queue_capacity,
                "submitted": self._submitted,
                "accepted": self._accepted,
                "queue_dropped": self._queue_dropped,
                "stopped_rejections": self._stopped_rejections,
                "admission_rejections": self._admission_rejections,
                "analysis_rejections": self._analysis_rejections,
                "processed_records": self._processed_records,
                "retained_events": len(self._records),
                "retained_capacity": self._max_events,
                "analyses_completed": self._analyses_completed,
                "analysis_failures": self._analysis_failures,
                "snapshot_revision": self._snapshot_revision,
                "last_analysis_at": self._last_analysis_at,
                "last_error_type": self._last_error_type,
                "clean_shutdown": self._clean_shutdown,
                "accepted_by_source": dict(self._accepted_by_source),
                "network_listener": False,
                "remediation_execution": False,
            }

    def snapshot(self) -> dict[str, Any]:
        """Return one immutable-by-convention snapshot copy plus current health."""
        with self._lock:
            snapshot = self._snapshot
        result = copy.deepcopy(snapshot)
        result["service_health"] = self.health()
        return result

    def stop(self, timeout: float = 3.0) -> bool:
        """Stop accepting, drain the bounded queue, and join within ``timeout``."""
        try:
            bounded_timeout = max(0.0, min(30.0, float(timeout)))
        except (TypeError, ValueError, OverflowError) as exc:
            raise SentinelLensInputError("service shutdown timeout is invalid") from exc
        with self._changed:
            thread = self._thread
            self._accepting = False
            if thread is None or not thread.is_alive():
                self._state = "stopped"
                self._clean_shutdown = self._queue.empty()
                self._changed.notify_all()
                return True
            self._state = "stopping"
            self._stop_requested.set()
            self._changed.notify_all()
        thread.join(bounded_timeout)
        stopped = not thread.is_alive()
        if not stopped:
            with self._lock:
                self._state = "stop-timeout"
                self._clean_shutdown = False
        return stopped


def render_narrative(snapshot: dict[str, Any], node_id: str) -> str:
    nodes = {str(row.get("id")): row for row in snapshot.get("nodes", ())}
    node = nodes.get(str(node_id))
    if node is None:
        return "The selected graph node is no longer present in the bounded snapshot."
    incoming = [row for row in snapshot.get("edges", ()) if row.get("target") == node_id]
    outgoing = [row for row in snapshot.get("edges", ()) if row.get("source") == node_id]
    related_ids = {str(node_id)}
    for edge in incoming + outgoing:
        related_ids.add(str(edge.get("source") or ""))
        related_ids.add(str(edge.get("target") or ""))
    anomalies = [
        row for row in snapshot.get("anomalies", ())
        if str(row.get("event_id") or "") in related_ids
        or related_ids.intersection(str(value) for value in row.get("evidence", ()))
    ]
    lines = [
        f"Selected {node.get('kind', 'node')}: {node.get('label') or node.get('message') or node_id}",
        f"Observed {node.get('first_ts', 0)} through {node.get('last_ts', 0)}.",
        f"Graph context: {len(incoming)} incoming and {len(outgoing)} outgoing explained relation(s).",
    ]
    for edge in incoming[:8] + outgoing[:8]:
        source = nodes.get(str(edge.get("source") or ""), {})
        target = nodes.get(str(edge.get("target") or ""), {})
        lines.append(
            f"- {source.get('label', edge.get('source'))} -> "
            f"{target.get('label', edge.get('target'))} [{edge.get('relation')}]: "
            f"{edge.get('basis')} "
            f"(confidence {float(edge.get('confidence', 0.0)):.2f})"
        )
    exact = node.get("exact_evidence")
    if isinstance(exact, dict):
        lines.append("Exact local evidence:")
        details = exact.get("details") if isinstance(exact.get("details"), dict) else {}
        for key in sorted(details)[:MAX_DETAIL_FIELDS]:
            lines.append(f"- {key}: {_bounded_text(details[key], 512)}")
    if anomalies:
        lines.append("Anomaly reasoning:")
        for finding in anomalies[:8]:
            lines.append(
                f"- {finding.get('title')} [{finding.get('score')}]: {finding.get('reason')}"
            )
    else:
        lines.append(
            "No deterministic SentinelLens anomaly rule selected this node; graph proximity alone is not labeled malicious."
        )
    lines.append(
        "Remediation remains proposal-only. Review exact identities and source evidence before applying any host change."
    )
    return "\n".join(lines)


__all__ = [
    "AnomalyFinding",
    "MAX_BUNDLE_BYTES",
    "MAX_IMPORT_BYTES",
    "MAX_IMPORT_RECORDS",
    "NormalizedHuntRecord",
    "SentinelLensInputError",
    "SentinelLensService",
    "analyze_events",
    "build_sentinel_snapshot",
    "parse_netflow",
    "parse_log_bundle",
    "parse_syslog",
    "parse_windows_event",
    "render_narrative",
]
