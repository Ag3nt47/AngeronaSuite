"""Safe local interoperability with established defensive security tools.

This module closes useful integration gaps without turning Angerona into a
remote shell or a packet sniffer.  It accepts bounded, explicitly selected
local JSON/JSONL exports from NDR tools and can run a small catalog of fixed,
read-only osquery snapshots when a system installation is present.

Arbitrary SQL, commands, network destinations, extension loading and automatic
tool installation are intentionally outside this boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
# External execution is restricted below to fixed install locations and queries.
import subprocess  # nosec B404
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from angerona.core.community_id import community_id_v1
from angerona.core.evidence_store import EvidenceEnvelope, EvidenceStore
from angerona.core.privacy import redact_text

MAX_IMPORT_BYTES = 32 * 1024 * 1024
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024
MAX_SCAN_LINES = 5_000
MAX_IMPORT_RECORDS = 1_000
MAX_OSQUERY_OUTPUT = 4 * 1024 * 1024

_FORMATS = frozenset({"suricata-eve", "zeek-json", "ocsf-json", "generic-json"})
_REMOTE_FILESYSTEMS = frozenset(
    {"9p", "afpfs", "cifs", "fuse.sshfs", "nfs", "nfs4", "smbfs", "sshfs"}
)
_LEVELS = frozenset({
    "operational", "integrated", "preview", "foundation", "external-gate",
})


@dataclass(frozen=True)
class CapabilityParity:
    """One honest capability comparison, never an unqualified parity claim."""

    domain: str
    level: str
    angerona: str
    reference_projects: tuple[str, ...]
    boundary: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.level not in _LEVELS:
            raise ValueError("invalid capability parity level")
        if not all((self.domain, self.angerona, self.boundary)):
            raise ValueError("capability parity text must not be empty")
        if not self.reference_projects or not self.evidence:
            raise ValueError("capability parity requires references and evidence")


CAPABILITY_PARITY = (
    CapabilityParity(
        "Endpoint telemetry and detection", "operational",
        "Process, memory, persistence, file, network and integrity sensors with local correlation.",
        ("Wazuh", "osquery/Fleet", "Security Onion"),
        "User-space visibility; privileged kernel telemetry remains a separately signed platform gate.",
        ("modules/", "engines/unified_edr.py", "core/evidence_store.py"),
    ),
    CapabilityParity(
        "Endpoint live query", "integrated",
        "Fixed read-only osquery snapshots plus Angerona's bounded local hunt tables.",
        ("osquery/Fleet", "Security Onion"),
        "No arbitrary SQL, remote shell, extension loading or automatic osquery installation.",
        ("core/security_interop.py", "core/commands.py"),
    ),
    CapabilityParity(
        "Network detection and response", "integrated",
        "Native network sensors plus bounded Suricata EVE, Zeek JSON and OCSF evidence import.",
        ("Security Onion", "Wazuh"),
        "Imports local evidence; full packet capture and distributed sensor storage require dedicated tools.",
        ("core/security_interop.py", "engines/sniffer.py", "core/ocsf_export.py"),
    ),
    CapabilityParity(
        "Threat hunting and DFIR collection", "preview",
        "Structured evidence hunts, registered artifact collections, signed receipts and hunt workspaces.",
        ("Velociraptor", "Security Onion", "osquery/Fleet"),
        "Fleet distribution is local-preview until production transport and endpoint enrollment are deployed.",
        ("core/fleet_hunts.py", "core/hunt_workspace.py", "core/hunt_operations.py"),
    ),
    CapabilityParity(
        "Cases, evidence and analyst workflow", "operational",
        "Local cases, timelines, custody verification, sanitized exports and append-only admin audit.",
        ("TheHive", "Security Onion"),
        "Single-operator local workflow; real-time multi-analyst tenancy requires external identity and services.",
        ("core/case_management.py", "core/operations_center.py", "gui/operations_center.py"),
    ),
    CapabilityParity(
        "Adversary emulation and purple testing", "operational",
        "Reversible marker-based ATT&CK drills, detection scorecards and proof-carrying remediation.",
        ("MITRE CALDERA",),
        "Deliberately non-exploitative: no credential theft, payload execution, C2 or destructive actions.",
        ("shark/", "core/drill_resolution.py", "core/purple_loop.py"),
    ),
    CapabilityParity(
        "Detection engineering", "operational",
        "Sigma subset, YARA-X integration, ATT&CK/D3FEND coverage and signed staged content lifecycle.",
        ("Security Onion", "Wazuh"),
        "Third-party content needs fixtures, performance budgets and trusted signatures before activation.",
        ("core/sigma_engine.py", "modules/yara_scanner.py", "core/detection_registry.py"),
    ),
    CapabilityParity(
        "Threat intelligence and interoperability", "foundation",
        "OCSF, STIX 2.1 and OTLP envelopes with privacy review, signed queues and local intelligence sync.",
        ("MISP", "TheHive", "Security Onion"),
        "External feeds and delivery remain explicit opt-ins with destination and egress approval.",
        ("core/interop_gateway.py", "core/ocsf_export.py", "modules/intel_sync.py"),
    ),
    CapabilityParity(
        "Vulnerability and exposure management", "foundation",
        "Local vulnerability inventory, CVE guidance, risk exceptions and remediation evidence.",
        ("Wazuh", "Fleet"),
        "Authoritative current vulnerability intelligence requires a reviewed feed and update policy.",
        ("core/cve_fix_advisor.py", "core/cve_ignore.py", "core/exposure_management.py"),
    ),
    CapabilityParity(
        "Fleet policy, identity and response", "preview",
        "Signed endpoint identity, scoped RBAC, staged policy, bounded ingestion and safe response sessions.",
        ("Wazuh", "Velociraptor", "Fleet"),
        "Loopback preview only; production mTLS, OIDC, hardware-backed keys and distributed control are gates.",
        ("core/fleet_control_plane.py", "core/fleet_service.py", "core/safe_response_session.py"),
    ),
    CapabilityParity(
        "Cross-platform endpoint support", "preview",
        "Explicit Windows, macOS and Linux capability contracts with platform-native observe sensors.",
        ("Wazuh", "osquery/Fleet", "Velociraptor"),
        "Feature depth differs by OS and is reported honestly; signing/notarization and compatibility labs remain.",
        ("core/platforms.py", "modules/macos_observe.py", "modules/linux_observe.py"),
    ),
    CapabilityParity(
        "Enterprise scale and availability", "external-gate",
        "Bounded local primitives, recovery tooling, release evidence and deployment contracts are present.",
        ("Wazuh", "Security Onion", "TheHive"),
        "HA search, multi-tenant services, SSO, independent DR, signing custody and soak evidence need infrastructure.",
        ("core/enterprise_readiness.py", "core/backup_restore.py", "core/release_evidence.py"),
    ),
)


@dataclass(frozen=True)
class EvidenceImportResult:
    format: str
    file_sha256: str
    imported: int
    duplicates: int
    skipped: int
    scanned: int
    truncated: bool


@dataclass(frozen=True)
class OsqueryTemplate:
    template_id: str
    name: str
    query: str
    columns: tuple[str, ...]
    platforms: tuple[str, ...] = ("Windows", "Darwin", "Linux")


OSQUERY_TEMPLATES = {
    item.template_id: item for item in (
        OsqueryTemplate(
            "processes", "Running processes",
            "SELECT pid, parent, name, path FROM processes LIMIT 500;",
            ("pid", "parent", "name", "path"),
        ),
        OsqueryTemplate(
            "listening-ports", "Listening ports",
            "SELECT pid, protocol, local_address, local_port FROM listening_ports LIMIT 500;",
            ("pid", "protocol", "local_address", "local_port"),
        ),
        OsqueryTemplate(
            "interfaces", "Network interfaces",
            "SELECT interface, address, mask, type FROM interface_addresses LIMIT 500;",
            ("interface", "address", "mask", "type"),
        ),
        OsqueryTemplate(
            "kernel-modules", "Loaded kernel modules",
            "SELECT name, size, used_by, status FROM kernel_modules LIMIT 500;",
            ("name", "size", "used_by", "status"),
            ("Linux",),
        ),
    )
}


def parity_summary() -> dict[str, Any]:
    counts = {level: 0 for level in sorted(_LEVELS)}
    for row in CAPABILITY_PARITY:
        counts[row.level] += 1
    return {
        "schema": "angerona.capability-parity/v1",
        "unqualified_parity_claim": False,
        "domains": len(CAPABILITY_PARITY),
        "counts": counts,
        "rows": tuple(asdict(row) for row in CAPABILITY_PARITY),
    }


def _is_reparse_or_link(path: Path) -> bool:
    try:
        attributes = int(getattr(path.lstat(), "st_file_attributes", 0))
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        return path.is_symlink() or bool(attributes & reparse)
    except OSError:
        return True


def _traverses_link(path: Path) -> bool:
    absolute = Path(os.path.abspath(os.fspath(path.expanduser())))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        if current.exists() and _is_reparse_or_link(current):
            return True
    return False


def _remote_mount(path: Path) -> bool:
    try:
        import psutil

        best: tuple[int, str, str] | None = None
        for mount in psutil.disk_partitions(all=True)[:256]:
            point = Path(str(mount.mountpoint)).resolve(strict=True)
            try:
                path.relative_to(point)
            except ValueError:
                continue
            candidate = (len(point.parts), str(mount.fstype).casefold(), str(mount.device))
            if best is None or candidate[0] > best[0]:
                best = candidate
        return bool(
            best
            and (best[1] in _REMOTE_FILESYSTEMS or best[2].startswith(("//", "\\\\")))
        )
    except (ImportError, OSError, RuntimeError):
        return False


def _regular_local_file(path: Path, *, expected_names: Sequence[str] = ()) -> Path:
    raw = str(path)
    if not raw or "\x00" in raw or raw.startswith(("\\\\", "//")):
        raise ValueError("network paths are outside the local interoperability boundary")
    if _traverses_link(Path(path)):
        raise ValueError("links and reparse points are not accepted")
    resolved = Path(path).expanduser().resolve(strict=True)
    if expected_names and resolved.name.casefold() not in {
        name.casefold() for name in expected_names
    }:
        raise ValueError("unexpected executable name")
    info = resolved.stat()
    if _is_reparse_or_link(resolved):
        raise ValueError("links and reparse points are not accepted")
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("a regular local file is required")
    if _remote_mount(resolved):
        raise ValueError("network-mounted files are outside the local interoperability boundary")
    if os.name != "nt" and expected_names:
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PermissionError("osqueryi must be root-owned and not group/world writable")
    return resolved


def _text(value: object, maximum: int = 1024) -> str:
    return str(value or "")[:maximum]


def _timestamp(value: object) -> float:
    if isinstance(value, (int, float)):
        return max(0.0, float(value))
    text = _text(value, 80).strip()
    if not text:
        return time.time()
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return max(0.0, parsed.timestamp())
    except (OverflowError, ValueError):
        return time.time()


def _event_id(kind: str, payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return "ext-" + kind[:16] + "-" + hashlib.sha256(encoded).hexdigest()[:32]


def _suricata(record: Mapping[str, Any]) -> EvidenceEnvelope:
    alert = record.get("alert") if isinstance(record.get("alert"), Mapping) else {}
    event_type = _text(record.get("event_type") or "event", 80)
    raw_severity = alert.get("severity", 4)
    try:
        severity = {1: 4, 2: 3, 3: 2}.get(int(raw_severity), 1) if alert else 1
    except (TypeError, ValueError):
        severity = 1
    signature = redact_text(alert.get("signature") or event_type, limit=500)
    attributes = {
        key: record[key] for key in (
            "app_proto", "community_id", "dest_port", "flow_id", "proto", "src_port"
        ) if key in record and isinstance(record[key], (str, int, float, bool))
    }
    for source, target in (("signature_id", "signature_id"), ("category", "alert_category")):
        if source in alert:
            attributes[target] = _text(alert[source], 300)
    subject = {
        "kind": "network_flow",
        "id": _text(record.get("community_id") or record.get("flow_id") or "flow", 256),
    }
    for key in ("src_ip", "dest_ip"):
        if key in record:
            subject[key] = _text(record[key], 128)
    core = {
        "timestamp": record.get("timestamp"), "event_type": event_type,
        "subject": subject, "attributes": attributes, "signature": signature,
    }
    return EvidenceEnvelope(
        event_id=_event_id("suricata", core), observed_at=_timestamp(record.get("timestamp")),
        category="network_detection" if alert else "network_activity",
        activity=event_type, severity=severity,
        message=f"Suricata {event_type}: {signature}", module="Suricata Import",
        subject=subject, attributes=attributes,
        provenance={"kind": "suricata_eve", "imported_local_file": True},
    )


def _zeek(record: Mapping[str, Any]) -> EvidenceEnvelope:
    log_type = _text(record.get("_path") or record.get("path") or "event", 80)
    attributes: dict[str, Any] = {}
    for key in (
        "uid", "proto", "service", "duration", "conn_state", "orig_bytes",
        "resp_bytes", "id.orig_p", "id.resp_p", "note",
    ):
        if key in record and isinstance(record[key], (str, int, float, bool)):
            attributes[key] = record[key]
    origin = record.get("id.orig_h")
    response = record.get("id.resp_h")
    community_id = community_id_v1(
        origin,
        response,
        record.get("id.orig_p"),
        record.get("id.resp_p"),
        record.get("proto"),
    )
    if community_id:
        attributes["community_id"] = community_id
    subject = {
        "kind": "network_flow",
        "id": _text(
            community_id
            or record.get("uid")
            or f"{origin or 'unknown'}->{response or 'unknown'}",
            256,
        ),
    }
    if origin is not None:
        subject["src_ip"] = _text(origin, 128)
    if response is not None:
        subject["dest_ip"] = _text(response, 128)
    message = f"Zeek {log_type} observation"
    if log_type == "notice" and record.get("note"):
        message += ": " + redact_text(record["note"], limit=400)
    core = {
        "timestamp": record.get("ts"), "log_type": log_type,
        "subject": subject, "attributes": attributes,
    }
    return EvidenceEnvelope(
        event_id=_event_id("zeek", core), observed_at=_timestamp(record.get("ts")),
        category="network_detection" if log_type == "notice" else "network_activity",
        activity=log_type, severity=3 if log_type == "notice" else 1,
        message=message, module="Zeek Import", subject=subject, attributes=attributes,
        provenance={"kind": "zeek_json", "imported_local_file": True},
    )


def _ocsf(record: Mapping[str, Any]) -> EvidenceEnvelope:
    try:
        severity = max(0, min(4, int(record.get("severity_id", 1)) - 1))
    except (TypeError, ValueError):
        severity = 1
    activity = _text(record.get("activity_name") or record.get("activity_id") or "finding", 80)
    category = _text(record.get("class_name") or "security_finding", 80)
    message = redact_text(record.get("message") or record.get("title") or category, limit=1000)
    metadata = record.get("metadata") if isinstance(record.get("metadata"), Mapping) else {}
    attributes = {
        "class_uid": _text(record.get("class_uid"), 80),
        "category_uid": _text(record.get("category_uid"), 80),
        "product": _text(metadata.get("product", "external OCSF"), 200),
    }
    core = {
        "time": record.get("time") or record.get("time_dt"),
        "activity": activity, "category": category, "message": message,
        "attributes": attributes,
    }
    return EvidenceEnvelope(
        event_id=_event_id("ocsf", core),
        observed_at=_timestamp(record.get("time") or record.get("time_dt")),
        category=category, activity=activity, severity=severity,
        message=message, module="OCSF Import", attributes=attributes,
        provenance={"kind": "ocsf_json", "imported_local_file": True},
    )


def _generic(record: Mapping[str, Any]) -> EvidenceEnvelope:
    module = _text(record.get("module") or record.get("source") or "External JSON", 200)
    message = redact_text(record.get("message") or record.get("event") or "Imported event", limit=1000)
    try:
        severity = max(0, min(4, int(record.get("severity", 1))))
    except (TypeError, ValueError):
        severity = 1
    attributes = {
        key: record[key] for key in ("event_type", "category", "action", "status")
        if key in record and isinstance(record[key], (str, int, float, bool))
    }
    core = {
        "time": record.get("timestamp") or record.get("time"), "module": module,
        "message": message, "attributes": attributes,
    }
    return EvidenceEnvelope(
        event_id=_event_id("generic", core),
        observed_at=_timestamp(record.get("timestamp") or record.get("time")),
        category=_text(record.get("category") or "external_event", 80),
        activity=_text(record.get("event_type") or record.get("action") or "observe", 80),
        severity=severity, message=message, module=module, attributes=attributes,
        provenance={"kind": "generic_json", "imported_local_file": True},
    )


_PARSERS = {
    "suricata-eve": _suricata,
    "zeek-json": _zeek,
    "ocsf-json": _ocsf,
    "generic-json": _generic,
}


def import_json_evidence(
    path: Path, format_name: str, store: EvidenceStore,
) -> EvidenceImportResult:
    """Validate then atomically append at most 1,000 local evidence records."""
    if format_name not in _FORMATS:
        raise ValueError("unsupported security evidence format")
    if not store.local_only:
        raise ValueError("security evidence import requires a local-only store")
    source = _regular_local_file(Path(path))
    if source.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError("security evidence file exceeds the 32 MiB import budget")
    with source.open("rb") as stream:
        data = stream.read(MAX_IMPORT_BYTES + 1)
    if len(data) > MAX_IMPORT_BYTES:
        raise ValueError("security evidence file grew beyond the 32 MiB import budget")
    digest = hashlib.sha256(data).hexdigest()
    records: list[EvidenceEnvelope] = []
    skipped = scanned = 0
    truncated = False
    parser = _PARSERS[format_name]
    lines = data.splitlines()
    decoded_records: list[Mapping[str, Any]] | None = None
    try:
        if len(data) > MAX_DOCUMENT_BYTES:
            raise ValueError("large imports must use JSON Lines")
        whole = json.loads(data.decode("utf-8-sig"))
        if isinstance(whole, Mapping):
            decoded_records = [whole]
        elif isinstance(whole, list) and all(isinstance(item, Mapping) for item in whole):
            decoded_records = list(whole)
    except (RecursionError, UnicodeError, ValueError):
        pass
    if decoded_records is not None:
        for value in decoded_records:
            scanned += 1
            if scanned > MAX_SCAN_LINES or len(records) >= MAX_IMPORT_RECORDS:
                truncated = True
                break
            try:
                records.append(parser(value))
            except (TypeError, ValueError):
                skipped += 1
        imported, duplicates = store.append_many(records)
        return EvidenceImportResult(
            format=format_name, file_sha256=digest, imported=imported,
            duplicates=duplicates, skipped=skipped,
            scanned=min(scanned, MAX_SCAN_LINES), truncated=truncated,
        )
    for line in lines:
        if not line.strip():
            continue
        scanned += 1
        if scanned > MAX_SCAN_LINES or len(records) >= MAX_IMPORT_RECORDS:
            truncated = True
            break
        if len(line) > MAX_LINE_BYTES:
            skipped += 1
            continue
        try:
            value = json.loads(line.decode("utf-8-sig"))
            if not isinstance(value, Mapping):
                raise ValueError("record must be an object")
            records.append(parser(value))
        except (RecursionError, TypeError, UnicodeError, ValueError):
            skipped += 1
    imported, duplicates = store.append_many(records)
    return EvidenceImportResult(
        format=format_name, file_sha256=digest, imported=imported,
        duplicates=duplicates, skipped=skipped, scanned=min(scanned, MAX_SCAN_LINES),
        truncated=truncated,
    )


def discover_osquery() -> Path | None:
    """Return a regular osqueryi from a known system installation location."""
    candidates: list[Path] = []
    if os.name == "nt":
        for root in (os.environ.get("ProgramW6432"), os.environ.get("ProgramFiles")):
            if root:
                candidates.append(Path(root) / "osquery" / "osqueryi.exe")
    else:
        candidates.extend((
            Path("/usr/bin/osqueryi"), Path("/usr/local/bin/osqueryi"),
            Path("/opt/homebrew/bin/osqueryi"),
        ))
    for candidate in candidates:
        try:
            return _regular_local_file(candidate, expected_names=("osqueryi", "osqueryi.exe"))
        except (OSError, ValueError):
            continue
    return None


def run_osquery_template(template_id: str) -> tuple[EvidenceEnvelope, ...]:
    """Run one fixed SELECT template; caller SQL and executable paths are forbidden."""
    try:
        template = OSQUERY_TEMPLATES[template_id]
    except KeyError as exc:
        raise ValueError("unknown osquery template") from exc
    current = platform.system()
    if current not in template.platforms:
        raise ValueError(f"{template.name} is unavailable on {current}")
    executable = discover_osquery()
    if executable is None:
        raise RuntimeError("osqueryi was not found in a known system install location")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    environment = {
        key: value for key in ("SystemRoot", "WINDIR", "TEMP", "TMP", "HOME")
        if (value := os.environ.get(key))
    }
    environment["PATH"] = str(executable.parent)
    # The argument vector contains no caller-provided executable, SQL, or command.
    completed = subprocess.run(  # nosec B603
        [str(executable), "--disable_extensions=true", "--json", template.query],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=15.0, check=False, shell=False, env=environment,
        creationflags=creationflags,
    )
    if completed.returncode:
        error = redact_text(completed.stderr or "osquery failed", limit=600)
        raise RuntimeError(f"osquery snapshot failed: {error}")
    if len(completed.stdout.encode("utf-8", errors="replace")) > MAX_OSQUERY_OUTPUT:
        raise ValueError("osquery output exceeds the 4 MiB response budget")
    try:
        rows = json.loads(completed.stdout or "[]")
    except ValueError as exc:
        raise ValueError("osquery returned invalid JSON") from exc
    if not isinstance(rows, list) or len(rows) > 500:
        raise ValueError("osquery returned an invalid or oversized result set")
    stamp = time.time()
    evidence: list[EvidenceEnvelope] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError("osquery result rows must be objects")
        attributes = {
            key: _text(row[key], 2_000) for key in template.columns if key in row
        }
        core = {
            "template": template_id, "snapshot_at": stamp,
            "index": index, "attributes": attributes,
        }
        evidence.append(EvidenceEnvelope(
            event_id=_event_id("osquery", core), observed_at=stamp,
            category="endpoint_snapshot", activity=template_id, severity=0,
            message=f"Read-only osquery snapshot: {template.name}",
            module="osquery Integration", attributes=attributes,
            provenance={
                "kind": "osquery_template", "template_id": template_id,
                "arbitrary_sql": False, "extensions": False,
            },
        ))
    return tuple(evidence)


__all__ = [
    "CAPABILITY_PARITY", "OSQUERY_TEMPLATES", "CapabilityParity",
    "EvidenceImportResult", "OsqueryTemplate", "discover_osquery",
    "import_json_evidence", "parity_summary", "run_osquery_template",
]
