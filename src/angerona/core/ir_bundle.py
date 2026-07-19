"""Privacy-bounded incident-response bundle generation.

The bundle is useful for support and after-action review, but it is not a raw
host image.  Collection requires explicit operator consent and applies a fixed,
documented redaction policy before any bytes enter the archive.  Credentials,
DPAPI material, usernames, hostnames, raw paths, command lines, and raw network
addresses are intentionally excluded.
"""
from __future__ import annotations

import getpass
import hashlib
import hmac
import ipaddress
import json
import os
import platform
import re
import secrets
import stat
import time
import zipfile
from collections import Counter
from itertools import islice
from pathlib import Path
from typing import Any

try:
    import psutil
except Exception:  # pragma: no cover - supported degraded mode
    psutil = None


POLICY_VERSION = "ir-privacy-v1"
MAX_PROCESSES = 512
MAX_CONNECTIONS = 1024
MAX_EVENTS = 200
MAX_INCIDENTS = 100
MAX_CONTAINER_ITEMS = 128
MAX_DEPTH = 6
MAX_SANITIZED_NODES = 4096
MAX_STRING_CHARS = 4096
MAX_ARTIFACT_BYTES = 512 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024

# Only these exact diagnostic products may be copied from shared_logs.  Secrets,
# databases, private keys, DPAPI blobs and operator-selected files are never
# eligible for inclusion.
_INCLUDE_FILES = (
    "remediation_stats.json",
    "incident_timeline.json",
    "daily_briefing.txt",
    "daily_briefing.json",
)

_SENSITIVE_KEY = re.compile(
    r"(?i)(?:^|[_-])(?:access[_-]?token|api[_-]?key|authorization|auth|cookie|"
    r"credential|dpapi|key|password|passwd|private|secret|session|token)(?:$|[_-])"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|bearer|access[_-]?token|api[_-]?key|password|passwd|"
    r"secret|session[_-]?id|token)\b\s*[:=]\s*([^\r\n,;]+)"
)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*")
_PROVIDER_TOKEN = re.compile(r"\b(?:sk|ghp|gho|github_pat|xox[baprs])-[A-Za-z0-9_-]{16,}\b")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_DPAPI_B64 = re.compile(r"\bAQAAANCMnd8BFdERjHoAwE[A-Za-z0-9+/=_-]{12,}")
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?"
    r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.DOTALL
)
_HIGH_ENTROPY_VALUE = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Fa-f0-9]{40,}|[A-Za-z0-9+/_-]{48,}={0,2})(?![A-Za-z0-9])"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_QUOTED_WIN_PATH = re.compile(r"(?i)([\"'])([A-Z]:\\[^\"'\r\n]+)\1")
_WIN_PATH = re.compile(r"(?i)\b[A-Z]:\\[^\s\"'<>|]+")
_USER_HOME_PATH = re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s\"'<>|]+(?:\\[^\s\"'<>|]+)*")
_POSIX_HOME_PATH = re.compile(r"(?<![\w.])/(?:home|Users)/[^/\s]+(?:/[^\s\"']+)*")
_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def _shared_logs() -> Path:
    from angerona.core.data_paths import data_dir

    return data_dir() / "shared_logs"


class _PrivacyFilter:
    """Deterministic-within-one-bundle redaction and audit counters."""

    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self.counts: Counter[str] = Counter()
        self._nodes = 0
        self._identities = {
            value.casefold(): label
            for value, label in (
                (getpass.getuser(), "user"),
                (os.environ.get("USERNAME", ""), "user"),
                (os.environ.get("USER", ""), "user"),
                (platform.node(), "host"),
            )
            if value and len(value) >= 2
        }

    def token(self, kind: str, value: Any) -> str:
        raw = str(value).encode("utf-8", errors="replace")
        digest = hmac.new(self._key, kind.encode("ascii") + b"\0" + raw,
                          hashlib.sha256).hexdigest()[:12]
        self.counts[kind] += 1
        return f"<{kind}:{digest}>"

    def text(self, value: Any) -> str:
        text = str(value)
        if len(text) > MAX_STRING_CHARS:
            text = text[:MAX_STRING_CHARS]
            self.counts["truncated_strings"] += 1

        def _assignment(match: re.Match) -> str:
            self.counts["secret_values"] += 1
            return f"{match.group(1)}=<redacted>"

        text = _BEARER.sub("Bearer <redacted>", text)
        text = _PROVIDER_TOKEN.sub(lambda m: self.token("credential", m.group(0)), text)
        text = _SECRET_ASSIGNMENT.sub(_assignment, text)
        text = _JWT.sub(lambda m: self.token("credential", m.group(0)), text)
        text = _DPAPI_B64.sub(lambda m: self.token("dpapi", m.group(0)), text)
        text = _PRIVATE_KEY.sub("<redacted:private-key>", text)
        text = _HIGH_ENTROPY_VALUE.sub(
            lambda m: self.token("credential", m.group(0)), text)
        text = _EMAIL.sub(lambda m: self.token("email", m.group(0).casefold()), text)
        text = _USER_HOME_PATH.sub(lambda m: self.token("path", m.group(0)), text)
        text = _QUOTED_WIN_PATH.sub(
            lambda m: m.group(1) + self.token("path", m.group(2)) + m.group(1), text)
        text = _WIN_PATH.sub(lambda m: self.token("path", m.group(0)), text)
        text = _POSIX_HOME_PATH.sub(lambda m: self.token("path", m.group(0)), text)

        def _ip(match: re.Match) -> str:
            try:
                ipaddress.ip_address(match.group(0))
            except ValueError:
                return match.group(0)
            return self.token("address", match.group(0))

        text = _IPV4.sub(_ip, text)
        # Replace known local identities last, including standalone occurrences.
        for identity, kind in self._identities.items():
            text = re.sub(re.escape(identity), lambda m, k=kind: self.token(k, m.group(0)),
                          text, flags=re.IGNORECASE)
        return text

    def value(self, value: Any, depth: int = 0) -> Any:
        self._nodes += 1
        if self._nodes > MAX_SANITIZED_NODES:
            self.counts["node_budget_limited"] += 1
            return "<redacted:node-budget>"
        if depth > MAX_DEPTH:
            self.counts["depth_limited"] += 1
            return "<redacted:depth-limit>"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, (bytes, bytearray, memoryview)):
            self.counts["binary_values"] += 1
            return "<redacted:binary>"
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            items = sorted(value.items(), key=lambda pair: str(pair[0]))
            for index, (key, item) in enumerate(items):
                if index >= MAX_CONTAINER_ITEMS:
                    self.counts["container_items_limited"] += len(items) - index
                    break
                safe_key = self.text(key)
                if _SENSITIVE_KEY.search(str(key)):
                    out[safe_key] = "<redacted:sensitive-field>"
                    self.counts["sensitive_fields"] += 1
                else:
                    out[safe_key] = self.value(item, depth + 1)
            return out
        if isinstance(value, (list, tuple, set)):
            items = sorted(value, key=repr) if isinstance(value, set) else list(value)
            if len(items) > MAX_CONTAINER_ITEMS:
                self.counts["container_items_limited"] += len(items) - MAX_CONTAINER_ITEMS
            return [self.value(item, depth + 1)
                    for item in items[:MAX_CONTAINER_ITEMS]]
        return self.text(value)


def _process_list(redactor: _PrivacyFilter) -> list[dict]:
    if psutil is None:
        return []
    procs: list[dict] = []
    for p in psutil.process_iter(["pid", "ppid", "name", "create_time"]):
        if len(procs) >= MAX_PROCESSES:
            redactor.counts["processes_limited"] += 1
            break
        row = {
            "pid": p.info.get("pid"),
            "ppid": p.info.get("ppid"),
            "name": redactor.text(p.info.get("name") or ""),
            "create_time": p.info.get("create_time"),
        }
        # Command lines, usernames and executable paths are never collected.
        try:
            row["mem_mb"] = round(p.memory_info().rss / (1024 * 1024), 1)
        except Exception:
            row["mem_mb"] = None
        procs.append(row)
    procs.sort(key=lambda item: (item.get("mem_mb") or 0), reverse=True)
    return procs


def _address_class(host: str) -> str:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return "hostname"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_private:
        return "private"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    return "public"


def _safe_endpoint(endpoint: Any, redactor: _PrivacyFilter) -> dict | None:
    if not endpoint:
        return None
    host = str(getattr(endpoint, "ip", ""))
    port = getattr(endpoint, "port", None)
    return {
        "address_class": _address_class(host),
        "address_id": redactor.token("address", host),
        "port": port if isinstance(port, int) and 0 <= port <= 65535 else None,
    }


def _connections(redactor: _PrivacyFilter) -> list[dict]:
    if psutil is None:
        return []
    out: list[dict] = []
    try:
        for connection in psutil.net_connections(kind="inet"):
            if len(out) >= MAX_CONNECTIONS:
                redactor.counts["connections_limited"] += 1
                break
            out.append({
                "pid": connection.pid,
                "status": str(connection.status),
                "local": _safe_endpoint(connection.laddr, redactor),
                "remote": _safe_endpoint(connection.raddr, redactor),
                "type": "tcp" if connection.type == 1 else "udp",
            })
    except Exception:
        redactor.counts["connection_collection_errors"] += 1
    return out


def _system_info() -> dict:
    # Deliberately excludes hostname and logged-on users.
    info: dict[str, Any] = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "architecture": platform.machine(),
        "python": platform.python_version(),
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }
    if psutil is not None:
        try:
            info["boot_time"] = time.strftime(
                "%Y-%m-%dT%H:%M:%S%z", time.localtime(psutil.boot_time()))
        except Exception:
            pass
        try:
            vm = psutil.virtual_memory()
            info["mem_total_mb"] = round(vm.total / (1024 * 1024))
            info["mem_percent"] = vm.percent
        except Exception:
            pass
    return info


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False,
                       default=str) + "\n").encode("utf-8")


def _safe_curated_artifact(logs: Path, name: str,
                           redactor: _PrivacyFilter) -> tuple[bytes | None, str | None]:
    """Read and sanitize one allow-listed regular file without following links."""
    if name not in _INCLUDE_FILES or Path(name).name != name:
        return None, "not-allow-listed"
    source = logs / name
    try:
        source_stat = source.lstat()
    except FileNotFoundError:
        return None, "not-present"
    except OSError:
        return None, "metadata-unavailable"
    if stat.S_ISLNK(source_stat.st_mode) or not stat.S_ISREG(source_stat.st_mode):
        return None, "unsafe-file-type"
    try:
        if source.resolve(strict=True).parent != logs.resolve(strict=True):
            return None, "outside-shared-logs"
    except OSError:
        return None, "resolution-failed"
    if source_stat.st_size > MAX_ARTIFACT_BYTES:
        return None, "size-limit"
    descriptor = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        opened_stat = os.fstat(descriptor)
        if not stat.S_ISREG(opened_stat.st_mode):
            return None, "unsafe-opened-file-type"
        if ((opened_stat.st_dev, opened_stat.st_ino) !=
                (source_stat.st_dev, source_stat.st_ino)):
            return None, "file-changed-before-read"
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_ARTIFACT_BYTES + 1)
    except OSError:
        return None, "read-failed"
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
    if len(raw) > MAX_ARTIFACT_BYTES:
        return None, "size-changed-during-read"
    text = raw.decode("utf-8", errors="replace")
    if name.endswith(".json"):
        try:
            return _json_bytes(redactor.value(json.loads(text))), None
        except (json.JSONDecodeError, ValueError):
            redactor.counts["invalid_json_artifacts"] += 1
    return (redactor.text(text) + "\n").encode("utf-8"), None


def _safe_destination(dest_dir: str | Path | None) -> Path:
    destination = Path(dest_dir) if dest_dir is not None else _shared_logs() / "ir_bundles"
    destination.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or not destination.is_dir():
        raise ValueError("IR bundle destination must be a real directory, not a link")
    return destination.resolve(strict=True)


def collect_triage_bundle(dest_dir: str | Path | None = None, bus=None, *,
                          consent: bool = False) -> Path:
    """Create a bounded, redacted triage ZIP after explicit operator consent.

    ``consent=True`` means the caller has shown the operator a warning that the
    sanitized archive still contains security telemetry and should be shared
    only with a trusted analyst.  This fail-closed contract prevents background
    or accidental one-click export.
    """
    if consent is not True:
        raise PermissionError(
            "IR bundle export requires explicit operator consent; sanitized "
            "security telemetry can still be sensitive"
        )

    destination = _safe_destination(dest_dir)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    zip_path = destination / f"ir_triage_{stamp}-{secrets.token_hex(4)}.zip"
    if zip_path.exists():  # defensive; random suffix makes this vanishingly unlikely
        raise FileExistsError("refusing to overwrite an existing IR bundle")

    redactor = _PrivacyFilter()
    system_info = _system_info()
    processes = _process_list(redactor)
    connections = _connections(redactor)

    recent_events: list[Any] = []
    incidents: list[Any] = []
    if bus is not None:
        try:
            events = list(islice(bus.recent(MAX_EVENTS + 1), MAX_EVENTS + 1))
            if len(events) > MAX_EVENTS:
                redactor.counts["events_limited"] += len(events) - MAX_EVENTS
            for event in events[-MAX_EVENTS:]:
                recent_events.append(redactor.value({
                    "ts": getattr(event, "ts", None),
                    "module": getattr(event, "module", None),
                    "severity": getattr(getattr(event, "severity", None), "name", None),
                    "message": getattr(event, "message", "") or "",
                    "details": getattr(event, "details", None),
                }))
        except Exception:
            redactor.counts["event_collection_errors"] += 1
        try:
            from angerona.core.incident_timeline import build_timeline

            class _BoundedBus:
                def recent(self, limit):
                    bounded = min(max(int(limit), 0), MAX_EVENTS * 2)
                    return list(islice(bus.recent(bounded), bounded))

            built = list(islice(build_timeline(_BoundedBus()), MAX_INCIDENTS + 1))
            if len(built) > MAX_INCIDENTS:
                redactor.counts["incidents_limited"] += len(built) - MAX_INCIDENTS
            incidents = redactor.value(built[-MAX_INCIDENTS:])
        except Exception:
            redactor.counts["incident_collection_errors"] += 1

    entries: dict[str, bytes] = {
        "01_system_info.json": _json_bytes(system_info),
        "02_processes.json": _json_bytes(processes),
        "03_connections.json": _json_bytes(connections),
    }
    if recent_events:
        entries["04_recent_events.json"] = _json_bytes(recent_events)
    if incidents:
        entries["05_incident_timeline.json"] = _json_bytes(incidents)

    skipped: dict[str, str] = {}
    logs = _shared_logs()
    for name in _INCLUDE_FILES:
        content, reason = _safe_curated_artifact(logs, name, redactor)
        if content is not None:
            entries[f"angerona/{name}"] = content
        elif reason != "not-present":
            skipped[name] = reason or "not-included"

    readme = (
        "ANGERONA PRIVACY-SANITIZED IR BUNDLE\n\n"
        "This archive contains bounded security diagnostics collected with explicit "
        "operator consent. Angerona removed credentials, usernames, hostnames, raw "
        "paths, command lines, and raw network addresses. No sanitizer can guarantee "
        "that free-form security telemetry is risk-free. Review the archive and share "
        "it only with a trusted analyst. Do not post it publicly or use it as a "
        "credential backup.\n\n"
        f"Redaction policy: {POLICY_VERSION}\n"
    ).encode("utf-8")
    entries["README.txt"] = readme

    accepted: dict[str, bytes] = {}
    total = 0
    for name in sorted(entries):
        content = entries[name]
        if len(content) > MAX_MEMBER_BYTES:
            skipped[name] = "member-size-limit"
            continue
        if total + len(content) > MAX_ARCHIVE_BYTES:
            skipped[name] = "archive-size-limit"
            continue
        accepted[name] = content
        total += len(content)

    manifest = {
        "bundle": zip_path.name,
        "generated": system_info["collected_at"],
        "operator_consent": True,
        "privacy": {
            "policy": POLICY_VERSION,
            "warning": "Sanitized security telemetry remains sensitive; review before sharing.",
            "excluded": [
                "credentials and credential-like fields", "DPAPI blobs and private keys",
                "hostnames and usernames", "raw filesystem paths and command lines",
                "raw IP addresses", "arbitrary operator-selected files",
            ],
            "redaction_counts": dict(sorted(redactor.counts.items())),
        },
        "limits": {
            "processes": MAX_PROCESSES, "connections": MAX_CONNECTIONS,
            "events": MAX_EVENTS, "incidents": MAX_INCIDENTS,
            "sanitized_nodes": MAX_SANITIZED_NODES,
            "artifact_bytes": MAX_ARTIFACT_BYTES,
            "member_bytes": MAX_MEMBER_BYTES,
            "archive_uncompressed_bytes": MAX_ARCHIVE_BYTES,
        },
        "counts": {
            "processes": len(processes), "connections": len(connections),
            "events": len(recent_events), "incidents": len(incidents),
        },
        "members": {
            name: {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
            for name, content in sorted(accepted.items())
        },
        "skipped": dict(sorted(skipped.items())),
    }
    manifest_bytes = _json_bytes(manifest)
    if len(manifest_bytes) > MAX_MEMBER_BYTES:
        raise RuntimeError("IR bundle manifest exceeded its fixed size limit")

    try:
        with zipfile.ZipFile(zip_path, "x", zipfile.ZIP_DEFLATED,
                             compresslevel=6, allowZip64=False) as archive:
            archive.writestr("00_MANIFEST.json", manifest_bytes)
            for name, content in sorted(accepted.items()):
                archive.writestr(name, content)
    except Exception:
        try:
            zip_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return zip_path


def self_test() -> tuple[bool, str]:
    """Build a consented bundle and verify its privacy contract and manifest."""
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        try:
            collect_triage_bundle(dest_dir=td)
            return False, "bundle was created without explicit consent"
        except PermissionError:
            pass
        path = collect_triage_bundle(dest_dir=td, consent=True)
        if not path.exists():
            return False, "bundle zip was not created"
        with zipfile.ZipFile(path) as archive:
            names = set(archive.namelist())
            manifest = json.loads(archive.read("00_MANIFEST.json"))
        required = {"00_MANIFEST.json", "01_system_info.json",
                    "02_processes.json", "03_connections.json", "README.txt"}
        ok = required.issubset(names) and manifest.get("operator_consent") is True
        return ok, (f"privacy-bounded IR bundle built with {len(names)} members "
                    f"({path.name})" if ok else
                    f"failed: missing {required - names}")
