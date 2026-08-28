"""core/ocsf_export.py — normalise Angerona events to the OCSF schema.

OCSF (Open Cybersecurity Schema Framework) is the emerging vendor-neutral event
schema used by modern SIEM/XDR/data lakes. Emitting OCSF "Detection Finding"
objects lets Angerona interoperate cleanly (via the existing SIEM forwarder)
instead of a bespoke shape. Pure mapping; no network.
"""
from __future__ import annotations

import ipaddress
import math
import re
import time
from itertools import islice

from angerona import __version__

# OCSF severity_id: 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal
_SEV_ID = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
_OCSF_VERSION = "1.8.0"
_MAPPING_SCOPE = "constrained-preview"
_ATTACK_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_OBSERVABLE_TYPES = {
    2: "IP Address",
    4: "User Name",
    9: "Process Name",
    15: "Process ID",
    21: "User",
    25: "Process",
    45: "File Path",
}


def _sev(event) -> tuple[int, str]:
    name = getattr(getattr(event, "severity", None), "name", "") or "INFO"
    return _SEV_ID.get(name.upper(), 1), name.title()


def _text(value: object, limit: int = 512) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, bytes):
        return value[:limit].decode("utf-8", errors="replace")
    if isinstance(value, (dict, list, tuple, set)):
        return f"<{type(value).__name__}:{len(value)} items>"[:limit]
    try:
        return str(value)[:limit]
    except Exception:
        return ""


def _first_text(det: dict, keys: tuple[str, ...], limit: int = 512) -> str:
    for key in keys:
        value = _text(det.get(key), limit).strip()
        if value:
            return value
    return ""


def _ip(value: object) -> str:
    raw = _text(value, 128).strip()
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    else:
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            if raw.count(":") == 1:
                host, port = raw.rsplit(":", 1)
                if port.isdigit():
                    raw = host
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return ""


def _file_object(value: str) -> dict:
    path = value[:1024]
    name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1][:255]
    obj = {"path": path}
    if name:
        obj["name"] = name
    return obj


def _absolute_file_path(value: str) -> str:
    path = value.strip()[:1024]
    if path.startswith(("/", "\\\\")) or re.match(r"^[A-Za-z]:[\\/]", path):
        return path
    return ""


def _evidence_and_observables(det: dict) -> tuple[list[dict], list[dict]]:
    """Map only fields with valid OCSF 1.8 evidence paths and type IDs."""
    evidence: dict = {}
    observables: list[dict] = []

    pid = det.get("pid")
    image = _first_text(det, ("image", "process_path"), 1024)
    image_path = _absolute_file_path(image)
    process_name = _first_text(det, ("name", "process_name"), 255)
    if not process_name and image:
        process_name = image.replace("\\", "/").rsplit("/", 1)[-1][:255]
    if isinstance(pid, int) and not isinstance(pid, bool) and 0 <= pid <= 2**63 - 1:
        process: dict = {"pid": pid}
        if process_name:
            process["name"] = process_name
        if image_path:
            process["file"] = _file_object(image_path)
        evidence["process"] = process
        observables.extend((
            {"name": "evidences[0].process", "type_id": 25, "type": "Process"},
            {"name": "evidences[0].process.pid", "type_id": 15,
             "type": "Process ID", "value": str(pid)},
        ))
        if process_name:
            observables.append({
                "name": "evidences[0].process.name", "type_id": 9,
                "type": "Process Name", "value": process_name,
            })
        if image_path:
            observables.append({
                "name": "evidences[0].process.file.path", "type_id": 45,
                "type": "File Path", "value": image_path,
            })

    remote = ""
    for key in ("remote", "raddr", "ip", "dest_ip"):
        remote = _ip(det.get(key))
        if remote:
            break
    if remote:
        evidence["dst_endpoint"] = {"ip": remote}
        observables.append({
            "name": "evidences[0].dst_endpoint.ip", "type_id": 2,
            "type": "IP Address", "value": remote,
        })

    path = _absolute_file_path(_first_text(det, ("path", "file"), 1024))
    if path:
        evidence["file"] = _file_object(path)
        observables.append({
            "name": "evidences[0].file.path", "type_id": 45,
            "type": "File Path", "value": path,
        })

    username = _first_text(det, ("user", "username"), 255)
    if username:
        evidence["user"] = {"name": username}
        observables.extend((
            {"name": "evidences[0].user", "type_id": 21, "type": "User"},
            {"name": "evidences[0].user.name", "type_id": 4,
             "type": "User Name", "value": username},
        ))
    return ([evidence] if evidence else []), observables


def _attack_ids(det: dict) -> list[str]:
    raw = det.get("mitre")
    if isinstance(raw, set):
        candidates = sorted(raw, key=lambda value: _text(value, 32))
    elif isinstance(raw, (list, tuple)):
        candidates = raw
    else:
        candidates = re.split(r"[,/\s]+", _text(raw, 4096))
    tids: list[str] = []
    for candidate in candidates:
        tid = _text(candidate, 16).strip().upper()
        if _ATTACK_ID.fullmatch(tid) and tid not in tids:
            tids.append(tid)
            if len(tids) >= 32:
                break
    return tids


def _bounded_unmapped(det: dict, module: str) -> dict:
    details: dict[str, str] = {}
    for key, value in islice(det.items(), 64):
        safe_key = _text(key, 80)
        if safe_key:
            details[safe_key] = _text(value, 200)
    return {
        "angerona_module": module[:200],
        "angerona_details": details,
        "ocsf_mapping": {
            "scope": _MAPPING_SCOPE,
            "schema": _OCSF_VERSION,
            "validation": "bounded-local-structural-contract",
        },
    }


def to_finding(event) -> dict:
    """Map one event to Angerona's constrained OCSF 1.8 Finding contract."""
    sev_id, sev_name = _sev(event)
    raw_details = getattr(event, "details", None)
    det = raw_details if isinstance(raw_details, dict) else {}
    try:
        ts = float(getattr(event, "ts", time.time()) or time.time())
    except (TypeError, ValueError):
        ts = time.time()
    if not math.isfinite(ts) or ts <= 0:
        ts = time.time()
    module = _text(getattr(event, "module", "") or "Angerona", 200)
    msg = _text(getattr(event, "message", "") or "", 1024)
    tids = _attack_ids(det)
    evidences, observables = _evidence_and_observables(det)
    return {
        "activity_id": 1, "activity_name": "Create",
        "category_uid": 2, "category_name": "Findings",
        "class_uid": 2004, "class_name": "Detection Finding",
        "type_uid": 200401, "type_name": "Detection Finding: Create",
        "severity_id": sev_id, "severity": sev_name,
        "status_id": 1, "status": "New",
        "time": int(ts * 1000),
        "message": msg,
        "is_alert": True,
        "metadata": {
            # The mapping intentionally stays on the stable Detection Finding
            # class while declaring the exact schema release it targets.  OCSF
            # 1.8 is backwards compatible with this 1.3-era event class and adds
            # newer profiles/objects without invalidating the core contract.
            "version": _OCSF_VERSION,
            "product": {"name": "Angerona", "vendor_name": "Angerona",
                        "version": __version__, "feature": {"name": module}},
        },
        "finding_info": {
            "title": f"{module}: {msg[:120]}",
            "types": ["Detection"],
            "kill_chain": [{"phase_id": 0, "phase": "Unknown"}],
        },
        "attacks": [{"technique": {"uid": t}} for t in tids],
        "evidences": evidences,
        "observables": observables,
        "unmapped": _bounded_unmapped(det, module),
    }


_PATH_PART = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)(?:\[(\d{1,4})\])?$")


def _resolve_path(document: dict, path: str) -> tuple[bool, object]:
    value: object = document
    for raw_part in path.split("."):
        part = _PATH_PART.fullmatch(raw_part)
        if part is None or not isinstance(value, dict) or part.group(1) not in value:
            return False, None
        value = value[part.group(1)]
        if part.group(2) is not None:
            if not isinstance(value, list):
                return False, None
            index = int(part.group(2))
            if index >= len(value):
                return False, None
            value = value[index]
    return True, value


def validate_finding_shape(document: object) -> tuple[bool, tuple[str, ...]]:
    """Validate Angerona's bounded OCSF 1.8 Detection Finding contract.

    This is deliberately a local structural admission check, not a claim that
    it replaces the upstream OCSF schema compiler.  Exporters can call it before
    queueing a document so malformed mappings fail closed.
    """
    errors: list[str] = []
    if not isinstance(document, dict):
        return False, ("document must be an object",)
    if document.get("class_uid") != 2004:
        errors.append("class_uid must be 2004")
    if document.get("category_uid") != 2:
        errors.append("category_uid must be 2")
    if document.get("type_uid") != 200401:
        errors.append("type_uid must be 200401")
    if document.get("severity_id") not in {1, 2, 3, 4, 5, 6}:
        errors.append("severity_id is outside the OCSF range")
    if not isinstance(document.get("time"), int) or document.get("time", 0) <= 0:
        errors.append("time must be a positive epoch-millisecond integer")
    metadata = document.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("version") != _OCSF_VERSION:
        errors.append(f"metadata.version must be {_OCSF_VERSION}")
    product = metadata.get("product") if isinstance(metadata, dict) else None
    if not isinstance(product, dict) or product.get("name") != "Angerona":
        errors.append("metadata.product.name must be Angerona")
    finding = document.get("finding_info")
    if not isinstance(finding, dict) or not str(finding.get("title") or "").strip():
        errors.append("finding_info.title is required")
    evidences = document.get("evidences")
    if not isinstance(evidences, list):
        errors.append("evidences must be an array")
    observables = document.get("observables")
    if not isinstance(observables, list):
        errors.append("observables must be an array")
    elif len(observables) > 32:
        errors.append("observables exceeds the constrained maximum of 32")
    else:
        for index, observable in enumerate(observables):
            prefix = f"observables[{index}]"
            if not isinstance(observable, dict):
                errors.append(f"{prefix} must be an object")
                continue
            type_id = observable.get("type_id")
            if type_id not in _OBSERVABLE_TYPES:
                errors.append(f"{prefix}.type_id is unsupported by this mapping")
            elif observable.get("type") != _OBSERVABLE_TYPES[type_id]:
                errors.append(f"{prefix}.type does not match type_id {type_id}")
            name = observable.get("name")
            if not isinstance(name, str) or not name or len(name) > 256:
                errors.append(f"{prefix}.name must be a bounded attribute path")
                continue
            found, actual = _resolve_path(document, name)
            if not found:
                errors.append(f"{prefix}.name does not resolve in the event")
            elif isinstance(actual, dict):
                if "value" in observable:
                    errors.append(f"{prefix}.value must be omitted for object observables")
            elif observable.get("value") != str(actual):
                errors.append(f"{prefix}.value does not match the referenced attribute")
    unmapped = document.get("unmapped")
    mapping = unmapped.get("ocsf_mapping") if isinstance(unmapped, dict) else None
    if not isinstance(mapping, dict) or mapping.get("scope") != _MAPPING_SCOPE:
        errors.append(f"unmapped.ocsf_mapping.scope must be {_MAPPING_SCOPE}")
    return not errors, tuple(errors)


def self_test() -> tuple[bool, str]:
    class _Sev:
        name = "HIGH"

    class _Ev:
        severity = _Sev()
        module = "BEAC"
        message = "Possible C2 beacon: evil.exe -> 8.8.8.8"
        ts = time.time()
        details = {"pid": 6624, "name": "evil.exe", "remote": "8.8.8.8:443", "mitre": "T1071"}

    f = to_finding(_Ev())
    shape_ok, _errors = validate_finding_shape(f)
    ok = (shape_ok and f["class_uid"] == 2004 and f["severity_id"] == 4 and f["severity"] == "High"
          and f["metadata"]["product"]["name"] == "Angerona"
          and f["attacks"] and f["attacks"][0]["technique"]["uid"] == "T1071"
          and any(o["name"] == "evidences[0].process.pid" and o["type_id"] == 15
                  and o["value"] == "6624" for o in f["observables"])
          and any(o["name"] == "evidences[0].dst_endpoint.ip" and o["type_id"] == 2
                  and o["value"] == "8.8.8.8" for o in f["observables"]))
    return ok, ("Constrained OCSF 1.8 Detection Finding mapping verified "
                "(class 2004, typed observables resolving to evidence paths)"
                if ok else f"failed: {f}")
