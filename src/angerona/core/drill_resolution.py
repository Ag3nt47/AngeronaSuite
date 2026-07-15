"""Time- and run-scoped resolution state for simulated drill findings."""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

_LOCK = threading.RLock()
_CACHE: dict[str, tuple[int, dict]] = {}
_DEFAULT_DATA_DIR: Path | None = None
_MITRE_RE = re.compile(r"\((T\d{4}(?:\.\d{3})?|RT-[^)]+)\)", re.I)

ResolutionSnapshot = Mapping[str, Mapping[str, object]]


def _data_dir(data_dir=None) -> Path:
    if data_dir is not None:
        return Path(data_dir)
    global _DEFAULT_DATA_DIR
    with _LOCK:
        if _DEFAULT_DATA_DIR is None:
            try:
                from angerona.core.config import Config
                _DEFAULT_DATA_DIR = Path(Config.load().data_dir)
            except Exception:
                from angerona.core.data_paths import data_dir as canonical_data_dir
                _DEFAULT_DATA_DIR = canonical_data_dir()
        return _DEFAULT_DATA_DIR


def state_path(data_dir=None) -> Path:
    return _data_dir(data_dir) / "shared_logs" / "drill_resolutions.json"


def _load(data_dir=None) -> dict:
    path = state_path(data_dir)
    key = str(path)
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        stamp = -1
    with _LOCK:
        cached = _CACHE.get(key)
        if cached and cached[0] == stamp:
            return json.loads(json.dumps(cached[1]))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {}
        data.setdefault("version", 1)
        data.setdefault("resolutions", {})
        _CACHE[key] = (stamp, data)
        return json.loads(json.dumps(data))


def _write(data: dict, data_dir=None) -> None:
    path = state_path(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(tmp, path)
    with _LOCK:
        _CACHE.pop(str(path), None)


def resolve(findings: list[dict], run_id: str = "", data_dir=None,
            resolved_at: float | None = None) -> list[dict]:
    at = float(resolved_at or time.time())
    data = _load(data_dir)
    out = []
    for finding in findings:
        mitre = str(finding.get("mitre") or "").strip()
        if not mitre:
            continue
        rec = {
            "mitre": mitre,
            "name": str(finding.get("name") or mitre),
            "run_id": str(run_id or finding.get("run_id") or ""),
            "resolved_at": at,
            "resolution": "operator-reviewed simulated detection gap",
        }
        data["resolutions"][mitre.casefold()] = rec
        out.append(rec)
    data["updated_at"] = at
    _write(data, data_dir)
    return out


def resolution_snapshot(data_dir=None) -> ResolutionSnapshot:
    """Return an immutable resolution view for one evaluation/report batch."""
    records = _load(data_dir).get("resolutions", {})
    if not isinstance(records, dict):
        records = {}
    return MappingProxyType({
        str(key): MappingProxyType(dict(value))
        for key, value in records.items() if isinstance(value, dict)
    })


def already_resolved(mitre: str, run_id: str, data_dir=None,
                     resolutions: ResolutionSnapshot | None = None) -> bool:
    rows = resolution_snapshot(data_dir) if resolutions is None else resolutions
    rec = rows.get(str(mitre).casefold(), {})
    return bool(run_id and rec.get("run_id") == run_id)


def event_mitre(event) -> str:
    details = getattr(event, "details", None) or {}
    mitre = details.get("mitre") or details.get("technique") or ""
    if mitre:
        return str(mitre).split()[0]
    match = _MITRE_RE.search(str(getattr(event, "message", "") or ""))
    return match.group(1) if match else ""


def is_resolved_event(event, data_dir=None,
                      resolutions: ResolutionSnapshot | None = None) -> bool:
    """Hide only old drill-gap alerts; later misses remain active automatically."""
    if getattr(event, "module", "") != "Posture Hardening":
        return False
    if "NEW WEAKNESS (Red Team)" not in str(getattr(event, "message", "") or ""):
        return False
    mitre = event_mitre(event)
    if not mitre:
        return False
    rows = resolution_snapshot(data_dir) if resolutions is None else resolutions
    rec = rows.get(mitre.casefold(), {})
    try:
        return float(getattr(event, "ts", 0)) <= float(rec.get("resolved_at", 0))
    except (TypeError, ValueError):
        return False
