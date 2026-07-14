"""core/ocsf_export.py — normalise Angerona events to the OCSF schema.

OCSF (Open Cybersecurity Schema Framework) is the emerging vendor-neutral event
schema used by modern SIEM/XDR/data lakes. Emitting OCSF "Detection Finding"
objects lets Angerona interoperate cleanly (via the existing SIEM forwarder)
instead of a bespoke shape. Pure mapping; no network.
"""
from __future__ import annotations

import time

# OCSF severity_id: 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical, 6 Fatal
_SEV_ID = {"INFO": 1, "LOW": 2, "MEDIUM": 3, "HIGH": 4, "CRITICAL": 5}
_PRODUCT_VERSION = "1.3.0"


def _sev(event) -> tuple[int, str]:
    name = getattr(getattr(event, "severity", None), "name", "") or "INFO"
    return _SEV_ID.get(name.upper(), 1), name.title()


def _observables(det: dict) -> list[dict]:
    obs: list[dict] = []
    if not isinstance(det, dict):
        return obs
    if isinstance(det.get("pid"), int):
        obs.append({"name": "process.pid", "type": "Process", "value": str(det["pid"])})
    for k, typ in (("name", "Process"), ("image", "Process")):
        if det.get(k):
            obs.append({"name": "process.name", "type": typ, "value": str(det[k])}); break
    for k in ("remote", "raddr", "ip", "dest_ip"):
        if det.get(k):
            obs.append({"name": "dst_endpoint.ip", "type": "IP Address",
                        "value": str(det[k]).split(":")[0]}); break
    for k in ("path", "file"):
        if det.get(k):
            obs.append({"name": "file.path", "type": "File", "value": str(det[k])}); break
    for k in ("user", "username"):
        if det.get(k):
            obs.append({"name": "actor.user.name", "type": "User", "value": str(det[k])}); break
    return obs


def to_finding(event) -> dict:
    """Map one Angerona event to an OCSF Detection Finding (class_uid 2004)."""
    sev_id, sev_name = _sev(event)
    det = getattr(event, "details", None) or {}
    ts = getattr(event, "ts", time.time()) or time.time()
    module = getattr(event, "module", "") or "Angerona"
    msg = getattr(event, "message", "") or ""
    tids = []
    mit = det.get("mitre") if isinstance(det, dict) else None
    if mit:
        tids = [t.strip() for t in str(mit).replace(",", "/").split("/") if t.strip().startswith("T")]
    return {
        "activity_id": 1, "activity_name": "Create",
        "category_uid": 2, "category_name": "Findings",
        "class_uid": 2004, "class_name": "Detection Finding",
        "type_uid": 200401,
        "severity_id": sev_id, "severity": sev_name,
        "status_id": 1, "status": "New",
        "time": int(ts * 1000),
        "message": msg[:1024],
        "metadata": {
            "version": "1.3.0",
            "product": {"name": "Angerona", "vendor_name": "Angerona",
                        "version": _PRODUCT_VERSION, "feature": {"name": module}},
        },
        "finding_info": {
            "title": f"{module}: {msg[:120]}",
            "types": ["Detection"],
            "kill_chain": [{"phase": "unknown"}],
        },
        "attacks": [{"technique": {"uid": t}} for t in tids],
        "observables": _observables(det if isinstance(det, dict) else {}),
        "unmapped": {"module": module,
                     "details": {k: str(v)[:200] for k, v in (det.items() if isinstance(det, dict) else [])}},
    }


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
    ok = (f["class_uid"] == 2004 and f["severity_id"] == 4 and f["severity"] == "High"
          and f["metadata"]["product"]["name"] == "Angerona"
          and f["attacks"] and f["attacks"][0]["technique"]["uid"] == "T1071"
          and any(o["name"] == "process.pid" and o["value"] == "6624" for o in f["observables"])
          and any(o["name"] == "dst_endpoint.ip" and o["value"] == "8.8.8.8" for o in f["observables"]))
    return ok, ("OCSF Detection Finding mapping verified (class 2004, severity, "
                "attack technique, observables)" if ok else f"failed: {f}")
