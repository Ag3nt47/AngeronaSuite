"""core/cve_ignore.py — expiring CVE applicability exclusions with history.

Only a verified host-correlation false positive may leave threat scoring. A
missing fix, accepted risk, compensating control, or AI outage is not an
applicability decision and remains active. Exclusions require a rationale,
approver identifier, and future expiry; legacy/untyped ignore records fail safe
and no longer suppress a CISA KEV.

Single JSON store at ``shared_logs/cve_ignore.json``:

    { "CVE-2024-1234": {
        "ignored": true, "classification": "not_applicable",
        "reason": "product not installed", "expires_at": 1234567890,
        "approver": "analyst-id",
        "history": [ {"action":"ignore","ts":...,"iso":"...","reason":"..."},
                     {"action":"revert","ts":...,"iso":"...","reason":""} ] } }

Read/modified by the GUI (Threat Intel dashboard) and read by the INTL module
so ignored CVEs stop raising the threat level. Local-only; no network.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_LOCK = threading.Lock()


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _store_path() -> Path:
    return _repo_root() / "shared_logs" / "cve_ignore.json"


def load() -> dict:
    """Return the whole ignore store ({} if missing/invalid)."""
    p = _store_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save(data: dict) -> None:
    p = _store_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _norm(cve: str) -> str:
    return (cve or "").strip().upper()


def _is_active_exclusion(rec: dict | None, now: float | None = None) -> bool:
    """Fail closed unless a typed, approved exclusion is still in force."""
    if not isinstance(rec, dict) or not rec.get("ignored"):
        return False
    if rec.get("classification") != "not_applicable":
        return False
    if not str(rec.get("reason", "")).strip() or not str(rec.get("approver", "")).strip():
        return False
    try:
        expiry = float(rec.get("expires_at", 0))
    except (TypeError, ValueError):
        return False
    return expiry > (time.time() if now is None else now)


def is_ignored(cve: str, data: dict | None = None) -> bool:
    """True only for a current, typed ``not_applicable`` exclusion."""
    data = load() if data is None else data
    return _is_active_exclusion(data.get(_norm(cve)))


def ignored_set(data: dict | None = None) -> set[str]:
    """All currently-ignored CVE IDs."""
    data = load() if data is None else data
    return {cid for cid, rec in data.items() if _is_active_exclusion(rec)}


def ignore(
    cve: str,
    reason: str,
    *,
    classification: str,
    expires_at: float,
    approver: str,
) -> dict:
    """Exclude a verified non-applicable CVE until a bounded future expiry.

    The intentionally strict signature prevents callers from turning AI/no-fix
    outcomes into a posture suppression without supplying the audit contract.
    """
    cve = _norm(cve)
    if not cve:
        raise ValueError("empty CVE id")
    reason = (reason or "").strip()
    approver = (approver or "").strip()
    if classification != "not_applicable":
        raise ValueError("only not_applicable findings may leave threat scoring")
    if not reason:
        raise ValueError("not-applicable evidence is required")
    if not approver:
        raise ValueError("approver identifier is required")
    try:
        expires_at = float(expires_at)
    except (TypeError, ValueError) as exc:
        raise ValueError("valid exclusion expiry is required") from exc
    now = time.time()
    if expires_at <= now:
        raise ValueError("exclusion expiry must be in the future")
    with _LOCK:
        data = load()
        rec = data.setdefault(cve, {"ignored": False, "reason": "", "history": []})
        rec["ignored"] = True
        rec["classification"] = classification
        rec["reason"] = reason
        rec["approver"] = approver
        rec["expires_at"] = expires_at
        rec["history"].append(_event(
            "ignore", reason, classification=classification,
            expires_at=expires_at, approver=approver,
        ))
        _save(data)
        return rec


def revert(cve: str, reason: str = "") -> dict:
    """Un-ignore *cve* (idempotent); append a history entry. Returns the record."""
    cve = _norm(cve)
    with _LOCK:
        data = load()
        rec = data.setdefault(cve, {"ignored": False, "reason": "", "history": []})
        rec["ignored"] = False
        rec["history"].append(_event("revert", reason))
        _save(data)
        return rec


def history(cve: str) -> list[dict]:
    return load().get(_norm(cve), {}).get("history", [])


def filter_active(matches: list[dict]) -> list[dict]:
    """Return only matches whose CVE is NOT ignored (for threat-level counting)."""
    ig = ignored_set()
    out = []
    for m in matches:
        cid = _norm(m.get("cve") or m.get("cveID") or "")
        if cid and cid in ig:
            continue
        out.append(m)
    return out


def counts(matches: list[dict]) -> tuple[int, int]:
    """(active, ignored) counts over a match list."""
    active = len(filter_active(matches))
    return active, len(matches) - active


def _event(action: str, reason: str, **audit) -> dict:
    now = time.time()
    event = {"action": action, "ts": now,
             "iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
             "reason": reason or ""}
    event.update(audit)
    return event


def self_test() -> tuple[bool, str]:
    """Round-trip ignore→revert against an isolated temp store."""
    import tempfile
    global _store_path
    orig = _store_path
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "shared_logs").mkdir()
        _store_path = lambda: Path(td) / "shared_logs" / "cve_ignore.json"  # type: ignore
        try:
            cve = "CVE-2024-9999"
            ignore(cve, "sample product is not installed", classification="not_applicable",
                   expires_at=time.time() + 60, approver="self-test")
            a = is_ignored(cve)
            matches = [{"cve": cve}, {"cve": "CVE-2024-0001"}]
            active_after_ignore, ignored_after = counts(matches)
            revert(cve, "changed my mind")
            b = is_ignored(cve)
            hist = history(cve)
            legacy = {"ignored": True, "reason": "no fix available", "history": []}
            expired = {"ignored": True, "classification": "not_applicable",
                       "reason": "old evidence", "approver": "self-test",
                       "expires_at": time.time() - 1, "history": []}
            ok = (a is True and b is False and active_after_ignore == 1
                  and ignored_after == 1 and len(hist) == 2
                  and hist[0]["action"] == "ignore" and hist[1]["action"] == "revert"
                  and not _is_active_exclusion(legacy)
                  and not _is_active_exclusion(expired))
            return ok, ("typed expiry + ignore/revert/history + active filtering verified"
                        if ok else f"failed: a={a} b={b} active={active_after_ignore} hist={hist}")
        finally:
            _store_path = orig  # type: ignore
