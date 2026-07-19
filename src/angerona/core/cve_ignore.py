"""core/cve_ignore.py — analyst "ignore" list for CVEs, with revertable history.

Some host-applicable CVEs are too vague to action, or have no fix available.
Leaving them in the feed keeps the dashboard (and the threat level) screaming
HIGH/CRITICAL about things the operator can't do anything about. This module
lets the analyst **ignore** a specific CVE: it's flagged and kept in memory
(never silently dropped), removed from threat-level consideration, and can be
**reverted** at any time. Every ignore/revert is recorded in a per-CVE history.

Single JSON store at ``shared_logs/cve_ignore.json``:

    { "CVE-2024-1234": {
        "ignored": true,
        "reason": "no fix available",
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


def is_ignored(cve: str, data: dict | None = None) -> bool:
    data = load() if data is None else data
    rec = data.get(_norm(cve))
    return bool(rec and rec.get("ignored"))


def ignored_set(data: dict | None = None) -> set[str]:
    """All currently-ignored CVE IDs."""
    data = load() if data is None else data
    return {cid for cid, rec in data.items() if rec.get("ignored")}


def ignore(cve: str, reason: str = "") -> dict:
    """Flag *cve* as ignored (idempotent); append a history entry. Returns the record."""
    cve = _norm(cve)
    if not cve:
        raise ValueError("empty CVE id")
    with _LOCK:
        data = load()
        rec = data.setdefault(cve, {"ignored": False, "reason": "", "history": []})
        rec["ignored"] = True
        rec["reason"] = reason or rec.get("reason", "")
        rec["history"].append(_event("ignore", reason))
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


def _event(action: str, reason: str) -> dict:
    now = time.time()
    return {"action": action, "ts": now,
            "iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
            "reason": reason or ""}


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
            ignore(cve, "no fix available")
            a = is_ignored(cve)
            matches = [{"cve": cve}, {"cve": "CVE-2024-0001"}]
            active_after_ignore, ignored_after = counts(matches)
            revert(cve, "changed my mind")
            b = is_ignored(cve)
            hist = history(cve)
            ok = (a is True and b is False and active_after_ignore == 1
                  and ignored_after == 1 and len(hist) == 2
                  and hist[0]["action"] == "ignore" and hist[1]["action"] == "revert")
            return ok, ("ignore/revert/history + active filtering verified"
                        if ok else f"failed: a={a} b={b} active={active_after_ignore} hist={hist}")
        finally:
            _store_path = orig  # type: ignore
