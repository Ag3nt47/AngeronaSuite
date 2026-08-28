"""core/cve_fix_advisor.py — local-AI CVE analysis + inert proposal staging.

For each host-applicable CVE, ask the LOCAL model (Ollama / llama3) to compare
the vulnerability against this machine's system info and decide whether a
*specific, actionable* fix (concrete PowerShell + a matching revert) is possible.

    analyze(cve_rec)  -> {
        "cve", "fix_available": bool, "confidence": 0..1,
        "summary", "instructions",
        "fix_script": "<powershell>",       # "" if none
        "revert_script": "<powershell>",    # "" if none
        "reason"                            # why no fix, when fix_available False
    }

If a potential fix is available, the GUI can stage the exact model-authored text
as a ``.ps1.txt`` review artifact. ``apply_fix()`` and ``revert_fix()`` never run
that text. Executable remediation must be converted to a registered typed
operation with its own authorization, postcondition, and receipt.

Local-first: the only network call is to 127.0.0.1 Ollama. Cloud escalation is
NOT done here — that stays behind the dashboard's explicit "Consult AI" button.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import stat
import subprocess
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Callable

from angerona.core.url_policy import (
    OLLAMA_SERVICE_POLICY,
    local_service_url,
    read_bounded,
    safe_urlopen,
)
from angerona.core.ollama_lifecycle import effective_keep_alive

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
_MODEL = os.environ.get("ANGERONA_MODEL", "llama3")
_CVE_ID = re.compile(r"CVE-(?:1999|2[0-9]{3})-[0-9]{4,}")
_APPLIED_LOCK = threading.RLock()
_APPLIED_MAX_BYTES = 8 * 1024 * 1024

_SYSTEM_PROMPT = (
    "You are a Windows security remediation engineer. Given a CVE and a host's "
    "system info, decide if a SPECIFIC, SAFE, host-applicable fix exists. Only claim "
    "a fix if you can give concrete PowerShell that a normal admin could run AND a "
    "matching revert. If the CVE is too vague, needs a vendor patch you can't script, "
    "or doesn't clearly apply, say no fix. Never suggest destructive or offensive "
    "actions. Respond with STRICT JSON only, no prose, using exactly these keys: "
    '{"fix_available": bool, "confidence": number 0..1, "summary": string, '
    '"instructions": string, "fix_script": string, "revert_script": string, '
    '"reason": string}.'
)


def _repo_root() -> Path:
    from angerona.core.data_paths import data_dir
    return data_dir()


def _canonical_cve(value: object) -> str | None:
    """Return a canonical CVE identifier, rejecting path-like or loose input."""
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    return candidate if _CVE_ID.fullmatch(candidate) else None


def _resolved_staging_dir() -> Path:
    """Create and attest the proposal directory beneath Angerona's data root."""
    root = Path(_repo_root()).resolve(strict=False)
    root.mkdir(parents=True, exist_ok=True)
    requested = root / "staged_remediation"
    requested.mkdir(parents=True, exist_ok=True)
    staged = requested.resolve(strict=True)
    if staged != requested:
        raise ValueError("staged remediation directory resolves outside the data root")
    return staged


def _same_regular_proposal(path: Path, script: str) -> bool:
    """Permit an idempotent retry, but never accept a link or changed artifact."""
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            return False
        return path.read_text(encoding="utf-8") == script
    except (OSError, UnicodeError):
        return False


def _stage_proposal(cve: str, script: str, digest: str, *, revert: bool = False) -> Path:
    """Publish a complete review artifact with exclusive, atomic creation."""
    staged = _resolved_staging_dir()
    marker = "-revert" if revert else ""
    target = staged / f"{cve}{marker}-{digest[:12]}.ps1.txt"
    if target.resolve(strict=False).parent != staged:
        raise ValueError("proposal path resolves outside the staging directory")
    if target.exists() or target.is_symlink():
        if _same_regular_proposal(target, script):
            return target
        raise FileExistsError("proposal path already exists with different or unsafe content")

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".angerona-proposal-", suffix=".tmp", dir=str(staged)
    )
    temporary = Path(temporary_name)
    try:
        if temporary.resolve(strict=True).parent != staged:
            raise ValueError("temporary proposal resolves outside the staging directory")
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            descriptor = -1
            handle.write(script)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            # A hard link exposes the already-complete inode and fails if the
            # final content-addressed name was claimed concurrently.
            os.link(temporary, target)
        except FileExistsError:
            if not _same_regular_proposal(target, script):
                raise
        if target.resolve(strict=True).parent != staged or not _same_regular_proposal(target, script):
            raise ValueError("published proposal failed staging containment checks")
        return target
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _applied_path() -> Path:
    return _repo_root() / "shared_logs" / "cve_fixes_applied.json"


def system_info() -> dict:
    """Compact host facts to give the model context (read-only)."""
    info = {
        "os": platform.platform(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "arch": platform.machine(),
        "hostname": platform.node(),
    }
    if psutil is not None:
        try:
            names = sorted({(p.info.get("name") or "").lower()
                            for p in psutil.process_iter(["name"]) if p.info.get("name")})
            # a bounded sample of running software helps the model judge applicability
            info["running_processes_sample"] = names[:60]
        except Exception:
            pass
    return info


def ollama_available() -> bool:
    try:
        req = urllib.request.Request(local_service_url(_HOST, "/api/tags"))
        with safe_urlopen(req, policy=OLLAMA_SERVICE_POLICY, timeout=4) as r:
            return r.status == 200
    except Exception:
        return False


def _extract_json(text: str) -> dict | None:
    if not text:
        return None
    # tolerate models that wrap JSON in prose / code fences
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


# ── A-03 hardening: destructive-command denylist ─────────────────────────────
# A "fix" that deletes data, wipes recovery, disables AV, or adds accounts is
# never auto-offered — even behind the confirm dialog — because a poisoned CVE
# feed could steer the model. Matches are refused with a clear reason.
_DESTRUCTIVE_PS = (
    "remove-item", "rd /s", "rmdir /s", "del /f", "format-volume", "format ",
    "clear-disk", "vssadmin delete", "wbadmin delete", "bcdedit",
    "set-mppreference -disable", "add-mppreference -exclusion",
    "disable-computerrestore", "cipher /w", "new-localuser", "net user ",
    "add-localgroupmember", "set-executionpolicy unrestricted",
    "invoke-expression", "iex ", "downloadstring", "start-bitstransfer",
    "reg delete", "stop-service", "uninstall-", "-encodedcommand",
    # Defense weakening / persistence / remote execution. These can be harmful
    # even though they do not look like data-deletion cmdlets.
    "enablelua' -value 0", 'enablelua" -value 0', "enablelua -value 0",
    "disablerealtimemonitoring $true", "disablebehaviormonitoring $true",
    "disableioavprotection $true", "disableintrusionpreventionsystem $true",
    "new-scheduledtask", "register-scheduledtask", "schtasks /create",
    "new-service", "sc.exe create", "win32_startupcommand",
    "currentversion\\run", "currentversion\\runonce",
    "invoke-command", "enter-pssession", "new-pssession",
    "set-netfirewallprofile -enabled false", "disable-netfirewallrule",
    # WMI/CIM access and process/member actions are never acceptable in an
    # AI-authored remediation. These precise tokens close the demonstrated
    # Terminate()/SetState() bypass without relying on process-name matching.
    "get-wmiobject", "gwmi ", "invoke-wmimethod", "[wmiclass]",
    "get-ciminstance", "gcim ", "invoke-cimmethod",
)

_DESTRUCTIVE_PS_REGEX = (
    (re.compile(r"\.\s*terminate\s*\(", re.IGNORECASE), "member:Terminate()"),
    (re.compile(r"\.\s*setstate\s*\(", re.IGNORECASE), "member:SetState()"),
    (re.compile(r"\bwin32_process\b", re.IGNORECASE), "class:Win32_Process"),
)


def scan_powershell(script: str) -> list[str]:
    """Return the destructive constructs found in *script* (empty = clean)."""
    low = (script or "").lower()
    found = [p for p in _DESTRUCTIVE_PS if p in low]
    found.extend(label for pattern, label in _DESTRUCTIVE_PS_REGEX
                 if pattern.search(script or ""))
    return list(dict.fromkeys(found))


_CONTAINMENT_PARAMETERS = {
    "displayname", "group", "direction", "remoteaddress", "localaddress",
    "remoteport", "localport", "protocol", "program", "service", "action",
    "profile", "enabled", "erroraction",
}
_CONTAINMENT_PARAM = re.compile(
    r"\s*-(?P<name>[A-Za-z][A-Za-z0-9]*)\s+"
    r"(?P<value>'[^']*'|\"[^\"]*\"|[^\s]+)"
)


def validate_containment_powershell(script: str) -> list[str]:
    """Strictly validate a generated network-containment playbook.

    Only independent ``New-NetFirewallRule`` commands with a bounded parameter
    set are accepted. Dynamic invocation, variables, member calls, pipelines,
    aliases, WMI/CIM, script blocks and command chaining therefore fail closed.
    Comments and blank lines are ignored.
    """
    problems: list[str] = []
    commands = 0
    for lineno, raw in enumerate((script or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        commands += 1
        if re.search(r"[|;&`{}$@()\[\]<>]", line):
            problems.append(f"line {lineno}: dynamic or chained syntax")
            continue
        match = re.match(r"(?i)^New-NetFirewallRule\b", line)
        if not match:
            command = line.split(None, 1)[0]
            problems.append(f"line {lineno}: command {command!r} is not allowed")
            continue
        rest = line[match.end():]
        pos = 0
        params: dict[str, str] = {}
        while pos < len(rest):
            pm = _CONTAINMENT_PARAM.match(rest, pos)
            if not pm:
                problems.append(f"line {lineno}: malformed parameter list")
                break
            name = pm.group("name").lower()
            value = pm.group("value")
            if value[:1] in {"'", '"'}:
                value = value[1:-1]
            if name not in _CONTAINMENT_PARAMETERS:
                problems.append(f"line {lineno}: parameter -{pm.group('name')} is not allowed")
            elif name in params:
                problems.append(f"line {lineno}: duplicate -{pm.group('name')}")
            else:
                params[name] = value
            pos = pm.end()

        required = {"displayname", "group", "direction", "action"}
        missing = sorted(required - params.keys())
        if missing:
            problems.append(f"line {lineno}: missing {', '.join('-' + p for p in missing)}")
            continue
        if not params["displayname"].startswith("Angerona-Dyn-"):
            problems.append(f"line {lineno}: DisplayName must start with Angerona-Dyn-")
        if params["group"] != "Angerona-SOAR":
            problems.append(f"line {lineno}: Group must be Angerona-SOAR")
        if params["direction"].lower() not in {"inbound", "outbound"}:
            problems.append(f"line {lineno}: invalid Direction")
        action = params["action"].lower()
        if action not in {"block", "allow"}:
            problems.append(f"line {lineno}: invalid Action")
        if action == "allow" and params.get("remoteaddress", "").lower() not in {
            "127.0.0.1", "::1"
        }:
            problems.append(f"line {lineno}: Allow is restricted to loopback")
        if "erroraction" in params and params["erroraction"].lower() != "silentlycontinue":
            problems.append(f"line {lineno}: ErrorAction must be SilentlyContinue")
    if not commands:
        problems.append("playbook contains no commands")
    return problems


def _normalize(cve: str, raw: dict | None) -> dict:
    raw = raw or {}
    fix_script = str(raw.get("fix_script") or "").strip()
    fa = bool(raw.get("fix_available")) and bool(fix_script)
    reason = str(raw.get("reason") or "").strip()
    # Refuse destructive fixes outright (A-03).
    danger = scan_powershell(fix_script) if fix_script else []
    if danger:
        fa = False
        reason = ("Refused: proposed fix contains destructive/high-risk commands "
                  f"({', '.join(danger)}). Apply manually after review if truly needed.")
    try:
        conf = float(raw.get("confidence", 0) or 0)
    except Exception:
        conf = 0.0
    return {
        "cve": cve,
        "fix_available": fa,
        "confidence": max(0.0, min(1.0, conf)),
        "summary": str(raw.get("summary") or "").strip(),
        "instructions": str(raw.get("instructions") or "").strip(),
        "fix_script": fix_script,
        "revert_script": str(raw.get("revert_script") or "").strip(),
        "reason": reason,
        "blocked_destructive": bool(danger),
    }


def analyze(cve_rec: dict, timeout: float = 90.0) -> dict:
    """Ask local llama3 whether a scriptable fix exists for this CVE on this host."""
    raw_cve = (cve_rec.get("cve") or cve_rec.get("cveID") or "") \
        if isinstance(cve_rec, dict) else ""
    cve = _canonical_cve(raw_cve)
    if cve is None:
        return {**_normalize("", None),
                "reason": "Invalid CVE identifier; expected CVE-YYYY-NNNN or longer."}
    if not ollama_available():
        return {**_normalize(cve, None), "reason": "Local AI (Ollama) unavailable — "
                "start Ollama or use 'Consult AI' for an online analysis."}
    facts = json.dumps({
        "cve": cve,
        "name": cve_rec.get("name"),
        "vendor": cve_rec.get("vendor"),
        "product": cve_rec.get("product"),
        "cisa_required_action": cve_rec.get("remediation"),
        "mitre": cve_rec.get("mitre"),
        "system_info": system_info(),
    }, indent=2)
    payload = json.dumps({
        "model": _MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": facts},
        ],
        "stream": False,
        "format": "json",
        "keep_alive": effective_keep_alive("30m"),
        "options": {"temperature": 0},
    }).encode("utf-8")
    req = urllib.request.Request(local_service_url(_HOST, "/api/chat"), data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with safe_urlopen(
            req, policy=OLLAMA_SERVICE_POLICY, timeout=timeout
        ) as resp:
            data = json.loads(read_bounded(resp).decode("utf-8"))
        content = (data.get("message", {}) or {}).get("content", "")
        return _normalize(cve, _extract_json(content))
    except Exception as exc:
        return {**_normalize(cve, None),
                "reason": f"Local AI analysis failed: {exc}"}


# ── stage / rollback-proposal (model-authored text is never executed) ─────────

def _run_powershell(script: str, timeout: float = 120.0) -> tuple[int, str]:
    """Compatibility guard: arbitrary model-authored PowerShell is forbidden."""
    return 1, (
        "Refused: arbitrary PowerShell execution was removed. Convert the "
        "reviewed proposal to a registered PowerShellBoundary operation."
    )


def _read_applied_unlocked() -> dict:
    p = _applied_path()
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(os.fspath(p), flags)
    except FileNotFoundError:
        return {}
    except OSError:
        return {}
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _APPLIED_MAX_BYTES:
            return {}
        chunks: list[bytes] = []
        remaining = _APPLIED_MAX_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > _APPLIED_MAX_BYTES:
            return {}
        decoded = json.loads(raw.decode("utf-8"))
        return decoded if isinstance(decoded, dict) else {}
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    finally:
        os.close(descriptor)


def _load_applied() -> dict:
    with _APPLIED_LOCK:
        return _read_applied_unlocked()


def _write_applied_unlocked(data: dict) -> None:
    p = _applied_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    if p.is_symlink() or p.parent.is_symlink():
        raise OSError("CVE proposal ledger path is redirected")
    payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
    if len(payload) > _APPLIED_MAX_BYTES:
        raise OSError("CVE proposal ledger exceeds its size bound")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".angerona-cve-ledger-", suffix=".tmp", dir=str(p.parent)
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, p)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _save_applied(data: dict) -> None:
    with _APPLIED_LOCK:
        _write_applied_unlocked(data)


def _update_applied(cve: str, update: Callable[[dict], dict]) -> dict:
    """Atomically update one CVE record without losing concurrent records."""
    with _APPLIED_LOCK:
        data = _read_applied_unlocked()
        current = data.get(cve)
        record = update(dict(current) if isinstance(current, dict) else {})
        data[cve] = record
        _write_applied_unlocked(data)
        return dict(record)


def applied_state(cve: str) -> dict | None:
    canonical = _canonical_cve(cve)
    return _load_applied().get(canonical) if canonical else None


def apply_fix(cve: str, analysis: dict) -> dict:
    """Stage an AI proposal for review; never execute model-generated script.

    Executable remediation must be expressed as a registered typed operation
    through ``PowerShellBoundary``. A deny-list scan is useful triage but is
    not an authority boundary for arbitrary model output.
    """
    canonical = _canonical_cve(cve)
    if canonical is None:
        return {"ok": False, "output":
                "Invalid CVE identifier; expected CVE-YYYY-NNNN or longer."}
    cve = canonical
    if not isinstance(analysis, dict):
        return {"ok": False, "output": "Invalid remediation analysis."}
    script = str(analysis.get("fix_script") or "").strip()
    if not script:
        return {"ok": False, "output": "No fix script to apply."}
    danger = scan_powershell(script)
    if danger:
        return {"ok": False, "output": "Refused: destructive/high-risk commands "
                f"in fix ({', '.join(danger)}). Not executed."}
    digest = hashlib.sha256(script.encode("utf-8")).hexdigest()
    try:
        staged_path = _stage_proposal(cve, script, digest)
    except (OSError, ValueError) as exc:
        return {"ok": False, "output": f"Proposal staging refused: {exc}"}
    out = (
        "Proposal staged for review; it was not executed. Convert approved "
        "steps to registered PowerShellBoundary operations."
    )
    record = {
        "applied": False,
        "staged": True,
        "executed": False,
        "verified": False,
        "staged_ts": time.time(),
        "staged_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
        "proposal_sha256": digest,
        "proposal_path": str(staged_path),
        "summary": analysis.get("summary", ""),
        "revert_script": analysis.get("revert_script", ""),
        "last_output": out[:4000],
        "reverted": False,
    }
    try:
        _update_applied(cve, lambda _current: record)
    except OSError as exc:
        return {"ok": False, "output": f"Proposal ledger update refused: {exc}"}
    return {
        "ok": True, "staged": True, "executed": False,
        "proposal_sha256": digest, "proposal_path": str(staged_path),
        "output": out,
    }


def revert_fix(cve: str) -> dict:
    """Stage a revert proposal; never execute stored model-generated script."""
    canonical = _canonical_cve(cve)
    if canonical is None:
        return {"ok": False, "output":
                "Invalid CVE identifier; expected CVE-YYYY-NNNN or longer."}
    cve = canonical
    data = _load_applied()
    rec = data.get(cve)
    if not rec:
        return {"ok": False, "output": "No staged remediation record exists for this CVE."}
    script = (rec.get("revert_script") or "").strip()
    if not script:
        return {"ok": False, "output": "No revert script was captured for this fix."}
    danger = scan_powershell(script)
    if danger:
        return {"ok": False, "output": "Refused: destructive/high-risk commands "
                f"in revert ({', '.join(danger)}). Not executed."}
    digest = hashlib.sha256(script.encode("utf-8")).hexdigest()
    try:
        staged_path = _stage_proposal(cve, script, digest, revert=True)
    except (OSError, ValueError) as exc:
        return {"ok": False, "output": f"Revert proposal staging refused: {exc}"}
    out = (
        "Revert proposal staged for review; it was not executed. Convert "
        "approved steps to registered PowerShellBoundary operations."
    )
    changes = {
        "reverted": False,
        "revert_staged": True,
        "revert_executed": False,
        "revert_verified": False,
        "revert_staged_ts": time.time(),
        "revert_proposal_sha256": digest,
        "revert_proposal_path": str(staged_path),
        "last_output": out[:4000],
    }
    try:
        _update_applied(cve, lambda current: {**current, **changes})
    except OSError as exc:
        return {"ok": False, "output": f"Proposal ledger update refused: {exc}"}
    return {
        "ok": True, "staged": True, "executed": False,
        "proposal_sha256": digest, "proposal_path": str(staged_path),
        "output": out,
    }


def self_test() -> tuple[bool, str]:
    """Offline: JSON extraction + normalization + no-Ollama path (no host change)."""
    good = _extract_json('noise before {"fix_available": true, "confidence": 0.8, '
                         '"summary":"disable svc","instructions":"do x",'
                         '"fix_script":"Set-Service foo -StartupType Disabled",'
                         '"revert_script":"Set-Service foo -StartupType Automatic",'
                         '"reason":""} trailing prose')
    n = _normalize("CVE-2024-0001", good)
    empty = _normalize("CVE-2024-0002", {"fix_available": True, "fix_script": ""})  # no script ⇒ not available
    # A-03: a destructive "fix" must be refused even when the model marks it available.
    danger = _normalize("CVE-2024-0003", {"fix_available": True, "confidence": 0.9,
                                       "fix_script": "Remove-Item C:\\Windows -Recurse -Force"})
    weaken = _normalize("CVE-2024-0004", {"fix_available": True, "confidence": 0.9,
        "fix_script": "Set-ItemProperty -Path 'HKLM:\\x' -Name 'EnableLUA' -Value 0"})
    persist = scan_powershell(
        "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name x -Value y")
    wmi = scan_powershell(
        "Get-WmiObject Win32_Process | ForEach-Object { $_.Terminate() }")
    safe_containment = validate_containment_powershell(
        "New-NetFirewallRule -DisplayName 'Angerona-Dyn-Test' -Group "
        "'Angerona-SOAR' -Direction Outbound -RemoteAddress Any -Action Block "
        "-ErrorAction SilentlyContinue")
    unsafe_containment = validate_containment_powershell(
        "Get-CimInstance Win32_Process | ForEach-Object { $_.SetState(0) }")
    ok = (n["fix_available"] is True and 0.79 < n["confidence"] < 0.81
          and n["fix_script"].startswith("Set-Service")
          and n["revert_script"].startswith("Set-Service")
          and empty["fix_available"] is False
          and danger["fix_available"] is False and danger["blocked_destructive"] is True
          and weaken["fix_available"] is False and weaken["blocked_destructive"] is True
          and "currentversion\\run" in persist
          and "get-wmiobject" in wmi and "member:Terminate()" in wmi
          and not safe_containment and bool(unsafe_containment)
          and scan_powershell("vssadmin delete shadows") == ["vssadmin delete"])
    return ok, ("JSON parse + normalize + destructive and containment guardrails verified"
                if ok else f"failed: n={n} empty={empty} danger={danger}")
