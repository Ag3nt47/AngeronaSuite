"""core/cve_fix_advisor.py — local-AI CVE fix analysis + gated apply/revert.

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

If a fix is available the GUI shows ❗ "Potential fix available" with an Action
button. Applying is **confirm-then-execute**: the caller shows the exact commands,
and only on approval calls apply_fix(), which runs the PowerShell and records an
applied-state entry (plus the AI's revert script) so revert_fix() can undo it.

Local-first: the only network call is to 127.0.0.1 Ollama. Cloud escalation is
NOT done here — that stays behind the dashboard's explicit "Consult AI" button.
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import time
import urllib.request
from pathlib import Path

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
_MODEL = os.environ.get("ANGERONA_MODEL", "llama3")

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
        req = urllib.request.Request(f"{_HOST}/api/tags")
        with urllib.request.urlopen(req, timeout=4) as r:
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
    cve = (cve_rec.get("cve") or cve_rec.get("cveID") or "").strip()
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
        "keep_alive": "30m",
        "options": {"temperature": 0},
    }).encode("utf-8")
    req = urllib.request.Request(f"{_HOST}/api/chat", data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content = (data.get("message", {}) or {}).get("content", "")
        return _normalize(cve, _extract_json(content))
    except Exception as exc:
        return {**_normalize(cve, None),
                "reason": f"Local AI analysis failed: {exc}"}


# ── apply / revert (confirm-then-execute; the GUI shows the commands first) ────

def _run_powershell(script: str, timeout: float = 120.0) -> tuple[int, str]:
    """Run a PowerShell script hidden; return (returncode, combined output)."""
    if os.name != "nt":
        return 1, "PowerShell execution is only available on Windows."
    try:
        from angerona.core.win import run_hidden  # hidden, no console flash
        cp = run_hidden(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout)
        out = (getattr(cp, "stdout", "") or "") + (getattr(cp, "stderr", "") or "")
        return getattr(cp, "returncode", 0), out.strip()
    except Exception as exc:
        try:  # fall back to a plain hidden subprocess if run_hidden signature differs
            cp = subprocess.run(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True, text=True, timeout=timeout)
            return cp.returncode, ((cp.stdout or "") + (cp.stderr or "")).strip()
        except Exception as exc2:
            return 1, f"execution error: {exc2 or exc}"


def _load_applied() -> dict:
    p = _applied_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_applied(data: dict) -> None:
    p = _applied_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def applied_state(cve: str) -> dict | None:
    return _load_applied().get((cve or "").strip().upper())


def apply_fix(cve: str, analysis: dict) -> dict:
    """Execute the AI's fix script (caller MUST have confirmed). Records applied
    state + the revert script so revert_fix() can undo it. Returns a result dict."""
    cve = (cve or "").strip().upper()
    script = (analysis or {}).get("fix_script", "").strip()
    if not script:
        return {"ok": False, "output": "No fix script to apply."}
    danger = scan_powershell(script)
    if danger:
        return {"ok": False, "output": "Refused: destructive/high-risk commands "
                f"in fix ({', '.join(danger)}). Not executed."}
    rc, out = _run_powershell(script)
    ok = rc == 0
    data = _load_applied()
    data[cve] = {
        "applied": ok,
        "applied_ts": time.time(),
        "applied_iso": time.strftime("%Y-%m-%d %H:%M:%S"),
        "summary": analysis.get("summary", ""),
        "fix_script": script,
        "revert_script": analysis.get("revert_script", ""),
        "last_output": out[:4000],
        "reverted": False,
    }
    _save_applied(data)
    return {"ok": ok, "returncode": rc, "output": out}


def revert_fix(cve: str) -> dict:
    """Run the stored revert script for a previously-applied CVE fix."""
    cve = (cve or "").strip().upper()
    data = _load_applied()
    rec = data.get(cve)
    if not rec:
        return {"ok": False, "output": "No applied fix recorded for this CVE."}
    script = (rec.get("revert_script") or "").strip()
    if not script:
        return {"ok": False, "output": "No revert script was captured for this fix."}
    danger = scan_powershell(script)
    if danger:
        return {"ok": False, "output": "Refused: destructive/high-risk commands "
                f"in revert ({', '.join(danger)}). Not executed."}
    rc, out = _run_powershell(script)
    ok = rc == 0
    rec["reverted"] = ok
    rec["reverted_ts"] = time.time()
    rec["reverted_iso"] = time.strftime("%Y-%m-%d %H:%M:%S")
    rec["last_output"] = out[:4000]
    _save_applied(data)
    return {"ok": ok, "returncode": rc, "output": out}


def self_test() -> tuple[bool, str]:
    """Offline: JSON extraction + normalization + no-Ollama path (no host change)."""
    good = _extract_json('noise before {"fix_available": true, "confidence": 0.8, '
                         '"summary":"disable svc","instructions":"do x",'
                         '"fix_script":"Set-Service foo -StartupType Disabled",'
                         '"revert_script":"Set-Service foo -StartupType Automatic",'
                         '"reason":""} trailing prose')
    n = _normalize("CVE-2024-1", good)
    empty = _normalize("CVE-2024-2", {"fix_available": True, "fix_script": ""})  # no script ⇒ not available
    # A-03: a destructive "fix" must be refused even when the model marks it available.
    danger = _normalize("CVE-2024-3", {"fix_available": True, "confidence": 0.9,
                                       "fix_script": "Remove-Item C:\\Windows -Recurse -Force"})
    weaken = _normalize("CVE-2024-4", {"fix_available": True, "confidence": 0.9,
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
