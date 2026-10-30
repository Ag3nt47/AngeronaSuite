"""Bounded, read-only host evidence for SpywareGuard.

These collectors inventory persistence and executable memory *metadata*. They
do not establish authorization, attribute spyware, inspect memory contents, or
intercept APIs. A missing or inaccessible source is reported as coverage loss.
"""
from __future__ import annotations

import ctypes
import json
import math
import os
import platform
import plistlib
import re
import stat
import subprocess
import time
from dataclasses import asdict, dataclass, fields
from itertools import islice
from pathlib import Path
from typing import Any, Callable, Iterable

from angerona.core.win import run_hidden

try:
    import winreg
except ImportError:  # pragma: no cover - platform import
    winreg = None

try:
    import psutil
except ImportError:  # pragma: no cover - optional dependency
    psutil = None

_MAX_ENTRIES = 4096
_MAX_TEXT = 4096
_MAX_FILE_BYTES = 256 * 1024
_MAX_WMI_BYTES = 4 * 1024 * 1024
_SOURCES = (
    "windows.run", "windows.services", "windows.wmi", "windows.com",
    "startup", "posix.launchd", "posix.systemd",
)
_RISK_PATH = re.compile(
    r"(?:%temp%|%tmp%|(?:^|[\\/\s\"'])temp[\\/]|[\\/]downloads[\\/]|"
    r"[\\/]users[\\/]public[\\/]|(?:^|[\s\"'])(?:/tmp|/var/tmp|/dev/shm)/)",
    re.IGNORECASE,
)
_HOST = re.compile(
    r"(?:^|[\\/\s\"'])(?:powershell|pwsh|mshta|rundll32|regsvr32|wscript|"
    r"cscript|cmd|bash|sh|python(?:\d(?:\.\d+)?)?)(?:\.exe)?(?:[\s\"']|$)",
    re.IGNORECASE,
)
_REMOTE = re.compile(r"(?:https?|ftp)://", re.IGNORECASE)
_TOKENS = re.compile(r'''(?:[^\s"']+|"[^"\r\n]*"|'[^'\r\n]*')+''')


def _command_parts(command: str) -> tuple[str, str]:
    """Separate an executable from arguments without treating log paths as code.

    This is deliberately a metadata parser, not a shell evaluator. Unquoted
    Windows executable paths containing spaces are retained for exposure review.
    """
    command = _text(command).strip()
    if not command:
        return "", ""
    if command[0] in {'"', "'"}:
        end = command.find(command[0], 1)
        if end != -1:
            return command[1:end], command[end + 1:].strip()
    windows_path = re.match(r"(?i)^((?:[a-z]:[\\/]|\\\\|%[^%]+%[\\/]).*?\.(?:exe|com|dll))(?=\s|$)", command)
    if windows_path:
        return windows_path[1], command[windows_path.end():].strip()
    pieces = command.split(None, 1)
    return pieces[0], pieces[1] if len(pieces) > 1 else ""


def _execution_host(executable: str) -> str:
    basename = executable.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return basename.removesuffix(".exe") if _HOST.fullmatch(basename) else ""


def _unquote(token: str) -> str:
    return token[1:-1] if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"} else token


def _execution_analysis(command: str, *, depth: int = 0) -> dict[str, Any]:
    """Bounded metadata parsing; unsupported shell syntax stays UNKNOWN."""
    executable, arguments = _command_parts(command)
    host = _execution_host(executable)
    matches = list(_TOKENS.finditer(arguments))
    tokens = [_unquote(match[0]) for match in matches]
    payloads: list[str] = []
    result = {"executable": executable, "targets": payloads, "host": host,
              "remote": False, "encoded": False, "ambiguous": executable.startswith(('"', "'")), "inline": ""}
    if host in {"powershell", "pwsh"}:
        index = 0
        while index < len(tokens):
            token = tokens[index]
            switch = token.lower().lstrip("-/")
            if token.startswith(("-", "/")) and switch and "file".startswith(switch):
                if index + 1 < len(tokens):
                    payloads.append(tokens[index + 1])
                    result["ambiguous"] = tokens[index + 1] == "-"
                else:
                    result["ambiguous"] = True
                break
            if token.startswith(("-", "/")) and switch and ("encodedcommand".startswith(switch) or switch == "ec"):
                result["encoded"] = index + 1 < len(tokens)
                result["ambiguous"] = not result["encoded"]
                break
            if token.startswith(("-", "/")) and switch and "command".startswith(switch):
                expression = _unquote(arguments[matches[index].end():].strip()).strip()
                result["inline"] = expression
                invocation = re.match(r"(?is)^(?:[&.]\s+|start-process\s+(?:-filepath\s+)?)(.+)$", expression)
                if invocation:
                    target, _ = _command_parts(invocation[1])
                    payloads.append(target)
                elif re.match(r"(?i)^(?:[a-z]:[\\/]|/|\.{1,2}[\\/])", expression):
                    target, _ = _command_parts(expression)
                    payloads.append(target)
                else:
                    result["ambiguous"] = True
                result["remote"] = bool(_REMOTE.search(expression) and re.match(
                    r"(?is)^(?:iex|invoke-expression|invoke-webrequest|iwr|curl|wget)\b", expression))
                break
            value_option = switch in {"ep", "if", "of", "wd", "ea"} or any(
                len(switch) >= len(minimum) and name.startswith(switch)
                for name, minimum in (("executionpolicy", "ex"), ("windowstyle", "w"),
                    ("inputformat", "inp"), ("outputformat", "o"), ("workingdirectory", "wo"),
                    ("configurationname", "config"), ("configurationfile", "configurationf"),
                    ("settingsfile", "settings"), ("version", "v"), ("custompipename", "custom"),
                    ("psconsolefile", "psconsole"), ("encodedarguments", "encodeda")))
            if token.startswith(("-", "/")) and value_option:
                if index + 1 >= len(tokens):
                    result["ambiguous"] = True
                    break
                index += 2
                continue
            flag_option = any(len(switch) >= len(minimum) and name.startswith(switch)
                for name, minimum in (("noprofile", "nop"), ("noninteractive", "noni"),
                    ("nologo", "nol"), ("noexit", "noe"), ("sta", "sta"), ("mta", "mta")))
            if token.startswith(("-", "/")) and flag_option:
                index += 1
                continue
            if not token.startswith("-") and token.lower().endswith(".ps1"):
                payloads.append(token)  # implicit File form; following values are script arguments
            else:
                result["ambiguous"] = True
            break
    elif host in {"cmd", "sh", "bash"}:
        nested = re.match(r"(?is)^(?:/[dsqau]\s+)*[/-](?:c|k)\s*(.+)$", arguments)
        if nested:
            expression = nested[1].strip()
            if (expression.startswith('""') and expression.endswith('"')) or (
                    len(expression) >= 2 and expression[0] == expression[-1]
                    and expression[0] in {'"', "'"} and expression.count(expression[0]) == 2):
                expression = expression[1:-1]
            if depth >= 3:
                result["ambiguous"] = True
            else:
                child = _execution_analysis(expression, depth=depth + 1)
                payloads.extend([child["executable"], *child["targets"]])
                for key in ("remote", "encoded", "ambiguous", "inline"):
                    result[key] = child[key]
                result["ambiguous"] |= bool(re.search(r"[&|;`]|\$\(", expression))
        elif tokens and host in {"sh", "bash"} and not tokens[0].startswith("-"):
            payloads.append(tokens[0])
        else:
            result["ambiguous"] = True
    elif host:
        index = 0
        while index < len(tokens):
            token = tokens[index]
            if token.lower() in {"-c", "-command", "-encodedcommand", "-enc", "-m", "-"}:
                result["ambiguous"] = True
                break
            if host.startswith("python") and token in {"-W", "-X", "--check-hash-based-pycs"}:
                index += 2
                if index >= len(tokens):
                    result["ambiguous"] = True
                continue
            if host == "regsvr32" and token.lower().startswith("/i:"):
                payloads.append(_unquote(token[3:]))
                index += 1
                continue
            if token.startswith("-") or (token.startswith("/") and not host.startswith("python")):
                index += 1
                continue
            payloads.append(token.split(",", 1)[0] if host == "rundll32" else token)
            break
    result["remote"] |= any(_REMOTE.match(target) for target in payloads)
    result["ambiguous"] |= bool(host and not executable)
    return result


def _execution_paths(command: str) -> tuple[str, list[str]]:
    result = _execution_analysis(command)
    return result["executable"], result["targets"]


def _limit(value: int, maximum: int = _MAX_ENTRIES) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("collection bound must be a positive integer")
    return min(value, maximum)


def _text(value: object, limit: int = _MAX_TEXT) -> str:
    return str(value or "")[:limit]


def _coverage(status: str, detail: str = "", count: int = 0) -> dict[str, Any]:
    return {"status": status, "detail": _text(detail, 512), "count": count}


def _failure(exc: BaseException, count: int = 0) -> dict[str, Any]:
    denied = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5
    if psutil is not None and isinstance(exc, psutil.AccessDenied):
        denied = True
    return _coverage("access_denied" if denied else "error", type(exc).__name__ + ": " + str(exc), count)


def _merge_coverage(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Do not let a later traversal bound erase an earlier permission failure."""
    priority = {"complete": 0, "partial": 1, "error": 2, "access_denied": 3, "unsupported": 4}
    status = max((previous["status"], current["status"]), key=priority.__getitem__)
    details = list(dict.fromkeys(detail for detail in (previous["detail"], current["detail"]) if detail))
    return _coverage(status, "; ".join(details))


def _finding(record: dict[str, Any], kind: str, severity: str, reason: str) -> dict[str, Any]:
    return {
        "source": record.get("source", ""), "id": record.get("id", ""),
        "kind": kind, "severity": severity, "reason": reason,
        "evidence": dict(record), "response_authorized": False,
    }


def analyze_persistence(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Classify concrete risky combinations; unfamiliar software alone is inert."""
    findings: list[dict[str, Any]] = []
    for record in islice(records, _MAX_ENTRIES):
        command = _text(record.get("command"))
        source = record.get("source", "")
        script = _text(record.get("script"))
        analysis = _execution_analysis(command)
        executable, payloads = analysis["executable"], analysis["targets"]
        host = bool(analysis["host"])
        risky_path = any(_RISK_PATH.search(path) for path in (executable, *payloads)
                         if not path.startswith(('"', "'")))
        if analysis["encoded"] or ((host or source == "windows.wmi" and script)
                and "frombase64string" in (analysis["inline"] + " " + script).lower()):
            findings.append(_finding(record, "persistence_encoded_execution", "high",
                "Persistence launches an encoded interpreter command; review the decoded payload."))
        elif analysis["remote"] or source == "windows.wmi" and script and _REMOTE.search(script):
            findings.append(_finding(record, "persistence_remote_execution", "high",
                "Persistence combines a script/execution host with a remote URL."))
        elif host and risky_path:
            findings.append(_finding(record, "persistence_writable_script", "medium",
                "Persistence uses an interpreter or DLL host with a temporary/public/download path."))
        elif source == "windows.com" and risky_path:
            findings.append(_finding(record, "com_transient_server", "medium",
                "COM in-process server points into a temporary/public/download directory."))
        elif risky_path and any(re.search(r"\.(?:exe|dll|ps1|vbs|js|sh|py)$", path, re.I)
                                for path in (executable, *payloads)):
            findings.append(_finding(record, "persistence_transient_payload", "medium",
                "Configured startup command references a target in a temporary/public/download directory; execution is unverified."))
        elif source == "windows.services" and _unquoted_service_path(command):
            finding = _finding(record, "service_unquoted_path", "low",
                "Unquoted service executable contains spaces; review path permissions and service configuration.")
            finding.update(response_eligible=False, finding_kind="exposure",
                           eligibility_reason="configuration-only; writable prefix or execution not established")
            findings.append(finding)
        elif analysis["ambiguous"] or source == "windows.wmi" and script:
            finding = _finding(record, "persistence_parser_ambiguous", "low",
                "Persistence execution syntax could not be fully resolved; execution coverage is UNKNOWN and requires review.")
            finding.update(response_eligible=False, finding_kind="observation", coverage_status="partial",
                           eligibility_reason="unsupported or ambiguous shell syntax; no verified execution target")
            findings.append(finding)
    return findings


def _unquoted_service_path(command: str) -> bool:
    command = command.strip()
    if command.startswith('"'):
        return False
    match = re.match(r"(?i)^([a-z]:\\.*?\.exe)(?:\s|$)", command)
    return bool(match and " " in match.group(1))


def _collect_run(limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    status = _coverage("complete")
    for hive_name in ("HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"):
        # HKCU Run/RunOnce inherit shared HKCU\SOFTWARE semantics: WOW64
        # flags select the same key. Keep the first existing record identity.
        views = (("32", winreg.KEY_WOW64_32KEY),)
        if hive_name == "HKEY_LOCAL_MACHINE":
            views += (("64", winreg.KEY_WOW64_64KEY),)
        for view_name, view in views:
            for name in ("Run", "RunOnce"):
                key_name = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\" + name
                try:
                    with winreg.OpenKey(getattr(winreg, hive_name), key_name, 0, winreg.KEY_READ | view) as key:
                        count = winreg.QueryInfoKey(key)[1]
                        budget = min(count, max(0, limit - len(records)))
                        for index in range(budget):
                            entry, value, value_type = winreg.EnumValue(key, index)
                            records.append({"source": "windows.run", "id": f"{hive_name}:{view_name}:{name}:{entry}",
                                "command": _text(value), "registry_key": f"{hive_name}\\{key_name}",
                                "registry_value": _text(entry), "registry_view": view_name, "value_type": value_type})
                            if len(str(value)) > _MAX_TEXT:
                                status = _merge_coverage(status, _coverage("partial", "Registry command evidence was truncated"))
                        if count > budget:
                            status = _merge_coverage(status, _coverage("partial", "Run/RunOnce inventory reached entry bound"))
                except FileNotFoundError:
                    continue
                except OSError as exc:
                    status = _merge_coverage(status, _failure(exc))
    status["count"] = len(records)
    return records, status


def _collect_services(limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if psutil is None or not hasattr(psutil, "win_service_iter"):
        return [], _coverage("unsupported", "Windows service API unavailable")
    records: list[dict[str, Any]] = []
    status = _coverage("complete")
    try:
        for index, service in enumerate(islice(psutil.win_service_iter(), limit + 1)):
            if index == limit:
                status = _merge_coverage(status, _coverage("partial", "Service inventory reached entry bound"))
                break
            try:
                info = service.as_dict()
                records.append({"source": "windows.services", "id": _text(info.get("name")),
                    "command": _text(info.get("binpath")), "start_type": _text(info.get("start_type")),
                    "username": _text(info.get("username"))})
                if len(str(info.get("binpath") or "")) > _MAX_TEXT:
                    status = _merge_coverage(status, _coverage("partial", "Service command evidence was truncated"))
            except Exception as exc:
                status = _merge_coverage(status, _failure(exc))
    except Exception as exc:
        status = _merge_coverage(status, _failure(exc))
    status["count"] = len(records)
    return records, status


def _collect_wmi(limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    # The only subprocess is a fixed, bounded, noninteractive metadata query.
    # Use the OS binary by absolute path rather than resolving an untrusted PATH.
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    script = (
        "$ErrorActionPreference='Stop'; [Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false); "
        "$rows=@(Get-CimInstance -Namespace root/subscription "
        f"-ClassName __EventConsumer | Select-Object -First {limit + 1} | ForEach-Object {{ "
        "[pscustomobject]@{Name=([string]$_.Name).Substring(0,[Math]::Min(512,([string]$_.Name).Length));"
        "CommandLineTemplate=([string]$_.CommandLineTemplate).Substring(0,[Math]::Min(4096,([string]$_.CommandLineTemplate).Length));"
        "ExecutablePath=([string]$_.ExecutablePath).Substring(0,[Math]::Min(4096,([string]$_.ExecutablePath).Length));"
        "ScriptText=([string]$_.ScriptText).Substring(0,[Math]::Min(4096,([string]$_.ScriptText).Length))} });"
        "$doc=ConvertTo-Json -InputObject $rows -Depth 3 -Compress;"
        "if($doc.Length -gt 1048576){throw 'WMI output exceeds bound'}; [Console]::Out.Write($doc)"
    )
    try:
        result = run_hidden([str(powershell), "-NoProfile", "-NonInteractive", "-Command", script],
                            capture_output=True, timeout=8, check=False)
        if result.returncode:
            error = _text(result.stderr.decode("utf-8", errors="replace"), 512)
            return [], _coverage("access_denied" if re.search(r"access.{0,10}denied|0x80070005", error, re.I) else "error", error)
        if len(result.stdout) > _MAX_WMI_BYTES:
            return [], _coverage("error", "WMI output exceeds byte bound")
        rows = json.loads(result.stdout.decode("utf-8-sig"))
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("WMI consumer inventory is not an object list")
        records = [{"source": "windows.wmi", "id": _text(row.get("Name"), 512),
                    "command": _text(row.get("CommandLineTemplate") or row.get("ExecutablePath")),
                    "script": _text(row.get("ScriptText"))} for row in rows[:limit]]
        return records, _coverage("partial" if len(rows) > limit else "complete",
            "WMI consumer inventory reached entry bound" if len(rows) > limit else "", len(records))
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return [], _failure(exc)


def _collect_com(limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    status = _coverage("complete")
    inspected = 0
    for hive_name in ("HKEY_CURRENT_USER", "HKEY_LOCAL_MACHINE"):
        for view_name, view in (("32", winreg.KEY_WOW64_32KEY), ("64", winreg.KEY_WOW64_64KEY)):
            try:
                with winreg.OpenKey(getattr(winreg, hive_name), r"SOFTWARE\Classes\CLSID", 0, winreg.KEY_READ | view) as root:
                    count = winreg.QueryInfoKey(root)[0]
                    budget = min(count, max(0, limit - inspected))
                    for index in range(budget):
                        inspected += 1
                        clsid = winreg.EnumKey(root, index)
                        try:
                            with winreg.OpenKey(root, clsid + r"\InprocServer32", 0, winreg.KEY_READ | view) as key:
                                value, _ = winreg.QueryValueEx(key, "")
                                records.append({"source": "windows.com", "id": f"{hive_name}:{view_name}:{clsid}",
                                    "command": _text(value), "registry_key": f"{hive_name}\\SOFTWARE\\Classes\\CLSID\\{clsid}\\InprocServer32",
                                    "registry_view": view_name})
                                if len(str(value)) > _MAX_TEXT:
                                    status = _merge_coverage(status, _coverage("partial", "COM server evidence was truncated"))
                        except FileNotFoundError:
                            continue
                        except OSError as exc:
                            status = _merge_coverage(status, _failure(exc))
                    if count > budget:
                        status = _merge_coverage(status, _coverage("partial", "COM CLSID traversal reached entry bound"))
            except FileNotFoundError:
                continue
            except OSError as exc:
                status = _merge_coverage(status, _failure(exc))
    status.update(count=len(records), inspected=inspected)
    return records, status


def _read_regular(path: Path) -> bytes:
    """Bound reads; refuse symlinks/reparse points and retain opened identity."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or getattr(before, "st_file_attributes", 0) & 0x400:
        raise ValueError("configuration is not a regular non-reparse file")
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("configuration identity changed")
        if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_FILE_BYTES:
            raise ValueError("configuration is not a bounded regular file")
        data = os.read(descriptor, _MAX_FILE_BYTES + 1)
        after = os.fstat(descriptor)
        if len(data) > _MAX_FILE_BYTES or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("configuration grew or changed during read")
        return data
    finally:
        os.close(descriptor)


def _collect_directories(source: str, directories: Iterable[Path], limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    status = _coverage("complete")
    inspected = 0
    for directory in directories:
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if inspected >= limit:
                        status = _merge_coverage(status, _coverage("partial", "Directory inventory reached entry bound"))
                        break
                    inspected += 1
                    path = Path(entry.path)
                    try:
                        if entry.is_symlink():
                            status = _merge_coverage(status, _coverage("partial", "Symlink configuration targets skipped"))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        record: dict[str, Any] = {"source": source, "id": str(path), "path": str(path), "command": ""}
                        if source == "posix.launchd" and path.suffix == ".plist":
                            data = plistlib.loads(_read_regular(path))
                            args = data.get("ProgramArguments", [])
                            record["command"] = _text(data.get("Program") or " ".join(str(arg) for arg in args))
                            record["label"] = _text(data.get("Label"), 512)
                        elif source == "posix.systemd" and path.suffix == ".service":
                            data = _read_regular(path).decode("utf-8", errors="replace")
                            record["command"] = _text(" ".join(re.findall(r"^\s*Exec(?:Start|StartPre|StartPost)\s*=\s*(.+)$", data, re.M)))
                        elif source == "startup":
                            info = entry.stat(follow_symlinks=False)
                            record.update(size=int(info.st_size), suffix=path.suffix.lower(),
                                          target_status="not_resolved" if path.suffix.lower() == ".lnk" else "not_inspected")
                            if path.suffix.lower() in {".exe", ".dll", ".ps1", ".vbs", ".js", ".sh", ".py"}:
                                record["command"] = str(path)
                        else:
                            continue
                        records.append(record)
                    except Exception as exc:
                        status = _merge_coverage(status, _failure(exc))
        except FileNotFoundError:
            continue
        except OSError as exc:
            status = _merge_coverage(status, _failure(exc))
    status.update(count=len(records), inspected=inspected)
    if source == "startup":
        status["detail"] = (status["detail"] + "; " if status["detail"] else "") + "Shortcut targets and contents are not resolved"
    return records, status


def collect_persistence(max_entries: int = 512) -> dict[str, Any]:
    """Inventory current-user/system surfaces, capped across all record sources.

    Other users' profiles and remote hosts are outside this snapshot. The COM
    bound also caps inspected CLSIDs; directory bounds include skipped entries.
    """
    limit = _limit(max_entries)
    system = platform.system().lower()
    result: dict[str, Any] = {"records": [], "findings": [], "coverage": {
        source: _coverage("unsupported", "Source is unavailable on this platform") for source in _SOURCES}}
    collectors: list[tuple[str, Any]] = []
    if system == "windows":
        if winreg is not None:
            collectors.extend((("windows.run", _collect_run), ("windows.com", _collect_com)))
        collectors.extend((("windows.services", _collect_services), ("windows.wmi", _collect_wmi)))
        dirs = [Path(value) / "Microsoft/Windows/Start Menu/Programs/Startup" for value in
                (os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")) if value]
        collectors.append(("startup", lambda bound: _collect_directories("startup", dirs, bound)))
    elif system in {"linux", "darwin"}:
        home = Path.home()
        if system == "darwin":
            directories = [Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons"), home / "Library/LaunchAgents"]
            collectors.append(("posix.launchd", lambda bound: _collect_directories("posix.launchd", directories, bound)))
        else:
            directories = [Path("/etc/systemd/system"), home / ".config/systemd/user",
                           Path("/usr/lib/systemd/system"), Path("/lib/systemd/system")]
            collectors.append(("posix.systemd", lambda bound: _collect_directories("posix.systemd", directories, bound)))
    for index, (source, collector) in enumerate(collectors):
        remaining = limit - len(result["records"])
        if remaining <= 0:
            result["coverage"][source] = _coverage("partial", "Global inventory entry bound exhausted")
            continue
        try:
            # Reserve capacity for later sources: COM registrations must not
            # consume the snapshot before services/WMI/startup can be inspected.
            source_limit = max(1, remaining // (len(collectors) - index))
            records, coverage = collector(source_limit)
            result["records"].extend(records[:source_limit])
            result["coverage"][source] = coverage
        except Exception as exc:
            result["coverage"][source] = _failure(exc)
    result["findings"] = analyze_persistence(result["records"])
    ambiguous = sum(finding["kind"] == "persistence_parser_ambiguous" for finding in result["findings"])
    if ambiguous:
        result["coverage"]["persistence.execution_analysis"] = _coverage("partial",
            "Unsupported or ambiguous execution syntax remains UNKNOWN; inventory completeness is separate", ambiguous)
    return result


def analyze_memory_regions(regions: Iterable[dict[str, Any]], pid: int = 0) -> list[dict[str, Any]]:
    """Anonymous private executable mappings are leads, including legitimate JITs."""
    findings: list[dict[str, Any]] = []
    for region in islice(regions, _MAX_ENTRIES):
        if region.get("path") in {"[vdso]", "[vsyscall]", "[vectors]"}:
            continue
        if not region.get("executable") or not region.get("private") or region.get("file_backed"):
            continue
        record = dict(region, pid=pid)
        writable = bool(region.get("writable"))
        findings.append(_finding(record, "private_executable_memory", "medium" if writable else "low",
            "Private executable memory has no disk-backed image metadata" + (" and is writable" if writable else "") +
            "; JIT engines and legitimate runtimes can produce this pattern. Review correlated evidence."))
    return findings


def _linux_memory(pid: int, limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    records: list[dict[str, Any]] = []
    # proc maps is kernel metadata; never open /proc/PID/mem or mapped files.
    with open(f"/proc/{pid}/maps", "r", encoding="utf-8", errors="replace") as stream:
        for index in range(limit + 1):
            line = stream.readline(_MAX_TEXT + 1)
            if not line:
                return records, _coverage("complete", count=len(records))
            if index == limit:
                return records, _coverage("partial", "Memory region bound exhausted", len(records))
            if len(line) > _MAX_TEXT:
                raise ValueError("Memory map metadata line exceeds bound")
            parts = line.rstrip("\n").split(None, 5)
            if len(parts) < 5:
                raise ValueError("Malformed memory map metadata")
            addresses, permissions, offset, device, inode = parts[:5]
            start, end = (int(value, 16) for value in addresses.split("-", 1))
            if end <= start or len(permissions) != 4:
                raise ValueError("Invalid memory map range or permissions")
            path = parts[5] if len(parts) == 6 else ""
            records.append({"source": "memory.linux.maps", "id": f"{pid}:{start:x}",
                "base_address": start, "size": end - start, "permissions": permissions,
                "executable": "x" in permissions, "writable": "w" in permissions,
                "private": permissions.endswith("p"), "file_backed": int(inode) != 0 and not path.startswith(("/memfd:", "/SYSV")),
                "path": _text(path), "device": device, "offset": offset})
    return records, _coverage("complete", count=len(records))



_MEMORY_IDENTITY_SCHEMA = "angerona.memory-identity.v1"
_MEMORY_IDENTITY_SOURCES = frozenset({
    "memory.windows.virtualquery", "memory.windows.inject_scanner",
    "memory.linux.maps", "memory",
})
_WINDOWS_MEMORY_SOURCES = frozenset({
    "memory.windows.virtualquery", "memory.windows.inject_scanner",
})
_FILETIME_EPOCH = 116444736000000000
_FILETIME_LIMIT = 2650467744000000000


def _valid_create_time(value: Any) -> bool:
    if type(value) not in (int, float):
        return False
    try:
        return math.isfinite(value) and value > 0
    except OverflowError:
        return False


def _matches_filetime(value: Any, ticks: int) -> bool:
    # These existing epoch conversion orders can round differently. Accept
    # exact canonical values only; native before/after FILETIME stays exact.
    return (_valid_create_time(value) and value in {
        (ticks - _FILETIME_EPOCH) / 10000000,
        ticks / 10000000 - 11644473600,
    })


@dataclass(frozen=True, slots=True)
class MemoryProcessIdentity:
    pid: int
    birth_filetime: int
    exit_filetime: int

    @property
    def create_time(self) -> float:
        return (self.birth_filetime - _FILETIME_EPOCH) / 10000000


def _valid_memory_object(value: Any) -> bool:
    return (type(value) is MemoryProcessIdentity
            and type(value.pid) is int and 0 < value.pid <= 0xFFFFFFFF
            and type(value.birth_filetime) is int
            and _FILETIME_EPOCH < value.birth_filetime < _FILETIME_LIMIT
            and type(value.exit_filetime) is int
            and 0 <= value.exit_filetime < 2**64)


@dataclass(frozen=True, slots=True)
class MemoryIdentityReceipt:
    source: str
    request_id: str
    pid: int
    expected_create_time: float | None
    before: MemoryProcessIdentity | None
    after: MemoryProcessIdentity | None
    started_at: float
    finished_at: float
    handle_closed: bool
    status: str
    reason: str
    schema: str = _MEMORY_IDENTITY_SCHEMA

    @property
    def bound(self) -> bool:
        return (self.source in _WINDOWS_MEMORY_SOURCES and self.status == "bound"
                and self.handle_closed is True and _valid_memory_object(self.before)
                and self.before == self.after and self.before.pid == self.pid
                and self.before.exit_filetime == 0
                and _valid_create_time(self.started_at) and _valid_create_time(self.finished_at)
                and self.before.create_time <= self.started_at <= self.finished_at
                and (self.expected_create_time is None
                     or _matches_filetime(self.expected_create_time, self.before.birth_filetime)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_memory_identity(value: Any) -> MemoryIdentityReceipt | None:
    """Decode a closed metadata receipt; this does not authenticate its source."""
    if type(value) is MemoryIdentityReceipt:
        value = value.to_dict()
    if type(value) is not dict or set(value) != {field.name for field in fields(MemoryIdentityReceipt)}:
        return None
    if (value.get("schema") != _MEMORY_IDENTITY_SCHEMA
            or type(value.get("source")) is not str
            or value["source"] not in _MEMORY_IDENTITY_SOURCES
            or not isinstance(value.get("request_id"), str)
            or re.fullmatch(r"[0-9a-f]{32}", value["request_id"]) is None
            or type(value.get("pid")) is not int or not 0 < value["pid"] <= 0xFFFFFFFF
            or (value.get("expected_create_time") is not None
                and not _valid_create_time(value["expected_create_time"]))
            or not _valid_create_time(value.get("started_at"))
            or not _valid_create_time(value.get("finished_at"))
            or value["finished_at"] < value["started_at"]
            or type(value.get("handle_closed")) is not bool
            or type(value.get("status")) is not str
            or value["status"] not in {"bound", "unavailable", "mismatch", "unsupported"}
            or not isinstance(value.get("reason"), str) or len(value["reason"]) > 160):
        return None
    decoded = dict(value)
    for key in ("before", "after"):
        obj = decoded[key]
        if obj is not None:
            if type(obj) is not dict or set(obj) != {"pid", "birth_filetime", "exit_filetime"}:
                return None
            obj = MemoryProcessIdentity(**obj)
            if not _valid_memory_object(obj):
                return None
            decoded[key] = obj
    receipt = MemoryIdentityReceipt(**decoded)
    if receipt.status == "bound" and not receipt.bound:
        return None
    return receipt


class _MemoryFiletime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


def read_memory_process_identity(kernel: Any, handle: Any, *,
                                 filetime_type: Any = _MemoryFiletime) -> MemoryProcessIdentity | None:
    """Query identity from the retained inspection handle; never reopen by PID."""
    try:
        pid = kernel.GetProcessId(handle)
        created, exited, kernel_time, user_time = (filetime_type() for _ in range(4))
        if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                      ctypes.byref(kernel_time), ctypes.byref(user_time)):
            return None
        ticks = lambda value: (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)
        identity = MemoryProcessIdentity(pid, ticks(created), ticks(exited))
        return identity if _valid_memory_object(identity) else None
    except (AttributeError, OSError, TypeError, ValueError, OverflowError, ctypes.ArgumentError):
        return None


def memory_identity_receipt(*, source: str, request_id: str, pid: int,
                            expected_create_time: float | None,
                            before: MemoryProcessIdentity | None,
                            after: MemoryProcessIdentity | None,
                            started_at: float, handle_closed: bool,
                            finished_at: float | None = None) -> MemoryIdentityReceipt:
    """Construct a receipt; missing expected birth never comes from enrichment."""
    finished_at = time.time() if finished_at is None else finished_at
    status, reason = "unavailable", "Same-handle process identity unavailable"
    if before is not None and after is not None:
        if before != after or before.pid != pid or before.exit_filetime != 0:
            status, reason = "mismatch", "Inspected process object changed, exited, or has a different PID"
        elif (expected_create_time is not None
              and not _matches_filetime(expected_create_time, before.birth_filetime)):
            status, reason = "mismatch", "Inspected process birth differs from the expected generation"
        elif not handle_closed:
            reason = "Inspection handle closure was not confirmed"
        else:
            status, reason = "bound", "Same retained query handle PID and raw FILETIME verified before and after inspection"
    if (not _valid_create_time(started_at) or not _valid_create_time(finished_at)
            or finished_at < started_at
            or (before is not None and before.create_time > started_at)):
        status, reason = "unavailable", "Inspection clock and process birth are inconsistent"
    if not isinstance(request_id, str) or re.fullmatch(r"[0-9a-f]{32}", request_id) is None:
        status, reason = "unavailable", "Collector request token missing or malformed"
    if source not in _WINDOWS_MEMORY_SOURCES:
        status, reason = "unsupported", "Native process-generation proof is unavailable for this collector"
    return MemoryIdentityReceipt(source, request_id, pid,
        expected_create_time if _valid_create_time(expected_create_time) else None,
        before, after, started_at, finished_at,
        handle_closed, status, reason)


def _windows_kernel32() -> Any:
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel.VirtualQueryEx.restype = ctypes.c_size_t
    kernel.GetProcessId.argtypes = [wintypes.HANDLE]
    kernel.GetProcessId.restype = wintypes.DWORD
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(_MemoryFiletime)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


class _MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32), ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32), ("Protect", ctypes.c_uint32), ("Type", ctypes.c_uint32),
    ]


def _windows_memory(pid: int, limit: int, *, expected_create_time: float | None = None,
                    request_id: str = "", cancelled: Callable[[], bool] | None = None
                    ) -> tuple[list[dict[str, Any]], dict[str, Any], MemoryIdentityReceipt]:
    kernel = _windows_kernel32()
    started_at = time.time()
    before = after = None
    closed = False
    records: list[dict[str, Any]] = []
    # PROCESS_QUERY_INFORMATION only: no VM_READ/WRITE/OPERATION rights.
    handle = kernel.OpenProcess(0x0400, False, pid)
    if not handle:
        code = ctypes.get_last_error()
        coverage = _coverage("access_denied" if code == 5 else "error", f"OpenProcess failed ({code})")
    else:
        address = 0
        coverage = _coverage("partial", "Memory query region bound exhausted")
        try:
            before = read_memory_process_identity(kernel, handle)
            for _index in range(limit):
                if cancelled is not None and cancelled():
                    coverage = _coverage("partial", "Memory metadata collection cancelled", len(records))
                    break
                info = _MemoryBasicInformation()
                queried = kernel.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info))
                if not queried:
                    code = ctypes.get_last_error()
                    # ERROR_INVALID_PARAMETER marks the end of the accessible VAS.
                    coverage = _coverage("complete" if code == 87 else "access_denied" if code == 5 else "error",
                        "Virtual address space enumeration ended" if code == 87 else f"VirtualQueryEx failed ({code})",
                        len(records))
                    break
                if queried != ctypes.sizeof(info):
                    coverage = _coverage("error", "Memory query returned an incomplete metadata structure", len(records))
                    break
                base, size = int(info.BaseAddress or 0), int(info.RegionSize)
                if size <= 0 or base + size <= address:
                    coverage = _coverage("error", "Memory query failed to advance", len(records))
                    break
                protection = int(info.Protect) & 0xFF
                if int(info.State) == 0x1000:  # MEM_COMMIT
                    records.append({"source": "memory.windows.virtualquery", "id": f"{pid}:{base:x}",
                        "base_address": base, "size": size, "protection": int(info.Protect),
                        "executable": protection in {0x10, 0x20, 0x40, 0x80},
                        "writable": protection in {0x04, 0x08, 0x40, 0x80},
                        "private": int(info.Type) == 0x20000, "file_backed": int(info.Type) in {0x1000000, 0x40000}})
                address = base + size
            else:
                coverage = _coverage("partial", "Memory query region bound exhausted", len(records))
        except Exception as exc:
            coverage = _failure(exc)
            coverage["count"] = len(records)
        finally:
            # Recheck this retained object even when metadata collection fails.
            # The query-only handle carries PID/times and cannot be replaced by
            # a separately opened Process(pid) or cached inventory record.
            try:
                after = read_memory_process_identity(kernel, handle)
            finally:
                try:
                    closed = bool(kernel.CloseHandle(handle))
                except Exception:
                    closed = False
    identity = memory_identity_receipt(source="memory.windows.virtualquery", request_id=request_id,
        pid=pid, expected_create_time=expected_create_time, before=before, after=after,
        started_at=started_at, handle_closed=closed)
    return records, coverage, identity


def inspect_process_memory(pid: int, max_regions: int = 1024, *,
                           expected_create_time: float | None = None, request_id: str = "",
                           cancelled: Callable[[], bool] | None = None) -> dict[str, Any]:
    """Inspect bounded metadata; native object proof is separate from coverage.

    Optional legacy callers without a request token receive observations only.
    Linux procfs generation proof is deliberately unavailable in this collector.
    """
    limit = _limit(max_regions)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1 or pid > 0xFFFFFFFF:
        raise ValueError("pid must be a positive 32-bit integer")
    system = platform.system().lower()
    source = "memory.windows.virtualquery" if system == "windows" else "memory.linux.maps" if system == "linux" else "memory"
    started_at = time.time()
    identity = memory_identity_receipt(source=source, request_id=request_id, pid=pid,
        expected_create_time=expected_create_time, before=None, after=None,
        started_at=started_at, handle_closed=False)
    if system not in {"windows", "linux"}:
        records, coverage = [], _coverage("unsupported", "Process memory metadata is supported on Windows/Linux")
    else:
        try:
            if system == "windows":
                records, coverage, identity = _windows_memory(pid, limit,
                    expected_create_time=expected_create_time, request_id=request_id, cancelled=cancelled)
            else:
                records, coverage = _linux_memory(pid, limit)
        except Exception as exc:
            records, coverage = [], _failure(exc)
    validated = parse_memory_identity(identity)
    bound = validated is not None and validated.bound
    findings = analyze_memory_regions(records, pid)
    for finding in findings:
        finding.update(memory_identity=identity.to_dict(), response_eligible=bound,
                       eligibility_reason=identity.reason,
                       process_create_time=identity.before.create_time if bound else None)
    return {"pid": pid, "records": records, "findings": findings,
            "memory_identity": identity.to_dict(), "coverage": {source: coverage,
                "memory.identity": _coverage("complete" if bound else "partial", identity.reason)}}
