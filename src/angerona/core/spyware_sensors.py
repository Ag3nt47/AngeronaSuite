"""Bounded, read-only host evidence for SpywareGuard.

These collectors inventory persistence and executable memory *metadata*. They
do not establish authorization, attribute spyware, inspect memory contents, or
intercept APIs. A missing or inaccessible source is reported as coverage loss.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import plistlib
import re
import stat
import subprocess
from itertools import islice
from pathlib import Path
from typing import Any, Iterable

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
                "Persistence executes a payload from a temporary/public/download directory."))
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
        for view_name, view in (("32", winreg.KEY_WOW64_32KEY), ("64", winreg.KEY_WOW64_64KEY)):
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


def _windows_kernel32() -> Any:
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.VirtualQueryEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    kernel.VirtualQueryEx.restype = ctypes.c_size_t
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


class _MemoryBasicInformation(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_uint32), ("RegionSize", ctypes.c_size_t),
        ("State", ctypes.c_uint32), ("Protect", ctypes.c_uint32), ("Type", ctypes.c_uint32),
    ]


def _windows_memory(pid: int, limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    kernel = _windows_kernel32()
    # PROCESS_QUERY_INFORMATION only: no VM_READ/WRITE/OPERATION rights.
    handle = kernel.OpenProcess(0x0400, False, pid)
    if not handle:
        code = ctypes.get_last_error()
        return [], _coverage("access_denied" if code == 5 else "error", f"OpenProcess failed ({code})")
    records: list[dict[str, Any]] = []
    address = 0
    try:
        for _index in range(limit):
            info = _MemoryBasicInformation()
            queried = kernel.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info))
            if not queried:
                code = ctypes.get_last_error()
                # ERROR_INVALID_PARAMETER marks the end of the accessible VAS.
                if code == 87:
                    return records, _coverage("complete", "Virtual address space enumeration ended", len(records))
                return records, _coverage("access_denied" if code == 5 else "error", f"VirtualQueryEx failed ({code})", len(records))
            base, size = int(info.BaseAddress or 0), int(info.RegionSize)
            if size <= 0 or base + size <= address:
                return records, _coverage("error", "Memory query failed to advance", len(records))
            protection = int(info.Protect) & 0xFF
            if int(info.State) == 0x1000:  # MEM_COMMIT
                records.append({"source": "memory.windows.virtualquery", "id": f"{pid}:{base:x}",
                    "base_address": base, "size": size, "protection": int(info.Protect),
                    "executable": protection in {0x10, 0x20, 0x40, 0x80},
                    "writable": protection in {0x04, 0x08, 0x40, 0x80},
                    "private": int(info.Type) == 0x20000, "file_backed": int(info.Type) in {0x1000000, 0x40000}})
            address = base + size
        return records, _coverage("partial", "Memory query region bound exhausted", len(records))
    finally:
        kernel.CloseHandle(handle)


def inspect_process_memory(pid: int, max_regions: int = 1024) -> dict[str, Any]:
    """Inspect one PID's region metadata; permissions and unsupported OSes are explicit."""
    limit = _limit(max_regions)
    if isinstance(pid, bool) or not isinstance(pid, int) or pid < 1 or pid > 0xFFFFFFFF:
        raise ValueError("pid must be a positive 32-bit integer")
    system = platform.system().lower()
    source = "memory.windows.virtualquery" if system == "windows" else "memory.linux.maps" if system == "linux" else "memory"
    if system not in {"windows", "linux"}:
        return {"pid": pid, "records": [], "findings": [], "coverage": {source: _coverage("unsupported", "Process memory metadata is supported on Windows/Linux")}}
    try:
        records, coverage = (_windows_memory if system == "windows" else _linux_memory)(pid, limit)
    except Exception as exc:
        records, coverage = [], _failure(exc)
    return {"pid": pid, "records": records, "findings": analyze_memory_regions(records, pid), "coverage": {source: coverage}}
