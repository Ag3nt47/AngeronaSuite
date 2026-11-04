"""Independent, bounded local observations for an explicit Spyware Scan."""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import ntpath
import os
from pathlib import Path, PureWindowsPath
import re
import sys

from angerona.core.source_sandbox import _hold_plain_directories, _read_bytes
from angerona.core.spyware_intel import normalize_indicator


# Public cookie-matching infrastructure from the original investigation.
# This separate advisory table cannot enroll a detection or response rule.
_COOKIE_MATCHING_SOURCE = "https://blog.confiant.com/p/adint-weaponized-ad-tech-for-zero-click-spyware-and-mass-identity-vacuuming"
_ADVISORIES = {
    "tracookiepixel.xyz": _COOKIE_MATCHING_SOURCE,
    "cookie-sync.xyz": _COOKIE_MATCHING_SOURCE,
}
_PROFILE = re.compile(r"Default|Profile [0-9]{1,6}")
_MAX_DIRECTORY_ENTRIES = 256
_MAX_HSTS_ROWS = 32768
_MAX_WINDOWS_TEMP_PATH = 4096
_SCOPED_FILE_LIMIT = 64
_SCOPED_BYTE_LIMIT = 32 * 1024**2
_WINDOWS_NAME_IS_RESERVED = getattr(ntpath, "isreserved", lambda part: PureWindowsPath(part).is_reserved())
_WINDOWS_TEMP_ALIASES = frozenset({
    "APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "SYSTEMDRIVE",
    "SYSTEMROOT", "WINDIR",
})


def _hsts_key(domain: str) -> str:
    labels = (label.encode("ascii") for label in domain.split("."))
    wire = b"".join(bytes((len(label),)) + label for label in labels) + b"\0"
    return base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii")


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError("Repeated evidence field")
        fields[key] = value
    return fields


def _advisory(domain, evidence_type, summary):
    return {"classification": "advisory", "indicator": domain, "source": _ADVISORIES[domain],
            "evidence_type": evidence_type, "summary": summary, "response_authorized": False}


def chromium_hsts_findings(raw: bytes, *, cancelled):
    """Match only exact known HSTS keys, without decoding browser history."""
    state = json.loads(raw, object_pairs_hook=_unique_fields)
    rows = state.get("sts") if type(state) is dict else None
    if type(rows) is not list or len(rows) > _MAX_HSTS_ROWS:
        raise ValueError("Unsupported Chromium transport-security store")
    by_key = {_hsts_key(domain): domain for domain in _ADVISORIES}
    findings = {}
    for row in rows:
        if cancelled():
            break
        if type(row) is not dict or type(row.get("host")) is not str:
            raise ValueError("Unsupported Chromium transport-security entry")
        domain = by_key.get(row["host"])
        if domain is None or row.get("mode") != "force-https":
            continue
        observed = row.get("sts_observed")
        if type(observed) not in (int, float) or not math.isfinite(observed) or observed <= 0:
            raise ValueError("Chromium transport-security observation has no valid time")
        finding = _advisory(
            domain, "chromium-hsts",
            "A browser profile contains a matching secure-connection record for published advertising infrastructure.",
        )
        finding["observed_at"] = observed
        if domain not in findings or observed > findings[domain]["observed_at"]:
            findings[domain] = finding
    return tuple(findings.values())


def hosts_findings(raw: bytes, *, cancelled):
    """Compare local name overrides without resolving or visiting any host."""
    findings = {}
    for line in raw.decode("utf-8-sig").splitlines():
        if cancelled():
            break
        fields = line.partition("#")[0].split()
        if len(fields) < 2:
            continue
        try:
            address = ipaddress.ip_address(fields[0])
        except ValueError:
            continue
        for name in fields[1:]:
            if cancelled():
                break
            domain = normalize_indicator("domain", name)
            if domain in _ADVISORIES:
                finding = _advisory(domain, "hosts-override",
                                    "The local hosts file overrides a published advertising domain.")
                finding["loopback_or_unspecified"] = address.is_loopback or address.is_unspecified
                findings[(domain, finding["loopback_or_unspecified"])] = finding
    return tuple(findings.values())


def chromium_roots() -> tuple[tuple[str, Path], ...]:
    home = Path.home()
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        paths = ("Google/Chrome/User Data", "Microsoft/Edge/User Data",
                 "BraveSoftware/Brave-Browser/User Data", "Chromium/User Data")
    elif sys.platform == "darwin":
        local = home / "Library" / "Application Support"
        paths = ("Google/Chrome", "Microsoft Edge", "BraveSoftware/Brave-Browser", "Chromium")
    else:
        local = home / ".config"
        paths = ("google-chrome", "microsoft-edge", "BraveSoftware/Brave-Browser", "chromium")
    return tuple((name, local / relative) for name, relative in zip(("Chrome", "Edge", "Brave", "Chromium"), paths))


def _is_local_root(root: Path) -> bool:
    if not root.is_absolute() or root.anchor.startswith(("\\\\", "//")) or ".." in root.parts:
        return False
    if sys.platform != "win32":
        return True
    import ctypes
    from ctypes import wintypes

    kind = ctypes.WinDLL("kernel32").GetDriveTypeW
    kind.argtypes = (wintypes.LPCWSTR,)
    kind.restype = wintypes.UINT
    return kind(root.anchor) == 3  # DRIVE_FIXED


def _hsts_artifact(root: Path, profile_name: str):
    profile = root / profile_name
    with _hold_plain_directories(root, profile):
        try:
            (profile / "Network").lstat()
        except FileNotFoundError:
            pass
        else:
            with _hold_plain_directories(root, profile / "Network"):
                current = profile / "Network" / "TransportSecurity"
                try:
                    current.lstat()
                except FileNotFoundError:
                    pass
                else:
                    return _read_bytes(current, root=root)
        legacy = profile / "TransportSecurity"
        legacy.lstat()
        return _read_bytes(legacy, root=root)


def scan_chromium_hsts(*, cancelled, roots=None):
    checked = skipped = 0
    findings = {}
    for browser, root in chromium_roots() if roots is None else roots:
        if cancelled():
            break
        if not _is_local_root(root):
            skipped += 1
            continue
        try:
            root.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            skipped += 1
            continue
        try:
            with _hold_plain_directories(root, root), os.scandir(root) as entries:
                for index, entry in enumerate(entries):
                    if cancelled():
                        break
                    if index >= _MAX_DIRECTORY_ENTRIES:
                        skipped += 1
                        break
                    if _PROFILE.fullmatch(entry.name) is None:
                        continue
                    try:
                        raw = _hsts_artifact(root, entry.name)
                        for item in chromium_hsts_findings(raw, cancelled=cancelled):
                            item["browser"] = browser
                            key = (browser, item["indicator"])
                            if key not in findings or item["observed_at"] > findings[key]["observed_at"]:
                                findings[key] = item
                        checked += 1
                    except FileNotFoundError:
                        continue
                    except (OSError, ValueError, RecursionError, OverflowError):
                        skipped += 1
        except (OSError, ValueError):
            skipped += 1
    state = "partial" if skipped or cancelled() else "completed" if checked else "unavailable"
    return {"state": state, "checked": checked, "skipped": skipped, "findings": list(findings.values())}


def scan_hosts_overrides(*, cancelled, path=None):
    try:
        if path is None:
            if sys.platform == "win32":
                from angerona.core.privilege import trusted_windows_directories

                _windows, system = trusted_windows_directories()
                path = system / "drivers" / "etc" / "hosts"
            else:
                path = Path("/private/etc/hosts" if sys.platform == "darwin" else "/etc/hosts")
        if not _is_local_root(path.parent):
            raise ValueError("Hosts file is outside fixed local storage")
        findings = hosts_findings(_read_bytes(path, root=path.parent), cancelled=cancelled)
    except (OSError, ValueError):
        return {"state": "unavailable", "checked": 0, "skipped": 1, "findings": []}
    return {"state": "partial" if cancelled() else "completed",
            "checked": 1, "skipped": 0, "findings": list(findings)}


def _read_windows_temp_setting():
    """Read only HKCU's TEMP value, without allocating its declared length."""
    import ctypes
    from ctypes import wintypes
    import winreg

    get_value = ctypes.WinDLL("advapi32").RegGetValueW
    get_value.argtypes = (
        wintypes.HKEY, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
        wintypes.LPDWORD, wintypes.LPVOID, wintypes.LPDWORD,
    )
    get_value.restype = wintypes.LONG
    data = ctypes.create_string_buffer(2 * (_MAX_WINDOWS_TEMP_PATH + 1))
    size, kind = wintypes.DWORD(len(data)), wintypes.DWORD()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_QUERY_VALUE) as key:
        # RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND.
        code = get_value(int(key), None, "TEMP", 0x10000006, ctypes.byref(kind), data, ctypes.byref(size))
    if code:
        raise ctypes.WinError(code)
    text = data.raw[:size.value].decode("utf-16-le")
    if not text.endswith("\0"):
        raise ValueError("Windows Temp setting is not terminated")
    return text[:-1], kind.value == winreg.REG_EXPAND_SZ


def _windows_temp_path(value, *, aliases=None):
    """Normalize only plain drive-letter paths, before any filesystem probe."""
    if type(value) is not str or not 1 <= len(value) <= _MAX_WINDOWS_TEMP_PATH:
        raise ValueError("Windows Temp setting exceeds its text bound")
    if aliases is not None:
        allowed = {key.upper(): text for key, text in aliases.items() if key.upper() in _WINDOWS_TEMP_ALIASES}
        value = re.sub(r"%([^%]+)%", lambda match: allowed.get(match[1].upper(), match[0]), value)
        if "%" in value:
            raise ValueError("Windows Temp setting has an unresolved folder variable")
    value = value.replace("/", "\\")
    if len(value) > _MAX_WINDOWS_TEMP_PATH or not re.fullmatch(r'[A-Za-z]:\\[^<>:"|?*\x00-\x1f]*', value):
        raise ValueError("Windows Temp setting is not a plain absolute drive path")
    components = value[3:].removesuffix("\\").split("\\")
    if len(components) > 64 or any(
        not part or part != part.strip() or part.endswith(".") or _WINDOWS_NAME_IS_RESERVED(part)
        for part in components
    ):
        raise ValueError("Windows Temp setting is not a plain absolute drive path")
    return PureWindowsPath(value)


def _configured_windows_temp():
    value, expandable = _read_windows_temp_setting()
    aliases = None
    if expandable:
        from angerona.core.privilege import _minimal_environment

        aliases = _minimal_environment({})
    return Path(str(_windows_temp_path(value, aliases=aliases)))


def scan_windows_user_temp(*, cancelled):
    """Sample the configured user's Temp without using the launch scratch environment."""
    reason = "platform-unavailable"
    if sys.platform == "win32" and not cancelled():
        reason = "setting-unverified"
        try:
            root = _configured_windows_temp()
            reason = "scope-unverified"
            if not cancelled() and _is_local_root(root):
                with _hold_plain_directories(root):
                    reason = "scan-unconfirmed"
                    return scan_selected_paths(
                        (root,), cancelled=cancelled, evidence_type="windows-temp-file",
                        require_signatures=True,
                    )
        except (OSError, ValueError):
            pass
    if cancelled():
        return {"state": "partial", "checked": 0, "skipped": 0, "findings": [], "reason": "cancelled"}
    return {"state": "unavailable", "checked": 0, "skipped": 1, "findings": [],
            "reason": reason}


def _windows_temp_scan_reason(status, metrics):
    """Project one observed limit without retaining Scan Center error text or paths."""
    if type(status) is not str:
        return "scan-unconfirmed"
    if status in {"cancelled", "rejected"}:
        return status
    if status == "limited":
        if metrics.get("timed_out") is True:
            return "deadline"
        traversal = metrics.get("traversal_limit_reason")
        if type(traversal) is str and traversal in {
            "directory-limit", "directory-queue-limit", "directory-entry-limit",
        }:
            return traversal
        budget_skips, scanned_bytes = metrics.get("budget_skips"), metrics.get("bytes_scanned")
        if ((type(budget_skips) is int and budget_skips > 0)
                or (type(scanned_bytes) is int and scanned_bytes == _SCOPED_BYTE_LIMIT)):
            return "byte-budget"
        files_scanned = metrics.get("files_scanned")
        if type(files_scanned) is int and files_scanned == _SCOPED_FILE_LIMIT:
            return "file-budget"
        oversize = metrics.get("oversize_files_skipped")
        if type(oversize) is int and oversize > 0:
            return "per-file-budget"
        if metrics.get("signature_limit_reached") is True:
            return "signature-limit"
    yara_status = metrics.get("yara_status")
    if (status in {"completed", "limited"} and type(yara_status) is str
            and yara_status in {"unavailable", "rules-unavailable", "compile-error"}):
        return "signatures-unavailable"
    return "scan-limited" if status == "limited" else "scan-unconfirmed"


def scan_selected_paths(targets, *, cancelled, evidence_type="selected-path-signature",
                        require_signatures=False):
    """Use the existing scoped, read-only Scan Center custody checks."""
    from angerona.core.security_scan_center import ScanCancellationToken, SecurityScanCenter

    class Cancellation(ScanCancellationToken):
        @property
        def cancelled(self):
            return cancelled() or super().cancelled

    temp_sample = evidence_type == "windows-temp-file"
    scanner = SecurityScanCenter(
        max_files=_SCOPED_FILE_LIMIT, max_total_bytes=_SCOPED_BYTE_LIMIT, max_file_bytes=4 * 1024**2,
        max_directory_entries=256, max_directories=32, max_duration_seconds=12,
        **({"sample_recent_root_directories": True} if temp_sample else {}),
    )
    token = Cancellation()
    findings = []
    checked = skipped = 0
    temp_reason = None
    for target in targets:
        if token.cancelled:
            break
        result = scanner.scan_path(target, cancellation=token)
        checked += int(result.metrics.get("files_scanned", 0))
        if result.status != "completed" or (require_signatures and result.metrics.get("yara_status") != "active"):
            skipped += 1
            if temp_sample and temp_reason is None:
                temp_reason = _windows_temp_scan_reason(result.status, result.metrics)
        for item in result.findings:
            findings.append({"classification": "advisory", "evidence_type": evidence_type,
                             "summary": item.title, "finding_id": item.finding_id,
                             "response_authorized": False})
    state = "partial" if skipped or token.cancelled else "completed"
    outcome = {"state": state, "checked": checked, "skipped": skipped, "findings": findings}
    if temp_sample and state == "partial":
        outcome["reason"] = temp_reason or "cancelled"
    return outcome
