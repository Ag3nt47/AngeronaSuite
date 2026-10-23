"""Opt-in, bounded local identity metadata collectors. No response or egress.

Windows Security records come from the native local Event Log API, not from
caller-named EventBus actors. Cursor HMAC authenticity is separate from whole-
profile rollback resistance, which is explicitly unavailable here. Browser
manifests are untrusted inventory, never signed or proof of enabled extensions.
"""
from __future__ import annotations

import hashlib
import contextlib
import hmac
import json
import math
import os
import re
import stat
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from defusedxml import ElementTree as SafeET

from angerona.core.event_log_integrity import (
    AuthenticatedEventLogCheckpoint, ChannelCheckpoint, assess_continuity,
)
from angerona.core.identity_session import IdentitySessionEvidence, TokenizedSessionEvent
from angerona.core.windows_event_log import WindowsEventLogSource


_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_PROVIDER = "Microsoft-Windows-Security-Auditing"
_PROVIDER_GUID = "54849625-5478-4994-a5ba-3e3b0328c30d"
_EVENT_IDS = (4624, 4625, 4634, 4647, 4672)
_BATCH = 64
_MAX_XML = 64 * 1024
_ID = re.compile(r"[a-p]{32}\Z")
_PROFILE = re.compile(r"(?:Default|Profile [0-9]{1,4})\Z")
_VERSION_DIRECTORY = re.compile(r"[0-9]+(?:\.[0-9]+){0,3}(?:_[0-9]+)?\Z")
_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,3}\Z")
_API_PERMISSION = re.compile(r"[A-Za-z][A-Za-z0-9_.]{0,95}\Z")
_HOST_PERMISSION = re.compile(r"(?:\*|https?|file|ftp)://[A-Za-z0-9*_.:\[\]-]*/[^\s?#@]{0,160}\Z")
_MAX_MANIFEST = 128 * 1024
_MAX_MANIFESTS = 256
_MAX_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_DIRECTORY_ENTRIES = 512
_SESSION_GAPS = (
    "only selected local Security audit events; audit-policy completeness is unknown",
    "existing sessions before enrollment and external IdP/device-code events are not reconstructed",
    "local HMAC cursor only; whole-profile rollback has no independent witness",
)


class IdentityCollectionError(ValueError):
    """An owned reason code, never raw XML, paths, or personal identifiers."""


def _plain(info, *, directory: bool) -> bool:
    return (not stat.S_ISLNK(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)))


def _local_path(path: Path) -> Path:
    text = str(path)
    if (not path.is_absolute() or ".." in path.parts or len(text) > 32760
            or text.startswith(("\\\\", "//"))
            or any(":" in part or part.endswith((".", " ")) for part in path.parts[1:])):
        raise IdentityCollectionError("unsafe-local-root")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        drive_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
        drive_type.argtypes = (wintypes.LPCWSTR,)
        drive_type.restype = wintypes.UINT
        if drive_type(path.anchor) not in (2, 3):
            raise IdentityCollectionError("remote-or-unavailable-volume")
    return path


def parse_windows_session_xml(xml: str) -> tuple[int, IdentitySessionEvidence]:
    """Admit fixed native Security schemas; never retain XML or Computer/name fields."""
    if not isinstance(xml, str) or len(xml) > _MAX_XML or len(xml.encode("utf-8")) > _MAX_XML:
        raise IdentityCollectionError("event-xml-bound")
    try:
        root = SafeET.fromstring(xml, forbid_dtd=True, forbid_entities=True, forbid_external=True)
        if root.tag != _NS + "Event" or sum(1 for _ in root.iter()) > 256:
            raise IdentityCollectionError("event-schema")
        systems, payloads = root.findall(_NS + "System"), root.findall(_NS + "EventData")
        if len(systems) != 1 or len(payloads) != 1:
            raise IdentityCollectionError("event-schema")
        system = systems[0]
        def one(name):
            values = system.findall(_NS + name)
            if len(values) != 1:
                raise IdentityCollectionError("event-system-duplicate-or-missing")
            return values[0]
        provider = one("Provider")
        if (provider.get("Name") != _PROVIDER
                or str(provider.get("Guid", "")).strip("{}").lower() != _PROVIDER_GUID
                or one("Channel").text != "Security"):
            raise IdentityCollectionError("event-provider-channel")
        event_id, record_id = int(one("EventID").text or ""), int(one("EventRecordID").text or "")
        if event_id not in _EVENT_IDS or not 0 < record_id < 2 ** 63:
            raise IdentityCollectionError("event-identity")
        stamp_text = one("TimeCreated").get("SystemTime", "")
        stamp = datetime.fromisoformat(stamp_text.replace("Z", "+00:00"))
        if stamp.tzinfo is None or not math.isfinite(stamp.timestamp()):
            raise IdentityCollectionError("event-time")
        values = {}
        for child in payloads[0]:
            name, value = child.get("Name", ""), child.text or ""
            if (child.tag != _NS + "Data" or not name or name in values
                    or len(value) > 4096 or len(values) >= 64):
                raise IdentityCollectionError("event-data-duplicate-or-bound")
            values[name] = value
        subject = event_id == 4672
        prefix = "Subject" if subject else "Target"
        principal = values.get(prefix + "UserSid", "")
        if not re.fullmatch(r"S-1-[0-9]+(?:-[0-9]+){1,16}", principal) or principal == "S-1-0-0":
            # Failed logons can lack a SID. The account reference is tokenized
            # immediately by the caller; no username survives in a snapshot.
            account, domain = values.get(prefix + "UserName", ""), values.get(prefix + "DomainName", "")
            if event_id != 4625 or not account or account == "-":
                raise IdentityCollectionError("event-principal-missing")
            principal = (domain + "\\" + account) if domain and domain != "-" else account
        if not principal or principal == "-":
            raise IdentityCollectionError("event-principal-missing")
        luid = values.get(prefix + "LogonId", "")
        if event_id != 4625 and not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", luid):
            raise IdentityCollectionError("event-session-missing")
        remote = values.get("LogonType", "") in {"3", "8", "10"}
        ip = values.get("IpAddress", "")
        if ip in {"-", "::1", "127.0.0.1"}:
            ip = ""
        evidence = IdentitySessionEvidence(
            stamp.timestamp(), "authentication_attempt" if event_id == 4625 else
            "privilege_change" if subject else "session_end" if event_id in {4634, 4647} else "logon_session",
            principal_ref=principal, luid="" if event_id == 4625 else luid,
            source_ref=ip, outcome="denied" if event_id == 4625 else "success",
            privileged=subject, remote=remote,
        )
        return record_id, evidence
    except IdentityCollectionError:
        raise
    except Exception as exc:
        raise IdentityCollectionError("event-schema-rejected") from exc


class WindowsSecuritySessionSource(WindowsEventLogSource):
    """Fixed local source; no remote sessions, listener, audit-policy changes, or commands."""

    def __init__(self) -> None:
        super().__init__("Security", _EVENT_IDS,
                         providers_by_event={value: (_PROVIDER,) for value in _EVENT_IDS})

    def _next(self, query, count):
        try:
            return list(self._api.EvtNext(query, min(_BATCH, max(1, count)), 500, 0) or ())
        except Exception as exc:
            code = getattr(exc, "winerror", (getattr(exc, "args", ()) or (0,))[0])
            if code == 259:
                return []
            raise

    def _render(self, handle):
        value = str(self._api.EvtRender(handle, self._api.EvtRenderEventXml))
        if len(value) > _MAX_XML or len(value.encode("utf-8")) > _MAX_XML:
            raise IdentityCollectionError("event-xml-bound")
        return value


@dataclass(frozen=True)
class SessionCollectionBatch:
    state: str
    reason: str
    records: tuple[TokenizedSessionEvent, ...] = ()
    cursor: int = 0
    newest: int = 0
    retained_oldest: int = 0
    rejected_or_stale: int = 0
    native_source: bool = False
    gaps: tuple[str, ...] = _SESSION_GAPS

    def summary(self) -> dict:
        return {"state": self.state, "reason": self.reason, "cursor": self.cursor,
                "newest": self.newest, "retained_oldest": self.retained_oldest,
                "admitted": len(self.records), "rejected_or_stale": self.rejected_or_stale,
                "native_source": self.native_source, "gaps": list(self.gaps),
                "channel": "Security", "event_ids": list(_EVENT_IDS),
                "response_authorized": False, "raw_identity_retained": False}


class WindowsSessionCollector:
    """One worker-owned native source and purpose-bound authenticated cursor."""

    def __init__(self, root: Path, privacy_key: bytes, tokenize: Callable, *, source=None,
                 clock=time.time) -> None:
        if not isinstance(privacy_key, bytes) or len(privacy_key) != 32 or not callable(tokenize):
            raise ValueError("identity collector requires a local purpose key and tokenizer")
        self._source = source
        self._native = source is None and os.name == "nt"
        self._owns_source = source is None
        self._tokenize = tokenize
        self._clock = clock
        self._cursor: ChannelCheckpoint | None = None
        self._loaded = False
        self._load_status = "missing"
        self._loss = False
        self._root = _local_path(Path(root))
        key = hmac.new(privacy_key, b"Angerona identity native cursor v1", hashlib.sha256).digest()
        self._store = AuthenticatedEventLogCheckpoint(
            self._root / "sensor-cursors" / "identity-sessions-v1.json", authority_key=key,
            enrollment_path=self._root / "security-state" / "identity-session-enrollment-v1.json",
        )

    def _checkpoint_call(self, method: str, *args, **kwargs):
        """Pin profile directories; checkpoint writes cannot follow replaced parents."""
        from angerona.core.agent_integrity import _held_bytes
        from angerona.core.source_sandbox import _ensure_directory, _hold_plain_directories
        with _hold_plain_directories(self._root):
            parents = (self._store.path.parent, self._store.enrollment_path.parent)
            for directory in parents:
                _ensure_directory(directory)
            with _hold_plain_directories(*parents), contextlib.ExitStack() as stack:
                if method == "load":
                    # No hard-linked state or replacement race may turn cursor
                    # loading into a read of an unrelated local file.
                    for path in (self._store.path, self._store.enrollment_path):
                        try:
                            path.lstat()
                        except FileNotFoundError:
                            continue
                        stack.enter_context(_held_bytes(path, 64 * 1024))
                return getattr(self._store, method)(*args, **kwargs)

    def poll(self, *, cancelled=lambda: False) -> SessionCollectionBatch:
        if cancelled():
            return SessionCollectionBatch("cancelled", "collection cancelled")
        if self._owns_source and os.name != "nt":
            return SessionCollectionBatch("unsupported", "Windows Security Event Log is unavailable on this platform")
        try:
            if not self._loaded:
                saved, self._load_status = self._checkpoint_call("load")
                self._cursor = saved.get("Security")
                self._loss = self._load_status == "authenticated" and not self._store.coverage_complete
                self._loaded = True
            if self._load_status == "untrusted":
                return SessionCollectionBatch("untrusted", "cursor/enrollment authentication failed; review required")
            if self._source is None:
                self._source = WindowsSecuritySessionSource()
            source = self._source
            oldest, newest = int(source.oldest_record_id()), int(source.newest_record_id())
            if not 0 <= oldest <= newest < 2 ** 63 or bool(oldest) != bool(newest):
                raise IdentityCollectionError("channel-watermark-invalid")
            previous = self._cursor
            anchor = source.record_anchor(previous.record_id) if previous and previous.record_id else ""
            continuity = assess_continuity(
                previous, oldest=oldest, newest=newest, retained_anchor=anchor,
                checkpoint_status="missing" if previous is None else "authenticated",
            )
            if continuity.state == "gap":
                self._loss = True
            if previous is None:
                # Enrollment starts at the current high water, explicitly
                # leaving existing sessions unknown instead of replaying days
                # of records slower than they arrive.
                terminal = newest
                terminal_anchor = source.record_anchor(terminal) if terminal else ""
                if terminal and not terminal_anchor:
                    raise IdentityCollectionError("baseline-anchor-unavailable")
                next_cursor = ChannelCheckpoint(terminal, terminal_anchor)
                if cancelled() or not self._checkpoint_call("save", {"Security": next_cursor}, coverage_complete=True):
                    return SessionCollectionBatch("untrusted", "baseline cursor could not be committed")
                self._cursor = next_cursor
                return SessionCollectionBatch("baseline", "current high water enrolled; earlier sessions remain unknown",
                                              cursor=terminal, newest=newest, retained_oldest=oldest,
                                              native_source=self._native)
            guard = previous.record_id if continuity.state == "live" and previous.record_id else oldest
            guard_anchor = source.record_anchor(guard) if guard else ""
            if guard and not guard_anchor:
                raise IdentityCollectionError("channel-guard-unavailable")
            raw = source.read_after(continuity.resume_after, _BATCH)
            if len(raw) > _BATCH:
                raise IdentityCollectionError("source-batch-bound")
            terminal, tokens, rejected = continuity.resume_after, [], 0
            terminal_xml_anchor = ""
            now = float(self._clock())
            if not math.isfinite(now):
                raise IdentityCollectionError("collection-clock-unavailable")
            for xml in raw:
                if cancelled():
                    return SessionCollectionBatch("cancelled", "collection cancelled")
                record_id, evidence = parse_windows_session_xml(xml)
                if record_id <= terminal:
                    raise IdentityCollectionError("source-record-replay-or-reordering")
                terminal = record_id
                terminal_xml_anchor = hashlib.sha256(xml.encode("utf-8", "replace")).hexdigest()
                if not now - 900 <= evidence.timestamp <= now + 5:
                    rejected += 1
                    continue
                tokens.append(self._tokenize(
                    evidence, evidence_grade="native-os-event-log" if self._native else "schema-admitted-local"))
            if guard and source.record_anchor(guard) != guard_anchor:
                self._loss = True
                return SessionCollectionBatch("loss", "channel generation changed during query; batch discarded")
            if len(raw) < _BATCH and terminal < newest:
                terminal, terminal_xml_anchor = newest, ""
            terminal_anchor = source.record_anchor(terminal) if terminal else ""
            if terminal and (not terminal_anchor or terminal_xml_anchor and terminal_anchor != terminal_xml_anchor):
                self._loss = True
                return SessionCollectionBatch("loss", "terminal record changed during query; batch discarded")
            next_cursor = ChannelCheckpoint(terminal, terminal_anchor)
            if cancelled() or not self._checkpoint_call("save", {"Security": next_cursor}, coverage_complete=not self._loss):
                return SessionCollectionBatch("untrusted", "cursor commit failed; batch discarded")
            self._cursor = next_cursor
            state = "loss" if self._loss else "replaying" if len(raw) == _BATCH and terminal < newest else "observing"
            reason = ("earlier source loss remains unacknowledged; " + continuity.reason
                      if self._loss else continuity.reason)
            return SessionCollectionBatch(state, reason, tuple(tokens), terminal, newest,
                                          oldest, rejected, self._native)
        except Exception as exc:
            code = getattr(exc, "winerror", (getattr(exc, "args", ()) or (None,))[0])
            state = "denied" if isinstance(exc, PermissionError) or code == 5 else "unavailable"
            reason = str(exc) if isinstance(exc, IdentityCollectionError) else "native-source-or-cursor-unavailable"
            if reason == "source-record-replay-or-reordering":
                state = "replay"
            elif reason.startswith("event-"):
                state = "rejected"
            return SessionCollectionBatch(state, reason, cursor=self._cursor.record_id if self._cursor else 0,
                                          native_source=self._native)

    def close(self) -> None:
        if self._owns_source and self._source is not None:
            self._source.close()
        self._source = None


@dataclass(frozen=True)
class BrowserExtension:
    browser: str
    profile_token: str
    extension_id: str
    version: str
    permissions: tuple[str, ...]
    host_permissions: tuple[str, ...]
    optional_permissions: tuple[str, ...]
    optional_host_permissions: tuple[str, ...]


def _strict_json(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise IdentityCollectionError("manifest-duplicate-field")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise IdentityCollectionError("manifest-json-rejected") from exc
    if not isinstance(value, dict):
        raise IdentityCollectionError("manifest-json-rejected")
    return value


def _permissions(value: object, *, hosts: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > 128:
        raise IdentityCollectionError("manifest-permission-bound")
    result = []
    for item in value:
        if (not isinstance(item, str) or len(item) > 256
                or not (item == "<all_urls>" or _HOST_PERMISSION.fullmatch(item)
                        or not hosts and _API_PERMISSION.fullmatch(item))):
            raise IdentityCollectionError("manifest-permission-rejected")
        result.append(item)
    return tuple(sorted(set(result)))


class BrowserExtensionCollector:
    """Current-user Chromium manifest inventory; no Preferences/SQLite/credential reads."""

    def __init__(self, privacy_key: bytes, *, roots=None, monotonic=time.monotonic) -> None:
        if not isinstance(privacy_key, bytes) or len(privacy_key) != 32:
            raise ValueError("extension inventory requires a local purpose key")
        if roots is not None and (
            not isinstance(roots, (tuple, list)) or len(roots) > 3
            or any(not isinstance(row, (tuple, list)) or len(row) != 2
                   or row[0] not in {"Chrome", "Edge", "Brave"}
                   or not isinstance(row[1], (str, Path)) for row in roots)
        ):
            raise ValueError("extension inventory accepts at most three fixed browser roots")
        self._key = privacy_key
        self._roots = tuple(roots) if roots is not None else None
        self._mono = monotonic

    def _locations(self):
        if self._roots is not None:
            return tuple(self._roots)
        if os.name != "nt" or not os.environ.get("LOCALAPPDATA"):
            return ()
        base = Path(os.environ["LOCALAPPDATA"])
        return (("Chrome", base / "Google/Chrome/User Data"),
                ("Edge", base / "Microsoft/Edge/User Data"),
                ("Brave", base / "BraveSoftware/Brave-Browser/User Data"))

    def collect(self, *, cancelled=lambda: False) -> dict:
        from angerona.core.agent_integrity import _held_bytes
        from angerona.core.source_sandbox import _hold_plain_directories
        rows, gaps, read_bytes, attempted = [], [], 0, 0
        deadline = self._mono() + 3.0
        def budget():
            if cancelled():
                raise IdentityCollectionError("inventory-cancelled")
            if self._mono() >= deadline or attempted >= _MAX_MANIFESTS or read_bytes >= _MAX_TOTAL_BYTES:
                raise IdentityCollectionError("inventory-budget-exhausted")
        def children(path):
            budget()
            with _hold_plain_directories(path):
                before = path.stat(follow_symlinks=False)
                if not _plain(before, directory=True):
                    raise IdentityCollectionError("inventory-nonplain-directory")
                result = []
                with os.scandir(path) as iterator:
                    for index, entry in enumerate(iterator):
                        budget()
                        if index >= _MAX_DIRECTORY_ENTRIES:
                            raise IdentityCollectionError("inventory-directory-bound")
                        info = entry.stat(follow_symlinks=False)
                        if not _plain(info, directory=True):
                            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                                gaps.append("redirected directory entries were excluded")
                            continue
                        result.append(Path(entry.path))
                after = path.stat(follow_symlinks=False)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                    raise IdentityCollectionError("inventory-directory-changed")
                return sorted(result, key=lambda value: value.name)
        locations = self._locations()
        if not locations:
            gaps.append("current-user Chromium roots unavailable on this platform")
        for browser, root_value in locations[:3]:
            # Fixed product labels are the only allowed output source names.
            if browser not in {"Chrome", "Edge", "Brave"}:
                gaps.append("unsupported browser root label")
                continue
            try:
                root = _local_path(Path(root_value))
                profiles = [v for v in children(root) if _PROFILE.fullmatch(v.name)]
                if len(profiles) > 16:
                    raise IdentityCollectionError("inventory-profile-bound")
                for profile in profiles:
                    extensions = profile / "Extensions"
                    try:
                        ids = children(extensions)
                    except FileNotFoundError:
                        continue
                    for extension in ids:
                        if not _ID.fullmatch(extension.name):
                            continue
                        versions = children(extension)
                        if len(versions) > 8:
                            raise IdentityCollectionError("inventory-version-bound")
                        for version in versions:
                            if not _VERSION_DIRECTORY.fullmatch(version.name):
                                continue
                            budget()
                            attempted += 1
                            try:
                                manifest_path = version / "manifest.json"
                                before = manifest_path.stat(follow_symlinks=False)
                                file_limit = min(_MAX_MANIFEST, _MAX_TOTAL_BYTES - read_bytes,
                                                 max(0, before.st_size))
                                # Reserve before opening, including subsequently
                                # rejected/raced manifests. Growth beyond this
                                # admitted size is rejected before content read.
                                read_bytes += file_limit
                                with _held_bytes(manifest_path, file_limit) as raw:
                                    after = manifest_path.stat(follow_symlinks=False)
                                    if (not _plain(after, directory=False) or after.st_nlink != 1
                                            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                                            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                                        raise IdentityCollectionError("manifest-changed")
                                    manifest = _strict_json(raw)
                                    value = manifest.get("version")
                                    if (not isinstance(value, str) or len(value) > 48
                                            or _VERSION.fullmatch(value) is None
                                            or any(int(part) > 65535 for part in value.split("."))
                                            or value != version.name.split("_")[0]):
                                        raise IdentityCollectionError("manifest-version-rejected")
                                    profile_token = hmac.new(self._key, (browser + ":" + profile.name).encode(),
                                                             hashlib.sha256).hexdigest()[:24]
                                    rows.append(BrowserExtension(
                                        browser, profile_token, extension.name, value,
                                        _permissions(manifest.get("permissions", [])),
                                        _permissions(manifest.get("host_permissions", []), hosts=True),
                                        _permissions(manifest.get("optional_permissions", [])),
                                        _permissions(manifest.get("optional_host_permissions", []), hosts=True),
                                    ))
                            except Exception:
                                gaps.append(browser + ": manifest unavailable, changed, linked, or schema rejected")
            except FileNotFoundError:
                gaps.append(browser + ": standard profile root absent; installation/coverage unknown")
            except Exception as exc:
                reason = str(exc) if isinstance(exc, IdentityCollectionError) else "root unavailable, denied, or redirected"
                gaps.append(browser + ": " + reason)
        gaps.extend(("Firefox/XPI, unpacked developer paths, other users and nonstandard profiles are not inventoried",
                     "manifest declarations do not prove extension activation, granted permissions, signature, or safety"))
        return {"schema": "angerona.browser-extension-inventory.v1", "state": "partial" if rows else "unknown",
                "rows": [asdict(row) for row in rows], "count": len(rows), "manifest_bytes": read_bytes,
                "gaps": list(dict.fromkeys(gaps))[:24], "source_trust": "unverified-local-manifest",
                "response_authorized": False, "browser_contents_read": False,
                "credentials_read": False, "raw_profile_paths_retained": False}
