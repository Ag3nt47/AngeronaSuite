"""Sysmon Event Bridge — G2-A.

Subscribes to the Microsoft-Windows-Sysmon/Operational event log and
translates the full current Sysmon event range into Angerona bus events.

Why a separate module instead of folding into etw_listener?
  - etw_listener covers Windows native process/logon audit (EID 4688 etc.)
  - Sysmon provides *richer* telemetry (command-line hashes, parent spoofing
    detection, remote-thread targets) under a separate channel, and the
    signal-to-noise ratio depends on our own sysmon_config.xml allowlists.
    Keeping them separate means a Sysmon crash doesn't take down ETW coverage.

Fallback: if Sysmon/win32evtlog is unavailable the module falls back to a
psutil process-diff loop that catches EID-1-equivalent events (new processes).
The fallback is notably weaker — it misses network, driver, thread, and tamper
events — but keeps the sensor alive and the bus healthy.

Dependencies (optional Windows-only):
  pip install pywin32
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import time
from pathlib import Path
from typing import Optional

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from angerona.core.community_id import community_id_v1
from angerona.core.module_base import BaseModule, Severity

# ── EID metadata ─────────────────────────────────────────────────────────────
# Maps Sysmon Event ID → (human label, MITRE tags, Severity)
_EID_MAP: dict[int, tuple[str, list[str], Severity]] = {
    1:  ("Process Created",          ["T1059", "T1106"],          Severity.INFO),
    2:  ("File Creation Time Changed", ["T1070.006"],              Severity.MEDIUM),
    3:  ("Network Connection",       ["T1071", "T1095"],          Severity.MEDIUM),
    4:  ("Sysmon Service State Changed", ["T1562.001"],            Severity.MEDIUM),
    5:  ("Process Terminated",       [],                            Severity.INFO),
    6:  ("Driver Loaded",            ["T1014", "T1547.006"],      Severity.HIGH),
    7:  ("Image Loaded",             ["T1055", "T1574.002"],      Severity.INFO),
    8:  ("CreateRemoteThread",       ["T1055.003"],               Severity.CRITICAL),
    9:  ("Raw Disk Access",          ["T1006"],                    Severity.MEDIUM),
    10: ("ProcessAccess",            ["T1003.001", "T1055"],      Severity.CRITICAL),
    11: ("File Created",             ["T1105", "T1204"],          Severity.INFO),
    12: ("Registry Object Created/Deleted", ["T1112", "T1060"],   Severity.MEDIUM),
    13: ("Registry Value Set",       ["T1112", "T1060"],          Severity.MEDIUM),
    14: ("Registry Object Renamed",  ["T1112"],                    Severity.MEDIUM),
    15: ("File Stream Created",      ["T1564.004"],                Severity.MEDIUM),
    16: ("Sysmon Configuration Changed", ["T1562.001"],            Severity.MEDIUM),
    17: ("Named Pipe Created",       ["T1559"],                    Severity.MEDIUM),
    18: ("Named Pipe Connected",     ["T1559"],                    Severity.MEDIUM),
    19: ("WMI Filter Registered",    ["T1047", "T1546.003"],       Severity.MEDIUM),
    20: ("WMI Consumer Registered",  ["T1047", "T1546.003"],       Severity.MEDIUM),
    21: ("WMI Binding Registered",   ["T1047", "T1546.003"],       Severity.MEDIUM),
    22: ("DNS Query",                ["T1071.004"],                Severity.INFO),
    23: ("File Deleted and Archived", ["T1070.004"],               Severity.MEDIUM),
    24: ("Clipboard Changed",        ["T1115"],                    Severity.INFO),
    25: ("ProcessTampering",         ["T1055.012"],               Severity.CRITICAL),
    26: ("File Delete Detected",     ["T1070.004"],                Severity.MEDIUM),
    27: ("Executable Creation Blocked", ["T1105", "T1204.002"],   Severity.MEDIUM),
    28: ("File Shredding Blocked",   ["T1070.004"],                Severity.MEDIUM),
    29: ("Executable File Detected", ["T1105", "T1204.002"],      Severity.MEDIUM),
    255: ("Sysmon Internal Error",    ["T1562.001"],                Severity.MEDIUM),
}
_MAX_EVENT_XML_CHARS = 1024 * 1024
_MAX_RECORD_ANCHOR_CHARS = 2 * 1024 * 1024

# win32evtlog constants (defined here so the module loads on non-Windows too)
_EVTLOG_SEQ_FWD = 0x0001 | 0x0004   # EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ
_EVTLOG_SEEK_FWD = 0x0002 | 0x0004  # EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ
_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_CURSOR_SCHEMA = 3
_MAX_CURSOR_BYTES = 4096
_CURSOR_SIG_FIELD = "_angerona_hmac"
_CURSOR_KEY_DOMAIN = b"angerona/sysmon-cursor/v3\x00"
_EMPTY_DIGEST = "0" * 64

# XML namespace Sysmon uses in its event payloads
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _extract_field(root: ET.Element, name: str) -> str:
    """Pull a named EventData field from the Sysmon XML payload."""
    for node in root.iter(f"{{{_NS}}}Data"):
        if node.get("Name") == name:
            return (node.text or "").strip()
    return ""


def _build_message(eid: int, root: ET.Element) -> str:
    """Produce a concise human-readable description for each EID type."""
    get = lambda n: _extract_field(root, n)  # noqa: E731

    if eid == 1:
        image   = get("Image").split("\\")[-1]
        cmdline = get("CommandLine")[:200]
        parent  = get("ParentImage").split("\\")[-1]
        hsh     = get("Hashes").split(",")[0]  # first hash (SHA256=...)
        return (f"Process created: {image} | parent={parent} | "
                f"cmd={cmdline} | {hsh}")

    if eid == 3:
        image = get("Image").split("\\")[-1]
        dst   = get("DestinationIp")
        dport = get("DestinationPort")
        proto = get("Protocol")
        return f"Network connection: {image} → {dst}:{dport} ({proto})"

    if eid == 6:
        driver = get("ImageLoaded").split("\\")[-1]
        sig    = get("Signature")
        signed = get("Signed")
        hsh    = get("Hashes").split(",")[0]
        return (f"Driver loaded: {driver} | signed={signed} | "
                f"signer={sig} | {hsh}")

    if eid == 8:
        src    = get("SourceImage").split("\\")[-1]
        dst    = get("TargetImage").split("\\")[-1]
        spid   = get("SourceProcessId")
        tpid   = get("TargetProcessId")
        return f"RemoteThread injected: {src}(PID={spid}) → {dst}(PID={tpid})"

    if eid == 10:
        src    = get("SourceImage").split("\\")[-1]
        dst    = get("TargetImage").split("\\")[-1]
        access = get("GrantedAccess")
        return f"ProcessAccess: {src} → {dst} (GrantedAccess={access})"

    if eid == 25:
        image = get("Image").split("\\")[-1]
        ptype = get("Type")
        return f"ProcessTampering ({ptype}): {image}"

    # The remaining Sysmon records are neutral telemetry building blocks. Keep
    # the operator message compact; the structured fields remain in details for
    # correlation, hunting and evidence export.
    label = _EID_MAP.get(eid, (f"Sysmon EID {eid}", [], Severity.INFO))[0]
    subject = (
        get("TargetFilename") or get("TargetObject") or get("QueryName")
        or get("PipeName") or get("ImageLoaded") or get("Image")
        or get("Name") or get("Description")
    )
    return f"{label}: {subject[:240]}" if subject else label

    return f"Sysmon EID {eid}"


def _build_details(eid: int, root: ET.Element, label: str, tags: list[str]) -> dict:
    """Collect all EventData fields into a details dict for the bus event."""
    get = lambda n: _extract_field(root, n)  # noqa: E731
    base: dict = {
        "eid":        eid,
        "label":      label,
        "mitre_tags": tags,
        "raw_sensor_evidence": True,
        # Sysmon records are observational building blocks, not verdicts.
        # Correlation/review layers may promote exact evidence later; raw event
        # severity alone never grants destructive response authority.
        "response_authorized": False,
    }
    if eid in {4, 16, 255}:
        base["disposition"] = "health"
    if eid == 1:
        base.update({
            "image":          get("Image"),
            "command_line":   get("CommandLine"),
            "parent_image":   get("ParentImage"),
            "parent_cmdline": get("ParentCommandLine"),
            "user":           get("User"),
            "hashes":         get("Hashes"),
            "pid":            get("ProcessId"),
            "parent_pid":     get("ParentProcessId"),
        })
    elif eid == 3:
        source_port = get("SourcePort")
        destination_port = get("DestinationPort")
        try:
            source_port_number = int(source_port)
            destination_port_number = int(destination_port)
        except (TypeError, ValueError):
            source_port_number = destination_port_number = -1
        community_id = community_id_v1(
            get("SourceIp"),
            get("DestinationIp"),
            source_port_number,
            destination_port_number,
            get("Protocol"),
        )
        base.update({
            "image":          get("Image"),
            "source_ip":      get("SourceIp"),
            "source_port":    source_port,
            "dest_ip":        get("DestinationIp"),
            "dest_port":      destination_port,
            "dest_hostname":  get("DestinationHostname"),
            "protocol":       get("Protocol"),
            "pid":            get("ProcessId"),
        })
        if community_id:
            base["community_id"] = community_id
    elif eid == 6:
        base.update({
            "image_loaded":   get("ImageLoaded"),
            "hashes":         get("Hashes"),
            "signed":         get("Signed"),
            "signature":      get("Signature"),
        })
    elif eid == 8:
        source_image = get("SourceImage")
        base.update({
            "source_image":   source_image,
            "image":          source_image,
            "source_pid":     get("SourceProcessId"),
            "target_image":   get("TargetImage"),
            "target_pid":     get("TargetProcessId"),
            "start_address":  get("StartAddress"),
            "start_module":   get("StartModule"),
        })
    elif eid == 10:
        source_image = get("SourceImage")
        base.update({
            "source_image":   source_image,
            "image":          source_image,
            "source_pid":     get("SourceProcessId"),
            "target_image":   get("TargetImage"),
            "target_pid":     get("TargetProcessId"),
            "granted_access": get("GrantedAccess"),
            "call_trace":     get("CallTrace")[:300],
        })
    elif eid == 25:
        image = get("Image")
        base.update({
            "image":    image,
            "pid":      get("ProcessId"),
            "type":     get("Type"),
        })
    else:
        field_map = {
            2: ("Image", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime", "ProcessId"),
            4: ("State", "Version", "SchemaVersion"),
            5: ("Image", "ProcessId", "ProcessGuid"),
            7: ("Image", "ImageLoaded", "Hashes", "Signed", "Signature", "ProcessId"),
            9: ("Image", "Device", "ProcessId"),
            11: ("Image", "TargetFilename", "CreationUtcTime", "ProcessId"),
            12: ("Image", "EventType", "TargetObject", "ProcessId"),
            13: ("Image", "EventType", "TargetObject", "Details", "ProcessId"),
            14: ("Image", "EventType", "TargetObject", "NewName", "ProcessId"),
            15: ("Image", "TargetFilename", "CreationUtcTime", "Hash", "Contents", "ProcessId"),
            16: ("Configuration", "ConfigurationFileHash"),
            17: ("Image", "PipeName", "ProcessId"),
            18: ("Image", "PipeName", "ProcessId"),
            19: ("Name", "Operation", "Query"),
            20: ("Name", "Type", "Destination"),
            21: ("Consumer", "Filter"),
            22: ("Image", "QueryName", "QueryStatus", "QueryResults", "ProcessId"),
            23: ("Image", "TargetFilename", "Hashes", "Archived", "ProcessId"),
            24: ("Image", "Hashes", "Archived", "ProcessId"),
            26: ("Image", "TargetFilename", "Hashes", "ProcessId"),
            27: ("Image", "TargetFilename", "Hashes", "ProcessId"),
            28: ("Image", "TargetFilename", "Hashes", "ProcessId"),
            29: ("Image", "TargetFilename", "Hashes", "ProcessId"),
            255: ("ID", "Description"),
        }
        for field_name in field_map.get(eid, ()):
            value = get(field_name)
            if value:
                key = "".join(
                    ("_" + char.lower()) if char.isupper() else char
                    for char in field_name
                ).lstrip("_")
                base[key] = value[:4096]
    return base


# ── Module ────────────────────────────────────────────────────────────────────

class SysmonListenerModule(BaseModule):
    CODE = "SYSL"
    NAME = "Sysmon Event Bridge"
    name = "Sysmon Event Bridge"
    version = "1.12.1"
    description = (
        "Reads the current Microsoft-Windows-Sysmon/Operational event range "
        "and emits them onto the Angerona bus. Falls back to psutil process-diff "
        "when Sysmon or win32evtlog is unavailable."
    )
    category = "Endpoint"

    # Polling interval between event-log reads (seconds).  Short enough not to
    # miss a burst, long enough not to burn CPU.
    _POLL_INTERVAL = 2.0

    # How often to scan the process table in fallback mode (seconds).
    _FALLBACK_INTERVAL = 5.0

    def __init__(
        self,
        data_root: Path | None = None,
        *,
        cursor_key: bytes | None = None,
    ) -> None:
        super().__init__()
        self._data_root = Path(data_root) if data_root is not None else None
        if cursor_key is not None and (
            not isinstance(cursor_key, bytes) or len(cursor_key) != 32
        ):
            raise ValueError("Sysmon cursor key must contain 32 bytes")
        self._cursor_key_override = cursor_key
        # The install authority is immutable for the lifetime of a running
        # EventBus.  Cache only a successfully derived, purpose-separated key;
        # an unavailable authority remains retryable so first-start ordering
        # cannot permanently disable cursor persistence.
        self._cursor_key_cache: bytes | None = None
        self._cursor_auth_failed = False
        self._cursor_persist_failed = False
        self._cursor_sequence = 0
        self._cursor_updated_at = 0.0
        self._cursor_rejection_count = 0
        self._parse_rejection_count = 0
        self._durable_record = 0
        self._loaded_cursor_anchor = ""
        self._loaded_cursor_generation: dict[str, object] | None = None
        self._channel_generation: dict[str, object] | None = None
        self._continuity_state = "unverified"
        self._continuity_evidence: dict[str, object] = {}
        self._using_fallback = False
        self._evtlog_handle = None   # win32evtlog handle, if available
        self._seen_pids: set[int] = set()   # for psutil fallback dedup

    @property
    def _cursor_path(self) -> Path:
        if self._data_root is None:
            from angerona.core.data_paths import data_dir
            root = data_dir()
        else:
            root = self._data_root
        return root / "sensor-cursors" / "sysmon.json"

    def _cursor_key(self) -> bytes | None:
        if self._cursor_key_cache is not None:
            return self._cursor_key_cache
        key = self._cursor_key_override
        if key is None:
            try:
                encoded = (self._cursor_path.parents[1] / "bus.key").read_text(
                    encoding="ascii"
                ).strip()
                key = bytes.fromhex(encoded)
            except (OSError, ValueError):
                return None
            if len(key) != 32:
                return None
        derived = hmac.new(key, _CURSOR_KEY_DOMAIN, hashlib.sha256).digest()
        self._cursor_key_cache = derived
        return derived

    @staticmethod
    def _cursor_body(value: dict) -> bytes:
        unsigned = {
            key: item for key, item in value.items() if key != _CURSOR_SIG_FIELD
        }
        return json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

    @staticmethod
    def _generation_id(value: dict[str, object]) -> str:
        body = {key: item for key, item in value.items() if key != "generation_id"}
        encoded = json.dumps(
            body, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def _generation(
        cls, state: str, oldest_record_number: int, oldest_record_anchor: str
    ) -> dict[str, object]:
        value: dict[str, object] = {
            "state": state,
            "channel": _SYSMON_CHANNEL,
            "oldest_record_number": max(0, int(oldest_record_number)),
            "oldest_record_anchor": str(oldest_record_anchor),
        }
        value["generation_id"] = cls._generation_id(value)
        return value

    @staticmethod
    def _is_digest(value: object) -> bool:
        return bool(
            isinstance(value, str)
            and len(value) == 64
            and all(char in "0123456789abcdef" for char in value)
        )

    @classmethod
    def _valid_generation(cls, value: object) -> bool:
        return bool(
            isinstance(value, dict)
            and set(value) == {
                "state", "channel", "oldest_record_number",
                "oldest_record_anchor", "generation_id",
            }
            and value.get("state") in {"observed", "empty", "unobserved"}
            and value.get("channel") == _SYSMON_CHANNEL
            and isinstance(value.get("oldest_record_number"), int)
            and not isinstance(value.get("oldest_record_number"), bool)
            and int(value["oldest_record_number"]) >= 0
            and cls._is_digest(value.get("oldest_record_anchor"))
            and cls._is_digest(value.get("generation_id"))
            and hmac.compare_digest(
                str(value["generation_id"]), cls._generation_id(value)
            )
        )

    @staticmethod
    def _record_digest(record: object) -> str:
        """Stable bounded identity covering every admitted security-data character.

        Fields are hashed incrementally. Oversized/over-wide records fail the
        continuity pass rather than being accepted under a truncated anchor.
        """
        when = getattr(record, "TimeGenerated", "")
        try:
            when_text = when.isoformat()
        except AttributeError:
            when_text = str(when)
        inserts = getattr(record, "StringInserts", None)
        if not isinstance(inserts, (list, tuple)):
            inserts = ()
        if len(inserts) > 64:
            raise ValueError("Sysmon record has too many anchor fields")
        fields = [
            ("record_number", str(SysmonListenerModule._record_number(record))),
            ("event_id", str(int(getattr(record, "EventID", 0)) & 0xFFFFFFFF)),
            ("time_generated", when_text),
            ("source_name", str(getattr(record, "SourceName", ""))),
            ("computer_name", str(getattr(record, "ComputerName", ""))),
        ]
        fields.extend(
            (f"string_insert_{index}", str(item))
            for index, item in enumerate(inserts)
        )
        if sum(len(value) for _label, value in fields) > _MAX_RECORD_ANCHOR_CHARS:
            raise ValueError("Sysmon record exceeds the exact-anchor safety bound")
        anchor = hashlib.sha256(b"angerona/sysmon-record-anchor/v2\x00")
        for label, value in fields:
            field_hash = hashlib.sha256()
            for offset in range(0, len(value), 64 * 1024):
                field_hash.update(
                    value[offset:offset + 64 * 1024].encode(
                        "utf-8", "backslashreplace"
                    )
                )
            anchor.update(label.encode("ascii"))
            anchor.update(b"\x00")
            anchor.update(str(len(value)).encode("ascii"))
            anchor.update(b"\x00")
            anchor.update(field_hash.digest())
        return anchor.hexdigest()

    def _degrade_cursor(self, reason: str) -> None:
        self._cursor_persist_failed = True
        self.last_error = reason
        self.set_health(25, reason)
        self.emit(
            reason,
            Severity.HIGH,
            disposition="health",
            cursor_persistence="failed",
            continuity_state=self._continuity_state,
        )

    def _load_cursor(self) -> int:
        path = self._cursor_path
        self._cursor_auth_failed = False
        prior_anchor = self._loaded_cursor_anchor
        prior_generation = self._loaded_cursor_generation
        prior_sequence = self._cursor_sequence
        prior_updated_at = self._cursor_updated_at
        prior_record = self._durable_record
        try:
            if not path.is_file() or path.stat().st_size > _MAX_CURSOR_BYTES:
                self._cursor_auth_failed = bool(path.exists() or prior_sequence)
                self._cursor_rejection_count += int(self._cursor_auth_failed)
                return prior_record if self._cursor_auth_failed else 0
            value = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(value, dict)
                or set(value) != {
                    "schema",
                    "channel",
                    "record_number",
                    "record_anchor",
                    "generation",
                    "cursor_sequence",
                    "updated_at",
                    _CURSOR_SIG_FIELD,
                }
                or type(value.get("schema")) is not int
                or value.get("schema") != _CURSOR_SCHEMA
                or value.get("channel") != _SYSMON_CHANNEL
                or not isinstance(value.get("record_number"), int)
                or isinstance(value.get("record_number"), bool)
                or int(value.get("record_number", -1)) < 0
                or not self._is_digest(value.get("record_anchor"))
                or not self._valid_generation(value.get("generation"))
                or not isinstance(value.get("cursor_sequence"), int)
                or isinstance(value.get("cursor_sequence"), bool)
                or int(value.get("cursor_sequence", -1)) < 1
                or not isinstance(value.get("updated_at"), (int, float))
                or isinstance(value.get("updated_at"), bool)
                or not math.isfinite(float(value.get("updated_at", float("nan"))))
                or float(value.get("updated_at", 0.0)) < 0.0
                or not isinstance(value.get(_CURSOR_SIG_FIELD), str)
            ):
                self._cursor_auth_failed = True
                self._cursor_rejection_count += 1
                return 0
            key = self._cursor_key()
            if key is None:
                self._cursor_auth_failed = True
                self._cursor_rejection_count += 1
                return 0
            expected = hmac.new(
                key, self._cursor_body(value), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(value[_CURSOR_SIG_FIELD], expected):
                self._cursor_auth_failed = True
                self._cursor_rejection_count += 1
                return 0
            record_number = max(0, int(value["record_number"]))
            candidate_anchor = str(value["record_anchor"])
            candidate_generation = dict(value["generation"])
            candidate_sequence = int(value["cursor_sequence"])
            candidate_updated_at = float(value["updated_at"])
            rollback = bool(
                candidate_sequence < prior_sequence
                or (
                    candidate_sequence == prior_sequence
                    and prior_sequence > 0
                    and (
                        record_number != prior_record
                        or candidate_anchor != prior_anchor
                        or candidate_generation != prior_generation
                        or candidate_updated_at != prior_updated_at
                    )
                )
                or (
                    candidate_sequence > prior_sequence
                    and prior_generation == candidate_generation
                    and record_number < prior_record
                )
            )
            if rollback:
                self._cursor_auth_failed = True
                self._cursor_rejection_count += 1
                self.set_health(30, "authenticated Sysmon cursor rollback/fork rejected")
                return prior_record
            self._loaded_cursor_anchor = candidate_anchor
            self._loaded_cursor_generation = candidate_generation
            self._cursor_sequence = candidate_sequence
            self._cursor_updated_at = candidate_updated_at
            self._durable_record = record_number
            return record_number
        except (OSError, ValueError, TypeError, RecursionError, json.JSONDecodeError):
            self._cursor_auth_failed = True
            self._cursor_rejection_count += 1
            return 0

    def _save_cursor(
        self,
        record_number: int,
        *,
        record_anchor: str | None = None,
        generation: dict[str, object] | None = None,
    ) -> bool:
        """Atomically persist a generation-bound last-consumed record."""
        if type(record_number) is not int or record_number < 0:
            self._degrade_cursor("Sysmon cursor not persisted: invalid record number")
            return False
        path = self._cursor_path
        key = self._cursor_key()
        if key is None:
            self._degrade_cursor("Sysmon cursor not persisted: HMAC authority unavailable")
            return False
        if generation is None:
            generation = self._channel_generation or self._generation(
                "unobserved", 0, _EMPTY_DIGEST
            )
        if not self._valid_generation(generation):
            self._degrade_cursor("Sysmon cursor not persisted: invalid channel generation")
            return False
        if (
            record_number < self._durable_record
            and generation == self._loaded_cursor_generation
        ):
            self._degrade_cursor(
                f"Sysmon cursor regression refused within one generation: "
                f"{record_number} < {self._durable_record}"
            )
            return False
        if record_anchor is None:
            # Compatibility for storage-only callers. Runtime continuity never
            # trusts this synthetic marker and replays retained records.
            record_anchor = hashlib.sha256(
                f"unobserved:{record_number}".encode("ascii")
            ).hexdigest()
        if not self._is_digest(record_anchor):
            self._degrade_cursor("Sysmon cursor not persisted: invalid record anchor")
            return False
        was_failed = self._cursor_persist_failed
        document = {
            "schema": _CURSOR_SCHEMA,
            "channel": _SYSMON_CHANNEL,
            "record_number": record_number,
            "record_anchor": record_anchor,
            "generation": dict(generation),
            "cursor_sequence": self._cursor_sequence + 1,
            "updated_at": time.time(),
        }
        document[_CURSOR_SIG_FIELD] = hmac.new(
            key, self._cursor_body(document), hashlib.sha256
        ).hexdigest()
        body = json.dumps(
            document, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        temporary = path.with_suffix(f".tmp-{os.getpid()}-{id(self):x}")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with temporary.open("wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            try:
                path.chmod(0o600)
            except OSError:
                pass
        except (OSError, ValueError, TypeError) as exc:
            self._degrade_cursor(f"Sysmon cursor persistence failed: {exc}")
            return False
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        self._cursor_sequence = int(document["cursor_sequence"])
        self._cursor_updated_at = float(document["updated_at"])
        self._durable_record = record_number
        self._loaded_cursor_anchor = record_anchor
        self._loaded_cursor_generation = dict(generation)
        self._cursor_persist_failed = False
        if was_failed:
            if self._continuity_state in {"verified", "generation-rebound-anchor-verified"}:
                if self._parse_rejection_count:
                    self.set_health(90, "Sysmon persistence recovered; parse rejections retained")
                else:
                    self.set_health(100, "Sysmon cursor persistence recovered")
            else:
                self.set_health(60, "Sysmon cursor persistence recovered; continuity degraded")
        return True

    @staticmethod
    def _record_number(record: object) -> int:
        try:
            return max(0, int(getattr(record, "RecordNumber")))
        except (TypeError, ValueError, AttributeError):
            return 0

    def _consume_records(
        self,
        records: object,
        *,
        generation: dict[str, object] | None = None,
    ) -> int:
        """Process a batch, checkpointing only after the batch is consumed."""
        last = 0
        last_record: object | None = None
        for record in records or ():
            self._process_record(record)
            number = self._record_number(record)
            if number >= last:
                last = number
                last_record = record
        if last and last_record is not None:
            self._save_cursor(
                last,
                record_anchor=self._record_digest(last_record),
                generation=generation or self._channel_generation,
            )
        return last

    def _consume_contiguous_records(
        self,
        records: object,
        *,
        expected: int,
        maximum: int,
        generation: dict[str, object] | None = None,
    ) -> tuple[int, int, int | None]:
        """Checkpoint only the exact contiguous prefix of a retained range.

        Returns ``(last_consumed, next_expected, first_observed_gap)``. A row
        beyond the captured high-water is left for the next generation pass.
        """
        last = 0
        last_record: object | None = None
        next_expected = expected
        observed_gap: int | None = None
        for record in records or ():
            if next_expected > maximum:
                break
            number = self._record_number(record)
            if number != next_expected:
                observed_gap = number
                break
            self._process_record(record)
            last = number
            last_record = record
            next_expected += 1
        if last and last_record is not None:
            self._save_cursor(
                last,
                record_anchor=self._record_digest(last_record),
                generation=generation or self._channel_generation,
            )
        return last, next_expected, observed_gap

    def _report_delivery_gap(
        self, *, expected: int, observed: int | None, newest: int
    ) -> None:
        """Fail closed when the collector omits a record it reports retained."""
        self._continuity_state = "delivery-gap"
        evidence = dict(self._continuity_evidence)
        evidence.update(
            state=self._continuity_state,
            expected_record=expected,
            observed_record=observed,
            newest_record=newest,
            durable_record=self._durable_record,
            cursor_persistence=(
                "failed" if self._cursor_persist_failed else "durable"
            ),
        )
        self._continuity_evidence = evidence
        observed_text = "end-of-delivery" if observed is None else str(observed)
        self.set_health(
            30,
            f"Sysmon retained delivery gap: expected {expected}, "
            f"observed {observed_text}",
        )
        self.emit(
            f"Sysmon retained range omitted record {expected}; collector delivered "
            f"{observed_text} and cursor remains at {self._durable_record}.",
            Severity.HIGH,
            disposition="health",
            **self._continuity_evidence,
        )

    def _read_exact_record(self, backend: object, record_number: int) -> object | None:
        records = backend.ReadEventLog(
            self._evtlog_handle, _EVTLOG_SEEK_FWD, int(record_number)
        )
        for record in records or ():
            if self._record_number(record) == int(record_number):
                return record
        return None

    def _capture_channel_generation(
        self, backend: object
    ) -> tuple[dict[str, object], int, int]:
        """Bind a generation to the exact oldest retained record, not its range."""
        oldest = max(1, int(backend.GetOldestEventLogRecord(self._evtlog_handle)))
        count = max(0, int(backend.GetNumberOfEventLogRecords(self._evtlog_handle)))
        newest = oldest + count - 1 if count else 0
        if not count:
            return self._generation("empty", 0, _EMPTY_DIGEST), oldest, newest
        record = self._read_exact_record(backend, oldest)
        if record is None:
            raise RuntimeError("oldest retained Sysmon record could not be anchored")
        return self._generation(
            "observed", oldest, self._record_digest(record)
        ), oldest, newest

    def _report_continuity(
        self,
        *,
        state: str,
        previous: dict[str, object] | None,
        current: dict[str, object],
        cursor: int,
        oldest: int,
        newest: int,
        replay_from: int,
        severity: Severity,
    ) -> None:
        self._continuity_state = state
        self._continuity_evidence = {
            "state": state,
            "previous_generation": (
                previous.get("generation_id", "") if previous else ""
            ),
            "current_generation": current.get("generation_id", ""),
            "cursor": cursor,
            "oldest_record": oldest,
            "newest_record": newest,
            "replay_from": replay_from,
            "cursor_persistence": (
                "failed" if self._cursor_persist_failed else "durable"
            ),
            "cursor_sequence": self._cursor_sequence,
            "cursor_age_seconds": (
                max(0.0, time.time() - self._cursor_updated_at)
                if self._cursor_updated_at else None
            ),
            "cursor_rejections": self._cursor_rejection_count,
            "parse_rejections": self._parse_rejection_count,
        }
        self.emit(
            f"Sysmon continuity {state}: cursor={cursor}, retained={oldest}-{newest}, "
            f"replay_from={replay_from}.",
            severity,
            disposition="health",
            **self._continuity_evidence,
        )

    def _establish_continuity(self, backend: object) -> tuple[int, int]:
        """Reload durable state, verify its exact anchor, and choose a replay point."""
        cursor = self._load_cursor()
        auth_failed = self._cursor_auth_failed
        previous = self._loaded_cursor_generation
        try:
            generation, oldest, newest = self._capture_channel_generation(backend)
        except Exception as exc:
            self._continuity_state = "collection-failed"
            self.set_health(30, f"Sysmon continuity collection failed: {exc}")
            self.emit(
                f"Sysmon continuity collection failed: {exc}",
                Severity.HIGH,
                disposition="health",
                continuity_state=self._continuity_state,
            )
            raise
        self._channel_generation = generation

        if auth_failed:
            resume = oldest - 1
            self.set_health(40, "Sysmon cursor authentication failed; replaying retained log")
            self._report_continuity(
                state="cursor-untrusted-replay", previous=previous, current=generation,
                cursor=cursor, oldest=oldest, newest=newest, replay_from=max(oldest, 1),
                severity=Severity.HIGH,
            )
            return resume, newest

        if cursor == 0 and previous is not None:
            if previous == generation and generation.get("state") == "empty":
                if self._parse_rejection_count:
                    self.set_health(90, "empty continuity verified; parse rejections retained")
                else:
                    self.set_health(100, "empty Sysmon generation continuity verified")
                self._report_continuity(
                    state="verified", previous=previous, current=generation,
                    cursor=0, oldest=oldest, newest=0, replay_from=oldest,
                    severity=Severity.INFO,
                )
                return 0, 0
            resume = oldest - 1
            self.set_health(40, "Sysmon empty generation changed; replaying retained log")
            self._report_continuity(
                state="generation-gap-replay", previous=previous, current=generation,
                cursor=0, oldest=oldest, newest=newest,
                replay_from=max(oldest, 1), severity=Severity.HIGH,
            )
            return resume, newest

        if cursor == 0:
            if newest:
                tail = self._read_exact_record(backend, newest)
                if tail is None:
                    resume = oldest - 1
                    self.set_health(40, "Sysmon tail anchor unavailable; replaying retained log")
                    self._report_continuity(
                        state="tail-anchor-missing-replay", previous=previous,
                        current=generation, cursor=0, oldest=oldest, newest=newest,
                        replay_from=oldest, severity=Severity.HIGH,
                    )
                    return resume, newest
                self._save_cursor(
                    newest,
                    record_anchor=self._record_digest(tail),
                    generation=generation,
                )
                if not self._cursor_persist_failed:
                    self.set_health(85, "Sysmon tail anchored; no prior durable cursor")
                self._report_continuity(
                    state="first-run-tail-anchored", previous=previous,
                    current=generation, cursor=newest, oldest=oldest, newest=newest,
                    replay_from=newest + 1, severity=Severity.INFO,
                )
                return newest, newest
            self._save_cursor(0, record_anchor=_EMPTY_DIGEST, generation=generation)
            if not self._cursor_persist_failed:
                self.set_health(90, "empty Sysmon generation durably anchored")
            self._report_continuity(
                state="empty-generation-anchored", previous=previous,
                current=generation, cursor=0, oldest=oldest, newest=0,
                replay_from=oldest, severity=Severity.INFO,
            )
            return 0, 0

        exact = None
        if newest and oldest <= cursor <= newest:
            exact = self._read_exact_record(backend, cursor)
        anchor_matches = bool(
            exact is not None
            and self._loaded_cursor_anchor
            and hmac.compare_digest(
                self._record_digest(exact), self._loaded_cursor_anchor
            )
        )
        if not anchor_matches:
            resume = oldest - 1
            self.set_health(40, "Sysmon generation/cursor discontinuity; replaying retained log")
            self._report_continuity(
                state="generation-gap-replay", previous=previous, current=generation,
                cursor=cursor, oldest=oldest, newest=newest,
                replay_from=max(oldest, 1), severity=Severity.HIGH,
            )
            return resume, newest

        changed = previous != generation
        if changed:
            # A matching tail record cannot prove that lower records in the new
            # generation were observed. Rebinding would skip a clear/refill
            # prefix, so every generation transition replays retained evidence.
            resume = oldest - 1
            self.set_health(40, "Sysmon generation changed; replaying retained log")
            self._report_continuity(
                state="generation-gap-replay", previous=previous,
                current=generation, cursor=cursor, oldest=oldest, newest=newest,
                replay_from=max(oldest, 1), severity=Severity.HIGH,
            )
            return resume, newest
        if not self._cursor_persist_failed:
            if self._parse_rejection_count:
                self.set_health(90, "Sysmon continuity verified; parse rejections retained")
            else:
                self.set_health(100, "Sysmon cursor generation and exact record anchor verified")
        self._report_continuity(
            state="verified",
            previous=previous, current=generation, cursor=cursor, oldest=oldest,
            newest=newest, replay_from=cursor + 1, severity=Severity.INFO,
        )
        return cursor, newest

    def _reseek_and_drain(self, backend: object) -> None:
        """Establish continuity and explicitly reseek after every channel open."""
        cursor, newest = self._establish_continuity(backend)
        desired = cursor + 1
        if not newest or desired > newest:
            return
        records = backend.ReadEventLog(
            self._evtlog_handle, _EVTLOG_SEEK_FWD, desired
        )
        expected = desired
        while records and expected <= newest:
            _last, expected, observed_gap = self._consume_contiguous_records(
                records,
                expected=expected,
                maximum=newest,
                generation=self._channel_generation,
            )
            if observed_gap is not None:
                self._report_delivery_gap(
                    expected=expected, observed=observed_gap, newest=newest
                )
                return
            if self._cursor_persist_failed or expected > newest:
                return
            records = backend.ReadEventLog(
                self._evtlog_handle, _EVTLOG_SEQ_FWD, 0
            )
        if expected <= newest:
            self._report_delivery_gap(
                expected=expected, observed=None, newest=newest
            )

    # ── Properties required by ModuleManager ────────────────────────────────
    @property
    def state(self) -> str:
        return self.status

    @property
    def health_pct(self) -> int:
        return self.health

    # ── Lifecycle ────────────────────────────────────────────────────────────
    def run(self) -> None:
        if self._try_open_sysmon():
            self._run_sysmon_loop()
        else:
            self._run_fallback_loop()

    def _try_open_sysmon(self) -> bool:
        """Attempt to open the Sysmon event log channel.

        Returns True if successful; False if Sysmon is not installed or
        win32evtlog is not available (non-Windows or missing pywin32).
        """
        try:
            import win32evtlog  # type: ignore[import]
            self._evtlog_handle = win32evtlog.OpenEventLog(None, _SYSMON_CHANNEL)
            self._using_fallback = False
            self._continuity_state = "unverified"
            self.set_health(70, "Sysmon channel open; durable continuity not yet verified")
            self.emit(
                f"Sysmon channel opened: {_SYSMON_CHANNEL}",
                Severity.INFO,
                channel=_SYSMON_CHANNEL,
            )
            return True
        except Exception as exc:
            self._using_fallback = True
            self.set_health(
                50,
                f"Sysmon unavailable — running psutil fallback: {exc}",
            )
            self.emit(
                f"Sysmon/win32evtlog not available ({exc}). "
                "Running psutil process-diff fallback (EID-1 equivalent only). "
                "Install Sysmon64 + pywin32 for full coverage.",
                Severity.MEDIUM,
                fallback=True,
            )
            return False

    # ── Sysmon event log loop ─────────────────────────────────────────────────
    def _run_sysmon_loop(self) -> None:
        """Continuously verify generation continuity and drain from durable state."""
        import win32evtlog  # type: ignore[import]
        # Generation capture itself moves a classic Event Log handle. Every
        # pass therefore reloads the durable cursor and explicitly SEEK_READs;
        # this also guarantees that a reopened handle cannot resume implicitly.
        while not self.stopping:
            try:
                self._reseek_and_drain(win32evtlog)
            except Exception as exc:
                if not self._cursor_persist_failed:
                    self.set_health(50, f"Sysmon continuity/read error: {exc}")
                self.emit(
                    f"Sysmon log continuity/read error: {exc}",
                    Severity.MEDIUM,
                    disposition="health",
                    continuity_state=self._continuity_state,
                )
                # Reopen once; the next operation is always a durable reload,
                # generation capture, exact-anchor verification and explicit seek.
                try:
                    self._evtlog_handle = win32evtlog.OpenEventLog(None, _SYSMON_CHANNEL)
                    self._continuity_state = "reopened-unverified"
                    self._reseek_and_drain(win32evtlog)
                except Exception as reopen_exc:
                    if not self._cursor_persist_failed:
                        self.set_health(35, f"Sysmon reopen continuity failed: {reopen_exc}")
            self.sleep(self._POLL_INTERVAL)

    def _process_record(self, rec: object) -> None:
        """Parse a single win32evtlog record and emit onto the bus."""
        try:
            eid = int(rec.EventID & 0xFFFF)  # strip facility/severity bits
        except Exception:
            self._parse_rejection_count += 1
            if not self._cursor_persist_failed:
                self.set_health(70, "Sysmon record rejected: invalid EventID")
            return
        if eid not in _EID_MAP:
            return

        label, tags, severity = _EID_MAP[eid]

        # Reconstruct the XML payload from the StringInserts field.
        # Sysmon stores the full event XML as the first StringInsert.
        xml_str: Optional[str] = None
        try:
            inserts = rec.StringInserts
            if inserts:
                xml_str = inserts[0] if isinstance(inserts[0], str) else None
        except Exception:
            pass

        if xml_str and len(xml_str) <= _MAX_EVENT_XML_CHARS:
            try:
                root = ET.fromstring(xml_str)
                msg     = _build_message(eid, root)
                details = _build_details(eid, root, label, tags)
            except (ET.ParseError, DefusedXmlException):
                self._parse_rejection_count += 1
                msg     = f"Sysmon EID {eid}: {label} (XML parse error)"
                details = {
                    "eid": eid, "label": label, "mitre_tags": tags,
                    "parse_rejection_count": self._parse_rejection_count,
                }
        elif xml_str and len(xml_str) > _MAX_EVENT_XML_CHARS:
            self._parse_rejection_count += 1
            msg = f"Sysmon EID {eid}: {label} (XML payload exceeded safety bound)"
            details = {
                "eid": eid,
                "label": label,
                "mitre_tags": tags,
                "xml_status": "oversized",
                "parse_rejection_count": self._parse_rejection_count,
            }
        else:
            msg     = f"Sysmon EID {eid}: {label}"
            details = {"eid": eid, "label": label, "mitre_tags": tags}

        self.emit(msg, severity, **details)

    # ── psutil fallback loop ──────────────────────────────────────────────────
    def _run_fallback_loop(self) -> None:
        """Psutil process-diff loop — EID-1-equivalent new-process detection.

        Much weaker than Sysmon (no network/driver/thread/tamper events), but
        keeps the module contributing useful signal on machines without Sysmon.
        """
        try:
            import psutil  # type: ignore[import]
        except ImportError:
            self.set_health(0, "psutil unavailable — sensor blind")
            self.emit(
                "psutil not installed; Sysmon fallback cannot run. "
                "pip install psutil to restore coverage.",
                Severity.HIGH,
            )
            # Park the thread so the module stays alive but idle
            while not self.stopping:
                self.sleep(30.0)
            return

        # Seed the seen-PID set with whatever is already running
        try:
            self._seen_pids = {p.pid for p in psutil.process_iter(["pid"])}
        except Exception:
            self._seen_pids = set()

        while not self.stopping:
            self.sleep(self._FALLBACK_INTERVAL)
            try:
                current: dict[int, psutil.Process] = {}
                for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid"]):
                    try:
                        current[proc.pid] = proc
                    except Exception:
                        pass

                new_pids = set(current.keys()) - self._seen_pids
                self._seen_pids = set(current.keys())

                for pid in new_pids:
                    proc = current.get(pid)
                    if proc is None:
                        continue
                    try:
                        info  = proc.as_dict(["name", "exe", "cmdline", "ppid"])
                        name  = info.get("name") or "unknown"
                        exe   = info.get("exe") or ""
                        cmd   = " ".join(info.get("cmdline") or [])[:200]
                        ppid  = info.get("ppid", 0)
                        pname = "unknown"
                        try:
                            pname = psutil.Process(ppid).name() if ppid else "unknown"
                        except Exception:
                            pass
                        self.emit(
                            f"[FALLBACK] Process created: {name} | parent={pname} | cmd={cmd}",
                            Severity.INFO,
                            eid=1,
                            label="Process Created (psutil fallback)",
                            mitre_tags=["T1059", "T1106"],
                            image=exe,
                            command_line=cmd,
                            pid=pid,
                            parent_pid=ppid,
                            parent_image=pname,
                            fallback=True,
                        )
                    except Exception:
                        pass
            except Exception as exc:
                self.set_health(40, f"Fallback loop error: {exc}")

    # ── Health check ─────────────────────────────────────────────────────────
    def self_test(self) -> tuple[bool, str]:
        if self.status != "running":
            first = self._generation("observed", 1, "a" * 64)
            second = self._generation("observed", 1, "b" * 64)
            ok = (
                _CURSOR_SCHEMA == 3
                and self._valid_generation(first)
                and self._valid_generation(second)
                and first["generation_id"] != second["generation_id"]
            )
            return (
                ok,
                "offline generation-bound cursor/anchor contract verified"
                if ok else "generation-bound cursor contract failed",
            )
        if self._using_fallback:
            return True, "Running psutil fallback (Sysmon not installed)"
        if self._evtlog_handle is not None:
            return True, f"Sysmon channel open: {_SYSMON_CHANNEL}"
        return False, "Not yet initialised"


def register() -> SysmonListenerModule:
    return SysmonListenerModule()
