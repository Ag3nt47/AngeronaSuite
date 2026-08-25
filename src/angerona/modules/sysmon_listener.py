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

# win32evtlog constants (defined here so the module loads on non-Windows too)
_EVTLOG_SEQ_FWD = 0x0001 | 0x0004   # EVENTLOG_SEQUENTIAL_READ | EVENTLOG_FORWARDS_READ
_EVTLOG_SEEK_FWD = 0x0002 | 0x0004  # EVENTLOG_SEEK_READ | EVENTLOG_FORWARDS_READ
_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_CURSOR_SCHEMA = 2
_MAX_CURSOR_BYTES = 4096
_CURSOR_SIG_FIELD = "_angerona_hmac"
_CURSOR_KEY_DOMAIN = b"angerona/sysmon-cursor/v2\x00"

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

    def _load_cursor(self) -> int:
        path = self._cursor_path
        self._cursor_auth_failed = False
        try:
            if not path.is_file() or path.stat().st_size > _MAX_CURSOR_BYTES:
                self._cursor_auth_failed = path.exists()
                return 0
            value = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(value, dict)
                or set(value) != {
                    "schema",
                    "channel",
                    "record_number",
                    "updated_at",
                    _CURSOR_SIG_FIELD,
                }
                or value.get("schema") != _CURSOR_SCHEMA
                or value.get("channel") != _SYSMON_CHANNEL
                or not isinstance(value.get("record_number"), int)
                or isinstance(value.get("record_number"), bool)
                or not isinstance(value.get("updated_at"), (int, float))
                or isinstance(value.get("updated_at"), bool)
                or not isinstance(value.get(_CURSOR_SIG_FIELD), str)
            ):
                self._cursor_auth_failed = True
                return 0
            key = self._cursor_key()
            if key is None:
                self._cursor_auth_failed = True
                return 0
            expected = hmac.new(
                key, self._cursor_body(value), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(value[_CURSOR_SIG_FIELD], expected):
                self._cursor_auth_failed = True
                return 0
            return max(0, int(value["record_number"]))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            self._cursor_auth_failed = True
            return 0

    def _save_cursor(self, record_number: int) -> None:
        """Atomically persist the last fully consumed channel record."""
        record_number = max(0, int(record_number))
        path = self._cursor_path
        key = self._cursor_key()
        if key is None:
            self.last_error = "Sysmon cursor not persisted: HMAC authority unavailable"
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        document = {
            "schema": _CURSOR_SCHEMA,
            "channel": _SYSMON_CHANNEL,
            "record_number": record_number,
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
            with temporary.open("wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            try:
                path.chmod(0o600)
            except OSError:
                pass
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def _record_number(record: object) -> int:
        try:
            return max(0, int(getattr(record, "RecordNumber")))
        except (TypeError, ValueError, AttributeError):
            return 0

    def _consume_records(self, records: object) -> int:
        """Process a batch, checkpointing only after the batch is consumed."""
        last = 0
        for record in records or ():
            self._process_record(record)
            last = max(last, self._record_number(record))
        if last:
            self._save_cursor(last)
        return last

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
            self.set_health(100, "")
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
        """Continuously poll the Sysmon event log and emit matching events."""
        import win32evtlog  # type: ignore[import]

        # Resume after the last durable record.  A first run intentionally seeks
        # to the current tail so installing Angerona does not replay an unbounded
        # historical log.  Later runs use SEEK_READ and therefore do not create a
        # telemetry blind spot during a restart.
        cursor = self._load_cursor()
        cursor_auth_failed = self._cursor_auth_failed
        positioned_at_tail = False
        try:
            oldest = max(1, int(win32evtlog.GetOldestEventLogRecord(
                self._evtlog_handle)))
            count = max(0, int(win32evtlog.GetNumberOfEventLogRecords(
                self._evtlog_handle)))
            newest = oldest + count - 1 if count else 0
            if cursor_auth_failed:
                self.set_health(60, "Sysmon cursor authentication failed; replaying retained log")
                self.emit(
                    "Sysmon cursor authentication failed; ignoring the saved position "
                    "and replaying the oldest records retained by Windows.",
                    Severity.HIGH,
                    disposition="health",
                    cursor_status="tampered-or-unverifiable",
                )
                cursor = oldest - 1
            elif cursor == 0:
                # Advance the classic Event Log handle to the tail. Range calls
                # report record numbers but do not change its read position.
                last_seen = 0
                while True:
                    existing = win32evtlog.ReadEventLog(
                        self._evtlog_handle, _EVTLOG_SEQ_FWD, 0,
                    )
                    if not existing:
                        break
                    for record in existing:
                        last_seen = max(last_seen, self._record_number(record))
                cursor = last_seen or newest
                if cursor:
                    self._save_cursor(cursor)
                positioned_at_tail = True
            elif newest and (cursor < oldest - 1 or cursor > newest):
                # The channel was cleared or wrapped. Resume at the oldest record
                # still available and make the loss visible as sensor health.
                self.emit(
                    "Sysmon cursor discontinuity detected; replaying the oldest "
                    "records still retained by Windows.",
                    Severity.MEDIUM,
                    disposition="health",
                    previous_record=cursor,
                    oldest_record=oldest,
                    newest_record=newest,
                )
                cursor = oldest - 1
        except Exception:
            # Older pywin32/fake backends may lack the range helpers. The saved
            # cursor is still useful with SEEK_READ below.
            pass

        if cursor == 0 and not positioned_at_tail:
            try:
                last_seen = 0
                while True:
                    existing = win32evtlog.ReadEventLog(
                        self._evtlog_handle, _EVTLOG_SEQ_FWD, 0,
                    )
                    if not existing:
                        break
                    for record in existing:
                        last_seen = max(last_seen, self._record_number(record))
                if last_seen:
                    self._save_cursor(last_seen)
                positioned_at_tail = True
            except Exception:
                pass

        if cursor and not positioned_at_tail:
            try:
                records = win32evtlog.ReadEventLog(
                    self._evtlog_handle,
                    _EVTLOG_SEEK_FWD,
                    cursor + 1,
                )
                while records:
                    self._consume_records(records)
                    records = win32evtlog.ReadEventLog(
                        self._evtlog_handle,
                        _EVTLOG_SEQ_FWD,
                        0,
                    )
            except Exception as exc:
                self.set_health(60, f"Cursor resume failed: {exc}")
                self.emit(
                    f"Sysmon cursor resume failed: {exc}",
                    Severity.MEDIUM,
                    disposition="health",
                    previous_record=cursor,
                )

        while not self.stopping:
            try:
                records = win32evtlog.ReadEventLog(
                    self._evtlog_handle,
                    _EVTLOG_SEQ_FWD,
                    0,
                )
                if records:
                    self._consume_records(records)
            except Exception as exc:
                self.set_health(60, f"Read error: {exc}")
                self.emit(
                    f"Sysmon log read error: {exc}",
                    Severity.MEDIUM,
                )
                # Try to reopen the channel once
                try:
                    self._evtlog_handle = win32evtlog.OpenEventLog(None, _SYSMON_CHANNEL)
                    self.set_health(100, "")
                except Exception:
                    pass
            self.sleep(self._POLL_INTERVAL)

    def _process_record(self, rec: object) -> None:
        """Parse a single win32evtlog record and emit onto the bus."""
        try:
            eid = int(rec.EventID & 0xFFFF)  # strip facility/severity bits
        except Exception:
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
                msg     = f"Sysmon EID {eid}: {label} (XML parse error)"
                details = {"eid": eid, "label": label, "mitre_tags": tags}
        elif xml_str and len(xml_str) > _MAX_EVENT_XML_CHARS:
            msg = f"Sysmon EID {eid}: {label} (XML payload exceeded safety bound)"
            details = {
                "eid": eid,
                "label": label,
                "mitre_tags": tags,
                "xml_status": "oversized",
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
            return super().self_test()   # not started yet — graceful "stopped" status
        if self._using_fallback:
            return True, "Running psutil fallback (Sysmon not installed)"
        if self._evtlog_handle is not None:
            return True, f"Sysmon channel open: {_SYSMON_CHANNEL}"
        return False, "Not yet initialised"


def register() -> SysmonListenerModule:
    return SysmonListenerModule()
