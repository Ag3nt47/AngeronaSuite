"""Bounded WER tampering observations; neither parsing nor a PID grants authority.

The composition supplies identities from retained native owners on its own
background refresh worker. The immutable cache is read here without process,
filesystem, policy or native queries. Observed WER flags and access rights are
precursors, not proof that suspension occurred or permission to kill a process.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import math
import ntpath
import re
from typing import Callable, Literal

MAX_OWNED_PROCESSES = 16
MAX_IDENTITY_AGE = 5.0
MAX_COMMAND_CHARS = 8192
_FILETIME_EPOCH = 116444736000000000
_ROLE = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
_HMAC = re.compile(r"[0-9a-f]{64}\Z")
_WER_IMAGES = frozenset({"werfault.exe", "werfaultsecure.exe"})
_GUID = re.compile(r"\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?\Z")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?(?:Z|\+00:00)?\Z")
_FIELDS = ("image", "command_line", "cmdline", "pid", "process_guid", "source_image",
           "source_pid", "source_process_guid", "target_image", "target_pid",
           "target_process_guid", "granted_access", "sensor_source", "source")
_FIELDS += ("source_utc_time",)
_FIELDS += ("process_birth_ticks",)


def _finite(value: object) -> bool:
    return type(value) in (float, int) and 0 <= value <= 253402300799 and math.isfinite(value)


def _image(value: object) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 32767
            or any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("Native image identity is unavailable")
    drive, tail = ntpath.splitdrive(value)
    if (len(drive) != 2 or not drive[0].isascii() or not drive[0].isalpha()
            or drive[1] != ":" or not tail.startswith(("/", "\\"))
            or ":" in tail or not ntpath.basename(tail)
            or any(part in {".", ".."} for part in re.split(r"[/\\]", tail))):
        raise ValueError("Native image must be an absolute local DOS path")
    return ntpath.normcase(ntpath.normpath(value))


@dataclass(frozen=True)
class OwnedProcessIdentity:
    """A short-lived cached retained-owner observation, never response authority.

    ``birth_ticks`` preserves exact native FILETIME identity as decimal text;
    ``create_time`` is only a compatible wall-clock projection. Constructing a
    DTO does not inspect the OS or establish that its supplier is authoritative.
    """

    pid: int
    birth_ticks: str
    create_time: float
    image: str
    role: str
    observed_monotonic: float
    expires_monotonic: float

    def __post_init__(self):
        object.__setattr__(self, "image", self._validated_image())

    def _validated_image(self) -> str:
        """Validate the complete DTO without changing a supplier-owned row."""
        if type(self.pid) is not int or not 1 <= self.pid <= 0xFFFFFFFF:
            raise ValueError("Owned PID is invalid")
        if (type(self.birth_ticks) is not str or not 1 <= len(self.birth_ticks) <= 20
                or not self.birth_ticks.isascii() or not self.birth_ticks.isdecimal()
                or self.birth_ticks != str(int(self.birth_ticks))
                or not _FILETIME_EPOCH < int(self.birth_ticks) <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("Exact native birth must be canonical FILETIME text")
        projected = (int(self.birth_ticks) - _FILETIME_EPOCH) / 10_000_000
        if not _finite(self.create_time) or abs(projected - self.create_time) > 0.001:
            raise ValueError("Native birth and wall-clock projection differ")
        if type(self.role) is not str or not _ROLE.fullmatch(self.role):
            raise ValueError("Owned role is invalid")
        if (not _finite(self.observed_monotonic) or not _finite(self.expires_monotonic)
                or not self.observed_monotonic < self.expires_monotonic
                <= self.observed_monotonic + MAX_IDENTITY_AGE):
            raise ValueError("Owned identity needs a bounded monotonic lease")
        return _image(self.image)

    def fresh(self, now: float) -> bool:
        return _finite(now) and self.observed_monotonic <= now < self.expires_monotonic


OwnedProcessSupplier = Callable[[], tuple[OwnedProcessIdentity, ...]]
OwnedProcessReadReason = Literal[
    "supplier_unbound", "caller_clock_invalid", "supplier_failed", "snapshot_type_invalid",
    "snapshot_empty", "snapshot_oversized", "observation_clock_invalid", "regressed",
    "row_type_invalid", "row_not_yet_valid", "row_expired", "duplicate_pid",
]


class OwnedProcessReadError(ValueError):
    """A fixed consumer rejection code, without supplier exception text or identity."""

    def __init__(self, reason_code: OwnedProcessReadReason, *, snapshot_count: int | None = None):
        if reason_code in {"row_type_invalid", "row_not_yet_valid", "row_expired"}:
            message = "Native-owned process cache is stale or malformed"
        elif reason_code == "duplicate_pid":
            message = "Native-owned process cache has ambiguous process IDs"
        else:
            message = "Current native-owned process cache is unavailable"
        super().__init__(message)
        self.reason_code = reason_code
        self.snapshot_count = snapshot_count


@dataclass(frozen=True)
class OwnedProcessRead:
    """An unchanged immutable cache admitted at its post-acquisition clock sample."""

    rows: tuple[OwnedProcessIdentity, ...]
    checked_monotonic: float


def _read_owned_supplier(supplier: OwnedProcessSupplier | None) -> object:
    if supplier is None or not callable(supplier):
        raise OwnedProcessReadError("supplier_unbound")
    try:
        return supplier()
    except Exception:
        raise OwnedProcessReadError("supplier_failed") from None


def _validate_owned_processes(rows: object, *, now: float) -> tuple[OwnedProcessIdentity, ...]:
    """Reject an entire cache on any type, lease or PID ambiguity failure."""
    if type(rows) is not tuple:
        raise OwnedProcessReadError("snapshot_type_invalid")
    count = len(rows)
    if not count:
        raise OwnedProcessReadError("snapshot_empty", snapshot_count=count)
    if count > MAX_OWNED_PROCESSES:
        raise OwnedProcessReadError("snapshot_oversized", snapshot_count=count)
    try:
        for row in rows:
            if (type(row) is not OwnedProcessIdentity
                    or OwnedProcessIdentity._validated_image(row) != row.image):
                raise OwnedProcessReadError("row_type_invalid", snapshot_count=count)
            if now < row.observed_monotonic:
                raise OwnedProcessReadError("row_not_yet_valid", snapshot_count=count)
            if not row.fresh(now):
                raise OwnedProcessReadError("row_expired", snapshot_count=count)
        if len({row.pid for row in rows}) != count:
            raise OwnedProcessReadError("duplicate_pid", snapshot_count=count)
    except OwnedProcessReadError:
        raise
    except Exception:
        raise OwnedProcessReadError("row_type_invalid", snapshot_count=count) from None
    return rows


def read_owned_processes(supplier: OwnedProcessSupplier | None, *, now: float) -> tuple[OwnedProcessIdentity, ...]:
    """Read a cached typed tuple at an explicitly fixed validation time."""
    if not _finite(now):
        raise OwnedProcessReadError("caller_clock_invalid")
    return _validate_owned_processes(_read_owned_supplier(supplier), now=now)


def read_owned_process_snapshot(supplier: OwnedProcessSupplier | None, *, not_before: float,
                                clock: Callable[[], float]) -> OwnedProcessRead:
    """Acquire once, then sample once; validate and correlate using that same time.

    A cache publisher may replace its immutable tuple between a caller's initial
    clock sample and acquisition. Sampling after acquisition admits a fresh row
    without changing its producer lease or accepting a future observation.
    """
    if not _finite(not_before):
        raise OwnedProcessReadError("caller_clock_invalid")
    if not callable(clock):
        raise OwnedProcessReadError("observation_clock_invalid")
    rows = _read_owned_supplier(supplier)
    try:
        checked = clock()
    except Exception:
        raise OwnedProcessReadError("observation_clock_invalid") from None
    if not _finite(checked):
        raise OwnedProcessReadError("observation_clock_invalid")
    if checked < not_before:
        raise OwnedProcessReadError("regressed")
    return OwnedProcessRead(_validate_owned_processes(rows, now=checked), float(checked))


def _pid(value: object) -> int | None:
    if type(value) is str and 1 <= len(value) <= 10 and value.isascii() and value.isdecimal():
        value = int(value)
    return value if type(value) is int and 1 <= value <= 0xFFFFFFFF else None


def _guid(value: object) -> str:
    if type(value) is not str or not _GUID.fullmatch(value):
        return ""
    # Require matching braces; a partial wrapper is not an exact native GUID.
    if value.startswith("{") != value.endswith("}"):
        return ""
    return value.strip("{}").lower()


def _source_time(value: object) -> float | None:
    if type(value) is not str or not 1 <= len(value) <= 48 or not _UTC.fullmatch(value):
        return None
    try:
        stamp = datetime.fromisoformat(value.removesuffix("Z") + ("+00:00" if value.endswith("Z") else ""))
        if stamp.tzinfo is None:
            stamp = stamp.replace(tzinfo=timezone.utc)  # Sysmon UtcTime is explicitly UTC.
        if stamp.utcoffset().total_seconds() != 0:
            return None
        result = stamp.timestamp()
        return result if _finite(result) else None
    except (ValueError, OverflowError, OSError):
        return None


def windows_arguments(command: object) -> tuple[str, ...]:
    """Parse bounded Windows quote/backslash syntax without shell or native I/O.

    Ambiguous/unclosed input is rejected. This parser neither expands variables
    nor executes command text. It is intentionally stricter than shell parsing.
    """
    if (type(command) is not str or not 1 <= len(command) <= MAX_COMMAND_CHARS
            or any(ord(char) < 32 and char != "\t" or ord(char) == 127 for char in command)):
        raise ValueError("WER command line is malformed or oversized")
    argv, index, size = [], 0, len(command)
    while index < size:
        while index < size and command[index] in " \t":
            index += 1
        if index == size:
            break
        token, quoted = [], False
        while index < size and (quoted or command[index] not in " \t"):
            slashes = 0
            while index < size and command[index] == "\\":
                slashes += 1
                index += 1
            if index < size and command[index] == '"':
                token.extend("\\" * (slashes // 2))
                if slashes % 2:
                    token.append('"')
                elif quoted and index + 1 < size and command[index + 1] == '"':
                    token.append('"')
                    index += 1
                else:
                    quoted = not quoted
                index += 1
            else:
                token.extend("\\" * slashes)
                if index < size and (quoted or command[index] not in " \t"):
                    token.append(command[index])
                    index += 1
        if quoted:
            raise ValueError("WER command line has an unclosed quote")
        argv.append("".join(token))
        if len(argv) > 64:
            raise ValueError("WER argument count exceeds bound")
    return tuple(argv)


@dataclass(frozen=True)
class WerTelemetry:
    """A bounded copy observed after original-event verification, not a new receipt."""

    module: str
    eid: int
    fields: tuple[tuple[str, object], ...]
    source_hmac: str
    event_ts: float
    observed_monotonic: float
    mesh_required_observed: bool


def capture_wer_telemetry(event, *, now: float, mesh_required: bool) -> WerTelemetry | None:
    """Project eligible source fields; caller must verify the original Event."""
    details = getattr(event, "details", None)
    module = getattr(event, "module", None)
    if type(details) is not dict or len(details) > 32 or not _finite(now):
        return None
    if module == "Sysmon Event Bridge":
        eid = details.get("eid")
        if (type(eid) is not int or eid not in {1, 10}
                or details.get("sensor_source") != "sysmon-native"
                or details.get("raw_sensor_evidence") is not True):
            return None
    elif (module == "ETW Real-Time Process Sensor"
          and details.get("source") == "ETW:Kernel-Process"
          and details.get("event_type") == "process_creation"):
        eid = 1
    else:
        return None
    signature, stamp = getattr(event, "hmac_sig", None), getattr(event, "ts", None)
    if type(signature) is not str or not _HMAC.fullmatch(signature) or not _finite(stamp):
        return None
    total = 0
    for value in details.values():
        if type(value) is str:
            if len(value) > MAX_COMMAND_CHARS:
                return None
            total += len(value)
        elif value is None or type(value) in {bool, int}:
            if type(value) is int and not -1 <= value <= 0xFFFFFFFFFFFFFFFF:
                return None
        elif type(value) in {list, tuple}:
            if len(value) > 16 or any(type(item) is not str or len(item) > 128 for item in value):
                return None
            total += sum(map(len, value))
        else:
            return None
    if total > 32 * 1024:
        return None
    fields = tuple((key, details[key]) for key in _FIELDS if key in details)
    return WerTelemetry(module, eid, fields, signature, stamp, now, mesh_required is True)


@dataclass(frozen=True)
class WerFaultObservation:
    kind: str
    protected: OwnedProcessIdentity
    wer_pid: int
    wer_image: str
    source_hmac: str
    source_ts: float
    mesh_required_observed: bool
    protected_generation_bound: bool = False
    actor_pid: int | None = None
    actor_image: str = ""
    granted_access: int | None = None

    def event_details(self) -> dict:
        return dict(
            finding_code="werfault." + self.kind,
            finding_kind="exposure", disposition="exposure", active_attack=False,
            response_authorized=False, response_authority="observe-only",
            cause_unconfirmed=True, suspension_confirmed=False, pre_dump_prevention_verified=False,
            microsoft_wer_identity_verified=False,
            candidate_protected_pid=self.protected.pid,
            protected_pid=self.protected.pid if self.protected_generation_bound else None,
            protected_birth_ticks=self.protected.birth_ticks if self.protected_generation_bound else None,
            protected_create_time=self.protected.create_time if self.protected_generation_bound else None,
            protected_image=self.protected.image if self.protected_generation_bound else "",
            protected_generation_bound=self.protected_generation_bound,
            protected_role=self.protected.role, wer_pid=self.wer_pid, wer_image=self.wer_image,
            trigger_hmac=self.source_hmac, trigger_ts=self.source_ts,
            mesh_required_observed=self.mesh_required_observed,
            source_pid=self.actor_pid, source_image=self.actor_image,
            granted_access=self.granted_access, native_response_contract_available=False,
        )


@dataclass(frozen=True)
class _DumpRequest:
    protected: OwnedProcessIdentity
    wer_pid: int
    wer_image: str
    expires: float
    created_utc: float
    protected_generation_bound: bool = False
    protected_guid: str = ""


class WerFaultCorrelator:
    """Worker-owned bounded precursor correlation; no mutation or host query."""

    MAX_REQUESTS = 64
    REQUEST_TTL = 10.0

    def __init__(self):
        self._requests: dict[str, _DumpRequest] = {}
        self._owned_guids: dict[str, tuple[int, str, str]] = {}
        self._ambiguous_owned: set[tuple[int, str, str]] = set()
        self._last_now = 0.0

    def observe(self, event: WerTelemetry, owned: tuple[OwnedProcessIdentity, ...], *, now: float) -> WerFaultObservation | None:
        if type(event) is not WerTelemetry or not _finite(now) or now < self._last_now:
            self._requests.clear()
            self._owned_guids.clear()
            self._ambiguous_owned.clear()
            return None
        self._last_now = now
        self._requests = {key: row for key, row in self._requests.items() if now < row.expires}
        if not 0 <= now - event.observed_monotonic <= MAX_IDENTITY_AGE:
            return None
        if (type(owned) is not tuple or not 1 <= len(owned) <= MAX_OWNED_PROCESSES
                or any(type(row) is not OwnedProcessIdentity or not row.fresh(now) for row in owned)
                or len({row.pid for row in owned}) != len(owned)):
            return None
        fields = dict(event.fields)
        current_identities = {(row.pid, row.birth_ticks, row.image) for row in owned}
        self._owned_guids = {guid: identity for guid, identity in self._owned_guids.items()
                             if identity in current_identities}
        self._ambiguous_owned.intersection_update(current_identities)
        if event.eid == 1:
            self._remember_owned_guid(event, fields, owned)
            return self._creation(event, fields, owned, now)
        if event.eid == 10:
            return self._access(event, fields, owned)
        return None

    def _remember_owned_guid(self, event, fields, owned):
        if event.module != "Sysmon Event Bridge":
            return
        guid, stamp, pid = _guid(fields.get("process_guid")), _source_time(fields.get("source_utc_time")), _pid(fields.get("pid"))
        if not guid or stamp is None:
            return
        try:
            image = _image(fields.get("image"))
        except ValueError:
            return
        current = next((row for row in owned if row.pid == pid and row.image == image
                        and abs(row.create_time - stamp) <= 0.001), None)
        if current is None:
            return
        identity = (current.pid, current.birth_ticks, current.image)
        if identity in self._ambiguous_owned:
            return
        if any(other == identity and other_guid != guid for other_guid, other in self._owned_guids.items()):
            self._owned_guids = {key: value for key, value in self._owned_guids.items() if value != identity}
            self._ambiguous_owned.add(identity)
            return  # Conflicting native GUID claims invalidate this generation's binding.
        if len(self._owned_guids) < MAX_OWNED_PROCESSES or guid in self._owned_guids:
            self._owned_guids[guid] = identity

    def _creation(self, event, fields, owned, now):
        try:
            image = _image(fields.get("image"))
            if ntpath.basename(image) not in _WER_IMAGES:
                return None
            argv = windows_arguments(fields.get("command_line", fields.get("cmdline")))
            if not argv:
                return None
        except ValueError:
            return None
        # CreateProcess can choose lpApplicationName independently of argv[0].
        # The observed image is the candidate gate; command text is not identity.
        flags, index = {}, 0 if argv[0].startswith("/") else 1
        while index < len(argv):
            flag = argv[index].lower()
            if flag == "/h":
                if flag in flags:
                    return None
                flags[flag] = True
                index += 1
                continue
            if flag not in {"/pid", "/tid", "/type", "/encfile", "/cancel"} or flag in flags or index + 1 >= len(argv):
                return None
            value = argv[index + 1]
            if not value.isascii() or not 1 <= len(value) <= 20 or not value.isdecimal():
                return None
            flags[flag] = int(value)
            if flags[flag] > (0xFFFFFFFFFFFFFFFF if flag in {"/encfile", "/cancel"} else 0xFFFFFFFF):
                return None
            index += 2
        if (flags.get("/type") != 268310 or not flags.get("/encfile")
                or not flags.get("/cancel")):
            return None
        target = next((row for row in owned if row.pid == flags.get("/pid")), None)
        wer_pid = _pid(fields.get("pid"))
        if target is None or wer_pid is None or wer_pid == target.pid:
            return None
        stamp = _source_time(fields.get("source_utc_time"))
        birth = fields.get("process_birth_ticks")
        if (stamp is None and event.module == "ETW Real-Time Process Sensor" and type(birth) is str
                and birth.isascii() and 1 <= len(birth) <= 20 and birth.isdecimal()
                and birth == str(int(birth)) and _FILETIME_EPOCH < int(birth) <= 0xFFFFFFFFFFFFFFFF):
            stamp = (int(birth) - _FILETIME_EPOCH) / 10_000_000
        if stamp is None or not target.create_time <= stamp <= event.event_ts or event.event_ts - stamp > 30:
            return None
        guid = _guid(fields.get("process_guid"))
        if guid and len(self._requests) < self.MAX_REQUESTS:
            self._requests[guid] = _DumpRequest(target, wer_pid, image, now + self.REQUEST_TTL, stamp)
        return WerFaultObservation("suite-dump-request", target, wer_pid, image,
                                   event.source_hmac, event.event_ts, event.mesh_required_observed)

    def _access(self, event, fields, owned):
        stamp = _source_time(fields.get("source_utc_time"))
        if stamp is None or not 0 <= event.event_ts - stamp <= 30:
            return None
        # Native WER -> suite access is the generation-linking leg. Creation
        # arguments alone identify only a PID candidate, even with a fresh cache.
        source_guid = _guid(fields.get("source_process_guid"))
        source_request = self._requests.get(source_guid)
        target_guid = _guid(fields.get("target_process_guid"))
        target_identity = self._owned_guids.get(target_guid)
        if source_request is not None and target_identity is not None:
            try:
                images_match = (_image(fields.get("source_image")) == source_request.wer_image
                                and _image(fields.get("target_image")) == source_request.protected.image)
            except ValueError:
                images_match = False
            if (stamp >= source_request.created_utc and images_match
                    and _pid(fields.get("source_pid")) == source_request.wer_pid
                    and _pid(fields.get("target_pid")) == source_request.protected.pid
                    and target_identity == (source_request.protected.pid, source_request.protected.birth_ticks,
                                            source_request.protected.image)):
                self._requests[source_guid] = replace(source_request, protected_generation_bound=True,
                                                       protected_guid=target_guid)
            return None
        guid = _guid(fields.get("target_process_guid"))
        request = self._requests.get(guid)
        if (request is None or stamp < request.created_utc
                or _pid(fields.get("target_pid")) != request.wer_pid):
            return None
        try:
            if _image(fields.get("target_image")) != request.wer_image:
                return None
            actor_image = _image(fields.get("source_image"))
        except ValueError:
            return None
        current = next((row for row in owned if row.pid == request.protected.pid), None)
        if (current is None or current.birth_ticks != request.protected.birth_ticks
                or current.image != request.protected.image):
            return None
        access = fields.get("granted_access")
        if (type(access) is not str or not re.fullmatch(r"(?:0[xX])?[0-9a-fA-F]{1,8}", access)):
            return None
        mask = int(access, 16)
        actor = _pid(fields.get("source_pid"))
        if actor is None or not mask & 0x0800 or actor == request.wer_pid:
            return None
        binding_current = (request.protected_generation_bound and request.protected_guid
                           and self._owned_guids.get(request.protected_guid)
                           == (current.pid, current.birth_ticks, current.image)
                           and (current.pid, current.birth_ticks, current.image) not in self._ambiguous_owned)
        return WerFaultObservation("suspend-capable-wer-access", current, request.wer_pid,
                                   request.wer_image, event.source_hmac, event.event_ts,
                                   event.mesh_required_observed,
                                   protected_generation_bound=bool(binding_current),
                                   actor_pid=actor, actor_image=actor_image, granted_access=mask)
