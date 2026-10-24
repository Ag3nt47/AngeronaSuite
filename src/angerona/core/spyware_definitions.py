"""Locally activated, inert SpywareGuard definition packs.

External JSON is data, never publisher authority. One exact pack activation
authorizes subsequent local matches; the purpose-separated installation HMAC
protects persisted local choices, not publisher identity or whole-file replay.
All filesystem and cryptographic methods belong on a worker. ``snapshot`` and
``lookup`` only consult bounded memory behind a separate, briefly held lock.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading
import time

from angerona.core.atomic_io import replace_with_retry
from angerona.core.engine_transport import create_private_file, private_directory, verify_private
from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.process_allowlist import _hash_identity, _open_hash_stream
from angerona.core.source_sandbox import _hold_plain_directories, _validate_regular_file
from angerona.core.spyware_intel import MAX_BYTES, MAX_ITEMS, normalize_indicator

SCHEMA = "angerona.spyware-definitions.v1"
STATE_SCHEMA = "angerona.spyware-definition-state.v1"
MAX_STATE_BYTES = 2 * MAX_BYTES + 65536
MAX_LIFETIME = 30 * 86400
_CONTEXT = b"angerona-spyware-definition-state-v1"
_BUNDLE_FIELDS = {"schema", "version", "published_at", "expires_at", "indicators"}
_STATE_FIELDS = {"schema", "generation", "highest_version", "highest_sha256",
                 "active", "previous", "last_update", "hmac_sha256"}
_REVIEW_FIELDS = {"store_session", "generation", "staged_revision", "active_sha256",
                  "previous_sha256", "candidate_sha256", "action"}


class DefinitionError(ValueError):
    """A definition or its existing local authority could not be proved."""


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DefinitionError("Duplicate definition JSON member")
        result[key] = value
    return result


def _json(raw: bytes, maximum: int):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum:
        raise DefinitionError("Definition input exceeds its byte budget")
    # Bound depth before invoking Python's recursive JSON parser.
    depth = 0
    quoted = escaped = False
    for value in raw:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            if depth > 12:
                raise DefinitionError("Definition JSON is too deeply nested")
        elif value in (93, 125):
            depth -= 1
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              DefinitionError("Definition JSON must contain finite values")))
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise DefinitionError("Invalid definition JSON") from exc


def _timestamp(value):
    if (type(value) not in (int, float) or not 0 < value < 253402300800
            or not math.isfinite(value)):
        raise DefinitionError("Invalid definition timestamp")
    return value


def _version(value):
    if (type(value) is not str or not re.fullmatch(
            r"(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){0,3}", value)):
        raise DefinitionError("Definition version must be one to four dotted integers")
    numbers = tuple(int(part) for part in value.split("."))
    return numbers + (0,) * (4 - len(numbers))


def _local_path(value) -> Path:
    if not isinstance(value, (str, Path)):
        raise DefinitionError("Definition path must be a local absolute path")
    text = os.fspath(value)
    path = Path(text)
    if (not path.is_absolute() or text.startswith(("\\\\", "//")) or "\x00" in text
            or ".." in path.parts or (os.name == "nt" and any(":" in p for p in path.parts[1:]))):
        raise DefinitionError("Definition path must be a plain local absolute path")
    if os.name == "nt":
        import ctypes
        from ctypes import wintypes
        get_type = ctypes.WinDLL("kernel32", use_last_error=True).GetDriveTypeW
        get_type.argtypes, get_type.restype = [wintypes.LPCWSTR], wintypes.UINT
        if get_type(path.anchor) not in {2, 3, 5, 6}:
            raise DefinitionError("Definition paths must use a known local volume")
    return path


def _reject_aliases(path):
    for part in (path, *path.parents):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise DefinitionError("Definition path traverses a link or reparse point")


def read_definition_file(value, maximum=MAX_BYTES) -> bytes:
    """Read admitted size plus one through one retained ordinary descriptor.

    Existing shared custody helpers hold plain Windows ancestors and deny file
    write/delete sharing for this read. POSIX identity checks remain snapshots.
    The cooperative five-second budget cannot preempt a stalled kernel call.
    """
    path = _local_path(value)
    deadline = time.monotonic() + 5.0
    with _hold_plain_directories(path.parent):
        _validate_regular_file(path)
        named = path.lstat()
        if named.st_nlink != 1 or not 0 < named.st_size <= maximum:
            raise DefinitionError("Definition input must be a bounded single-link regular file")
        identity = _hash_identity(named)
        with _open_hash_stream(path) as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or _hash_identity(before) != identity:
                raise DefinitionError("Definition input changed before opening")
            remaining = before.st_size
            chunks = []
            while remaining:
                if time.monotonic() >= deadline:
                    raise DefinitionError("Definition read budget exhausted")
                chunk = stream.read(min(65536, remaining))
                if not chunk or len(chunk) > remaining:
                    raise DefinitionError("Definition read is incomplete")
                chunks.append(chunk)
                remaining -= len(chunk)
            if stream.read(1):
                raise DefinitionError("Definition input grew during its read")
            after = os.fstat(stream.fileno())
            _validate_regular_file(path)
            final = path.lstat()
            if (after.st_nlink != 1 or final.st_nlink != 1 or _hash_identity(after) != identity
                    or _hash_identity(final) != identity or time.monotonic() >= deadline):
                raise DefinitionError("Definition input changed during its read")
        return b"".join(chunks)


@dataclass(frozen=True)
class DefinitionBundle:
    version: str
    published_at: int | float
    expires_at: int | float
    indicators: tuple[tuple[str, str], ...]
    sha256: str
    source_sha256: str

    def document(self):
        return {"schema": SCHEMA, "version": self.version, "published_at": self.published_at,
                "expires_at": self.expires_at,
                "indicators": [{"kind": kind, "value": value} for kind, value in self.indicators]}

    def fresh(self, now):
        return self.published_at <= now < self.expires_at

    def summary(self):
        counts = {kind: sum(row[0] == kind for row in self.indicators)
                  for kind in ("sha256", "ip", "domain")}
        return {"version": self.version, "published_at": self.published_at,
                "expires_at": self.expires_at, "sha256": self.sha256,
                "source_sha256": self.source_sha256, "indicator_count": len(self.indicators),
                "counts": counts, "publisher_verified": False,
                "indicator_preview": [{"kind": kind, "value": value}
                                      for kind, value in self.indicators[:25]],
                "preview_truncated": len(self.indicators) > 25}


def parse_definition_bundle(raw: bytes, *, now=None, require_fresh=True) -> DefinitionBundle:
    document = _json(raw, MAX_BYTES)
    if type(document) is not dict or set(document) != _BUNDLE_FIELDS or document["schema"] != SCHEMA:
        raise DefinitionError("Unsupported definition bundle fields or schema")
    _version(document["version"])
    published, expires = (_timestamp(document[key]) for key in ("published_at", "expires_at"))
    if not 0 < expires - published <= MAX_LIFETIME:
        raise DefinitionError("Definition validity must be positive and at most 30 days")
    observed = time.time() if now is None else _timestamp(now)
    if require_fresh and not published <= observed < expires:
        raise DefinitionError("Definition bundle is future-dated or expired")
    rows = document["indicators"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_ITEMS:
        raise DefinitionError("Invalid definition indicator count")
    indicators = set()
    for row in rows:
        if (type(row) is not dict or set(row) != {"kind", "value"}
                or type(row["kind"]) is not str or row["kind"] not in {"sha256", "ip", "domain"}):
            raise DefinitionError("Definitions accept only inert SHA256, IP and domain literals")
        normalized = normalize_indicator(row["kind"], row["value"])
        if normalized is None or (row["kind"], normalized) in indicators:
            raise DefinitionError("Invalid or duplicate definition literal")
        indicators.add((row["kind"], normalized))
    ordered = tuple(sorted(indicators))
    canonical = {**document, "indicators": [{"kind": k, "value": v} for k, v in ordered]}
    digest = hashlib.sha256(_canonical(canonical)).hexdigest()
    return DefinitionBundle(document["version"], published, expires, ordered, digest,
                            hashlib.sha256(raw).hexdigest())


def parse_definition_review(value):
    if type(value) is not dict or set(value) != _REVIEW_FIELDS:
        return None
    if (type(value["store_session"]) is not str or not re.fullmatch(r"[0-9a-f]{32}", value["store_session"])
            or any(type(value[key]) is not int or not 0 <= value[key] < 2**53
                   for key in ("generation", "staged_revision"))
            or type(value["action"]) is not str or value["action"] not in {"activate", "rollback"}
            or any(type(value[key]) is not str or not re.fullmatch(r"(?:[0-9a-f]{64})?", value[key])
                   for key in ("active_sha256", "previous_sha256", "candidate_sha256"))):
        return None
    return dict(value)


class DefinitionStore:
    """Worker-owned durable operations with a separate small in-memory view."""
    def __init__(self, root: Path, *, clock=time.time):
        self.root = _local_path(root)
        self.directory = self.root / "spyware_guard"
        self.path = self.directory / "definitions-state.json"
        self._clock = clock
        self._lock = threading.RLock()
        self._operations = threading.Lock()
        self._session = secrets.token_hex(16)
        self._staged_revision = 0
        self._staged = None
        self._generation = 0
        self._active = self._previous = None
        self._active_record = self._previous_record = None
        self._highest_version = self._highest_sha256 = ""
        self._state_raw = None
        self._last_update = None
        self._lookup = frozenset()
        self._publication_uncertain = False
        self._summaries = {"active": None, "previous": None, "staged": None}
        verify_private(self.root / "bus.key")
        self._key_raw = read_definition_file(self.root / "bus.key", 256)
        self._key_identity = _hash_identity((self.root / "bus.key").lstat())
        try:
            key = bytes.fromhex(self._key_raw.decode("ascii").strip())
        except (ValueError, UnicodeError) as exc:
            raise DefinitionError("Existing definition installation authority is malformed") from exc
        if len(key) != 32:
            raise DefinitionError("Existing definition installation authority is malformed")
        self._key = hmac.new(key, _CONTEXT, hashlib.sha256).digest()
        raw = self._read_state()
        if raw is not None:
            state, active, previous = self._decode_state(raw)
            self._publish(state, active, previous, raw)

    def _read_state(self):
        _reject_aliases(self.path)
        if not os.path.lexists(self.path):
            return None
        verify_private(self.directory, directory=True)
        verify_private(self.path)
        return read_definition_file(self.path, MAX_STATE_BYTES)

    def _pack(self, record):
        if type(record) is not dict or set(record) != {"bundle", "source_sha256", "activated_at"}:
            raise DefinitionError("Invalid locally activated definition record")
        if type(record["source_sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", record["source_sha256"]):
            raise DefinitionError("Invalid definition source digest")
        _timestamp(record["activated_at"])
        bundle = parse_definition_bundle(_canonical(record["bundle"]), now=self._clock(), require_fresh=False)
        return DefinitionBundle(bundle.version, bundle.published_at, bundle.expires_at,
                                bundle.indicators, bundle.sha256, record["source_sha256"])

    def _decode_state(self, raw):
        state = _json(raw, MAX_STATE_BYTES)
        if type(state) is not dict or set(state) != _STATE_FIELDS or state["schema"] != STATE_SCHEMA:
            raise DefinitionError("Invalid authenticated definition state")
        signature = state["hmac_sha256"]
        body = {key: value for key, value in state.items() if key != "hmac_sha256"}
        if (type(signature) is not str or not re.fullmatch(r"[0-9a-f]{64}", signature)
                or not hmac.compare_digest(signature, hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest())):
            raise DefinitionError("Definition state authentication failed")
        if type(state["generation"]) is not int or not 1 <= state["generation"] < 2**53:
            raise DefinitionError("Invalid definition state generation")
        highest = _version(state["highest_version"])
        if type(state["highest_sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", state["highest_sha256"]):
            raise DefinitionError("Invalid highest accepted definition digest")
        _timestamp(state["last_update"])
        active = self._pack(state["active"])
        previous = self._pack(state["previous"]) if state["previous"] is not None else None
        if any(_version(pack.version) > highest for pack in (active, previous) if pack is not None):
            raise DefinitionError("Definition version exceeds its local acceptance record")
        for pack in (active, previous):
            if pack is not None and _version(pack.version) == highest and pack.sha256 != state["highest_sha256"]:
                raise DefinitionError("Accepted definition version has conflicting contents")
        return state, active, previous

    def _publish(self, state, active, previous, raw):
        # Build large immutable indexes and summaries before the paint lock.
        lookup = frozenset(active.indicators)
        summaries = {"active": active.summary(),
                     "previous": previous.summary() if previous is not None else None,
                     "staged": self._staged.summary() if self._staged is not None else None}
        with self._lock:
            self._generation, self._active, self._previous = state["generation"], active, previous
            self._active_record, self._previous_record = state["active"], state["previous"]
            self._highest_version, self._highest_sha256 = state["highest_version"], state["highest_sha256"]
            self._last_update, self._state_raw, self._lookup = state["last_update"], raw, lookup
            self._summaries = summaries

    def _review(self, action):
        candidate = self._staged if action == "activate" else self._previous
        return {"store_session": self._session, "generation": self._generation,
                "staged_revision": self._staged_revision,
                "active_sha256": self._active.sha256 if self._active else "",
                "previous_sha256": self._previous.sha256 if self._previous else "",
                "candidate_sha256": candidate.sha256 if candidate else "", "action": action}

    def snapshot(self):
        with self._lock:
            now = self._clock()
            result = {"state": "unavailable" if self._publication_uncertain else "active" if self._active and self._active.fresh(now) else "expired" if self._active else "empty",
                      "generation": self._generation, "busy": False, "error": "",
                      "publication_uncertain": self._publication_uncertain,
                      "highest_version": self._highest_version, "last_update": self._last_update,
                      "authentication": "local activation HMAC; publisher unverified; no independent rollback witness"}
            result.update({key: dict(value) if value else None for key, value in self._summaries.items()})
            for key, action in (("staged", "activate"), ("previous", "rollback")):
                if result[key] is not None:
                    result[key]["review_identity"] = self._review(action)
            return json.loads(json.dumps(result))

    def stage(self, path):
        with self._operations:
            bundle = parse_definition_bundle(read_definition_file(path), now=self._clock())
            summary = bundle.summary()
            with self._lock:
                self._staged = bundle
                self._staged_revision += 1
                self._summaries["staged"] = summary
        return self.snapshot()

    def lookup(self, kind, value):
        normalized = normalize_indicator(kind, value)
        with self._lock:
            if (self._publication_uncertain or self._active is None or not self._active.fresh(self._clock())
                    or (kind, normalized) not in self._lookup):
                return None
            return {"version": self._active.version, "sha256": self._active.sha256,
                    "source_sha256": self._active.source_sha256, "generation": self._generation,
                    "published_at": self._active.published_at, "expires_at": self._active.expires_at,
                    "indicator_kind": kind, "indicator": normalized, "publisher_verified": False,
                    "locally_activated": True}

    def has_hashes(self):
        with self._lock:
            return bool(not self._publication_uncertain and self._active and self._active.fresh(self._clock())
                        and self._summaries["active"]["counts"]["sha256"])

    def _prior_publication_unchanged(self):
        """A failed replace call can still have published; prove the old state."""
        try:
            with _hold_plain_directories(self.root):
                key_path = self.root / "bus.key"
                _validate_regular_file(key_path)
                verify_private(key_path)
                named = key_path.lstat()
                with _open_hash_stream(key_path) as authority:
                    before = os.fstat(authority.fileno())
                    if (before.st_nlink != 1 or named.st_nlink != 1
                            or _hash_identity(before) != self._key_identity
                            or _hash_identity(named) != self._key_identity
                            or authority.read(before.st_size + 1) != self._key_raw
                            or self._read_state() != self._state_raw):
                        return False
                    after, final = os.fstat(authority.fileno()), key_path.lstat()
                    return (after.st_nlink == final.st_nlink == 1
                            and _hash_identity(after) == self._key_identity
                            and _hash_identity(final) == self._key_identity)
        except Exception:
            return False

    def _persist(self, raw, *, commit_guard, publish):
        temporary = self.directory / (".definitions-" + secrets.token_hex(16) + ".tmp")
        descriptor = create_private_file(temporary)
        replaced = False
        attempted = False
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            if read_definition_file(temporary, MAX_STATE_BYTES) != raw:
                raise DefinitionError("Definition state staging verification failed")
            if self._read_state() != self._state_raw:
                raise DefinitionError("Definition state changed; restart before updating")
            # The existing key is held sealed throughout final publication.
            with _hold_plain_directories(self.root):
                key_path = self.root / "bus.key"
                _validate_regular_file(key_path)
                verify_private(key_path)
                named = key_path.lstat()
                with _open_hash_stream(key_path) as authority:
                    before = os.fstat(authority.fileno())
                    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or named.st_nlink != 1
                            or _hash_identity(before) != self._key_identity
                            or _hash_identity(named) != self._key_identity
                            or authority.read(before.st_size + 1) != self._key_raw):
                        raise DefinitionError("Existing definition authority changed")
                    with commit_guard():
                        attempted = True
                        replace_with_retry(temporary, self.path)
                        replaced = True
                        if self._read_state() != raw:
                            raise DefinitionError("Definition state publication could not be verified")
                        after, final = os.fstat(authority.fileno()), key_path.lstat()
                        if (after.st_nlink != 1 or final.st_nlink != 1
                                or _hash_identity(after) != self._key_identity
                                or _hash_identity(final) != self._key_identity):
                            raise DefinitionError("Existing definition authority changed")
                        publish()
        except Exception as exc:
            if replaced or (attempted and not self._prior_publication_unchanged()):
                with self._lock:
                    self._publication_uncertain = True
                raise DefinitionError("Definition publication is uncertain; retain state for restart review") from exc
            raise
        finally:
            temporary.unlink(missing_ok=True)

    def apply(self, expected, *, action="activate", commit_guard=nullcontext):
        with self._operations:
            if self._publication_uncertain:
                raise DefinitionError("An uncertain definition publication requires restart review")
            with self._lock:
                if (parse_definition_review(expected) is None
                        or action not in {"activate", "rollback"} or expected != self._review(action)):
                    raise DefinitionError("Definition selection is stale; refresh before updating")
                bundle = self._staged if action == "activate" else self._previous
                if bundle is None or not bundle.fresh(self._clock()):
                    raise DefinitionError("Selected definitions are absent, future-dated or expired")
                if action == "activate" and self._highest_version and _version(bundle.version) <= _version(self._highest_version):
                    raise DefinitionError("Normal definition updates must advance the highest accepted version")
                if self._generation >= 2**53 - 1:
                    raise DefinitionError("Definition generation is exhausted")
                generation = self._generation + 1
                previous, previous_record = self._active, self._active_record
            now = _timestamp(self._clock())
            record = {"bundle": bundle.document(), "source_sha256": bundle.source_sha256, "activated_at": now}
            body = {"schema": STATE_SCHEMA, "generation": generation, "active": record,
                    "previous": previous_record, "last_update": now,
                    "highest_version": bundle.version if action == "activate" else self._highest_version,
                    "highest_sha256": bundle.sha256 if action == "activate" else self._highest_sha256}
            raw = _canonical({**body, "hmac_sha256": hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()})
            if len(raw) > MAX_STATE_BYTES:
                raise DefinitionError("Active and rollback definitions exceed the state budget")
            _reject_aliases(self.directory)
            with _hold_plain_directories(self.root):
                private_directory(self.directory)
                with _hold_plain_directories(self.directory):
                    with ExclusiveFileLease(self.directory / "definitions.writer.lock"):
                        self._persist(raw, commit_guard=commit_guard,
                                      publish=lambda: self._publish(body, bundle, previous, raw))
        return self.snapshot()
