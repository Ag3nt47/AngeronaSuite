"""Governed, data-only reference memory for ARIA.

The bundled JSON is a read-only defensive reference, not a prompt, tool
manifest, action plan, or telemetry store.  It is duplicate-key rejecting,
strict-schema validated, structurally bounded, and pinned to a canonical
SHA-256 digest before any text enters local retrieval.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Final, Mapping


SCHEMA_VERSION: Final = 1
DEFENSE_MEMORY_SOURCE: Final = "angerona://defense-memory"
BUILTIN_DEFENSE_MEMORY_SHA256: Final = (
    "sha256:97a7771a9ce38ac66c6889dc90e0d591b64e07c2f169a0cebd7a57c119d67d57"
)
MAX_FILE_BYTES: Final = 64 * 1024
MAX_JSON_DEPTH: Final = 6
MAX_JSON_NODES: Final = 2048
MAX_ENTRIES: Final = 24
MAX_MARKDOWN_CHARS: Final = 48 * 1024

_ROOT_FIELDS = frozenset({
    "schema_version", "memory_id", "version", "governance", "entries",
})
_GOVERNANCE_FIELDS = frozenset({
    "classification",
    "authority",
    "contains_live_data",
    "contains_secrets",
    "contains_executable_actions",
    "contains_offensive_procedures",
    "agency_attribution",
})
_ENTRY_FIELDS = frozenset({
    "id", "title", "summary", "keywords", "guidance", "limits",
    "tradecraft_mappings",
})
_MAPPING_FIELDS = frozenset({
    "threat_pattern", "defensive_objective", "evidence_grade",
})
_EVIDENCE_GRADES = frozenset({
    "advisory", "attested-path", "corroborated", "sensor-dependent",
})
_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")
_VERSION = re.compile(r"[0-9][0-9a-z.-]{0,31}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_SENSITIVE = re.compile(
    r"(?i)(?:password|passwd|secret|token|api[-_ ]?key|authorization)"
    r"\s*[:=]|-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:sk-|gh[pousr]_|github_pat_)[A-Za-z0-9_-]{8,}"
)
_RAW_IDENTIFIER = re.compile(
    r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|"
    r"(?:^|\s)(?:[A-Z]:[\\/]|\\\\|/(?:home|users|var|tmp|etc)/)"
)
_PROMPT_OR_CODE = re.compile(
    r"(?i)ignore (?:all |the )?(?:previous|prior) instructions|"
    r"system prompt|assistant\s*:|user\s*:|jailbreak|<\|[^>]+\|>|"
    r"\[INST\]|```|\$\(|\b(?:powershell|cmd\.exe|bash -c|python -c|"
    r"curl|wget|wevtutil|netsh|reg\.exe)\b"
)
_OFFENSIVE_PROCEDURE = re.compile(
    r"(?i)\b(?:weaponize|shellcode|reverse shell|payload builder|exploit chain|"
    r"credential dumping instructions|persistence procedure)\b"
)
_AGENCY = re.compile(r"\b(?:CIA|NSA|FBI|FSB|GRU|MSS|GCHQ)\b", re.I)
_REPARSE_POINT: Final = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class DefenseMemoryError(RuntimeError):
    """The bundled defensive reference failed its governance boundary."""


@dataclass(frozen=True)
class TradecraftMapping:
    threat_pattern: str
    defensive_objective: str
    evidence_grade: str


@dataclass(frozen=True)
class DefenseMemoryEntry:
    id: str
    title: str
    summary: str
    keywords: tuple[str, ...]
    guidance: tuple[str, ...]
    limits: tuple[str, ...]
    tradecraft_mappings: tuple[TradecraftMapping, ...]


@dataclass(frozen=True)
class DefenseMemory:
    schema_version: int
    memory_id: str
    version: str
    entries: tuple[DefenseMemoryEntry, ...]

    def to_markdown(self) -> str:
        """Synthesize one bounded, inert in-memory retrieval document."""
        lines = ["# Angerona Defense Memory"]
        for entry in self.entries:
            lines.extend([
                "",
                f"## {entry.title}",
                entry.summary,
                "",
                "Keywords: " + ", ".join(entry.keywords) + ".",
                "",
                "Operator guidance:",
            ])
            lines.extend(f"- {item}" for item in entry.guidance)
            lines.extend(["", "Limits:"])
            lines.extend(f"- {item}" for item in entry.limits)
            if entry.tradecraft_mappings:
                lines.extend(["", "Defensive tradecraft mappings:"])
                lines.extend(
                    "- "
                    + item.threat_pattern
                    + ". Defensive objective: "
                    + item.defensive_objective
                    + " Evidence grade: "
                    + item.evidence_grade
                    + "."
                    for item in entry.tradecraft_mappings
                )
        document = "\n".join(lines).strip() + "\n"
        if len(document) > MAX_MARKDOWN_CHARS:
            raise DefenseMemoryError("synthesized defense memory exceeds its bound")
        return document


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if not isinstance(key, str) or key in result:
            raise DefenseMemoryError("defense memory contains a duplicate JSON field")
        result[key] = value
    return result


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise DefenseMemoryError("defense memory is not canonical JSON") from exc


def canonical_sha256(value: Any) -> str:
    """Return the canonical content digest used by the pinned loader."""
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _exact_fields(value: Mapping[str, Any], expected: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != expected:
        raise DefenseMemoryError(f"{label} does not match the strict schema")


def _bounded_structure(value: Any, *, depth: int = 0) -> int:
    stack = [(value, depth)]
    count = 0
    while stack:
        current, current_depth = stack.pop()
        if current_depth > MAX_JSON_DEPTH:
            raise DefenseMemoryError("defense memory exceeds its depth bound")
        count += 1
        if count > MAX_JSON_NODES:
            raise DefenseMemoryError("defense memory exceeds its node bound")
        if isinstance(current, dict):
            for key, child in current.items():
                if not isinstance(key, str):
                    raise DefenseMemoryError("defense memory keys must be text")
                stack.append((child, current_depth + 1))
        elif isinstance(current, list):
            stack.extend((child, current_depth + 1) for child in current)
    return count


def _text(value: Any, label: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise DefenseMemoryError(f"{label} is invalid")
    if (
        _SENSITIVE.search(value)
        or _RAW_IDENTIFIER.search(value)
        or _PROMPT_OR_CODE.search(value)
        or _OFFENSIVE_PROCEDURE.search(value)
        or _AGENCY.search(value)
    ):
        raise DefenseMemoryError(f"{label} violates the inert defensive boundary")
    return value


def _text_list(
    value: Any,
    label: str,
    *,
    minimum: int,
    maximum: int,
    item_maximum: int,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise DefenseMemoryError(f"{label} must be a bounded list")
    items = tuple(
        _text(item, f"{label}[{index}]", maximum=item_maximum)
        for index, item in enumerate(value)
    )
    if len({item.casefold() for item in items}) != len(items):
        raise DefenseMemoryError(f"{label} contains duplicates")
    return items


def _is_link_or_reparse(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        int(getattr(info, "st_file_attributes", 0)) & _REPARSE_POINT
    )


def _absolute_path(value: str | Path) -> Path:
    try:
        return Path(os.path.abspath(os.fspath(value)))
    except (OSError, TypeError, ValueError) as exc:
        raise DefenseMemoryError("defense memory path is invalid") from exc


def _reject_link_or_reparse_components(path: Path) -> None:
    """Reject links/reparse points in every existing path component."""
    if not path.is_absolute():
        raise DefenseMemoryError("defense memory path is invalid")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except OSError as exc:
            raise DefenseMemoryError("defense memory is unavailable") from exc
        if _is_link_or_reparse(info):
            raise DefenseMemoryError("defense memory path is unsafe")


def _file_identity(info: os.stat_result) -> tuple[object, ...]:
    return (
        getattr(info, "st_dev", None),
        getattr(info, "st_ino", None),
        stat.S_IFMT(info.st_mode),
        info.st_size,
        getattr(info, "st_mtime_ns", None),
    )


def _path_state(info: os.stat_result) -> tuple[object, ...]:
    return (
        *_file_identity(info),
        getattr(info, "st_ctime_ns", None),
    )


def _bounded_stable_read(
    path: str | Path,
    *,
    allowed_root: str | Path | None,
) -> bytes:
    """Read one root-contained regular file without following path redirects."""
    source = _absolute_path(path)
    root = _absolute_path(allowed_root if allowed_root is not None else source.parent)
    try:
        common = Path(os.path.commonpath((os.fspath(source), os.fspath(root))))
    except (OSError, ValueError) as exc:
        raise DefenseMemoryError("defense memory path is outside its resource root") from exc
    if os.path.normcase(os.fspath(common)) != os.path.normcase(os.fspath(root)):
        raise DefenseMemoryError("defense memory path is outside its resource root")

    _reject_link_or_reparse_components(root)
    _reject_link_or_reparse_components(source)
    try:
        root_info = root.lstat()
        before = source.lstat()
    except OSError as exc:
        raise DefenseMemoryError("defense memory is unavailable") from exc
    if not stat.S_ISDIR(root_info.st_mode) or _is_link_or_reparse(root_info):
        raise DefenseMemoryError("defense memory resource root is unsafe")
    if not stat.S_ISREG(before.st_mode) or _is_link_or_reparse(before):
        raise DefenseMemoryError("defense memory file is unsafe")
    if before.st_size > MAX_FILE_BYTES:
        raise DefenseMemoryError("defense memory exceeds its file-size bound")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(os.fspath(source), flags)
    except OSError as exc:
        raise DefenseMemoryError("defense memory could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or _is_link_or_reparse(opened)
            # Windows descriptor stat reports creation/change time differently
            # from path stat. Device, inode, type, size, and mtime remain the
            # stable cross-API admission identity; path state is rechecked below.
            or _file_identity(opened) != _file_identity(before)
        ):
            raise DefenseMemoryError("defense memory changed while opening")
        chunks: list[bytes] = []
        remaining = MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    except DefenseMemoryError:
        raise
    except OSError as exc:
        raise DefenseMemoryError("defense memory could not be read safely") from exc
    finally:
        os.close(descriptor)

    if len(raw) > MAX_FILE_BYTES:
        raise DefenseMemoryError("defense memory exceeds its file-size bound")
    try:
        after = source.lstat()
    except OSError as exc:
        raise DefenseMemoryError("defense memory changed during read") from exc
    if _is_link_or_reparse(after) or _path_state(after) != _path_state(before):
        raise DefenseMemoryError("defense memory changed during read")
    # Recheck the full route after the descriptor read so a parent redirect
    # cannot be accepted merely because the opened file identity stayed valid.
    _reject_link_or_reparse_components(source)
    return raw


def load_defense_memory(
    path: str | Path,
    *,
    expected_sha256: str,
    allowed_root: str | Path | None = None,
) -> DefenseMemory:
    """Load one explicitly pinned, strict-schema Defense Memory document."""
    raw = _bounded_stable_read(path, allowed_root=allowed_root)
    if not raw:
        raise DefenseMemoryError("defense memory is empty")
    try:
        document = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_object
        )
    except DefenseMemoryError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DefenseMemoryError("defense memory is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise DefenseMemoryError("defense memory root must be an object")
    if not isinstance(expected_sha256, str) or not _DIGEST.fullmatch(expected_sha256):
        raise DefenseMemoryError("expected defense memory digest is invalid")
    # Apply structural bounds before canonicalization so deeply nested or
    # high-node documents never reach the JSON serializer.
    _bounded_structure(document)
    if not hmac.compare_digest(canonical_sha256(document), expected_sha256):
        raise DefenseMemoryError("defense memory content digest is invalid")
    _exact_fields(document, _ROOT_FIELDS, "defense memory root")
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise DefenseMemoryError("defense memory schema version is unsupported")
    if document["memory_id"] != "angerona-defense-memory":
        raise DefenseMemoryError("defense memory identity is invalid")
    version = _text(document["version"], "defense memory version", maximum=32)
    if not _VERSION.fullmatch(version):
        raise DefenseMemoryError("defense memory version is invalid")

    governance = document["governance"]
    if not isinstance(governance, dict):
        raise DefenseMemoryError("defense memory governance must be an object")
    _exact_fields(governance, _GOVERNANCE_FIELDS, "defense memory governance")
    required_governance = {
        "classification": "defensive-reference",
        "authority": "read-only",
        "contains_live_data": False,
        "contains_secrets": False,
        "contains_executable_actions": False,
        "contains_offensive_procedures": False,
        "agency_attribution": "prohibited",
    }
    false_flags = (
        "contains_live_data",
        "contains_secrets",
        "contains_executable_actions",
        "contains_offensive_procedures",
    )
    if (
        governance != required_governance
        or any(governance[field] is not False for field in false_flags)
    ):
        raise DefenseMemoryError("defense memory governance is not fail-closed")

    rows = document["entries"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ENTRIES:
        raise DefenseMemoryError("defense memory entries must be a bounded list")
    entries: list[DefenseMemoryEntry] = []
    identities: set[str] = set()
    for index, row in enumerate(rows):
        label = f"entry[{index}]"
        if not isinstance(row, dict):
            raise DefenseMemoryError(f"{label} must be an object")
        _exact_fields(row, _ENTRY_FIELDS, label)
        entry_id = _text(row["id"], f"{label}.id", maximum=64)
        if not _ID.fullmatch(entry_id) or entry_id in identities:
            raise DefenseMemoryError(f"{label}.id is invalid or duplicated")
        identities.add(entry_id)
        title = _text(row["title"], f"{label}.title", maximum=96)
        summary = _text(row["summary"], f"{label}.summary", maximum=800)
        keywords = _text_list(
            row["keywords"], f"{label}.keywords",
            minimum=3, maximum=16, item_maximum=64,
        )
        guidance = _text_list(
            row["guidance"], f"{label}.guidance",
            minimum=2, maximum=8, item_maximum=500,
        )
        limits = _text_list(
            row["limits"], f"{label}.limits",
            minimum=1, maximum=6, item_maximum=500,
        )
        mapping_rows = row["tradecraft_mappings"]
        if not isinstance(mapping_rows, list) or len(mapping_rows) > 8:
            raise DefenseMemoryError(f"{label}.tradecraft_mappings is invalid")
        mappings: list[TradecraftMapping] = []
        for map_index, mapping in enumerate(mapping_rows):
            map_label = f"{label}.tradecraft_mappings[{map_index}]"
            if not isinstance(mapping, dict):
                raise DefenseMemoryError(f"{map_label} must be an object")
            _exact_fields(mapping, _MAPPING_FIELDS, map_label)
            grade = _text(
                mapping["evidence_grade"], f"{map_label}.evidence_grade",
                maximum=32,
            )
            if grade not in _EVIDENCE_GRADES:
                raise DefenseMemoryError(f"{map_label}.evidence_grade is invalid")
            mappings.append(TradecraftMapping(
                threat_pattern=_text(
                    mapping["threat_pattern"], f"{map_label}.threat_pattern",
                    maximum=300,
                ),
                defensive_objective=_text(
                    mapping["defensive_objective"],
                    f"{map_label}.defensive_objective", maximum=500,
                ),
                evidence_grade=grade,
            ))
        entries.append(DefenseMemoryEntry(
            id=entry_id,
            title=title,
            summary=summary,
            keywords=keywords,
            guidance=guidance,
            limits=limits,
            tradecraft_mappings=tuple(mappings),
        ))
    memory = DefenseMemory(
        schema_version=SCHEMA_VERSION,
        memory_id="angerona-defense-memory",
        version=version,
        entries=tuple(entries),
    )
    memory.to_markdown()
    return memory


def bundled_defense_memory_path() -> Path:
    """Return the read-only source or packaged asset path."""
    from angerona.core.data_paths import resource_root

    return resource_root() / "assets" / "angerona_defense_memory.json"


@lru_cache(maxsize=1)
def bundled_defense_memory() -> DefenseMemory:
    """Load and verify the built-in memory exactly once per process."""
    source = bundled_defense_memory_path()
    resource_root = source.parent.parent
    return load_defense_memory(
        source,
        expected_sha256=BUILTIN_DEFENSE_MEMORY_SHA256,
        allowed_root=resource_root,
    )
