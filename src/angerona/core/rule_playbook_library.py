"""Bounded, data-only YARA and declarative response-playbook workspace.

Remote discovery pins public GitHub source before listing members. Importing
preserves original bytes and provenance; it grants no execution authority.
Activation selects reviewed data only. Native response gates remain mandatory.
The local digests detect inconsistent state, not compromise by the same user.
"""
from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import threading
import time
import unicodedata
from urllib.parse import urlsplit

from angerona.core.file_lease import ExclusiveFileLease
from angerona.core.github_tool_catalog import (
    GitHubToolCatalog, ImportOperation, _bounded_read, repository_identity,
    resolve_import,
)
from angerona.core.source_sandbox import (
    _absolute, _atomic_bytes_write, _ensure_directory, _hold_plain_directories,
)

MAX_ITEM_BYTES = 64 * 1024
MAX_ITEMS = 256
MAX_BATCH = 32
MAX_STORE_BYTES = 32 * 1024 * 1024
MAX_INDEX_BYTES = 512 * 1024
MAX_STORE_FILES = 2048
_DIGEST = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,119}")
_LOCK = threading.RLock()
_SOURCES = (
    {"name": "Angerona native examples", "url": "builtin:angerona", "kind": "all",
     "description": "Local YARA sample and declarative SOAR examples; no download."},
    {"name": "YARA Forge", "url": "https://github.com/YARAHQ/yara-forge", "kind": "yara",
     "description": "Community rule aggregation. Per-rule licenses and dependencies vary."},
    {"name": "Signature Base", "url": "https://github.com/Neo23x0/signature-base", "kind": "yara",
     "description": "YARA and IOC source. Includes/imports need a compatible reviewed adapter."},
    {"name": "Shuffle workflows", "url": "https://github.com/Shuffle/workflows", "kind": "soar",
     "description": "External workflow review. Shuffle workflows are not executed by Angerona."},
    {"name": "Cortex analyzers and responders", "url": "https://github.com/TheHive-Project/Cortex-Analyzers", "kind": "soar",
     "description": "External analyzer descriptors for review; Python/scripts remain inactive."},
)
_EXAMPLES = {
    "examples/angerona-sample.yar": b'rule Angerona_User_Sample { meta: description = "Inert authoring sample" strings: $a = "ANGERONA_RULE_LIBRARY_SAMPLE" condition: $a }\n',
    "examples/review-high.angerona-playbook.json": json.dumps({
        "schema": "angerona-playbook/v1", "id": "review-high", "name": "Review high-severity detections",
        "description": "Add a plain-language review note for original active detections.",
        "trigger": {"minimum_severity": "HIGH", "modules": []},
        "actions": [{"type": "notify", "message": "Review the original detection and its coverage before responding."}],
    }, sort_keys=True, indent=2).encode(),
    "examples/request-containment.angerona-playbook.json": json.dumps({
        "schema": "angerona-playbook/v1", "id": "request-containment", "name": "Request verified containment",
        "description": "Request existing SOAR containment. This never arms response or bypasses corroboration.",
        "trigger": {"minimum_severity": "CRITICAL", "modules": []},
        "actions": [{"type": "request_containment"}],
    }, sort_keys=True, indent=2).encode(),
}


class _LibraryOperation(ImportOperation):
    """Share cancellation and keep the caller's original finite deadline."""
    def __init__(self, outer=None):
        super().__init__()
        self._outer = outer
        if outer is not None:
            self.cancelled = outer.cancelled
            self.deadline = min(self.deadline, outer.deadline)

    def check(self):
        if self._outer is not None:
            self._outer.check()
        super().check()

    def next_phase(self):
        self.check()


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON keys are not supported.")
        result[key] = value
    return result


def _document(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_ITEM_BYTES:
        raise ValueError("Choose a nonempty UTF-8 document up to 64 KiB.")
    text = raw.decode("utf-8-sig", "strict")
    if "\0" in text:
        raise ValueError("Binary documents are not supported.")
    return text


def validate_playbook(raw):
    """Closed, non-executable schema. No command strings, paths or target IDs."""
    value = json.loads(_document(raw), object_pairs_hook=_pairs)
    if (type(value) is not dict or set(value) != {"schema", "id", "name", "description", "trigger", "actions"}
            or value["schema"] != "angerona-playbook/v1"
            or type(value["id"]) is not str or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", value["id"])
            or type(value["name"]) is not str or not _NAME.fullmatch(value["name"])
            or type(value["description"]) is not str or len(value["description"]) > 2048):
        raise ValueError("Unsupported playbook. Use the closed angerona-playbook/v1 JSON schema.")
    trigger = value["trigger"]
    if (type(trigger) is not dict or set(trigger) != {"minimum_severity", "modules"}
            or trigger["minimum_severity"] not in {"HIGH", "CRITICAL"}
            or type(trigger["modules"]) is not list or len(trigger["modules"]) > 32
            or any(type(name) is not str or not 1 <= len(name) <= 160 or name.strip() != name
                   or any(unicodedata.category(char)[0] == "C" for char in name)
                   for name in trigger["modules"])
            or len(set(trigger["modules"])) != len(trigger["modules"])):
        raise ValueError("Choose HIGH/CRITICAL and a bounded list of exact module names.")
    actions = value["actions"]
    if type(actions) is not list or not 1 <= len(actions) <= 8:
        raise ValueError("A playbook needs 1–8 fixed actions.")
    for action in actions:
        if type(action) is not dict or action.get("type") not in {"notify", "request_containment"}:
            raise ValueError("Only notify and request_containment actions are supported; scripts are review-only.")
        if action["type"] == "notify":
            if (set(action) != {"type", "message"} or type(action["message"]) is not str
                    or not 1 <= len(action["message"]) <= 1024):
                raise ValueError("A notification needs one bounded plain-text message.")
        elif set(action) != {"type"}:
            raise ValueError("Containment uses the original event's verified target; target overrides are forbidden.")
    return value


def _kind(path):
    lower = path.casefold()
    if lower.endswith((".yar", ".yara")):
        return "yara"
    if lower.endswith((".json", ".yaml", ".yml")):
        return "soar"
    return ""


def _source_url(url):
    """Accept repo URLs and immutable blob/tree URLs without arbitrary HTTP."""
    if type(url) is not str or len(url) > 2048:
        raise ValueError("Paste an HTTPS GitHub repository or immutable file/folder URL.")
    parsed = urlsplit(url.strip())
    parts = parsed.path.strip("/").split("/")
    if parsed.query or parsed.fragment or parsed.scheme != "https" or parsed.netloc != "github.com":
        raise ValueError("Only public HTTPS github.com source URLs are supported; no local or redirected fetches.")
    if len(parts) == 2:
        repo = repository_identity(url)
        return "https://github.com/" + repo, "HEAD", ""
    if (len(parts) >= 4 and parts[2] in {"tree", "blob"}
            and re.fullmatch(r"[0-9a-fA-F]{40}", parts[3])):
        repo = repository_identity("https://github.com/" + "/".join(parts[:2]))
        prefix = "/".join(parts[4:])
        if any(part in {"", ".", ".."} for part in parts[4:]) or "\\" in prefix or "%" in prefix:
            raise ValueError("Unsupported source member path.")
        return "https://github.com/" + repo, parts[3].lower(), prefix
    raise ValueError("Use the repository URL, or a file/folder URL pinned to a full 40-character commit.")


class RulePlaybookLibrary:
    def __init__(self, root, *, catalog: GitHubToolCatalog, yara_probe=None):
        self.root = _absolute(root)
        self.catalog = catalog
        self._probe = yara_probe

    @staticmethod
    def _view(row):
        return dict(row, name=PurePosixPath(row["path"]).name,
            state="active" if row["active_sha256"] else "draft")

    @staticmethod
    def sources():
        return json.loads(json.dumps(_SOURCES))

    @contextlib.contextmanager
    def _transaction(self):
        with _LOCK:
            _ensure_directory(self.root)
            with _hold_plain_directories(self.root), ExclusiveFileLease(self.root / "library.lock"):
                yield

    def _index(self):
        try:
            value = json.loads(_bounded_read(self.root / "index.json", self.root, MAX_INDEX_BYTES), object_pairs_hook=_pairs)
        except FileNotFoundError:
            return []
        if type(value) is not list or len(value) > MAX_ITEMS:
            raise ValueError("Rule library index is invalid or exceeds its bound.")
        seen = set()
        for row in value:
            keys = {"id", "source_id", "repository", "commit", "license", "path", "kind", "original_sha256", "draft_sha256", "active_sha256", "previous_sha256", "bytes", "imported_at", "validation"}
            if (type(row) is not dict or set(row) != keys or type(row["id"]) is not str
                    or not _DIGEST.fullmatch(row["id"]) or row["id"] in seen
                    or row["kind"] not in {"yara", "soar"} or type(row["bytes"]) is not int
                    or not 0 < row["bytes"] <= MAX_ITEM_BYTES):
                raise ValueError("Rule library record is malformed.")
            for key in ("original_sha256", "draft_sha256", "active_sha256", "previous_sha256"):
                if type(row[key]) is not str or (row[key] and not _DIGEST.fullmatch(row[key])):
                    raise ValueError("Rule library digest is malformed.")
            if (not row["original_sha256"] or not row["draft_sha256"] or type(row["path"]) is not str
                    or len(row["path"]) > 1024 or type(row["validation"]) is not dict):
                raise ValueError("Rule library provenance is malformed.")
            if (type(row["source_id"]) is not str
                    or row["source_id"] not in {"builtin:angerona", "local"} and not _DIGEST.fullmatch(row["source_id"])
                    or row["id"] != _sha((row["source_id"] + "\n" + row["path"]).encode())
                    or any(type(row[key]) is not str or len(row[key]) > 512 for key in ("repository", "commit", "license"))
                    or type(row["imported_at"]) is not int or not 0 <= row["imported_at"] <= 10**12):
                raise ValueError("Rule library source identity is inconsistent.")
            seen.add(row["id"])
        return value

    def _save(self, rows):
        raw = _canonical(rows)
        if len(raw) > MAX_INDEX_BYTES:
            raise ValueError("Rule library metadata budget reached.")
        _atomic_bytes_write(self.root / "index.json", raw, root=self.root)

    def _blob(self, raw):
        digest = _sha(raw)
        path = self.root / (digest + ".txt")
        try:
            existing = _bounded_read(path, self.root, MAX_ITEM_BYTES)
            if existing != raw:
                raise ValueError("Rule content custody is inconsistent.")
        except FileNotFoundError:
            total = 0
            for count, entry in enumerate(self.root.iterdir(), 1):
                if count >= MAX_STORE_FILES:
                    raise ValueError("Rule library revision-file limit reached; export and review unused revisions.")
                if total > MAX_STORE_BYTES:
                    break
                if entry.name == "library.lock":
                    continue
                info = entry.lstat()
                if entry.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400 or not entry.is_file() or info.st_nlink != 1:
                    raise ValueError("Rule storage contains an unexpected object; review it before writing.")
                total += info.st_size
            if total + len(raw) > MAX_STORE_BYTES:
                raise ValueError("Rule storage reached its 32 MiB budget; export/review unused revisions.")
            _atomic_bytes_write(path, raw, root=self.root)
        return digest

    def _read_blob(self, digest):
        if type(digest) is not str or not _DIGEST.fullmatch(digest):
            raise ValueError("Unknown content digest.")
        raw = _bounded_read(self.root / (digest + ".txt"), self.root, MAX_ITEM_BYTES)
        if _sha(raw) != digest:
            raise ValueError("Rule content failed its consistency check.")
        _document(raw)
        return raw

    def _row(self, rows, item_id):
        if type(item_id) is not str or not _DIGEST.fullmatch(item_id):
            raise ValueError("Unknown rule/playbook ID.")
        for row in rows:
            if row["id"] == item_id:
                return row
        raise ValueError("Rule/playbook no longer exists.")

    def discover(self, url, *, kind="all", query="", operation=None, progress=None):
        if kind not in {"all", "yara", "soar"} or type(query) is not str or len(query) > 256:
            raise ValueError("Invalid catalog filter.")
        operation = _LibraryOperation(operation)
        operation.check()
        if url == "builtin:angerona":
            source = dict(id="builtin:angerona", repository="Ag3nt47/AngeronaSuite", commit="bundled", license="MIT")
            names = list(_EXAMPLES)
            prefix = ""
        else:
            canonical, revision, prefix = _source_url(url)
            if progress:
                progress({"phase": "resolve", "message": "Resolving source to an immutable commit", "percent": None})
            source = self.catalog.import_source(resolve_import(canonical, revision, operation), operation)
            names = self.catalog.files(source["id"])
        entries = []
        for name in names:
            operation.check()
            candidate = _kind(name)
            if (candidate and (kind == "all" or kind == candidate)
                    and (not prefix or name == prefix or name.startswith(prefix + "/"))
                    and query.casefold() in name.casefold()):
                entries.append({"id": _sha((source["id"] + "\n" + name).encode()), "path": name,
                    "name": PurePosixPath(name).name, "kind": candidate,
                    "compatibility": "Needs validation; foreign SOAR formats are review-only" if candidate == "soar" else "Needs native YARA-X validation",
                    "license": source["license"]})
        return {"source_id": source["id"], "commit": source["commit"], "repository": source["repository"],
                "license": source["license"], "entries": entries, "response_authorized": False}

    def install_batch(self, source_id, paths, *, operation=None, progress=None):
        if (type(paths) is not list or not 1 <= len(paths) <= MAX_BATCH or len(set(paths)) != len(paths)
                or any(type(path) is not str or len(path) > 1024 or not _kind(path) for path in paths)):
            raise ValueError("Choose 1–32 distinct YARA/playbook members per batch.")
        operation = _LibraryOperation(operation)
        operation.check()
        if source_id == "builtin:angerona":
            source = dict(id=source_id, repository="Ag3nt47/AngeronaSuite", commit="bundled", license="MIT")
            selected = {name: _EXAMPLES[name] for name in paths if name in _EXAMPLES}
            if len(selected) != len(paths):
                raise ValueError("Unknown bundled example.")
        else:
            source = next((row for row in self.catalog.list_imports() if row["id"] == source_id), None)
            if source is None or source["state"] != "reviewed":
                raise ValueError("Review the pinned source and license in Source Library before installing selected data.")
            selected = self.catalog.raw_members(source_id, paths, max_bytes=MAX_ITEM_BYTES,
                total_bytes=MAX_BATCH * MAX_ITEM_BYTES, require_reviewed=True)
        for raw in selected.values():
            _document(raw)
        with self._transaction():
            rows = self._index()
            result = []
            for position, name in enumerate(paths):
                operation.check()
                identity = _sha((source_id + "\n" + name).encode())
                prior = next((row for row in rows if row["id"] == identity), None)
                if prior is not None:
                    result.append(dict(prior, preserved=True))
                    continue
                if len(rows) >= MAX_ITEMS:
                    raise ValueError("Rule library reached its 256-item metadata bound.")
                raw = selected[name]
                digest = self._blob(raw)
                row = dict(id=identity, source_id=source_id, repository=source["repository"],
                    commit=source["commit"], license=source["license"], path=name, kind=_kind(name),
                    original_sha256=digest, draft_sha256=digest, active_sha256="", previous_sha256="",
                    bytes=len(raw), imported_at=int(time.time()), validation={})
                rows.append(row)
                result.append(dict(row, preserved=False))
                if progress:
                    progress({"phase": "install", "message": name, "percent": round(100 * (position + 1) / len(paths))})
            operation.check()
            self._save(rows)
            return result

    def items(self):
        with self._transaction():
            return [self._view(row) for row in self._index()]

    def read(self, item_id):
        with self._transaction():
            row = self._row(self._index(), item_id)
            return dict(self._view(row), text=_document(self._read_blob(row["draft_sha256"])))

    def create_draft(self, kind, text, *, name):
        if kind not in {"yara", "soar"} or type(name) is not str or not _NAME.fullmatch(name):
            raise ValueError("Choose YARA or SOAR and a bounded plain name.")
        if type(text) is not str:
            raise ValueError("Draft must be UTF-8 text.")
        raw = text.encode("utf-8")
        _document(raw)
        path = "local/" + name + (".yar" if kind == "yara" else ".angerona-playbook.json")
        identity = _sha(("local\n" + path).encode())
        with self._transaction():
            rows = self._index()
            if any(row["id"] == identity for row in rows):
                raise ValueError("A draft with that name already exists; edit its retained copy.")
            if len(rows) >= MAX_ITEMS:
                raise ValueError("Rule library reached its item bound.")
            digest = self._blob(raw)
            row = dict(id=identity, source_id="local", repository="local", commit="local draft", license="User-authored",
                path=path, kind=kind, original_sha256=digest, draft_sha256=digest, active_sha256="", previous_sha256="",
                bytes=len(raw), imported_at=int(time.time()), validation={})
            rows.append(row)
            self._save(rows)
            return self._view(row)

    def save_draft(self, item_id, text):
        if type(text) is not str:
            raise ValueError("Draft must be plain UTF-8 text.")
        raw = text.encode("utf-8")
        _document(raw)
        with self._transaction():
            rows = self._index()
            row = self._row(rows, item_id)
            row.update(draft_sha256=self._blob(raw), bytes=len(raw), validation={})
            self._save(rows)
            return dict(row, state="draft", response_authorized=False)

    def _validate_content(self, row, raw, *, operation=None):
        if operation is not None:
            operation.check()
        if row["kind"] == "soar":
            document = validate_playbook(raw)
            return {"state": "valid", "message": "Closed declarative playbook validated; host response remains policy/identity/receipt gated.",
                    "actions": [action["type"] for action in document["actions"]]}
        if self._probe is None:
            from angerona.core.community_tool_adapters import AdapterOperation
            from angerona.core.community_tool_probe_worker import run_yara_probe
            probe, operation = run_yara_probe, operation or AdapterOperation(timeout=20)
        else:
            probe, operation = self._probe, operation or ImportOperation()
        result = probe(self.root.parent / (self.root.name + "-probes"), [{"path": row["id"], "text": _document(raw)}],
                      [b"ANGERONA_RULE_LIBRARY_SAMPLE", b"ordinary inert negative sample"], operation)
        if result.get("state") != "completed" or result.get("worker_retired") is not True:
            raise ValueError("Native YARA validation did not complete with verified worker retirement.")
        return {"state": "valid", "message": "Native YARA-X compile and explicit sample scans completed. This is not a host scan or an accuracy claim.",
                "matches": result["matches"], "worker_retired": True}

    def validate(self, item_id, *, operation=None):
        if operation is not None:
            operation.check()
        with self._transaction():
            row = dict(self._row(self._index(), item_id))
            raw = self._read_blob(row["draft_sha256"])
        try:
            validation = self._validate_content(row, raw, operation=operation)
        except (ValueError, RuntimeError, OSError, UnicodeError, RecursionError) as exc:
            if operation is not None and operation.cancelled.is_set():
                raise
            validation = {"state": "invalid", "message": str(exc)[:2048]}
        validation.update(sha256=row["draft_sha256"], response_authorized=False)
        validation["checked_at"] = int(time.time())
        with self._transaction():
            if operation is not None:
                operation.check()
            rows = self._index()
            current = self._row(rows, item_id)
            if current["draft_sha256"] != row["draft_sha256"]:
                raise ValueError("Draft changed while validation ran; validate the current revision.")
            previous = current["validation"]
            if validation["state"] == "valid" and previous.get("sha256") == validation["sha256"]:
                for key in ("sample_checks", "sample_passed", "sample_checked_at"):
                    if key in previous:
                        validation[key] = previous[key]
            current["validation"] = validation
            self._save(rows)
        return validation

    def sample_test(self, item_id, *, operation=None):
        result = self.validate(item_id, operation=operation)
        if result["state"] == "valid":
            row = self.read(item_id)
            if row["draft_sha256"] != result["sha256"]:
                raise ValueError("Draft changed before sample testing; test the validated revision.")
            if row["kind"] == "soar":
                from types import SimpleNamespace
                document = validate_playbook(row["text"].encode())
                source = next(iter(document["trigger"]["modules"]), "Example Native Detector")
                positive = SimpleNamespace(details={"disposition": "active", "response_authorized": True}, severity=4, module=source)
                negative = SimpleNamespace(details={"disposition": "observation", "response_authorized": False}, severity=4, module=source)
                low = SimpleNamespace(details={"disposition": "active", "response_authorized": True}, severity=0, module=source)
                checks = {"active_trigger": playbook_matches(document, positive),
                          "advisory_refused": not playbook_matches(document, negative),
                          "low_severity_refused": not playbook_matches(document, low)}
                result = dict(result, sample_checks=checks, sample_passed=all(checks.values()),
                    actions_executed=False, message="Inert positive/negative trigger checks completed; no host action was executed.")
            elif (row["source_id"] == "builtin:angerona"
                    and row["path"] == "examples/angerona-sample.yar"
                    and row["draft_sha256"] == _sha(_EXAMPLES[row["path"]])):
                matches = result.get("matches", [])
                # The owned worker returns one bounded result per explicit
                # buffer. Only this exact known fixture has expected truth.
                first = [match for match in matches if match.get("sample") == 0]
                second = [match for match in matches if match.get("sample") == 1]
                checks = {"known_positive": len(first) == 1 and first[0].get("rules") == ["Angerona_User_Sample"],
                          "known_negative": len(second) == 1 and second[0].get("rules") == []}
                result = dict(result, sample_checks=checks, sample_passed=all(checks.values()), actions_executed=False)
            with self._transaction():
                if operation is not None:
                    operation.check()
                rows = self._index()
                current = self._row(rows, item_id)
                if current["draft_sha256"] != result["sha256"]:
                    raise ValueError("Draft changed during sample testing; test the current revision.")
                current["validation"] = result
                current["validation"]["sample_checked_at"] = int(time.time())
                self._save(rows)
        return result

    def _require_source_review(self, row):
        if row["source_id"] not in {"builtin:angerona", "local"}:
            source = next((entry for entry in self.catalog.list_imports() if entry["id"] == row["source_id"]), None)
            if source is None or source["state"] != "reviewed":
                raise ValueError("Source is missing, unreviewed or revoked.")

    def _selected_yara(self, rows, target, candidate):
        if target["kind"] != "yara":
            return None
        selected = [(row, row["active_sha256"]) for row in rows
                    if row["kind"] == "yara" and row["active_sha256"] and row["id"] != target["id"]]
        selected.append((target, candidate))
        if len(selected) > 32:
            raise ValueError("Keep the active community YARA set within 32 sources / 64 KiB; disable selected packs first.")
        selected.sort(key=lambda pair: pair[0]["id"])
        sources, total = [], 0
        for row, digest in selected:
            self._require_source_review(row)
            raw = self._read_blob(digest)
            total += len(raw)
            if total > 64 * 1024:
                raise ValueError("Keep the active community YARA set within 32 sources / 64 KiB; disable selected packs first.")
            sources.append({"path": row["id"], "text": _document(raw)})
        return tuple((row["id"], digest) for row, digest in selected), sources

    def _validate_selected_yara(self, selected, operation):
        if selected is None:
            return
        operation.check()
        if self._probe is None:
            from angerona.core.community_tool_probe_worker import run_yara_probe
            probe = run_yara_probe
        else:
            probe = self._probe
        result = probe(self.root.parent / (self.root.name + "-probes"), selected[1],
                       [b"ordinary inert aggregate compile sample"], operation)
        if result.get("state") != "completed" or result.get("worker_retired") is not True:
            raise ValueError("Combined native YARA admission did not complete with verified worker retirement.")
        operation.check()

    def activate(self, item_id, *, operation=None):
        from angerona.core.community_tool_adapters import AdapterOperation
        operation = operation or AdapterOperation(timeout=20)
        result = self.validate(item_id, operation=operation)
        if result["state"] != "valid":
            raise ValueError(result["message"])
        with self._transaction():
            operation.check()
            rows = self._index()
            row = self._row(rows, item_id)
            if row["draft_sha256"] != result["sha256"]:
                raise ValueError("Draft changed before activation.")
            self._require_source_review(row)
            self._read_blob(row["draft_sha256"])
            selected = self._selected_yara(rows, row, row["draft_sha256"])
        # The native probe may take time; no global library lock is held here.
        self._validate_selected_yara(selected, operation)
        with self._transaction():
            operation.check()
            rows = self._index()
            row = self._row(rows, item_id)
            if row["draft_sha256"] != result["sha256"]:
                raise ValueError("Draft changed during activation admission.")
            self._require_source_review(row)
            current = self._selected_yara(rows, row, row["draft_sha256"])
            if selected is not None and current[0] != selected[0]:
                raise ValueError("Active YARA selection changed during native admission; retry the current set.")
            if row["active_sha256"] != row["draft_sha256"]:
                row["previous_sha256"] = row["active_sha256"]
                row["active_sha256"] = row["draft_sha256"]
            self._save(rows)
            return dict(row, state="active-data", response_authorized=False)

    def disable(self, item_id):
        with self._transaction():
            rows = self._index()
            row = self._row(rows, item_id)
            if row["active_sha256"]:
                row["previous_sha256"], row["active_sha256"] = row["active_sha256"], ""
            self._save(rows)
            return dict(row, state="disabled")

    def rollback(self, item_id, *, operation=None):
        from angerona.core.community_tool_adapters import AdapterOperation
        operation = operation or AdapterOperation(timeout=20)
        operation.check()
        with self._transaction():
            rows = self._index()
            row = self._row(rows, item_id)
            candidate = row["previous_sha256"]
            if not candidate:
                raise ValueError("No previous active revision is retained.")
            raw = self._read_blob(candidate)
            snapshot = dict(row)
            self._require_source_review(row)
            selected = self._selected_yara(rows, row, candidate)
        result = self._validate_content(snapshot, raw, operation=operation)
        if result["state"] != "valid":
            raise ValueError("Previous revision did not pass validation.")
        self._validate_selected_yara(selected, operation)
        with self._transaction():
            operation.check()
            rows = self._index()
            row = self._row(rows, item_id)
            if row["previous_sha256"] != candidate:
                raise ValueError("Rollback selection changed during validation.")
            self._require_source_review(row)
            current = self._selected_yara(rows, row, candidate)
            if selected is not None and current[0] != selected[0]:
                raise ValueError("Active YARA selection changed during rollback admission; retry the current set.")
            row["active_sha256"], row["previous_sha256"] = candidate, row["active_sha256"]
            self._save(rows)
            return dict(row, state="rolled-back-data", response_authorized=False)

    def diff(self, item_id):
        with self._transaction():
            row = self._row(self._index(), item_id)
            original = _document(self._read_blob(row["original_sha256"]))
            draft = _document(self._read_blob(row["draft_sha256"]))
        return "".join(difflib.unified_diff(original.splitlines(True), draft.splitlines(True),
                                            fromfile="pinned original", tofile="local draft"))

    def active_data(self, kind):
        """Worker-only snapshot; source revocation and full bytes rechecked."""
        if kind not in {"yara", "soar"}:
            raise ValueError("Unknown active data type.")
        sources = {row["id"]: row for row in self.catalog.list_imports()}
        with self._transaction():
            result = []
            for row in self._index():
                if row["kind"] != kind or not row["active_sha256"]:
                    continue
                source = sources.get(row["source_id"])
                if row["source_id"] not in {"builtin:angerona", "local"} and (source is None or source["state"] != "reviewed"):
                    raise ValueError("An active source is missing or revoked; coverage remains unavailable.")
                raw = self._read_blob(row["active_sha256"])
                text = _document(raw)
                result.append(dict(row, text=text, compile_input_sha256=_sha(text.encode("utf-8"))))
            return result

    def credits(self):
        return [{key: row[key] for key in ("repository", "commit", "license", "path", "original_sha256")}
                for row in self.items()]


def playbook_matches(document, event):
    """Pure selection only; original event verification belongs to the owner."""
    try:
        details = event.details
        if (type(details) is not dict or details.get("disposition") != "active"
                or details.get("response_authorized") is not True):
            return False
        floor = 4 if document["trigger"]["minimum_severity"] == "CRITICAL" else 3
        modules = document["trigger"]["modules"]
        return int(event.severity) >= floor and (not modules or event.module in modules)
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def configured_library(config):
    root = Path(config.data_dir)
    return RulePlaybookLibrary(root / "rule-playbook-library",
        catalog=GitHubToolCatalog(root / "github-source-library"))


class CommunityPlaybookRuntime:
    """Background-only bounded data cache. It never owns a mutation capability."""
    def __init__(self, config, *, library=None, clock=time.monotonic):
        self.config = config
        self.library = library or configured_library(config)
        self.clock = clock
        self._next_read = self._last_read = 0.0
        self._rows = ()
        self._reason = "disabled"

    def matching(self, event):
        if getattr(self.config, "community_playbooks_enabled", False) is not True:
            self._rows, self._next_read, self._reason = (), 0.0, "disabled"
            self._last_read = 0.0
            return ()
        try:
            now = self.clock()
            valid_clock = type(now) in (int, float) and math.isfinite(now) and now >= self._last_read
        except Exception:
            valid_clock = False
        if not valid_clock:
            self._rows, self._next_read, self._reason = (), 0.0, "community playbook clock unavailable"
            return ()
        self._last_read = now
        if now >= self._next_read:
            self._next_read = now + 5.0
            try:
                rows = self.library.active_data("soar")
                self._rows = tuple((row, validate_playbook(row["text"].encode())) for row in rows)
                self._reason = "ready"
            except (OSError, ValueError, TypeError, KeyError, RuntimeError, RecursionError):
                # Do not retain a revoked/invalid policy as a healthy fallback.
                self._rows, self._reason = (), "community playbook data unavailable"
        return tuple((row, document) for row, document in self._rows if playbook_matches(document, event))

    def snapshot(self):
        return {"state": self._reason, "loaded": len(self._rows), "response_authorized": False}
