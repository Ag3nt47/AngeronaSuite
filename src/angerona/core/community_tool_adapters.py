"""Bounded community data adapters; imported source never becomes Python code.

Every mutating or parsing method is worker-side (never call it from Qt).  The
catalog's explicit reviewed, immutable full-commit ZIP is the only pack source.
Review is operator intent, not an upstream signature or response authority.
"""
from __future__ import annotations

import ast
from contextlib import contextmanager
import copy
import difflib
import fnmatch
import hashlib
from itertools import islice
import json
import math
from pathlib import Path
import re
import threading
import time
import uuid
import xml.etree.ElementTree as ET

from angerona.core.github_tool_catalog import (
    GitHubToolCatalog, MAX_PREVIEW_BYTES, _bounded_read, plain_text,
)
from angerona.core.source_sandbox import (
    SourceSandboxWorkspace, _absolute, _atomic_bytes_write, _ensure_directory,
    _hold_plain_directories, _relative_source, _validate_chain,
)
from angerona.core.file_lease import ExclusiveFileLease

MAX_PACK_FILES = 256
MAX_PACK_BYTES = 8 * 1024 * 1024
MAX_SANDBOXES = 16
MAX_SANDBOX_FILES = 64
MAX_SANDBOX_BYTES = 2 * 1024 * 1024
MAX_EDITOR_BYTES = 1024 * 1024
MAX_RECORDS = 512
MAX_DTO_BYTES = 1024 * 1024
_ID = re.compile(r"[0-9a-f]{32}")
_SHA = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_LOCKS_GUARD = threading.Lock()
_LOCKS: dict[tuple[str, str], threading.Lock] = {}


class AdapterError(ValueError):
    pass


class AdapterCancelled(AdapterError):
    pass


class AdapterOperation:
    def __init__(self, timeout=120, *, cancelled=None):
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValueError("Choose a finite operation budget up to 300 seconds.")
        self.cancelled = cancelled if cancelled is not None else threading.Event()
        if not isinstance(self.cancelled, threading.Event):
            raise ValueError("Cancellation requires a threading.Event.")
        self.started = time.monotonic()
        self.deadline = self.started + timeout

    def cancel(self):
        self.cancelled.set()

    def check(self):
        now = time.monotonic()
        if self.cancelled.is_set():
            raise AdapterCancelled("Operation cancelled; existing packs and custom copies remain.")
        if not math.isfinite(now) or now < self.started or now >= self.deadline:
            raise AdapterCancelled("Operation deadline reached; existing data remains.")


_SPECS = (
    dict(id="zero-breach", name="Zero-Breach Toolkit", repository="interplains/zero-breach-toolkit", license="Apache-2.0",
         license_files=["LICENSE", "NOTICE", "iocs/LICENSE.md"], authors=["interplains / archivegenocide.com"],
         capabilities=["pinned-scanner", "reports", "managed-uninstall", "source-sandbox"], mode="managed-scanner"),
    dict(id="atomic-red-team", name="Atomic Red Team", repository="redcanaryco/atomic-red-team", license="MIT",
         license_files=["LICENSE.txt"], authors=["Red Canary and Atomic Red Team contributors"],
         capabilities=["test-catalog", "reviewed-control-map", "source-sandbox"], mode="data"),
    dict(id="sigma", name="SigmaHQ rules", repository="sigmahq/sigma", license="DRL-1.1",
         license_files=["LICENSE"], authors=["SigmaHQ contributors; individual rule author retained in matches"],
         capabilities=["rule-catalog", "normalized-event-match-subset", "source-sandbox"], mode="data"),
    dict(id="sysmon-modular", name="Sysmon Modular", repository="olafhartong/sysmon-modular", license="MIT",
         license_files=["license.md"], authors=["Olaf Hartong and contributors; inspired by SwiftOnSecurity"],
         capabilities=["xml-preview", "event-coverage", "storage-impact", "source-sandbox"], mode="data"),
    dict(id="yara-x", name="YARA-X", repository="virustotal/yara-x", license="BSD-3-Clause",
         license_files=["LICENSE"], authors=["The YARA-X Authors"],
         capabilities=["rule-pack-preview", "owned-buffer-scan", "existing-engine-self-check", "source-sandbox"], mode="data"),
    dict(id="caldera", name="Apache Caldera", repository="apache/caldera", license="Apache-2.0",
         license_files=["LICENSE", "NOTICE"], authors=["The Apache Software Foundation; MITRE and contributors"],
         capabilities=["external-result-import"], mode="external"),
    dict(id="velociraptor", name="Velociraptor", repository="velocidex/velociraptor", license="AGPL-3.0",
         license_files=["LICENSE"], authors=["Velocidex and contributors"],
         capabilities=["external-result-import"], mode="external"),
    dict(id="wazuh", name="Wazuh", repository="wazuh/wazuh", license="GPL-2.0; engine AGPL-3.0",
         license_files=["LICENSE", "src/engine/LICENSE-engine"], authors=["Wazuh Inc.; OSSEC/Trend Micro and contributors"],
         capabilities=["external-result-import"], mode="external"),
)
_BY_ID = {row["id"]: row for row in _SPECS}
# These are catalog links to reviewed Angerona controls, never executable upstream commands.
_CONTROL_MAP = {"T1059": "process-execution", "T1059.001": "process-execution",
                "T1046": "network-discovery", "T1087": "account-discovery",
                "T1190": "public-facing-application", "T1562.001": "defense-impairment"}


def tool_specs():
    return copy.deepcopy(list(_SPECS))


def _plain_dto(value):
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False).encode()
    if len(raw) > MAX_DTO_BYTES:
        raise AdapterError("Adapter result exceeded its bounded DTO budget.")
    return json.loads(raw)


def _spec(tool_id):
    if not isinstance(tool_id, str) or tool_id not in _BY_ID:
        raise AdapterError("Choose a known community adapter.")
    return _BY_ID[tool_id]


def _emit(progress, op, phase, done=0, total=0, **extra):
    op.check()
    if progress is not None:
        progress(_plain_dto(dict(phase=phase, finished=done, total=total,
                                percent=(100 * done // total if total else None), **extra)))
    op.check()


def _yaml(text):
    import yaml
    if len(text.encode("utf-8")) > MAX_PREVIEW_BYTES:
        raise AdapterError("YAML input exceeded its member budget.")
    depth = count = 0
    for event in yaml.parse(text, Loader=yaml.SafeLoader):
        count += 1
        if count > 20000 or isinstance(event, yaml.events.AliasEvent):
            raise AdapterError("YAML aliases or excessive parser events are unsupported.")
        if isinstance(event, (yaml.events.MappingStartEvent, yaml.events.SequenceStartEvent)):
            depth += 1
            if depth > 24:
                raise AdapterError("YAML nesting exceeded its budget.")
        elif isinstance(event, (yaml.events.MappingEndEvent, yaml.events.SequenceEndEvent)):
            depth -= 1
    class UniqueLoader(yaml.SafeLoader):
        pass
    def mapping(loader, node, deep=False):
        out = {}
        for key, value in node.value:
            name = loader.construct_object(key, deep=deep)
            if not isinstance(name, str) or name in out:
                raise AdapterError("YAML mapping keys must be unique strings.")
            out[name] = loader.construct_object(value, deep=deep)
        return out
    UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
    documents = list(yaml.load_all(text, Loader=UniqueLoader))
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise AdapterError("One YAML mapping is required per catalog member.")
    return documents[0]


def _xml(text):
    if "<!" in text:
        raise AdapterError("XML declarations, entities and DTDs are unsupported.")
    root = ET.fromstring(text)
    if sum(1 for _ in root.iter()) > 4096:
        raise AdapterError("XML element budget exceeded.")
    events = sorted({element.tag for element in root.iter() if element.tag not in {"Sysmon", "EventFiltering", "RuleGroup", "Rule"} and ("onmatch" in element.attrib or element.tag.endswith("Event"))})
    return dict(events=events[:128], archives_deleted_files=any(e.tag == "FileDelete" for e in root.iter()),
                message="FileDelete can archive deleted files; review disk limits before deployment.", service_installed=False)


def _atomic(document):
    technique, tests = document.get("attack_technique"), document.get("atomic_tests")
    if not isinstance(technique, str) or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique) or not isinstance(tests, list) or len(tests) > 128:
        raise AdapterError("Invalid bounded Atomic test catalog.")
    rows = []
    for test in tests:
        if not isinstance(test, dict) or not isinstance(test.get("auto_generated_guid"), str):
            raise AdapterError("Atomic test GUID is missing.")
        identifier = str(uuid.UUID(test["auto_generated_guid"]))
        rows.append(dict(id=identifier, name=plain_text(str(test.get("name", ""))[:200]), technique=technique,
                         platforms=[plain_text(str(v)[:32]) for v in test.get("supported_platforms", [])[:8]],
                         mapped_control=_CONTROL_MAP.get(technique),
                         execution="catalog-only; upstream commands/prerequisites/cleanup are never executed"))
    return rows


def _parse(tool_id, name, raw, provenance=None):
    try:
        text = raw.decode("utf-8-sig", errors="strict")
        if "\0" in text:
            raise AdapterError("Binary content is unavailable for data parsing.")
        if tool_id == "atomic-red-team":
            return _atomic(_yaml(text))
        if tool_id == "sigma":
            from angerona.core.community_sigma import prepare_sigma_document
            prepared = prepare_sigma_document(raw, provenance)
            if prepared.get("accepted") is not True:
                raise AdapterError(str(prepared.get("code", "unsupported")) + ": " + str(prepared.get("reason", "Rule was refused")))
            return prepared
        if tool_id == "sysmon-modular":
            return _xml(text)
        if tool_id == "yara-x":
            return dict(path=name, text_bytes=len(raw), execution="explicit buffers only; owned supervised worker, no includes/imports")
    except AdapterError:
        raise
    except Exception as exc:
        raise AdapterError("Invalid adapter data: " + plain_text(type(exc).__name__)) from None
    raise AdapterError("This adapter does not parse local rule data.")


def _selected(tool_id, names):
    if tool_id == "atomic-red-team":
        return [name for name in names if re.fullmatch(r"atomics/T\d{4}(?:\.\d{3})?/T\d{4}(?:\.\d{3})?\.ya?ml", name)]
    if tool_id == "sigma":
        return [name for name in names if name.startswith("rules/") and name.endswith((".yml", ".yaml"))]
    if tool_id == "sysmon-modular":
        return [name for name in names if name.endswith(".xml")]
    return [name for name in names if name.endswith((".yar", ".yara"))]


class CommunityToolService:
    """Explicit worker API. No threads, downloads, host discovery or I/O at init."""
    def __init__(self, root, *, catalog: GitHubToolCatalog, curated=None):
        self.root = _absolute(Path(root))
        self.catalog = catalog
        self.curated = curated

    tool_specs = staticmethod(tool_specs)

    @contextmanager
    def _transaction(self, tool_id, operation):
        _spec(tool_id)
        operation.check()
        key = (str(self.root).casefold(), tool_id)
        with _LOCKS_GUARD:
            if key not in _LOCKS:
                if len(_LOCKS) >= 256:
                    raise AdapterError("Community adapter lock inventory is full.")
                _LOCKS[key] = threading.Lock()
            lock = _LOCKS[key]
        if not lock.acquire(blocking=False):
            raise AdapterError("This tool is busy; other adapters remain available.")
        try:
            _ensure_directory(self.root / tool_id)
            with _hold_plain_directories(self.root, self.root / tool_id), ExclusiveFileLease(self.root / tool_id / "adapter.lock"):
                operation.check()
                yield self.root / tool_id
        finally:
            lock.release()

    def _manifest(self, tool_id):
        path = self.root / tool_id / "installed.json"
        try:
            raw = _bounded_read(path, self.root, MAX_DTO_BYTES)
        except FileNotFoundError:
            return None
        row = json.loads(raw)
        if not isinstance(row, dict) or row.get("schema") != 1 or row.get("tool_id") != tool_id or not _SHA.fullmatch(str(row.get("source_id", ""))) or not _COMMIT.fullmatch(str(row.get("commit", ""))):
            raise AdapterError("Adapter installation manifest requires review.")
        if not isinstance(row.get("files"), dict) or len(row["files"]) > MAX_PACK_FILES:
            raise AdapterError("Invalid adapter member inventory.")
        for name, digest in row["files"].items():
            if _relative_source(name) != name or not isinstance(digest, str) or not _SHA.fullmatch(digest):
                raise AdapterError("Invalid adapter member identity.")
        return row

    def _source(self, tool_id, source_id):
        spec = _spec(tool_id)
        row = next((row for row in self.catalog.list_imports() if row["id"] == source_id), None)
        if row is None or row["repository"] != spec["repository"] or row["state"] != "reviewed" or not _COMMIT.fullmatch(row["commit"]):
            raise AdapterError("Select a reviewed full-commit import from this adapter's canonical repository.")
        return row

    def _member(self, tool_id, manifest, name):
        row = self._source(tool_id, manifest["source_id"])
        self._source_binding(manifest, row)
        raw = self.catalog.raw_member(manifest["source_id"], name, max_bytes=MAX_PREVIEW_BYTES, require_reviewed=True)
        if hashlib.sha256(raw).hexdigest() != manifest["files"].get(name):
            raise AdapterError("Pack member differs from its installed identity.")
        return raw

    def _snapshot(self, tool_id, manifest, names=None):
        row = self._source(tool_id, manifest["source_id"])
        self._source_binding(manifest, row)
        names = list(manifest["files"]) if names is None else names
        rows = self.catalog.raw_members(manifest["source_id"], names, max_bytes=MAX_PREVIEW_BYTES,
                                        total_bytes=MAX_PACK_BYTES, require_reviewed=True)
        if any(hashlib.sha256(raw).hexdigest() != manifest["files"].get(name) for name, raw in rows.items()):
            raise AdapterError("Pack member differs from its installed identity.")
        return rows

    @staticmethod
    def _source_binding(manifest, row):
        if manifest.get("commit") != row["commit"] or manifest.get("archive_sha256") != row["sha256"]:
            raise AdapterError("Adapter provenance differs from its exact pinned source identity.")

    def _provenance(self, tool_id, row, name, raw):
        return dict(repository=_spec(tool_id)["repository"], commit=row["commit"], path=name,
                    sha256=hashlib.sha256(raw).hexdigest(), source_id=row.get("source_id", row.get("id")),
                    license=_spec(tool_id)["license"])

    def credits(self, tool_id):
        spec = copy.deepcopy(_spec(tool_id))
        rows = [dict(name=author, url="https://github.com/" + spec["repository"], license=spec["license"], license_files=spec["license_files"]) for author in spec["authors"]]
        if tool_id == "zero-breach":
            from angerona.core.curated_tools import credits
            rows.extend(credits())
        return _plain_dto(rows)

    def status(self, tool_id=None):
        if tool_id is None:
            return [self.status(spec["id"]) for spec in _SPECS]
        spec = _spec(tool_id)
        base = dict(tool_id=tool_id, state="not-installed", installed=False, customized=False,
                    source_authority=False, response_authority=False, capabilities=spec["capabilities"], credits=self.credits(tool_id))
        if tool_id == "zero-breach":
            scanner = self.curated.status() if self.curated else None
            sandboxes = self._sandbox_status(tool_id)
            return _plain_dto(dict(base, scanner=scanner, installed=bool(scanner and scanner.get("installed")),
                                   customized=any(row["customized"] for row in sandboxes), sandboxes=sandboxes,
                                   state=scanner.get("state", "unavailable") if scanner else "unavailable"))
        if spec["mode"] == "external":
            return dict(base, state="external-only", message="Optional external-result adapter; platform installation and remote execution are not embedded.")
        try:
            manifest = self._manifest(tool_id)
            if manifest is None:
                return base
            row = self._source(tool_id, manifest["source_id"])
            self._source_binding(manifest, row)
            sandbox_status = self._sandbox_status(tool_id)
            return _plain_dto(dict(base, installed=True, state="ready-data", commit=row["commit"],
                                   source_id=row["id"], files=len(manifest["files"]), coverage=manifest["coverage"],
                                   customized=any(item["customized"] for item in sandbox_status), sandboxes=sandbox_status,
                                   message="Reviewed data adapter. Imported source cannot execute or grant response authority."))
        except (OSError, ValueError) as exc:
            return dict(base, state="needs-review", message=plain_text(str(exc))[:512])

    def install(self, tool_id, operation=None, progress=None, *, source_id=None):
        op = operation or AdapterOperation()
        spec = _spec(tool_id)
        with self._transaction(tool_id, op) as root:
            if spec["mode"] == "external":
                return dict(state="external-only", tool_id=tool_id, message="Configure an existing external platform; no installer or agent is run.")
            if tool_id == "zero-breach":
                if self.curated is None:
                    return dict(state="unavailable", message="Managed scanner service is unavailable.")
                from angerona.core.curated_tools import ToolOperation
                child = ToolOperation(timeout=max(1, min(300, op.deadline - time.monotonic())))
                child.cancelled = op.cancelled
                return self.curated.prepare(child, progress=lambda text: _emit(progress, op, "prepare-scanner", message=text), restore_uninstalled=True)
            row = self._source(tool_id, source_id)
            names = self.catalog.files(source_id)
            licenses = [name for name in spec["license_files"] if name in names]
            if not licenses or spec["license_files"][0] not in licenses:
                raise AdapterError("The pinned source is missing its required license file.")
            available = _selected(tool_id, names)
            selected, skipped, total_bytes = {}, [], 0
            raw_members = self.catalog.raw_members(source_id, available[:MAX_PACK_FILES], max_bytes=MAX_PREVIEW_BYTES,
                                                   total_bytes=MAX_PACK_BYTES, require_reviewed=True) if available else {}
            for index, name in enumerate(available[:MAX_PACK_FILES]):
                _emit(progress, op, "validate-members", index, min(len(available), MAX_PACK_FILES), current_file=name)
                try:
                    raw = raw_members[name]
                    if total_bytes + len(raw) > MAX_PACK_BYTES:
                        raise AdapterError("Selected rule pack reached its 8 MiB budget.")
                    _parse(tool_id, name, raw, self._provenance(tool_id, row, name, raw))
                except ValueError as exc:
                    skipped.append(dict(path=name, reason=plain_text(str(exc))[:180]))
                    continue
                total_bytes += len(raw)
                selected[name] = hashlib.sha256(raw).hexdigest()
            if not selected:
                return dict(state="unavailable", tool_id=tool_id, message="No supported data members were found; no installation was activated.", skipped=skipped[:32])
            for name in licenses:
                op.check()
                self.catalog.raw_member(source_id, name, max_bytes=MAX_PREVIEW_BYTES, require_reviewed=True)
            self._source(tool_id, source_id)  # revocation remains a hold at publication.
            manifest = dict(schema=1, tool_id=tool_id, source_id=row["id"], commit=row["commit"], archive_sha256=row["sha256"],
                            files=selected, licenses=licenses,
                            coverage=dict(available=len(available), supported=len(selected), skipped=skipped[:32],
                                          truncated=max(0, len(available)-MAX_PACK_FILES), whole_repository=False))
            op.check()
            _atomic_bytes_write(root / "installed.json", json.dumps(manifest, ensure_ascii=True).encode(), root=self.root, private=True)
            _emit(progress, op, "installed", len(selected), len(selected))
            return self.status(tool_id)

    def uninstall(self, tool_id, operation=None, progress=None):
        op = operation or AdapterOperation()
        with self._transaction(tool_id, op) as root:
            if tool_id == "zero-breach":
                if self.curated is None:
                    return dict(state="unavailable", message="Managed scanner service unavailable.")
                from angerona.core.curated_tools import ToolOperation
                child = ToolOperation(timeout=max(1, min(300, op.deadline-time.monotonic())))
                child.cancelled = op.cancelled
                return self.curated.uninstall(child, progress=lambda text: _emit(progress, op, "uninstall", message=text))
            # Retire activation only; never delete source imports, edited files, settings or reports.
            marker = root / "installed.json"
            if marker.exists():
                expected = self._manifest(tool_id)
                from angerona.core.curated_tools import _ReportDeletion
                with _ReportDeletion(marker, MAX_DTO_BYTES) as held:
                    if json.loads(held.raw) != expected:
                        raise AdapterError("Installed adapter identity changed before retirement.")
                    held.delete()
            return dict(state="uninstalled", tool_id=tool_id, preserved="Source imports, sandbox copies, preferences and reports remain.")

    def evaluate(self, tool_id, records, operation=None, progress=None):
        op = operation or AdapterOperation()
        if not isinstance(records, list) or len(records) > MAX_RECORDS:
            raise AdapterError("At most 512 explicit normalized records may be evaluated.")
        _plain_dto(records)
        with self._transaction(tool_id, op):
            manifest = self._manifest(tool_id)
            if manifest is None:
                return dict(state="unavailable", message="Install a reviewed data pack first.")
            members = self._snapshot(tool_id, manifest)
            if tool_id == "yara-x":
                from angerona.core.community_tool_probe_worker import run_yara_probe
                if any(not isinstance(row, dict) or set(row) != {"base64"} or not isinstance(row["base64"], str) for row in records):
                    raise AdapterError("YARA evaluation requires explicit base64 sample-buffer envelopes; no host paths are followed.")
                import base64
                samples = [base64.b64decode(row["base64"], validate=True) for row in records]
                sources = [{"path": name, "text": members[name].decode("utf-8-sig")} for name in manifest["files"]]
                return run_yara_probe(self.root / tool_id / "probes", sources, samples, op, progress)
            findings, previews, gaps = [], [], []
            for index, name in enumerate(manifest["files"]):
                _emit(progress, op, "evaluate", index, len(manifest["files"]), current_file=name)
                raw = members[name]
                parsed = _parse(tool_id, name, raw, self._provenance(tool_id, manifest, name, raw))
                if tool_id == "sigma":
                    from angerona.core.community_sigma import evaluate_prepared
                    for record_index, record in enumerate(records):
                        op.check()
                        checked = evaluate_prepared(parsed, record)
                        if checked.get("matched") is True:
                            findings.append(dict(record_index=record_index, **checked["finding"]))
                        elif checked.get("code") != "NO_MATCH":
                            if len(gaps) < 32:
                                gaps.append(dict(record_index=record_index, code=checked.get("code"), reason=checked.get("reason")))
                elif tool_id == "sysmon-modular":
                    previews.append(dict(path=name, **parsed))
                else:
                    previews.extend(parsed)
                if len(findings) > 512 or len(previews) > 512:
                    raise AdapterError("Evaluation output budget exceeded; narrow the selected pack.")
            return _plain_dto(dict(state="completed", tool_id=tool_id, findings=findings, preview=previews,
                                   coverage=manifest["coverage"], gaps=gaps, source_id=manifest["source_id"],
                                   response_authority=False, host_scan=False))

    def self_check(self, tool_id, operation=None, progress=None):
        op = operation or AdapterOperation()
        _spec(tool_id)
        with self._transaction(tool_id, op):
            _emit(progress, op, "self-check", 0, 2)
            if tool_id == "zero-breach":
                if self.curated is None:
                    return dict(state="unavailable", message="Managed scanner service unavailable.")
                from angerona.core.curated_tools import ToolOperation
                child = ToolOperation(timeout=max(1, min(300, op.deadline-time.monotonic())))
                child.cancelled = op.cancelled
                result = self.curated.self_test(child, progress=lambda text: _emit(progress, op, "scanner-metadata", message=text))
                return dict(state=result.get("state", "unavailable"), scanner=result,
                            coverage="Existing synthetic-profile pinned metadata contract; not a full host scan or positive spyware fixture.")
            if _spec(tool_id)["mode"] == "external":
                return dict(state="unavailable", message="No external platform connection was supplied; no remote test was fabricated.")
            if tool_id == "sigma":
                from angerona.core.community_sigma import self_check
                result = self_check()
                op.check()
                return result
            elif tool_id == "sysmon-modular":
                positive = _xml('<Sysmon><EventFiltering><FileDelete onmatch="include"/></EventFiltering></Sysmon>')["archives_deleted_files"]
                negative = not _xml('<Sysmon><EventFiltering><ProcessCreate onmatch="include"/></EventFiltering></Sysmon>')["archives_deleted_files"]
            elif tool_id == "atomic-red-team":
                rows = _atomic(dict(attack_technique="T1059.001", atomic_tests=[dict(auto_generated_guid="c62c08fd-114a-40b2-9376-53100946988d", name="inert mapped control", supported_platforms=["windows"])]))
                positive = rows[0]["mapped_control"] == "process-execution"
                negative = "T9999" not in _CONTROL_MAP
            else:
                from angerona.core.community_tool_probe_worker import run_yara_probe
                probe = run_yara_probe(self.root / tool_id / "probes", [{"path": "inert.yar", "text": 'rule Angerona_Inert_Adapter_Check { strings: $a = "ANGERONA_INERT_ADAPTER_FIXTURE" condition: $a }'}],
                                       [b"ANGERONA_INERT_ADAPTER_FIXTURE", b"ordinary inert negative fixture"], op, progress)
                if probe["state"] != "completed":
                    return probe
                positive = probe["matches"][0]["rules"] == ["Angerona_Inert_Adapter_Check"]
                negative = not probe["matches"][1]["rules"]
                manifest = self._manifest(tool_id)
                pack = dict(state="not-installed", tested=False)
                if manifest is not None:
                    members = self._snapshot(tool_id, manifest)
                    pack = run_yara_probe(self.root / tool_id / "probes", [{"path": name, "text": raw.decode("utf-8-sig")} for name, raw in members.items()],
                                          [b"ordinary inert compile-check buffer"], op, progress)
                    pack["tested"] = True
                    if pack["state"] != "completed":
                        return dict(state="failed" if pack["state"] == "invalid" else "unavailable", positive=positive,
                                    negative=negative, installed_pack=pack, response_authority=False)
            _emit(progress, op, "self-check", 2, 2)
            result = dict(state="passed" if positive and negative else "failed", positive=positive, negative=negative,
                          coverage="Fixed inert adapter behavior only; installed-pack coverage and host collectors remain separately reported.", response_authority=False)
            if tool_id == "yara-x":
                result["installed_pack"] = pack
            return result

    def import_external_result(self, tool_id, document, operation=None):
        op = operation or AdapterOperation()
        if _spec(tool_id)["mode"] != "external":
            raise AdapterError("Select an external platform result adapter.")
        op.check()
        if not isinstance(document, dict) or set(document) != {"origin", "job_id", "findings"} or not isinstance(document["origin"], str) or not document["origin"].startswith("https://") or len(document["origin"]) > 256 or not isinstance(document["job_id"], str) or len(document["job_id"]) > 128 or not isinstance(document["findings"], list) or len(document["findings"]) > 256:
            raise AdapterError("Supply a bounded normalized external-result envelope.")
        detached = _plain_dto(document)
        return dict(state="imported-advisory", tool_id=tool_id, result=detached,
                    provenance="Operator supplied; no remote authentication or local sensor receipt is asserted.", response_authority=False)

    def create_sandbox(self, tool_id, operation=None, progress=None, *, paths=None):
        op = operation or AdapterOperation()
        with self._transaction(tool_id, op) as root:
            bundle = None
            if tool_id == "zero-breach" and self.curated is not None:
                from angerona.core.curated_tools import _catalog, ZERO_BREACH
                bundle = self.curated._bundle()
                rows = _catalog(bundle)["files"]
                manifest = dict(source_id=hashlib.sha256((ZERO_BREACH["commit"] + ZERO_BREACH["sha256"]).encode()).hexdigest(),
                                commit=ZERO_BREACH["commit"], files={row["path"]: row["sha256"] for row in rows})
            else:
                manifest = self._manifest(tool_id)
            if manifest is None:
                return dict(state="unavailable", message="Install a reviewed data pack first; executable scanner copying is not implied.")
            selected = (["engine.py", "LICENSE", "NOTICE"] if bundle else list(manifest["files"])[:MAX_SANDBOX_FILES]) if paths is None else paths
            if not isinstance(selected, list) or not selected or len(selected) > MAX_SANDBOX_FILES or len(set(selected)) != len(selected) or any(name not in manifest["files"] for name in selected):
                raise AdapterError("Choose up to 64 distinct installed data members.")
            base = root / "sandboxes"
            _ensure_directory(base)
            with _hold_plain_directories(base):
                entries = list(islice(base.iterdir(), MAX_SANDBOXES+1))
                if len(entries) >= MAX_SANDBOXES:
                    raise AdapterError("Sandbox copy budget reached; existing experiments were preserved.")
                if any(not _ID.fullmatch(path.name) for path in entries):
                    raise AdapterError("Unknown sandbox entries require review.")
            identity = uuid.uuid4().hex
            destination = base / identity
            baseline = destination / "baseline"
            _ensure_directory(baseline)
            total = 0
            if bundle:
                from angerona.core.curated_tools import _read
                members = {name: _read(bundle / name, MAX_EDITOR_BYTES) for name in selected}
                if any(hashlib.sha256(raw).hexdigest() != manifest["files"][name] for name, raw in members.items()):
                    raise AdapterError("Bundled scanner source failed its pinned digest; no custom copy was activated.")
            else:
                members = self._snapshot(tool_id, manifest, selected)
            for index, name in enumerate(selected):
                _emit(progress, op, "copy-sandbox", index, len(selected), current_file=name)
                raw = members[name]
                total += len(raw)
                if total > MAX_SANDBOX_BYTES:
                    raise AdapterError("Sandbox copy exceeded its 2 MiB budget; partial copy remains inert.")
                _ensure_directory((baseline / name).parent)
                _atomic_bytes_write(baseline / name, raw, root=baseline)
            meta = dict(schema=1, tool_id=tool_id, sandbox_id=identity, source_id=manifest["source_id"],
                        commit=manifest["commit"], files={name: manifest["files"][name] for name in selected})
            workspace = SourceSandboxWorkspace("working", selected, source_root=baseline, sandbox_root=destination)
            workspace.ensure()
            _atomic_bytes_write(destination / "sandbox.json", json.dumps(meta).encode(), root=destination)
            return dict(state="created", sandbox_id=identity, tool_id=tool_id, files=selected,
                        analysis_path=str(workspace.root),
                        customized=False, activation="disabled; edits are never executed or activated automatically")

    def _workspace(self, tool_id, sandbox_id):
        _spec(tool_id)
        if not isinstance(sandbox_id, str) or not _ID.fullmatch(sandbox_id):
            raise AdapterError("Invalid sandbox identity.")
        base = self.root / tool_id / "sandboxes" / sandbox_id
        meta = json.loads(_bounded_read(base / "sandbox.json", self.root, MAX_DTO_BYTES))
        if meta.get("schema") != 1 or meta.get("tool_id") != tool_id or meta.get("sandbox_id") != sandbox_id or not _COMMIT.fullmatch(str(meta.get("commit", ""))) or not _SHA.fullmatch(str(meta.get("source_id", ""))) or not isinstance(meta.get("files"), dict) or not 0 < len(meta["files"]) <= MAX_SANDBOX_FILES:
            raise AdapterError("Sandbox manifest requires review.")
        total = 0
        for name, digest in meta["files"].items():
            if _relative_source(name) != name or not isinstance(digest, str) or not _SHA.fullmatch(digest):
                raise AdapterError("Invalid sandbox member identity.")
            raw = _bounded_read(base / "baseline" / name, self.root, MAX_EDITOR_BYTES)
            total += len(raw)
            if total > MAX_SANDBOX_BYTES:
                raise AdapterError("Sandbox baseline exceeded its aggregate copy budget.")
            if hashlib.sha256(raw).hexdigest() != digest:
                raise AdapterError("Sandbox baseline changed; original source must be reviewed again.")
        workspace = SourceSandboxWorkspace("working", meta["files"], source_root=base / "baseline", sandbox_root=base)
        self._working_budget(workspace)
        return workspace

    def _working_budget(self, workspace, *, replacement=None):
        total = 0
        for item in workspace.files:
            if replacement is not None and item.relative_path == replacement[0]:
                total += len(replacement[1].encode("utf-8"))
            else:
                try:
                    raw = _bounded_read(item.working_path, self.root, MAX_EDITOR_BYTES)
                except FileNotFoundError:
                    raw = _bounded_read(item.source_path, self.root, MAX_EDITOR_BYTES)
                total += len(raw)
            if total > MAX_SANDBOX_BYTES:
                raise AdapterError("Sandbox working copies reached their 2 MiB aggregate budget; existing experiments were preserved.")
        return total

    def _sandbox_status(self, tool_id):
        base = self.root / tool_id / "sandboxes"
        if not base.exists():
            return []
        _validate_chain(base)
        with _hold_plain_directories(base):
            entries = list(islice(base.iterdir(), MAX_SANDBOXES+1))
        if len(entries) > MAX_SANDBOXES or any(not _ID.fullmatch(item.name) for item in entries):
            raise AdapterError("Sandbox inventory requires review.")
        return [dict(sandbox_id=item.name, customized=bool(self._workspace(tool_id, item.name).changed_paths())) for item in entries]

    def sandbox_files(self, tool_id, sandbox_id):
        workspace = self._workspace(tool_id, sandbox_id)
        return [dict(path=item.relative_path, customized=workspace.changed(item.relative_path)) for item in workspace.files]

    def sandbox_read(self, tool_id, sandbox_id, path):
        workspace = self._workspace(tool_id, sandbox_id)
        text = workspace.read(path)
        if len(text.encode()) > MAX_EDITOR_BYTES:
            raise AdapterError("Sandbox text exceeded the editor budget.")
        return dict(path=path, text=text, customized=workspace.changed(path))

    def sandbox_write(self, tool_id, sandbox_id, path, text):
        if not isinstance(text, str) or len(text.encode()) > MAX_EDITOR_BYTES:
            raise AdapterError("Supply UTF-8 text up to 1 MiB.")
        with self._transaction(tool_id, AdapterOperation()):
            workspace = self._workspace(tool_id, sandbox_id)
            workspace.file(path)
            self._working_budget(workspace, replacement=(path, text))
            workspace.save(path, text)
            return dict(state="saved-custom-copy", path=path, customized=workspace.changed(path), activated=False)

    def sandbox_diff(self, tool_id, sandbox_id, path):
        workspace = self._workspace(tool_id, sandbox_id)
        item = workspace.file(path)
        original = _bounded_read(item.source_path, self.root, MAX_EDITOR_BYTES).decode("utf-8-sig")
        working = workspace.read(path)
        if len(original.splitlines()) > 4096 or len(working.splitlines()) > 4096:
            return dict(diff="Diff preview exceeds 4,096 lines; read the bounded copies individually.", truncated=True, customized=workspace.changed(path))
        lines = list(difflib.unified_diff(original.splitlines(), working.splitlines(), fromfile="pinned/"+path, tofile="custom/"+path, n=2))
        text = "\n".join(lines)
        content = text.encode("utf-8")
        return dict(diff=content[:MAX_PREVIEW_BYTES].decode("utf-8", errors="replace"), truncated=len(content) > MAX_PREVIEW_BYTES, customized=workspace.changed(path))

    def sandbox_revert(self, tool_id, sandbox_id, *, paths=None):
        with self._transaction(tool_id, AdapterOperation()):
            workspace = self._workspace(tool_id, sandbox_id)
            workspace.rollback(paths)
            return dict(state="reverted-working-copy", activated=False, customized=bool(workspace.changed_paths()))

    def sandbox_analysis(self, tool_id, sandbox_id, path):
        row = self.sandbox_read(tool_id, sandbox_id, path)
        try:
            if tool_id == "zero-breach":
                if path.endswith(".py"):
                    tree = ast.parse(row["text"], filename=path)
                    parsed = dict(syntax="valid Python", nodes=sum(1 for _ in ast.walk(tree)), execution="never executed")
                else:
                    parsed = dict(text_bytes=len(row["text"].encode()), execution="never executed")
            else:
                base = self.root / tool_id / "sandboxes" / sandbox_id
                manifest = json.loads(_bounded_read(base / "sandbox.json", self.root, MAX_DTO_BYTES))
                raw = row["text"].encode()
                parsed = _parse(tool_id, path, raw, self._provenance(tool_id, manifest, path, raw))
            result = dict(state="parsed", summary="Data structure parsed; no source was executed.", details=parsed)
        except (AdapterError, SyntaxError) as exc:
            result = dict(state="invalid", message=str(exc))
        return _plain_dto(dict(result, customized=row["customized"], activated=False,
                               analysis_lab="For code analysis, use the existing reviewed VMware/QEMU Analysis Lab on a copy; readiness and user-run activation are separate."))
