"""Reviewed, data-only Sigma-to-Sysmon adapter; never response authority.

Canonical Sigma taxonomy is translated into the fields actually published by
Sysmon Event Bridge. Source, native-collector and Event ID guards are inserted
into EVERY selection branch, including filters. The original logsource and
credits remain in the digest-bound sidecar. An unsupported construct is a
refusal, never an invitation to strip a logsource or approximate a condition.

Prepared results are review candidates. Their SHA-256 binds content for
consistency; it is not an authentication signature, promotion receipt, or
permission to respond. Activation still requires Detection Forge's reviewed
fixtures and the existing DetectionRegistry/Promotion gates. This module does
not fetch files, install code, run sensors, write settings, or execute commands.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import time
from types import SimpleNamespace
from urllib.parse import quote

from angerona.core.sigma_engine import _rule_supported, match

SCHEMA = "angerona.community-sigma-sysmon.v1"
MAX_RULE_BYTES = 128 * 1024
MAX_NODES = 4096
MAX_DEPTH = 12
MAX_STRING = 4096
MAX_SELECTIONS = 32
MAX_BRANCHES = 64
MAX_FIELDS = 20  # source guards also occupy fields in closed detection packages
MAX_VALUES = 32
MAX_MATCH_VALUES = 256
MAX_MATCH_CHARS = 32 * 1024
PARSE_BUDGET_SECONDS = 0.5
EVALUATION_BUDGET_SECONDS = 0.05

_SELECTOR = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,79}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ATTACK = re.compile(r"attack\.(t\d{4}(?:\.\d{3})?)\Z", re.IGNORECASE)
_MODIFIERS = {"", "contains", "startswith", "endswith"}
_SOURCE = "Sysmon Event Bridge"
_NATIVE = "sysmon-native"

# These are mappings of the current bridge, not guessed snake-case names.
# EID 1/3/6/8/10/25 have explicit decoders; the remaining listed EIDs use
# sysmon_listener._build_details's generic uppercase-to-underscore conversion.
_FIELDS_BY_EID = {
    1: {"ProcessGuid": "process_guid", "ParentProcessGuid": "parent_process_guid",
        "UtcTime": "source_utc_time", "Image": "image", "CommandLine": "command_line",
        "ParentImage": "parent_image", "ParentCommandLine": "parent_cmdline",
        "User": "user", "Hashes": "hashes", "ProcessId": "pid", "ParentProcessId": "parent_pid"},
    3: {"Image": "image", "SourceIp": "source_ip", "SourcePort": "source_port",
        "DestinationIp": "dest_ip", "DestinationPort": "dest_port",
        "DestinationHostname": "dest_hostname", "Protocol": "protocol",
        "ProcessId": "pid", "ProcessGuid": "process_guid", "UtcTime": "source_utc_time",
        "Initiated": "initiated"},
    6: {"ImageLoaded": "image_loaded", "Hashes": "hashes", "Signed": "signed", "Signature": "signature"},
    8: {"SourceImage": "source_image", "SourceProcessId": "source_pid",
        "TargetImage": "target_image", "TargetProcessId": "target_pid",
        "StartAddress": "start_address", "StartModule": "start_module"},
    10: {"SourceImage": "source_image", "SourceProcessId": "source_pid",
         "SourceProcessGUID": "source_process_guid", "TargetImage": "target_image",
         "TargetProcessId": "target_pid", "TargetProcessGUID": "target_process_guid",
         "UtcTime": "source_utc_time", "GrantedAccess": "granted_access", "CallTrace": "call_trace"},
    25: {"Image": "image", "ProcessId": "pid", "Type": "type"},
}
_GENERIC_FIELDS = {
    2: ("Image", "TargetFilename", "CreationUtcTime", "PreviousCreationUtcTime", "ProcessId"),
    5: ("Image", "ProcessId", "ProcessGuid"),
    7: ("Image", "ImageLoaded", "Hashes", "Signed", "Signature", "ProcessId"),
    9: ("Image", "Device", "ProcessId"),
    11: ("Image", "TargetFilename", "CreationUtcTime", "ProcessId"),
    12: ("Image", "EventType", "TargetObject", "ProcessId"),
    13: ("Image", "EventType", "TargetObject", "Details", "ProcessId"),
    14: ("Image", "EventType", "TargetObject", "NewName", "ProcessId"),
    15: ("Image", "TargetFilename", "CreationUtcTime", "Hash", "Contents", "ProcessId"),
    17: ("Image", "PipeName", "ProcessId"),
    18: ("Image", "PipeName", "ProcessId"),
    22: ("Image", "QueryName", "QueryStatus", "QueryResults", "ProcessId"),
    23: ("Image", "TargetFilename", "Hashes", "Archived", "ProcessId"),
    24: ("Image", "Hashes", "Archived", "ProcessId"),
    26: ("Image", "TargetFilename", "Hashes", "ProcessId"),
    27: ("Image", "TargetFilename", "Hashes", "ProcessId"),
    28: ("Image", "TargetFilename", "Hashes", "ProcessId"),
    29: ("Image", "TargetFilename", "Hashes", "ProcessId"),
}
for _eid, _fields in _GENERIC_FIELDS.items():
    _FIELDS_BY_EID[_eid] = {
        field: "".join("_" + char.lower() if char.isupper() else char for char in field).lstrip("_")
        for field in _fields
    }
_FIELDS_BY_EID[22].update(ProcessGuid="process_guid", UtcTime="source_utc_time")

# SigmaHQ's Sysmon taxonomy, constrained to bridge decoders with usable fields.
# Registry add/delete additionally require EventType; EID 12 alone is ambiguous.
_CATEGORIES = {
    "process_creation": (1,), "file_change": (2,), "network_connection": (3,),
    "process_termination": (5,), "driver_load": (6,), "image_load": (7,),
    "create_remote_thread": (8,), "raw_access_thread": (9,), "process_access": (10,),
    "file_event": (11,), "registry_add": (12,), "registry_delete": (12,),
    "registry_set": (13,), "registry_rename": (14,), "registry_event": (12, 13, 14),
    "create_stream_hash": (15,), "pipe_created": (17, 18), "dns_query": (22,),
    "file_delete": (23, 26), "clipboard_capture": (24,), "process_tampering": (25,),
    "file_delete_detected": (26,), "file_block_executable": (27,),
    "file_block_shredding": (28,), "file_executable_detected": (29,),
}
_EVENT_TYPES = {"registry_add": ["CreateKey"], "registry_delete": ["DeleteKey", "DeleteValue"]}
_METADATA_KEYS = ("id", "author", "license", "title", "description", "status", "level",
                  "date", "modified", "tags", "references", "falsepositives", "related", "scope")


class _Refusal(ValueError):
    def __init__(self, code: str, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


def _refuse(code: str, reason: str) -> None:
    raise _Refusal(code, reason)


def _bounded(value: object, *, maximum_nodes: int = MAX_NODES) -> bool:
    """Exact built-in JSON types only; never coerce arbitrary caller objects."""
    remaining = maximum_nodes

    def walk(item: object, depth: int) -> bool:
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > MAX_DEPTH:
            return False
        if item is None or type(item) is bool:
            return True
        if type(item) is int:
            return -(2**63) <= item < 2**63
        if type(item) is float:
            return math.isfinite(item)
        if type(item) is str:
            return len(item) <= MAX_STRING
        if type(item) is list:
            return len(item) <= 256 and all(walk(child, depth + 1) for child in item)
        if type(item) is dict:
            return len(item) <= 256 and all(
                type(key) is str and 0 < len(key) <= 256 and walk(child, depth + 1)
                for key, child in item.items()
            )
        return False

    return walk(value, 0)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(internal_rule: dict, sidecar: dict) -> str:
    return "sha256:" + hashlib.sha256(_canonical({
        "schema": SCHEMA, "internal_rule": internal_rule, "sidecar": sidecar,
    })).hexdigest()


def _parse(raw: bytes) -> dict:
    if type(raw) is not bytes or not raw or len(raw) > MAX_RULE_BYTES:
        _refuse("INVALID_OR_OVERSIZE_INPUT", "Supply one UTF-8 Sigma document of at most 128 KiB.")
    try:
        import yaml
    except ImportError:
        _refuse("DEPENDENCY_UNAVAILABLE", "PyYAML is unavailable; no rule was imported.")
    started = time.monotonic()

    class BoundedLoader(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self.remaining = MAX_NODES
            self.depth = 0

        def compose_node(self, parent, index):
            self.remaining -= 1
            self.depth += 1
            try:
                if self.remaining < 0 or self.depth > MAX_DEPTH:
                    raise yaml.YAMLError("YAML node/depth budget exceeded")
                if time.monotonic() - started > PARSE_BUDGET_SECONDS:
                    raise yaml.YAMLError("YAML parsing budget exceeded")
                if self.check_event(yaml.AliasEvent):
                    raise yaml.YAMLError("YAML aliases are unsupported")
                node = super().compose_node(parent, index)
                if isinstance(node, yaml.ScalarNode) and len(node.value) > MAX_STRING:
                    raise yaml.YAMLError("YAML scalar budget exceeded")
                return node
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            if not isinstance(node, yaml.MappingNode):
                raise yaml.YAMLError("Expected map")
            result = {}
            for key_node, value_node in node.value:
                key = self.construct_object(key_node, deep=deep)
                if type(key) is not str or key in result:
                    raise yaml.YAMLError("Duplicate or non-string YAML map key")
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    # Sigma dates commonly use unquoted ISO dates. Retain their scalar text;
    # SafeLoader's datetime constructor would produce a non-JSON runtime object.
    BoundedLoader.add_constructor("tag:yaml.org,2002:timestamp",
                                  lambda loader, node: loader.construct_scalar(node))
    try:
        document = yaml.load(raw.decode("utf-8-sig", errors="strict"), Loader=BoundedLoader)
    except Exception:
        _refuse("UNSAFE_OR_INVALID_YAML", "YAML is invalid, ambiguous, unsupported, or exceeds its parsing budget.")
    if type(document) is not dict or not _bounded(document):
        _refuse("UNBOUNDED_DOCUMENT", "Rule must be one bounded map of plain data.")
    return document


def _provenance(raw: bytes, provenance: dict) -> dict:
    if type(provenance) is not dict or not _bounded(provenance):
        _refuse("INVALID_PROVENANCE", "Bounded repository, commit, path, SHA-256 and license provenance is required.")
    repository = provenance.get("repository")
    commit = provenance.get("commit")
    path = provenance.get("path")
    sha256 = provenance.get("sha256")
    license_text = provenance.get("license")
    source_id = provenance.get("source_id", "")
    if type(repository) is not str or not _REPOSITORY.fullmatch(repository) or any(
        part in {".", ".."} or part.endswith(".") for part in repository.split("/")
    ):
        _refuse("INVALID_PROVENANCE", "Repository must be a canonical GitHub owner/repository identifier.")
    if type(commit) is not str or not _COMMIT.fullmatch(commit):
        _refuse("INVALID_PROVENANCE", "An exact lowercase 40-hex source commit is required.")
    if (type(path) is not str or not 1 <= len(path) <= 512 or "\\" in path
            or path.startswith("/") or any(part in {"", ".", ".."} for part in path.split("/"))
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", path)):
        _refuse("INVALID_PROVENANCE", "A bounded repository-relative rule path is required.")
    actual = hashlib.sha256(raw).hexdigest()
    if type(sha256) is not str or not _SHA256.fullmatch(sha256) or not hmac.compare_digest(sha256, actual):
        _refuse("SOURCE_DIGEST_MISMATCH", "Rule bytes do not match the supplied source SHA-256.")
    if type(license_text) is not str or not license_text or len(license_text) > 512:
        _refuse("MISSING_LICENSE", "Preserve the reviewed source license; no license is inferred.")
    if type(source_id) is not str or len(source_id) > 256:
        _refuse("INVALID_PROVENANCE", "Catalog source identifier is invalid.")
    return {"repository": repository.lower(), "commit": commit, "path": path,
            "sha256": actual, "license": license_text, "source_id": source_id,
            "url": f"https://github.com/{repository.lower()}/blob/{commit}/{quote(path, safe='/')}"}


def _source_plan(logsource: object) -> tuple[dict, dict]:
    if type(logsource) is not dict or set(logsource) - {"product", "category", "service", "definition"}:
        _refuse("UNSUPPORTED_LOGSOURCE", "Only explicit Windows/Sysmon category log sources are supported.")
    category = logsource.get("category")
    if (logsource.get("product") != "windows" or type(category) is not str or category not in _CATEGORIES
            or logsource.get("service", "sysmon") != "sysmon"):
        _refuse("UNSUPPORTED_LOGSOURCE", "This adapter requires a supported Windows category and native Sysmon collector.")
    if "definition" in logsource and type(logsource["definition"]) is not str:
        _refuse("UNSUPPORTED_LOGSOURCE", "Logsource definition must remain descriptive text.")
    eids = _CATEGORIES[category]
    common = dict(_FIELDS_BY_EID[eids[0]])
    for eid in eids[1:]:
        common = {key: value for key, value in common.items()
                  if _FIELDS_BY_EID[eid].get(key) == value}
    guard = {"module": _SOURCE, "sensor_source": _NATIVE,
             "raw_sensor_evidence": True, "eid": list(eids)}
    if category in _EVENT_TYPES:
        guard["event_type"] = list(_EVENT_TYPES[category])
    return guard, common


def _literal(value: object) -> str | int | bool:
    if type(value) not in {str, int, bool}:
        _refuse("UNSUPPORTED_VALUE", "Only nonempty strings, bounded integers and booleans are supported.")
    if type(value) is int and not -(2**63) <= value < 2**63:
        _refuse("UNSUPPORTED_VALUE", "Integer value exceeds the adapter bound.")
    if type(value) is str:
        if not value or len(value) > MAX_STRING:
            _refuse("UNSUPPORTED_VALUE", "Empty or oversized string predicates require explicit unsupported semantics.")
        if "*" in value or "?" in value:
            _refuse("UNSUPPORTED_WILDCARD", "Wildcard/escaped-wildcard strings need a reviewed converter; they are never treated as literals.")
        # With no wildcard present, Sigma pairs of backslashes represent one
        # literal backslash; single backslashes are retained (Windows paths).
        value = value.replace("\\\\", "\\")
    return value


def _translate(document: dict, guard: dict, fields: dict) -> dict:
    detection = document.get("detection")
    if type(detection) is not dict or not 2 <= len(detection) <= MAX_SELECTIONS + 1:
        _refuse("INVALID_DETECTION", "A bounded detection map with selections and one condition is required.")
    names = [key for key in detection if key != "condition"]
    if any(not _SELECTOR.fullmatch(key) for key in names) or len({key.lower() for key in names}) != len(names):
        _refuse("AMBIGUOUS_SELECTOR", "Selection names must be bounded identifiers without case collisions.")
    condition = detection.get("condition")
    if type(condition) is not str or len(condition) > 512:
        _refuse("UNSUPPORTED_CONDITION", "A bounded string condition from the supported subset is required.")
    condition = " ".join(condition.lower().split())
    if " and not " in condition and " or " in condition.partition(" and not ")[0]:
        _refuse("UNSUPPORTED_CONDITION", "Explicit OR followed by AND NOT requires precedence/grouping support; no approximation is made.")
    translated = {"condition": condition}
    branches = values_count = chars_count = 0
    for name in names:
        original = detection[name]
        choices = original if type(original) is list else [original]
        if not choices or len(choices) > MAX_VALUES:
            _refuse("UNSUPPORTED_SELECTION", "Selection branches must be a nonempty bounded list of maps.")
        mapped_choices = []
        for choice in choices:
            branches += 1
            if (type(choice) is not dict or not choice or len(choice) > min(MAX_FIELDS, 24 - len(guard))
                    or branches > MAX_BRANCHES):
                _refuse("UNSUPPORTED_SELECTION", "Selection fields or total branches exceed the adapter bound.")
            mapped = {}
            for key, expected in choice.items():
                parts = key.split("|")
                if len(parts) > 2 or (len(parts) == 2 and parts[1] not in _MODIFIERS - {""}):
                    _refuse("UNSUPPORTED_MODIFIER", "Only exact, contains, startswith and endswith are supported; no regex or chained transformations.")
                field = parts[0]
                modifier = parts[1] if len(parts) == 2 else ""
                if field != "EventID" and field not in fields:
                    _refuse("UNAVAILABLE_FIELD", f"Field {field[:80]} is not collected consistently for this logsource; no substitute is inferred.")
                expected_values = expected if type(expected) is list else [expected]
                if not expected_values or len(expected_values) > MAX_VALUES:
                    _refuse("UNSUPPORTED_VALUE", "Predicate lists must contain 1-32 scalar values.")
                converted = [_literal(value) for value in expected_values]
                values_count += len(converted)
                chars_count += sum(len(str(value)) for value in converted)
                if values_count > MAX_MATCH_VALUES or chars_count > MAX_MATCH_CHARS:
                    _refuse("MATCH_BUDGET_EXCEEDED", "Total match-value count or text exceeds the evaluation bound.")
                if field == "EventID":
                    if modifier or any(type(value) not in {str, int} or not str(value).isdigit()
                                       or int(value) not in guard["eid"] for value in converted):
                        _refuse("UNSUPPORTED_EVENT_ID", "EventID must be an exact supported integer within the logsource category.")
                    mapped["eid"] = [int(value) for value in converted]
                else:
                    native = fields[field] + ("|" + modifier if modifier else "")
                    mapped[native] = converted if type(expected) is list else converted[0]
            for key, value in guard.items():
                if key not in mapped:
                    mapped[key] = list(value) if type(value) is list else value
                elif key == "event_type":
                    # Category and explicit EventType are AND constraints. An
                    # incompatible branch is refused instead of overwriting it.
                    wanted = mapped[key] if type(mapped[key]) is list else [mapped[key]]
                    if any(str(item).lower() not in {str(v).lower() for v in value} for item in wanted):
                        _refuse("INCOMPATIBLE_EVENT_TYPE", "Explicit EventType conflicts with the registry logsource category.")
            mapped_choices.append(mapped)
        translated[name.lower()] = mapped_choices if type(original) is list else mapped_choices[0]
    result = {"title": document["title"], "detection": translated}
    ok, code, reason = _rule_supported(result)
    if not ok:
        _refuse(code, reason)
    # The registry's closed package grammar permits fewer prefix spellings
    # than the public matcher. Expand only the already-validated bounded
    # prefix set; this preserves Boolean meaning without adding a parser.
    base, separator, negative = condition.partition(" and not ")
    prefix = re.fullmatch(r"(all|1) of ([a-z_][a-z0-9_-]*)\*", base)
    if prefix:
        selected = [name.lower() for name in names if name.lower().startswith(prefix.group(2))]
        base = (" and " if prefix.group(1) == "all" else " or ").join(selected)
        translated["condition"] = base + (separator + negative if separator else "")
    return result


def prepare_sigma_document(raw: bytes, provenance: dict) -> dict:
    """Return a bounded, source-guarded review candidate or an explicit refusal."""
    try:
        document = _parse(raw)
        source = _provenance(raw, provenance)
        if "correlation" in document or "filter" in document or "action" in document:
            _refuse("UNSUPPORTED_CORRELATION", "Correlation, filter-meta and multi-document collection actions are unsupported.")
        if document.get("taxonomy", "sigma") != "sigma":
            _refuse("UNSUPPORTED_TAXONOMY", "Only the explicit default Sigma taxonomy is translated.")
        title = document.get("title")
        if type(title) is not str or not title.strip() or len(title) > 256:
            _refuse("INVALID_TITLE", "Sigma title must contain 1-256 characters.")
        status = document.get("status", "test")
        if type(status) is not str or status not in {"stable", "test", "experimental", "deprecated", "unsupported"}:
            _refuse("INVALID_METADATA", "Upstream status must be a recognized plain-text Sigma status.")
        if status in {"deprecated", "unsupported"}:
            _refuse("UNSUPPORTED_STATUS", "Deprecated or upstream-unsupported rules are retained for review, not evaluated.")
        guard, fields = _source_plan(document.get("logsource"))
        internal = _translate(document, guard, fields)
        metadata = {key: document[key] for key in _METADATA_KEYS if key in document}
        for key in ("id", "description", "date", "modified"):
            if key in metadata and type(metadata[key]) is not str:
                _refuse("INVALID_METADATA", "Rule identity, descriptions and dates must remain plain text.")
        if "level" in metadata and (type(metadata["level"]) is not str or metadata["level"] not in {"informational", "low", "medium", "high", "critical"}):
            _refuse("INVALID_METADATA", "Rule severity must be a recognized Sigma level.")
        if "license" in metadata and (type(metadata["license"]) is not str or not metadata["license"]):
            _refuse("INVALID_LICENSE", "Rule license must be preserved as nonempty text.")
        if "author" in metadata and type(metadata["author"]) not in {str, list}:
            _refuse("INVALID_METADATA", "Author credits must be text or a bounded text list.")
        if type(metadata.get("author")) is list and any(type(value) is not str for value in metadata["author"]):
            _refuse("INVALID_METADATA", "Author credits must contain only text.")
        tags = metadata.get("tags", [])
        if type(tags) is not list or len(tags) > 64 or any(type(tag) is not str for tag in tags):
            _refuse("INVALID_METADATA", "Tags must be a bounded list of text identifiers.")
        attack = sorted({found.group(1).upper() for tag in tags if (found := _ATTACK.fullmatch(tag))})
        sidecar = {"schema": SCHEMA, "source": source, "original_logsource": document["logsource"],
                   "metadata": metadata, "license": metadata.get("license", source["license"]),
                   "attack": attack, "guard": guard,
                   "field_mapping": fields, "mode": "observe-only-review-candidate",
                   "response_authorized": False,
                   "promotion": "Reviewed fixtures and existing DetectionRegistry/Promotion gates required.",
                   "coverage": ["Native Sysmon evidence only; process-diff fallback is not equivalent.",
                                "Only fields actually collected by the current bridge are translated.",
                                "Upstream definition/scope notes remain review context, not automatic machine enrollment.",
                                "Collector absence, truncation, kernel blinding and missing events remain coverage gaps.",
                                "A match is a review lead; neither a breach verdict nor response authority."]}
        if not _bounded({"internal_rule": internal, "sidecar": sidecar}):
            _refuse("PREPARED_BUDGET_EXCEEDED", "Expanded source-guarded plan exceeds its plain-data bound.")
        return {"accepted": True, "code": "PREPARED_OBSERVE_ONLY", "reason": "Explicit native Sysmon source and EventID guards translated; review and promotion remain required.",
                "refusal": None, "unsupported": [], "errors": [], "internal_rule": internal,
                "sidecar": sidecar, "digest": _digest(internal, sidecar), "response_authorized": False}
    except _Refusal as exc:
        issue = {"code": exc.code, "reason": exc.reason}
        malformed = exc.code.startswith(("INVALID", "UNSAFE", "UNBOUNDED", "SOURCE_DIGEST", "PREPARED_BUDGET"))
        return {"accepted": False, "code": exc.code, "reason": exc.reason, "refusal": issue,
                "unsupported": [] if malformed else [issue], "errors": [issue] if malformed else [],
                "internal_rule": None, "sidecar": None, "digest": None, "response_authorized": False}
    except Exception:
        issue = {"code": "PREPARATION_UNAVAILABLE", "reason": "Rule preparation could not complete; no candidate was admitted."}
        return {"accepted": False, **issue, "refusal": issue, "unsupported": [], "errors": [issue],
                "internal_rule": None, "sidecar": None, "digest": None, "response_authorized": False}


def _event_fields(event: object) -> dict:
    if type(event) is dict:
        details = event.get("details", {})
        nested = type(details) is dict
        # The envelope owns reserved names; details cannot impersonate a module.
        # A FLAT Sysmon registry-set field named "details" is scalar data;
        # distinguish it from an Event-shaped nested details container.
        fields = {key: value for key, value in event.items() if not (nested and key == "details")}
        for key, value in details.items() if nested else ():
            if key not in {"module", "message", "severity"}:
                fields[key] = value
    else:
        details = getattr(event, "details", None)
        if type(details) is not dict:
            _refuse("INVALID_EVENT", "Event details must be plain fields.")
        fields = {key: value for key, value in details.items() if key not in {"module", "message", "severity"}}
        fields["module"] = getattr(event, "module", None)
    if len(fields) > 128:
        _refuse("INVALID_EVENT", "Event exceeds the field budget.")
    for key, value in fields.items():
        if type(key) is not str or len(key) > 256:
            _refuse("INVALID_EVENT", "Event field names are invalid.")
        if type(value) is str and len(value) > MAX_STRING:
            _refuse("EVENT_BUDGET_EXCEEDED", "Event field text exceeds the match budget.")
    return fields


def _validate_prepared_internal(internal: dict, guard: dict, mapping: dict) -> None:
    """Recheck untrusted deserialized plans before even the bounded matcher."""
    ok, _code, _reason = _rule_supported(internal)
    if not ok or set(internal) != {"title", "detection"}:
        _refuse("INVALID_PREPARED", "Prepared internal detection is no longer a supported rule.")
    detection = internal["detection"]
    if not 2 <= len(detection) <= MAX_SELECTIONS + 1 or len(detection["condition"]) > 512:
        _refuse("INVALID_PREPARED", "Prepared detection exceeds its selection/condition bound.")
    branches = values_count = chars_count = 0
    allowed = set(mapping.values())
    for name, selection in detection.items():
        if name == "condition":
            continue
        choices = selection if type(selection) is list else [selection]
        for branch in choices:
            branches += 1
            if type(branch) is not dict or len(branch) > 24 or branches > MAX_BRANCHES:
                _refuse("INVALID_PREPARED", "Prepared branch exceeds the closed package bound.")
            for key, value in guard.items():
                actual = branch.get(key)
                if key in {"eid", "event_type"}:
                    actual_values = actual if type(actual) is list else [actual]
                    if not actual_values or any(type(item) is not type(value[0]) or item not in value for item in actual_values):
                        _refuse("INVALID_PREPARED", "A branch lost its category/EventID constraint.")
                elif type(actual) is not type(value) or actual != value:
                    _refuse("INVALID_PREPARED", "A branch lost its native source constraint.")
            for key, expected in branch.items():
                if key in guard:
                    continue
                parts = key.split("|")
                if len(parts) > 2 or parts[0] not in allowed or (len(parts) == 2 and parts[1] not in _MODIFIERS - {""}):
                    _refuse("INVALID_PREPARED", "Prepared field or modifier is outside this adapter's safe subset.")
                values = expected if type(expected) is list else [expected]
                if not values or len(values) > MAX_VALUES:
                    _refuse("INVALID_PREPARED", "Prepared predicate values exceed the bound.")
                for item in values:
                    # Already-decoded literal backslashes are retained here.
                    if type(item) not in {str, int, bool} or (type(item) is str and (not item or "*" in item or "?" in item)):
                        _refuse("INVALID_PREPARED", "Prepared predicate has unsupported scalar semantics.")
                values_count += len(values)
                chars_count += sum(len(str(item)) for item in values)
            if values_count > MAX_MATCH_VALUES or chars_count > MAX_MATCH_CHARS:
                _refuse("INVALID_PREPARED", "Prepared match budget exceeds the bound.")


def evaluate_prepared(prepared: dict, event: object) -> dict:
    """Evaluate one candidate without granting activation, trust, or response."""
    started = time.monotonic()
    base = {"matched": False, "response_authorized": False, "provenance": None, "finding": None}
    try:
        if type(prepared) is not dict or prepared.get("accepted") is not True:
            _refuse("NOT_PREPARED", "No accepted review candidate is available.")
        internal = prepared.get("internal_rule")
        sidecar = prepared.get("sidecar")
        if type(internal) is not dict or type(sidecar) is not dict or not _bounded({"internal_rule": internal, "sidecar": sidecar}):
            _refuse("INVALID_PREPARED", "Prepared rule data exceeds its plain-data bound.")
        # Canonicalize once into owned plain containers; every subsequent
        # check and match uses the same generation of mutable caller data.
        owned = json.loads(_canonical({"i": internal, "s": sidecar}))
        internal, sidecar = owned["i"], owned["s"]
        digest = prepared.get("digest")
        if type(digest) is not str or not hmac.compare_digest(digest, _digest(internal, sidecar)):
            _refuse("PREPARED_DIGEST_MISMATCH", "Prepared rule or provenance changed after preparation.")
        if sidecar.get("schema") != SCHEMA or sidecar.get("response_authorized") is not False:
            _refuse("INVALID_PREPARED", "Prepared adapter schema or authority marker is invalid.")
        guard, mapping = _source_plan(sidecar.get("original_logsource"))
        if guard != sidecar.get("guard") or mapping != sidecar.get("field_mapping"):
            _refuse("INVALID_PREPARED", "Prepared source constraints differ from the supported decoder mapping.")
        _validate_prepared_internal(internal, guard, mapping)
        fields = _event_fields(event)
        if fields.get("module") != _SOURCE or fields.get("sensor_source") != _NATIVE or fields.get("raw_sensor_evidence") is not True or fields.get("fallback") is True:
            _refuse("WRONG_SOURCE", "This rule requires native Sysmon evidence from Sysmon Event Bridge; fallback and other providers are excluded.")
        if type(fields.get("eid")) is not int or fields["eid"] not in guard["eid"]:
            _refuse("WRONG_EVENT_ID", "Event ID does not belong to this rule's native logsource category.")
        allowed = set(mapping.values()) | set(guard)
        selected_fields = {key: value for key, value in fields.items() if key in allowed}
        for value in selected_fields.values():
            if value is not None and type(value) not in {str, int, bool}:
                _refuse("INVALID_EVENT", "A selected event field contains a non-scalar runtime object.")
            if type(value) is int and not -(2**63) <= value < 2**63:
                _refuse("INVALID_EVENT", "A selected event integer exceeds the bound.")
        candidate = SimpleNamespace(module=_SOURCE, message="", severity=SimpleNamespace(name="INFO"),
                                    details={key: value for key, value in selected_fields.items() if key != "module"})
        matched = bool(match(internal, candidate))
        if time.monotonic() - started > EVALUATION_BUDGET_SECONDS:
            _refuse("EVALUATION_BUDGET_EXCEEDED", "Evaluation exceeded its deadline; no match or coverage claim is returned.")
        provenance = {"source": sidecar["source"], "metadata": sidecar["metadata"],
                      "license": sidecar["license"], "attack": sidecar["attack"], "prepared_digest": digest}
        finding = None
        if matched:
            finding = {"title": internal["title"], "rule_id": sidecar["metadata"].get("id"),
                       "author": sidecar["metadata"].get("author"), "license": sidecar["license"],
                       "attack": sidecar["attack"], "source": sidecar["source"],
                       "severity": sidecar["metadata"].get("level", "medium"),
                       "disposition": "review-required", "response_authorized": False}
        return {**base, "matched": matched, "code": "MATCH" if matched else "NO_MATCH",
                "reason": "Source-guarded rule matched; review evidence before any separate response." if matched else "Native source was eligible; rule predicates did not match.",
                "provenance": provenance, "finding": finding}
    except _Refusal as exc:
        return {**base, "code": exc.code, "reason": exc.reason}
    except Exception:
        return {**base, "code": "EVALUATION_UNAVAILABLE", "reason": "Evaluation failed closed; no detection or coverage claim is made."}


def self_check() -> dict:
    """Pure positive/negative/refusal fixtures, never host or sensor tests."""
    raw = b"""title: Benign adapter fixture
id: a9e93e79-c044-4bb3-97a9-7ddf3ad41f87
author: Angerona adapter self-check
license: DRL-1.1
date: 2026-11-08
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\\benign-fixture.exe'
  condition: selection
tags: [attack.t1059.001]
level: low
"""
    provenance = {"repository": "sigmahq/sigma", "commit": "0" * 40,
                  "path": "rules/windows/process_creation/adapter_benign_fixture.yml",
                  "sha256": hashlib.sha256(raw).hexdigest(), "license": "DRL-1.1",
                  "source_id": "offline-fixture-not-upstream-rule"}
    prepared = prepare_sigma_document(raw, provenance)
    positive = {"module": _SOURCE, "sensor_source": _NATIVE, "raw_sensor_evidence": True,
                "eid": 1, "image": "C:\\fixtures\\benign-fixture.exe"}
    checks = [{"name": "prepare-guarded-fixture", "passed": prepared["accepted"] is True}]
    for name, event, expected in (
        ("positive-native-eid1", positive, "MATCH"),
        ("negative-other-image", {**positive, "image": "C:\\fixtures\\other.exe"}, "NO_MATCH"),
        ("negative-other-source", {**positive, "module": "Process Monitor"}, "WRONG_SOURCE"),
        ("negative-fallback", {**positive, "fallback": True}, "WRONG_SOURCE"),
        ("negative-wrong-eid", {**positive, "eid": 7}, "WRONG_EVENT_ID"),
    ):
        result = evaluate_prepared(prepared, event)
        checks.append({"name": name, "passed": result["code"] == expected and result["response_authorized"] is False,
                       "actual": result["code"]})
    for name, bad in (
        ("refuse-unsupported-logsource", raw.replace(b"product: windows", b"product: linux")),
        ("refuse-regex", raw.replace(b"Image|endswith", b"Image|re")),
        ("refuse-correlation", raw + b"correlation: {type: event_count}\n"),
    ):
        refused = prepare_sigma_document(bad, {**provenance, "sha256": hashlib.sha256(bad).hexdigest()})
        checks.append({"name": name, "passed": refused["accepted"] is False, "actual": refused["code"]})
    return {"ok": all(check["passed"] for check in checks), "state": "passed" if all(check["passed"] for check in checks) else "failed",
            "checks": checks, "coverage": "Offline adapter semantics only; does not verify installed Sysmon or host protection.",
            "response_authorized": False}
