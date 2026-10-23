"""Group explicitly selected live-debug JSONL captures for offline AI review.

This utility has no transport, provider, source execution or response authority.
Source text remains untrusted evidence; a summary never establishes a clean host.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from contextlib import contextmanager, ExitStack
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import time

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from angerona.core.live_debug import PROTOCOL, sanitize_text  # noqa: E402

MAX_FRAME_BYTES = 32 * 1024
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_RECORDS = 100_000
MAX_CASES = 512
_REFERENCE_LIMIT = 8192
_ANNOTATION_LIMIT = 1024
_SEVERITIES = {"UNKNOWN": -1, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_KINDS = {"hello", "heartbeat", "event", "diagnostic", "coverage", "gap", "annotation", "client_error"}
_VERDICTS = {"threat", "confirmed-threat", "false-positive", "needs-review", "health", "exposure"}
_HASH = re.compile(r"[0-9a-f]{64}")
_MESH_HASH = re.compile(r"[0-9a-f]{128}")
_RUN = re.compile(r"[0-9a-f]{32}")


class SummaryError(ValueError):
    pass


def view_sha256(record: dict) -> str:
    """Same canonical view binding used by the read-only capture CLI."""
    return hashlib.sha256(json.dumps(record, ensure_ascii=True, sort_keys=True,
        separators=(",", ":"), allow_nan=False).encode("ascii")).hexdigest()


def _capture_path(value: str | Path, suffix: str) -> Path:
    path = Path(os.path.abspath(value))
    supported_suffix = (bool(re.fullmatch(r"(?i).+\.jsonl(?:\.[1-5])?", path.name))
        if suffix == ".jsonl" else path.suffix.lower() == suffix)
    if len(str(path)) > 4096 or not supported_suffix:
        raise SummaryError(f"Choose an explicit {suffix} file path")
    if str(path).startswith(("\\\\", "//")):
        raise SummaryError("Network and device paths are not supported")
    if os.name == "nt":
        import ctypes
        if ctypes.windll.kernel32.GetDriveTypeW(str(path.anchor)) == 4:
            raise SummaryError("Network drives are not supported")
    return path


@contextmanager
def _parent_chain(path: Path):
    """Pin no-follow parents; do not create directories or change their ACLs."""
    with ExitStack() as stack:
        if os.name == "nt":
            import win32con
            import win32file
            for parent in (*reversed(path.parent.parents), path.parent):
                handle = win32file.CreateFile(str(parent), 0x81, 3, None,
                    win32con.OPEN_EXISTING, 0x02000000 | 0x00200000, None)
                stack.callback(handle.Close)
                info = win32file.GetFileInformationByHandle(handle)
                actual = win32file.GetFinalPathNameByHandle(handle, 0)
                actual = actual[4:] if actual.startswith("\\\\?\\") else actual
                if info[0] & 0x400 or not info[0] & 0x10 or os.path.normcase(os.path.abspath(actual)) != os.path.normcase(str(parent)):
                    raise SummaryError("Linked or redirected capture directories are refused")
            yield None
        else:
            descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
            stack.callback(os.close, descriptor)
            for part in path.parts[1:-1]:
                descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor)
                stack.callback(os.close, descriptor)
            yield descriptor


@contextmanager
def _open_file(path: Path, *, write: bool = False):
    with _parent_chain(path) as parent_fd:
        if os.name == "nt":
            import msvcrt
            import win32con
            import win32file
            attributes = None
            if write:
                from angerona.core.engine_transport import _windows_private_attributes
                attributes = _windows_private_attributes()
            handle = win32file.CreateFile(str(path), win32con.GENERIC_WRITE if write else win32con.GENERIC_READ,
                1 if write else 3, attributes, win32con.CREATE_NEW if write else win32con.OPEN_EXISTING,
                0x00200000, None)
            try:
                info = win32file.GetFileInformationByHandle(handle)
                actual = win32file.GetFinalPathNameByHandle(handle, 0)
                actual = actual[4:] if actual.startswith("\\\\?\\") else actual
                if info[0] & (0x400 | 0x10) or info[7] != 1 or os.path.normcase(os.path.abspath(actual)) != os.path.normcase(str(path)):
                    raise SummaryError("Capture must be a regular, single-link, non-reparse file")
                descriptor = msvcrt.open_osfhandle(int(handle), (os.O_WRONLY if write else os.O_RDONLY) | os.O_BINARY)
                handle.Detach()
            except BaseException:
                handle.Close()
                raise
        else:
            flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL if write else os.O_RDONLY)
            flags |= os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        with os.fdopen(descriptor, "wb" if write else "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SummaryError("Capture must be a regular single-link file")
            yield stream, info


def _decode(raw: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    def invalid_constant(_value):
        raise ValueError("non-finite JSON value")
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
        parse_constant=invalid_constant)
    remaining = 4096
    def visit(item, depth=0):
        nonlocal remaining
        remaining -= 1
        if remaining < 0 or depth > 12:
            raise ValueError("JSON structure exceeds bound")
        if type(item) is float and not math.isfinite(item):
            raise ValueError("non-finite JSON value")
        if isinstance(item, dict):
            for child in item.values():
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
    visit(value)
    if (not isinstance(value, dict) or value.get("protocol") != PROTOCOL
            or not isinstance(value.get("kind"), str) or value["kind"] not in _KINDS):
        raise SummaryError("Not a live-debug capture record")
    return value


def _text(value, maximum=512) -> str:
    return sanitize_text(value, maximum) if isinstance(value, str) else ""


def _stamp(value):
    return value if type(value) in (int, float) and 0 <= value <= 253402300799 and math.isfinite(value) else None


def _identity(record):
    run, sequence = record.get("run_id"), record.get("seq")
    if isinstance(run, str) and _RUN.fullmatch(run) and type(sequence) is int and 0 < sequence <= 0x7FFFFFFFFFFFFFFF:
        return run, sequence
    return None


def _number(value) -> int:
    return value if type(value) is int and 0 <= value <= 0x7FFFFFFFFFFFFFFF else 0


class CaseSummary:
    """Bounded evidence groups; producer claims and local review stay separate."""

    def __init__(self, max_cases=MAX_CASES):
        if type(max_cases) is not int or not 1 <= max_cases <= MAX_CASES:
            raise ValueError("Case limit must be between 1 and 512")
        self.max_cases = max_cases
        self.cases: dict[str, dict] = {}
        self.references: OrderedDict[tuple[str, int], tuple[str | None, str | None]] = OrderedDict()
        self.notes: list[dict] = []
        self.counts = dict.fromkeys(("bytes_read", "lines_read", "valid_records", "malformed_json",
            "invalid_records", "oversized_records", "truncated_records", "blank_lines",
            "event_records", "diagnostic_records", "coverage_records", "inaccessible_records", "gap_records",
            "reported_lost_records", "reported_skipped_bytes", "duplicate_records", "identity_conflicts",
            "case_overflow_records", "annotation_records", "annotation_overflow_records", "reference_evictions"), 0)
        self.limits = {"byte_budget_reached": False, "record_budget_reached": False, "time_budget_reached": False}
        self.max_severity = "UNKNOWN"

    def _case(self, record: dict, capture: int, line: int) -> str | None:
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        evidence = details.get("evidence") if isinstance(details.get("evidence"), dict) else {}
        module = record.get("module") if isinstance(record.get("module"), str) else ""
        code = next((details.get(key) for key in ("finding_code", "rule_id", "rule")
            if isinstance(details.get(key), str) and details[key]), "")
        sources = [value for value in (record.get("source"), details.get("source"), details.get("surface"), evidence.get("source"))
            if isinstance(value, str) and value]
        kind = record["kind"]
        message = record.get("message") or record.get("reason") or record.get("error") or ""
        signature = _text(message, 8192)
        context = [record.get(key) for key in ("reason", "state", "error_type")] if kind in {"coverage", "gap", "client_error"} else []
        grouping = [kind, module, code, sources, context, "" if code else signature]
        case_id = hashlib.sha256(json.dumps(grouping, ensure_ascii=True, sort_keys=True,
            separators=(",", ":")).encode("ascii")).hexdigest()
        severity = record.get("severity")
        severity = severity.upper() if isinstance(severity, str) and severity.upper() in _SEVERITIES else "UNKNOWN"
        if _SEVERITIES[severity] > _SEVERITIES[self.max_severity]:
            self.max_severity = severity
        if case_id not in self.cases:
            if len(self.cases) >= self.max_cases:
                self.counts["case_overflow_records"] += 1
                return None
            self.cases[case_id] = {"case_id": case_id, "kind": kind, "module": _text(module, 160),
                "finding_code": _text(code, 160), "sources": [_text(source, 160) for source in sources[:4]],
                "message_signature": hashlib.sha256(signature.encode("utf-8")).hexdigest() if not code else None,
                "occurrences": 0, "samples_omitted": 0, "first_seen": None, "last_seen": None, "max_severity": "UNKNOWN",
                "producer_dispositions": {}, "review_status": "needs-review", "local_reviews": [],
                "samples": [], "verification_scope": "reported original-event metadata; not reverified offline"}
        case = self.cases[case_id]
        case["occurrences"] += 1
        case["samples_omitted"] = max(0, case["occurrences"] - 2)
        stamp = _stamp(record.get("event_ts"))
        if stamp is None:
            stamp = _stamp(record.get("ts"))
        if stamp is not None:
            case["first_seen"] = stamp if case["first_seen"] is None else min(case["first_seen"], stamp)
            case["last_seen"] = stamp if case["last_seen"] is None else max(case["last_seen"], stamp)
        if _SEVERITIES[severity] > _SEVERITIES[case["max_severity"]]:
            case["max_severity"] = severity
        disposition = details.get("disposition", record.get("disposition", "unknown"))
        disposition = disposition if isinstance(disposition, str) and disposition in {"active", "health", "exposure", "practice", "observation", "informational"} else "unknown"
        counts = case["producer_dispositions"]
        counts[disposition] = counts.get(disposition, 0) + 1
        sample = {"capture": capture, "line": line, "run_id": record.get("run_id") if _identity(record) else None,
            "seq": record.get("seq") if _identity(record) else None, "ts": stamp, "severity": severity,
            "text": _text(message), "source_file": _text(details.get("source_file"), 256),
            "original_integrity_verified": record.get("original_integrity_verified") is True,
            "live_receipt_verified_at_export": record.get("live_receipt_verified_at_export") is True,
            "original_hmac": record.get("original_hmac") if isinstance(record.get("original_hmac"), str) and _HASH.fullmatch(record["original_hmac"]) else "",
            "original_mesh_signature": record.get("original_mesh_signature") if isinstance(record.get("original_mesh_signature"), str) and _MESH_HASH.fullmatch(record["original_mesh_signature"]) else "",
            "original_mesh_peer": _text(record.get("original_mesh_peer"), 160)}
        if len(case["samples"]) < 2:
            case["samples"].append(sample)
        else:
            case["samples"][1] = sample
        return case_id

    def consume(self, record: dict, capture=0, line=0) -> None:
        self.counts["valid_records"] += 1
        kind = record["kind"]
        if kind == "annotation":
            self.counts["annotation_records"] += 1
            if len(self.notes) >= _ANNOTATION_LIMIT:
                self.counts["annotation_overflow_records"] += 1
                return
            run, sequence = record.get("run_id"), record.get("target_seq")
            target = (run, sequence) if isinstance(run, str) and _RUN.fullmatch(run) and type(sequence) is int and sequence > 0 else None
            self.notes.append({"run_id": run, "target_seq": sequence,
                "target_view_sha256": record.get("target_view_sha256"), "verdict": record.get("verdict"),
                "note": record.get("note"), "capture": capture, "line": line,
                "target_previously_seen": target in self.references if target else False})
            return
        if kind in {"hello", "heartbeat"}:
            return
        identity, digest = _identity(record), view_sha256(record)
        if kind != "client_error" and identity is None:
            self.counts["invalid_records"] += 1
            return
        previous = self.references.get(identity) if identity else None
        if previous and previous[0] == digest:
            self.counts["duplicate_records"] += 1
            return
        if previous:
            self.counts["identity_conflicts"] += 1
            self.references[identity] = (None, None)
            self._case({"kind": "coverage", "source": "offline-capture-integrity",
                "message": "Conflicting views share a run ID and sequence; their provenance is unresolved.",
                "reason": "conflicting-record-identity", "ts": record.get("ts")}, capture, line)
        for expected, key in (("event", "event_records"), ("diagnostic", "diagnostic_records"),
                              ("coverage", "coverage_records"), ("gap", "gap_records")):
            self.counts[key] += int(kind == expected)
        if kind == "gap":
            self.counts["reported_lost_records"] += max((_number(record.get(key)) for key in
                ("lost_records", "dropped_events", "dropped_records")), default=0)
            self.counts["reported_skipped_bytes"] += _number(record.get("skipped_bytes"))
        if kind == "coverage" and ((isinstance(record.get("state"), str) and record["state"] in {"unavailable", "access_denied", "unknown", "error"})
                or (isinstance(record.get("error_type"), str) and record["error_type"] in {"PermissionError", "AccessDenied"})):
            self.counts["inaccessible_records"] += 1
        case_id = self._case(record, capture, line)
        if identity and not previous:
            if len(self.references) >= _REFERENCE_LIMIT:
                self.references.popitem(last=False)
                self.counts["reference_evictions"] += 1
            self.references[identity] = (digest, case_id)

    def report(self, inputs: list[dict]) -> dict:
        unverified, verified, verified_omitted = [], 0, 0
        for case in self.cases.values():
            case["local_reviews"] = []
            case["local_reviews_omitted"] = 0
        for note in self.notes:
            run, sequence, digest = note["run_id"], note["target_seq"], note["target_view_sha256"]
            identity = (run, sequence) if isinstance(run, str) and _RUN.fullmatch(run) and type(sequence) is int and sequence > 0 else None
            reference = self.references.get(identity) if identity else None
            reason = ("missing-target-binding" if identity is None or not isinstance(digest, str) or not _HASH.fullmatch(digest)
                else "target-not-seen-before-note" if not note["target_previously_seen"]
                else "target-not-retained-or-conflicted" if not reference or reference[0] is None
                else "target-digest-mismatch" if reference[0] != digest
                else "invalid-verdict-or-empty-reason" if not isinstance(note["verdict"], str) or note["verdict"] not in _VERDICTS or not isinstance(note["note"], str) or not note["note"].strip()
                else "case-not-retained" if reference[1] not in self.cases else "")
            projected = {"run_id": run if identity else None, "target_seq": sequence if identity else None,
                "verdict": note["verdict"] if isinstance(note["verdict"], str) and note["verdict"] in _VERDICTS else "unknown",
                "note": _text(note["note"]), "capture": note["capture"], "line": note["line"],
                "binding_verified": not reason, "reviewer_identity_authenticated": False,
                "scope": "local-review-only; digest binds a view, not reviewer identity"}
            if reason:
                projected["reason"] = reason
                if len(unverified) < 128:
                    unverified.append(projected)
            else:
                verified += 1
                reviews = self.cases[reference[1]]["local_reviews"]
                if len(reviews) < 2:
                    reviews.append(projected)
                else:
                    verified_omitted += 1
                    self.cases[reference[1]]["local_reviews_omitted"] += 1
        partial = any(self.counts[key] for key in ("malformed_json", "invalid_records", "oversized_records",
            "truncated_records", "identity_conflicts", "case_overflow_records", "annotation_overflow_records"))
        partial |= any(self.limits.values()) or any(row["state"] != "read" for row in inputs)
        return {"schema": "angerona.live-debug.summary.v1", "advisory_only": True,
            "processing_complete": not partial, "evidence_continuity_complete": False,
            "continuity_assessment": "reported-gaps-or-unavailable-evidence" if partial or self.counts["gap_records"] or self.counts["inaccessible_records"]
                else "not-independently-verified",
            "security_conclusion": "Unknown. Zero events or missing evidence do not establish a clean host.",
            "automatic_response": False, "default_review_status": "needs-review", "max_severity": self.max_severity,
            "identity_reference_window": _REFERENCE_LIMIT,
            "occurrence_scope": "Deduplicated inside the retained identity window; older duplicates may recur.",
            "counts": dict(self.counts, verified_local_annotations=verified,
                verified_notes_omitted=verified_omitted,
                unverified_local_annotations=len(self.notes) - verified,
                unverified_notes_omitted=max(0, len(self.notes) - verified - len(unverified))),
            "limits_reached": dict(self.limits), "inputs": inputs,
            "cases": list(self.cases.values()), "unverified_local_notes": unverified,
            "review_policy": "Producer disposition and reviewer notes are separate claims; no alert or policy is changed."}


def summarize(paths, *, max_bytes=MAX_INPUT_BYTES, max_records=MAX_RECORDS, max_seconds=10.0,
              max_cases=MAX_CASES, monotonic=time.monotonic) -> dict:
    """Read only the selected captures; budgets apply across all input files."""
    if not 1 <= len(paths) <= 16:
        raise ValueError("Select between 1 and 16 JSONL captures")
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_INPUT_BYTES:
        raise ValueError("Input byte budget must be between 1 and 64 MiB")
    if type(max_records) is not int or not 1 <= max_records <= MAX_RECORDS:
        raise ValueError("Record budget must be between 1 and 100000")
    if type(max_seconds) not in (int, float) or not math.isfinite(max_seconds) or not 0 < max_seconds <= 60:
        raise ValueError("Time budget must be finite and between 0 and 60 seconds")
    summary, inputs = CaseSummary(max_cases), []
    deadline = monotonic() + max_seconds
    def remaining():
        if monotonic() >= deadline:
            summary.limits["time_budget_reached"] = True
        if summary.counts["bytes_read"] >= max_bytes:
            summary.limits["byte_budget_reached"] = True
        return max_bytes - summary.counts["bytes_read"] if not any(summary.limits.values()) else 0
    for number, value in enumerate(paths):
        if not remaining():
            break
        item = {"capture": number, "name": _text(Path(value).name, 160), "state": "unavailable"}
        inputs.append(item)
        try:
            path = _capture_path(value, ".jsonl")
            with _open_file(path) as (stream, before):
                line = 0
                while remaining():
                    if summary.counts["lines_read"] >= max_records:
                        summary.limits["record_budget_reached"] = True
                        break
                    raw = stream.readline(min(MAX_FRAME_BYTES + 1, remaining()))
                    summary.counts["bytes_read"] += len(raw)
                    if not raw:
                        break
                    line += 1
                    summary.counts["lines_read"] += 1
                    oversized = len(raw) > MAX_FRAME_BYTES
                    if oversized:
                        summary.counts["oversized_records"] += 1
                        while not raw.endswith(b"\n") and remaining():
                            raw = stream.readline(min(8192, remaining()))
                            summary.counts["bytes_read"] += len(raw)
                            if not raw:
                                break
                    if not raw.endswith(b"\n"):
                        summary.counts["truncated_records"] += 1
                        continue
                    if oversized:
                        continue
                    if not raw.strip():
                        summary.counts["blank_lines"] += 1
                        continue
                    try:
                        record = _decode(raw)
                    except SummaryError:
                        summary.counts["invalid_records"] += 1
                    except (ValueError, UnicodeError, RecursionError):
                        summary.counts["malformed_json"] += 1
                    else:
                        summary.consume(record, number, line)
                after = os.fstat(stream.fileno())
                item["state"] = "changed-during-read" if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) else "read"
        except Exception as exc:
            item["error_type"] = type(exc).__name__
            summary.counts["coverage_records"] += 1
            summary.counts["inaccessible_records"] += 1
            summary._case({"kind": "coverage", "source": f"selected-capture:{number}",
                "reason": "capture-unavailable", "state": "unavailable", "error_type": type(exc).__name__,
                "message": "Selected capture could not be read safely; its evidence remains unavailable."}, number, 0)
    for number in range(len(inputs), len(paths)):
        inputs.append({"capture": number, "name": _text(Path(paths[number]).name, 160), "state": "not-read-budget"})
    report = summary.report(inputs)
    report["counts"]["input_files_requested"] = len(paths)
    report["counts"]["input_files_read"] = sum(item["state"] == "read" for item in inputs)
    return report


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("captures", nargs="+", type=Path, help="Explicit local CLI .jsonl capture files")
    result.add_argument("--output", type=Path, help="Create a new caller-owned .json file; never overwrite")
    result.add_argument("--max-mib", type=int, choices=range(1, 65), default=64, metavar="1..64")
    result.add_argument("--max-records", type=int, default=MAX_RECORDS)
    result.add_argument("--max-seconds", type=float, default=10.0)
    result.add_argument("--max-cases", type=int, default=MAX_CASES)
    return result


def main(argv=None) -> int:
    arguments = parser().parse_args(argv)
    try:
        report = summarize(arguments.captures, max_bytes=arguments.max_mib * 1024 * 1024,
            max_records=arguments.max_records, max_seconds=arguments.max_seconds, max_cases=arguments.max_cases)
        raw = (json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n").encode("ascii")
        if arguments.output:
            output = _capture_path(arguments.output, ".json")
            with _open_file(output, write=True) as (stream, _info):
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        else:
            sys.stdout.write(raw.decode("ascii"))
        return 0 if report["processing_complete"] else 1
    except BrokenPipeError:
        return 0
    except Exception as exc:
        print(f"Summary failed: {type(exc).__name__}: {_text(str(exc))}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
