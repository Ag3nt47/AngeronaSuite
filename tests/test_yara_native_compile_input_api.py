"""Native prerequisites for an explicit control-only compilation-input recipe.

Each probe runs in one directly launched, retained interpreter process. Native
instances and traceback cleanup stay in that process. Pytest reads a bounded
plain result after retirement. The probes exercise no product capability.
"""
from __future__ import annotations

import hashlib
from importlib.metadata import distribution, version
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryFile
import time
import traceback
import weakref


_SOURCE_A = (
    b'rule AngeronaCompileInputProbe { strings: $m = "ANGERONA-INERT-INPUT-A" '
    b'condition: $m }'
)
_SOURCE_B = _SOURCE_A.replace(b"INPUT-A", b"INPUT-B")
_COMMENTED_SOURCE = "// contrôle inerte — entrée UTF-8\n".encode("utf-8") + _SOURCE_A
_MARKER_A = b"ANGERONA-INERT-INPUT-A"
_MARKER_B = b"ANGERONA-INERT-INPUT-B"
_SCANNER_OPTIONS = {"timeout_seconds": 2, "max_matches_per_pattern": 64,
                    "fast_scan": True}


_MAX_RESULT_BYTES = 8192


def _owner_case(case: str, tmp_path: Path) -> dict:
    """Run one closed probe and retire its original child even after timeout."""
    from beacon_native_fixture import OwnedChild, _physical_image

    assert case in _NATIVE_CASES
    interpreter = _physical_image()
    installed_site = Path(distribution("yara-x").locate_file("")).resolve(strict=True)
    script = Path(__file__).resolve(strict=True)
    # Use the current physical interpreter, not a Windows venv redirector.
    # -S avoids startup hooks. Add only the installed YARA distribution's site.
    bootstrap = (
        f"import runpy, sys; sys.path.append({str(installed_site)!r}); "
        f"runpy.run_path({str(script)!r}, run_name='__main__')"
    )
    with TemporaryFile("w+b", dir=tmp_path) as output:
        process = subprocess.Popen(
            [str(interpreter), "-I", "-B", "-S", "-c", bootstrap, "--native-case", case],
            stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        owner = OwnedChild(process, reader=False)
        try:
            owner.pin()
            if os.name == "nt":
                assert owner.identity["image"] == os.path.normcase(os.path.abspath(interpreter))
            # Release the worker only after pinning, even for the quick version probe.
            assert process.stdin is not None
            assert process.stdin.write(b"1") == 1
            process.stdin.close()
            exit_code = owner.wait(time.monotonic() + 15)
        finally:
            owner.retire(time.monotonic() + 5)
        assert exit_code == 0, f"native API worker exited with {exit_code}"
        output.seek(0)
        raw = output.read(_MAX_RESULT_BYTES + 1)
    assert 0 < len(raw) <= _MAX_RESULT_BYTES, "native API result is missing or oversized"
    assert raw.endswith(b"\n") and raw.count(b"\n") == 1, "expected one native API result"
    row = json.loads(raw)
    assert type(row) is dict and row.get("case") == case
    assert row.get("ok") is True, row
    assert set(row) == {"case", "ok", "observation"} and type(row["observation"]) is dict
    return row["observation"]


def _compile_scan_summary(source_snapshot: bytes, payloads: tuple[bytes, ...]) -> dict:
    """Exercise actual API input/output; this helper issues no authority."""
    import yara_x

    rules = scanner = result = None
    try:
        assert type(source_snapshot) is bytes and 0 < len(source_snapshot) <= 4096
        source = source_snapshot.decode("utf-8", errors="strict")
        rules = yara_x.compile(source)
        assert type(rules) is yara_x.Rules
        scanner = yara_x.Scanner(rules)
        assert type(scanner) is yara_x.Scanner
        scanner.set_timeout(_SCANNER_OPTIONS["timeout_seconds"])
        scanner.max_matches_per_pattern(_SCANNER_OPTIONS["max_matches_per_pattern"])
        scanner.fast_scan(_SCANNER_OPTIONS["fast_scan"])
        matches = []
        for payload in payloads:
            result = scanner.scan(payload)
            assert type(result) is yara_x.ScanResults
            matches.append([str(rule.identifier) for rule in result.matching_rules])
            result = None
        recipe = {"binding": "canonical-yara-compile-input-v1",
                  "compile_input_sha256": hashlib.sha256(source_snapshot).hexdigest(),
                  "compile_api": "yara_x.compile", "compiler_options": {},
                  "scanner_options": dict(_SCANNER_OPTIONS),
                  "native_version": version("yara-x")}
        return {"recipe": recipe, "matches": matches,
                "rules_type": type(rules).__name__,
                "scanner_type": type(scanner).__name__}
    finally:
        result = scanner = rules = None


def _version_case() -> dict:
    return {"native_version": version("yara-x")}


def _compile_snapshot_case() -> dict:
    return _compile_scan_summary(_SOURCE_A, (_MARKER_A, _MARKER_B, b""))


def _changed_input_case() -> dict:
    return {"first": _compile_scan_summary(_SOURCE_A, (_MARKER_A, _MARKER_B)),
            "second": _compile_scan_summary(_SOURCE_B, (_MARKER_A, _MARKER_B))}


def _utf8_input_case() -> dict:
    return {"plain": _compile_scan_summary(_SOURCE_A, (_MARKER_A, _MARKER_B)),
            "commented": _compile_scan_summary(_COMMENTED_SOURCE, (_MARKER_A, _MARKER_B))}


def _compile_error_case() -> dict:
    failure = None
    try:
        _compile_scan_summary(b"rule Broken { condition: }", (_MARKER_A,))
    except Exception as exc:
        failure = {"type": type(exc).__name__, "message": str(exc)[:300]}
        traceback.clear_frames(exc.__traceback__)
        exc.__traceback__ = None
    assert failure is not None, "invalid rule unexpectedly compiled"
    return {"failure": failure,
            "fresh": _compile_scan_summary(_SOURCE_A, (_MARKER_A,))}


def _retained_traceback_case() -> dict:
    def fail_after_native_result(native_result) -> None:
        assert native_result.matching_rules
        raise RuntimeError("inert native result extraction failure")

    import yara_x

    rules = scanner = result = retained = None
    result_reference = None
    try:
        rules = yara_x.compile(_SOURCE_A.decode("utf-8", errors="strict"))
        scanner = yara_x.Scanner(rules)
        scanner.set_timeout(_SCANNER_OPTIONS["timeout_seconds"])
        scanner.max_matches_per_pattern(_SCANNER_OPTIONS["max_matches_per_pattern"])
        scanner.fast_scan(_SCANNER_OPTIONS["fast_scan"])
        result = scanner.scan(_MARKER_A)
        assert type(result) is yara_x.ScanResults
        try:
            result_reference = weakref.ref(result)
        except TypeError:
            pass
        try:
            fail_after_native_result(result)
        except RuntimeError as exc:
            retained = exc
        assert retained is not None and retained.__traceback__ is not None
        result = scanner = rules = None
        traceback.clear_frames(retained.__traceback__)
        cursor = retained.__traceback__
        cleared = False
        while cursor is not None:
            if cursor.tb_frame.f_code is fail_after_native_result.__code__:
                assert cursor.tb_frame.f_locals == {}
                cleared = True
            cursor = cursor.tb_next
        assert cleared
        retained.__traceback__ = None
        message = str(retained)
        retained = None
        if result_reference is not None:
            assert result_reference() is None
        return {"failure": message, "native_callback_frame_cleared": True,
                "scan_result_weakref_supported": result_reference is not None}
    finally:
        result = scanner = rules = retained = None


_NATIVE_CASES = {
    "version": _version_case,
    "compile-snapshot": _compile_snapshot_case,
    "changed-input": _changed_input_case,
    "utf8-input": _utf8_input_case,
    "compile-error": _compile_error_case,
    "retained-traceback": _retained_traceback_case,
}


def _run_native_case() -> None:
    if len(sys.argv) != 3 or sys.argv[1] != "--native-case" or sys.argv[2] not in _NATIVE_CASES:
        raise SystemExit("expected one known native API case")
    case = sys.argv[2]
    if sys.stdin.buffer.read(1) != b"1":
        raise SystemExit("native API worker was not released")
    try:
        row = {"case": case, "ok": True, "observation": _NATIVE_CASES[case]()}
        result = json.dumps(row, allow_nan=False).encode("ascii") + b"\n"
        if len(result) > _MAX_RESULT_BYTES:
            raise AssertionError("native API observation exceeded 8 KiB")
    except BaseException as exc:
        row = {"case": case, "ok": False, "error_type": type(exc).__name__,
               "error": str(exc)[:600]}
        traceback.clear_frames(exc.__traceback__)
        exc.__traceback__ = None
        result = json.dumps(row, allow_nan=False).encode("ascii") + b"\n"
    assert len(result) <= _MAX_RESULT_BYTES
    sys.stdout.buffer.write(result)


def test_native_compile_input_api_uses_current_release_pin(record_property, tmp_path) -> None:
    root = next(parent for parent in Path(__file__).resolve().parents
                if (parent / "constraints-release.txt").is_file()
                and (parent / "pyproject.toml").is_file())
    pin = re.search(r"(?m)^yara-x==([^\s;]+)\s*$",
                    (root / "constraints-release.txt").read_text(encoding="utf-8"))
    assert pin is not None
    row = _owner_case("version", tmp_path)
    record_property("yara_x_release_pin", pin.group(1))
    record_property("yara_x_observed_version", row["native_version"])
    assert row["native_version"] == pin.group(1)


def test_native_compile_snapshot_constructs_exact_types_and_positive_negative_scans(record_property, tmp_path) -> None:
    row = _owner_case("compile-snapshot", tmp_path)
    assert row["matches"] == [["AngeronaCompileInputProbe"], [], []]
    assert row["recipe"]["compile_input_sha256"] == hashlib.sha256(_SOURCE_A).hexdigest()
    record_property("yara_compile_input_native_api", json.dumps(row, sort_keys=True))


def test_changed_compilation_input_changes_digest_and_actual_matching_behavior(tmp_path) -> None:
    row = _owner_case("changed-input", tmp_path)
    assert row["first"]["matches"] == [["AngeronaCompileInputProbe"], []]
    assert row["second"]["matches"] == [[], ["AngeronaCompileInputProbe"]]
    assert (row["first"]["recipe"]["compile_input_sha256"]
            != row["second"]["recipe"]["compile_input_sha256"])


def test_utf8_snapshot_digest_honestly_binds_input_even_for_same_semantics(record_property, tmp_path) -> None:
    # An input hash must not be described as a fingerprint of compiled output.
    row = _owner_case("utf8-input", tmp_path)
    assert row["plain"]["matches"] == row["commented"]["matches"]
    assert (row["plain"]["recipe"]["compile_input_sha256"]
            != row["commented"]["recipe"]["compile_input_sha256"])
    record_property("yara_utf8_compile_input_bytes", len(_COMMENTED_SOURCE))


def test_real_compile_error_is_cleaned_on_owner_before_fresh_compilation(record_property, tmp_path) -> None:
    row = _owner_case("compile-error", tmp_path)
    assert row["fresh"]["matches"] == [["AngeronaCompileInputProbe"]]
    record_property("yara_real_compile_error", json.dumps(row["failure"], sort_keys=True))


def test_real_scan_result_in_retained_traceback_is_detached_on_owner(record_property, tmp_path) -> None:
    row = _owner_case("retained-traceback", tmp_path)
    assert row["failure"] == "inert native result extraction failure"
    record_property("yara_native_traceback_cleanup", json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    _run_native_case()
