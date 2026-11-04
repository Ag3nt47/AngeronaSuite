"""Pure original-code recovery derivation; fixture source bytes never execute.

The one reference test calls the existing reviewed generator on inert private
files. All other tests pass concrete byte dictionaries to the pure helper.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import MappingProxyType

import pytest

from angerona.core import startup_recovery as recovery
from test_startup_recovery_bundle import BUILDER


ROOT = Path(__file__).resolve().parents[1]
_FIELDS = (("manifestSha", 64, b"a"), ("manifestBlob", 40, b"b"),
           ("verifierSha", 64, b"c"), ("verifierBlob", 40, b"d"))
_MARKER = b":__ANGERONA_PINNED_BOOTSTRAP__"


def _encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def _batch():
    lines = [b"@echo off\r\n", b"rem custom source launcher remains byte-identical\r\n", _MARKER + b"\r\n"]
    lines += [b"$" + name.encode() + b"='" + digit * width + b"'\r\n"
              for name, width, digit in _FIELDS]
    lines += [b"$manifestShaExtra='custom-control-not-a-pin'\r\n",
              b"# literal $manifestSha='" + b"a" * 64 + b"' must remain unchanged\r\n",
              b"function CustomControl { Write-Output 'private local choice' }\r\n"]
    return b"".join(lines)


def _expected_batch(original, values):
    # Fixture ground truth uses complete literal lines. The comment containing
    # an identical hash assignment substring is deliberately NOT a slot.
    substitutions = {
        b"$" + name.encode() + b"='" + digit * width + b"'\r\n":
        b"$" + name.encode() + b"='" + values[name] + b"'\r\n"
        for name, width, digit in _FIELDS
    }
    return b"".join(substitutions.get(line, line) for line in original.splitlines(keepends=True))


def _tree():
    names = recovery.RECOVERY_COHERENCE_FILES
    tree = {name: ("# inert file: " + name + "\n").encode() for name in names}
    entries = [{"path": name, "bytes": 0, "sha256": "0" * 64, "git_blob_sha1": "0" * 40}
               for name in names]
    # This is recognizable STALE metadata, not an assertion of source hashes.
    tree[recovery.RECOVERY_MANIFEST_PATH] = _encoded({"schema": 1,
        "repository": "Ag3nt47/AngeronaSuite", "canonical_text": "utf8-lf-no-bom", "files": entries})
    members = [b"    '" + name.encode() + b"'" + (b"," if index + 1 < len(names) else b"")
               for index, name in enumerate(names)]
    tree[recovery.RECOVERY_VERIFIER_PATH] = b"$script:BundleFiles = @(\n" + b"\n".join(members) + b"\n)\n# custom verifier text\n"
    tree[recovery.RECOVERY_BATCH_PATH] = _batch()
    tree["custom-local.py"] = b"# keep this local file exactly\n"
    return tree


def test_pure_derivation_matches_actual_reviewed_generator_and_preserves_raw_custom_source(tmp_path):
    tree = _tree()
    assert tuple(BUILDER.FILES) == recovery.RECOVERY_COHERENCE_FILES
    # Also exercise the actual current verifier declaration, not just a test list.
    tree[recovery.RECOVERY_VERIFIER_PATH] = (ROOT / BUILDER.VERIFIER).read_bytes()
    sample = recovery.RECOVERY_COHERENCE_FILES[0]
    tree[sample] = b"\xef\xbb\xbf# inert BOM and CRLF content\r\n# retained raw bytes\r\n"
    before = dict(tree)
    reference = tmp_path / "reference"
    for name in (*BUILDER.FILES, BUILDER.VERIFIER):
        path = reference / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(tree[name])
    expected, pins = BUILDER.build_manifest(reference)
    effective, proof = recovery.derive_recovery_coherent_tree(tree)
    values = {"manifestSha": pins["manifest_sha256"].encode(),
              "manifestBlob": pins["manifest_blob_sha1"].encode(),
              "verifierSha": pins["verifier_sha256"].encode(),
              "verifierBlob": pins["verifier_blob_sha1"].encode()}
    assert effective[recovery.RECOVERY_MANIFEST_PATH] == expected
    assert effective[recovery.RECOVERY_BATCH_PATH] == _expected_batch(_batch(), values)
    assert tree == before and set(effective) == set(tree)
    generated = {recovery.RECOVERY_MANIFEST_PATH, recovery.RECOVERY_BATCH_PATH}
    assert all(effective[name] is tree[name] for name in tree if name not in generated)
    assert proof["profile"] == "angerona-operational39/v1" and proof["schema"] == 1
    assert set(proof["generated_files"]) == generated
    assert set(proof["derived_paths"]) == generated
    for name in generated:
        assert proof["generated_files"][name] == {
            "sha256": hashlib.sha256(effective[name]).hexdigest(), "bytes": len(effective[name])}
    assert proof["candidate_code_executed"] is False
    assert recovery.verify_recovery_coherence(effective)["derived_paths"] == []


def test_derivation_is_idempotent_and_changed_operational_bytes_require_new_manifest_and_pins():
    first, _ = recovery.derive_recovery_coherent_tree(_tree())
    again, proof = recovery.derive_recovery_coherent_tree(first)
    assert again == first and proof["derived_paths"] == []
    changed = dict(first)
    changed[recovery.RECOVERY_COHERENCE_FILES[0]] += b"# changed effective source\n"
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.verify_recovery_coherence(changed)
    second, after = recovery.derive_recovery_coherent_tree(changed)
    assert second[recovery.RECOVERY_MANIFEST_PATH] != first[recovery.RECOVERY_MANIFEST_PATH]
    assert second[recovery.RECOVERY_BATCH_PATH] != first[recovery.RECOVERY_BATCH_PATH]
    assert after["verifier_sha256"] == proof["verifier_sha256"]
    assert after["manifest_sha256"] != proof["manifest_sha256"]
    assert recovery.verify_recovery_coherence(second)["derived_paths"] == []
    assert changed[recovery.RECOVERY_MANIFEST_PATH] == first[recovery.RECOVERY_MANIFEST_PATH]


def test_mask_and_restore_change_only_four_values_and_never_copy_reference_controls():
    original = _batch()
    masked = recovery.mask_recovery_batch_pins(original)
    assert masked == _expected_batch(original, {name: b"0" * width for name, width, _ in _FIELDS})
    assert len(masked) == len(original)
    reference_values = {name: str(index + 1).encode() * width
                        for index, (name, width, _) in enumerate(_FIELDS)}
    reference = _expected_batch(original, reference_values).replace(b"custom source launcher", b"different reference controls")
    restored = recovery.restore_recovery_batch_pins(masked, reference)
    assert restored == _expected_batch(original, reference_values)
    assert b"different reference controls" not in restored
    assert b"custom-control-not-a-pin" in restored
    assert b"# literal $manifestSha='" + b"a" * 64 in restored
    assert original == _batch()


@pytest.mark.parametrize("change", ["missing-marker", "two-markers", "missing-pin", "duplicate-pin",
    "before-marker", "indent", "spaces", "double-quotes", "uppercase", "short", "expression", "comment",
    "invalid-utf8", "nul", "lone-cr", "nonbytes"])
def test_unknown_batch_declarations_are_held_instead_of_overwriting_custom_controls(change):
    raw = _batch()
    line = b"$manifestSha='" + b"a" * 64 + b"'\r\n"
    if change == "missing-marker":
        raw = raw.replace(_MARKER, b":custom-marker")
    elif change == "two-markers":
        raw += _MARKER + b"\n"
    elif change == "missing-pin":
        raw = raw.replace(line, b"")
    elif change == "duplicate-pin":
        raw += line
    elif change == "before-marker":
        raw = line + raw.replace(line, b"")
    elif change == "indent":
        raw = raw.replace(line, b" " + line)
    elif change == "spaces":
        raw = raw.replace(line, line.replace(b"=", b" = "))
    elif change == "double-quotes":
        raw = raw.replace(line, line.replace(b"'", b'"'))
    elif change == "uppercase":
        raw = raw.replace(line, line.replace(b"a" * 64, b"A" * 64))
    elif change == "short":
        raw = raw.replace(line, line.replace(b"a" * 64, b"a" * 63))
    elif change == "expression":
        raw = raw.replace(line, b"$manifestSha=(Get-UnapprovedValue)\r\n")
    elif change == "comment":
        raw = raw.replace(line, line.rstrip(b"\r\n") + b" # unknown syntax\r\n")
    elif change == "invalid-utf8":
        raw += b"\xff"
    elif change == "nul":
        raw += b"\x00"
    elif change == "lone-cr":
        raw += b"bad\rtext"
    else:
        raw = bytearray(raw)
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.mask_recovery_batch_pins(raw)
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.restore_recovery_batch_pins(_batch(), raw)


@pytest.mark.parametrize("change", ["schema-bool", "repository", "extra-root", "missing-row", "order",
    "path", "duplicate-path", "bytes-bool", "bytes-negative", "hash", "blob", "extra-row-key",
    "aggregate", "pretty", "duplicate-root-key", "duplicate-row-key", "oversize", "invalid-utf8"])
def test_manifest_profile_rejects_unknown_metadata_instead_of_treating_it_as_generated(change):
    raw = _tree()[recovery.RECOVERY_MANIFEST_PATH]
    value = json.loads(raw)
    if change == "schema-bool":
        value["schema"] = True
    elif change == "repository":
        value["repository"] = "unapproved/project"
    elif change == "extra-root":
        value["unapproved"] = True
    elif change == "missing-row":
        value["files"].pop()
    elif change == "order":
        value["files"].reverse()
    elif change == "path":
        value["files"][0]["path"] = "../unknown.py"
    elif change == "duplicate-path":
        value["files"][1]["path"] = value["files"][0]["path"]
    elif change == "bytes-bool":
        value["files"][0]["bytes"] = False
    elif change == "bytes-negative":
        value["files"][0]["bytes"] = -1
    elif change == "hash":
        value["files"][0]["sha256"] = "A" * 64
    elif change == "blob":
        value["files"][0]["git_blob_sha1"] = "0" * 39
    elif change == "extra-row-key":
        value["files"][0]["unapproved"] = True
    elif change == "aggregate":
        for row in value["files"][:17]:
            row["bytes"] = 2 * 1024**2
    if change == "pretty":
        raw = json.dumps(value, indent=2).encode()
    elif change == "duplicate-root-key":
        raw = raw[:-2] + b',"schema":1}\n'
    elif change == "duplicate-row-key":
        raw = raw.replace(b'"bytes":0', b'"bytes":0,"bytes":0', 1)
    elif change == "oversize":
        raw += b" " * (128 * 1024 + 1)
    elif change == "invalid-utf8":
        raw = b"\xff"
    else:
        raw = _encoded(value)
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.validate_recovery_manifest_profile(raw)


def test_manifest_profile_accepts_known_stale_hashes_and_builder_canonical_newline_forms():
    raw = _tree()[recovery.RECOVERY_MANIFEST_PATH]
    assert recovery.validate_recovery_manifest_profile(raw) is None
    assert recovery.validate_recovery_manifest_profile(b"\xef\xbb\xbf" + raw.replace(b"\n", b"\r\n")) is None


@pytest.mark.parametrize("kind", ["mapping-proxy", "dict-subclass", "too-many"])
def test_derivation_requires_bounded_concrete_dictionary(kind):
    tree = _tree()
    if kind == "mapping-proxy":
        tree = MappingProxyType(tree)
    elif kind == "dict-subclass":
        class ForeignTree(dict):
            pass
        tree = ForeignTree(tree)
    else:
        tree.update({"extra-" + str(number): b"" for number in range(8193)})
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.derive_recovery_coherent_tree(tree)


@pytest.mark.parametrize("which", ["operation", "manifest", "verifier", "batch"])
def test_missing_supported_member_never_yields_partial_generated_output(which):
    tree = _tree()
    name = {"operation": recovery.RECOVERY_COHERENCE_FILES[0], "manifest": recovery.RECOVERY_MANIFEST_PATH,
            "verifier": recovery.RECOVERY_VERIFIER_PATH, "batch": recovery.RECOVERY_BATCH_PATH}[which]
    del tree[name]
    before = dict(tree)
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.derive_recovery_coherent_tree(tree)
    assert tree == before


@pytest.mark.parametrize("raw", ["not bytes", bytearray(b"no"), b"\xff", b"bad\0text", b"bad\rtext", b"x" * (2 * 1024**2 + 1)],
                         ids=["string", "bytearray", "invalid-utf8", "nul", "lone-cr", "oversize"])
def test_unsupported_member_text_or_size_never_mutates_input(raw):
    tree = _tree()
    tree[recovery.RECOVERY_COHERENCE_FILES[0]] = raw
    before = dict(tree)
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.derive_recovery_coherent_tree(tree)
    assert tree == before


def test_actual_member_byte_sum_is_bounded_without_allocating_unbounded_duplicate_payloads():
    tree = _tree()
    bounded = b"x" * (2 * 1024**2)
    for name in recovery.RECOVERY_COHERENCE_FILES[:17]:
        tree[name] = bounded
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.derive_recovery_coherent_tree(tree)


@pytest.mark.parametrize("change", ["different-member", "duplicate-header", "missing-close", "computed-member"])
def test_unknown_verifier_member_contract_is_held(change):
    tree = _tree()
    raw = tree[recovery.RECOVERY_VERIFIER_PATH]
    if change == "different-member":
        raw = raw.replace(recovery.RECOVERY_COHERENCE_FILES[0].encode(), b"unknown.py", 1)
    elif change == "duplicate-header":
        raw += raw
    elif change == "missing-close":
        raw = raw.replace(b"\n)\n", b"\n")
    else:
        raw = raw.replace(b"    'Repair-Angerona-Python.ps1',", b"    (Get-UnapprovedPath),")
    tree[recovery.RECOVERY_VERIFIER_PATH] = raw
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.derive_recovery_coherent_tree(tree)


@pytest.mark.parametrize("target", ["manifest", "batch"])
def test_verification_detects_generated_metadata_or_pin_tampering(target):
    tree, _ = recovery.derive_recovery_coherent_tree(_tree())
    if target == "manifest":
        value = json.loads(tree[recovery.RECOVERY_MANIFEST_PATH])
        value["files"][0]["sha256"] = "0" * 64
        tree[recovery.RECOVERY_MANIFEST_PATH] = _encoded(value)
    else:
        before = tree[recovery.RECOVERY_BATCH_PATH]
        name, width, _ = _FIELDS[0]
        start = before.index(b"$" + name.encode() + b"='") + len(name) + 3
        tree[recovery.RECOVERY_BATCH_PATH] = before[:start] + b"0" * width + before[start + width:]
    with pytest.raises(recovery.RecoveryCoherenceError):
        recovery.verify_recovery_coherence(tree)


def test_candidate_program_bytes_are_hashed_without_import_exec_or_side_effects(tmp_path):
    tree = _tree()
    sentinel = tmp_path / "candidate-code-must-not-run"
    payload = ("from pathlib import Path\nPath(" + repr(str(sentinel)) + ").write_text('bad')\n"
               "raise RuntimeError('candidate program executed')\n").encode()
    tree["src/angerona/__main__.py"] = payload
    tree["tools/build_startup_recovery_manifest.py"] = payload
    tree["tools/update_startup_bootstrap.py"] = payload
    before = dict(tree)
    effective, proof = recovery.derive_recovery_coherent_tree(tree)
    assert not sentinel.exists() and proof["candidate_code_executed"] is False
    assert tree == before and effective["src/angerona/__main__.py"] is payload
    assert effective["tools/build_startup_recovery_manifest.py"] is payload
    assert recovery.verify_recovery_coherence(effective)["candidate_code_executed"] is False


@pytest.mark.parametrize("kind", ["nonstring-key", "extra-nonbytes", "extra-file-bound", "tree-byte-bound"])
def test_unselected_source_entries_still_obey_whole_tree_type_and_byte_limits(kind):
    tree = _tree()
    if kind == "nonstring-key":
        tree[True] = b"not a source path"
    elif kind == "extra-nonbytes":
        tree["custom-local.py"] = "not immutable file bytes"
    elif kind == "extra-file-bound":
        tree["custom-large.bin"] = b"x" * (16 * 1024**2 + 1)
    else:
        # Logical budget coverage without allocating17 separate16MiB buffers.
        bounded = b"x" * (16 * 1024**2)
        tree.update({"custom-block-" + str(index): bounded for index in range(17)})
    before = dict(tree)
    with pytest.raises(recovery.RecoveryCoherenceError, match="source tree exceeds its byte/type bounds"):
        recovery.derive_recovery_coherent_tree(tree)
    assert tree == before


def test_generated_growth_is_reserved_even_when_original_tree_is_exactly_at_byte_limit():
    tree = _tree()
    limit, block_size = 256 * 1024**2, 16 * 1024**2
    remaining = limit - sum(len(raw) for raw in tree.values())
    shared = b"x" * block_size
    whole, tail = divmod(remaining, block_size)
    tree.update({"retained-block-" + str(index): shared for index in range(whole)})
    if tail:
        tree["retained-tail"] = b"x" * tail
    assert sum(len(raw) for raw in tree.values()) == limit
    # Actual known member sizes need more decimal digits than the recognizable
    # stale zero-byte profile; hashes and four pins retain their fixed widths.
    with pytest.raises(recovery.RecoveryCoherenceError, match="Derived effective source tree exceeds its byte limit"):
        recovery.derive_recovery_coherent_tree(tree)
