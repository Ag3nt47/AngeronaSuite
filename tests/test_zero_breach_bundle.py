"""Offline integrity and attribution checks without importing third-party code."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import stat
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "assets/integrations/zero_breach"
ENGINE_SIZE = 968_987
ENGINE_SHA256 = "075b2a0ac20f285fa4385d6b6c5cda2cedd410364c4f4686db3c1b8b033265d3"
COMMIT = "81bd556ba604685dbd1c0ecb48138c10f43cccf8"
REQUIRED = {
    "engine.py", "LICENSE", "NOTICE", "PRIVACY.md", "iocs/LICENSE.md",
    "third_party/candiru/README.md", "third_party/candiru/LICENSE-DRL-1.1.txt",
    "third_party/candiru/LICENSE-CC-BY-SA-4.0.txt", "third_party/candiru/PROVENANCE.json",
    "third_party/candiru/apt_candiru.yar", "third_party/candiru/win_devilstongue_auto.yar",
    "verification/SHA256SUMS.txt", "verification/SHA256SUMS.txt.asc",
    "verification/zero-breach-toolkit.py.asc", "verification/archivegenocide-signing-key.asc",
}


def catalog():
    return json.loads((BUNDLE / "catalog.json").read_bytes())


def test_curated_engine_matches_independent_stable_release_pin():
    data = catalog()
    raw = (BUNDLE / "engine.py").read_bytes()
    assert len(raw) == ENGINE_SIZE
    assert hashlib.sha256(raw).hexdigest() == ENGINE_SHA256
    assert data["schema"] == 1
    assert data["tool_id"] == "zero-breach"
    assert data["version"] == "0.1.10"
    assert data["commit"] == COMMIT
    assert data["repository"] == "https://github.com/interplains/Zero-Breach-Toolkit"
    assert data["artifact"]["bytes"] == data["artifact"]["size"] == ENGINE_SIZE
    assert data["artifact"]["sha256"] == ENGINE_SHA256
    assert data["artifact"]["release_asset_id"] == 686634209
    checksums = (BUNDLE / "verification/SHA256SUMS.txt").read_text(encoding="utf-8")
    assert ENGINE_SHA256 + "  zero-breach-toolkit.py" in checksums
    assert data["integration"]["engine_modified"] is False


def test_catalog_inventory_preserves_plain_pinned_license_and_provenance_bytes():
    rows = catalog()["files"]
    assert len(rows) == len(REQUIRED) == 15
    assert {row["path"] for row in rows} == REQUIRED
    assert sum(row["bytes"] for row in rows) <= 2 * 1024 * 1024
    for row in rows:
        relative = Path(row["path"])
        assert not relative.is_absolute() and not any(part in {"", ".", ".."} for part in relative.parts)
        path = BUNDLE / relative
        info = path.lstat()
        assert stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode)
        assert info.st_nlink == 1 and not getattr(info, "st_file_attributes", 0) & 0x400
        raw = path.read_bytes()
        assert len(raw) == row["bytes"]
        assert hashlib.sha256(raw).hexdigest() == row["sha256"]
        if "git_blob_sha1" in row:
            assert hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest() == row["git_blob_sha1"]
        source = urlsplit(row["source_url"])
        assert source.scheme == "https" and source.username is source.password is None
        assert source.hostname in {"github.com", "raw.githubusercontent.com"}
        if source.hostname == "raw.githubusercontent.com":
            assert source.path.startswith("/interplains/Zero-Breach-Toolkit/" + COMMIT + "/")
        else:
            assert source.path.startswith("/interplains/Zero-Breach-Toolkit/releases/download/v0.1.10/")


def test_embedded_optional_rules_and_match_authorship_are_retained_verbatim():
    # Literal parsing inspects the source; it does not import or execute it.
    tree = ast.parse((BUNDLE / "engine.py").read_bytes())
    values = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {"CANDIRU_RULE_SOURCES", "CANDIRU_RULE_METADATA"}:
                    values[target.id] = ast.literal_eval(node.value)
    provenance = json.loads((BUNDLE / "third_party/candiru/PROVENANCE.json").read_bytes())
    rules = provenance["rules"]
    assert len(values["CANDIRU_RULE_SOURCES"]) == len(rules) == 2
    for source, expected in zip(values["CANDIRU_RULE_SOURCES"], rules):
        raw = (BUNDLE / "third_party/candiru" / expected["filename"]).read_bytes()
        assert source.encode("utf-8") == raw
        assert hashlib.sha256(raw).hexdigest() == provenance["files_sha256"][expected["filename"]]
        assert values["CANDIRU_RULE_METADATA"][expected["identifier"]] == expected
        assert expected["author"] in source
    notice = (BUNDLE / "NOTICE").read_text(encoding="utf-8")
    assert "Microsoft Threat Intelligence Center" in notice
    assert "Felix Bilstein" in notice
    assert "NOT AFFILIATED, NOT ENDORSED" in notice
    assert "messages based on" in (BUNDLE / "third_party/candiru/LICENSE-DRL-1.1.txt").read_text(encoding="utf-8")
    credits = catalog()["credits"]
    assert {entry["license"] for entry in credits} == {"Apache-2.0", "CC0-1.0", "DRL-1.1", "CC-BY-SA-4.0"}
    assert all(entry["match_attribution_required"] for entry in credits if entry["license"] in {"DRL-1.1", "CC-BY-SA-4.0"})


def test_public_signing_material_does_not_claim_unestablished_key_trust():
    signature = catalog()["signature"]
    assert signature["independent_key_trust_verified"] is False
    assert signature["signatures_verified"] is False
    assert signature["published_fingerprint"] == "C24E C92B 12D6 670A 2516 065F 9B4D 5754 99AF A53C"
    assert b"BEGIN PGP PUBLIC KEY BLOCK" in (BUNDLE / "verification/archivegenocide-signing-key.asc").read_bytes()
    for name in ("SHA256SUMS.txt.asc", "zero-breach-toolkit.py.asc"):
        assert b"BEGIN PGP SIGNATURE" in (BUNDLE / "verification" / name).read_bytes()
