import io
import zipfile

import pytest

from angerona.core.sigma_engine import load_rules
from angerona.modules.soar_engine import ActiveResponseSOAR
from angerona.shark.shark_attack import EICAR_MARKER, _file_has_marker


pytest.importorskip("yaml")


def test_sigma_yaml_import_accepts_bounded_plain_documents():
    rules = load_rules(
        """
title: Safe process rule
detection:
  selection:
    image|endswith: safe.exe
  condition: selection
---
title: Safe network rule
detection:
  selection:
    destination_port: 443
  condition: selection
"""
    )
    assert [rule["title"] for rule in rules] == [
        "Safe process rule",
        "Safe network rule",
    ]


@pytest.mark.parametrize(
    "document",
    (
        "base: &base [one, two]\ncopy: *base\n",
        "value: .nan\n",
        "timestamp: 2026-07-29\n",
        f"value: {'x' * 4097}\n",
    ),
)
def test_sigma_yaml_import_rejects_aliases_nonfinite_types_and_oversize(document):
    assert load_rules(document) == []


def _zip_bytes(*, marker: bytes, unsafe: bool = False) -> io.BytesIO:
    memory = io.BytesIO()
    with zipfile.ZipFile(memory, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("shipping_label.txt", marker)
        if unsafe:
            archive.writestr("COM1.log", b"unsafe alias")
    memory.seek(0)
    return memory


def test_drill_marker_zip_readers_prevalidate_before_trusting_content(tmp_path):
    marker = f"{EICAR_MARKER} :: Angerona Shark Attack drill sample".encode(
        "ascii"
    )
    safe = tmp_path / "safe.zip"
    safe.write_bytes(_zip_bytes(marker=marker).read())
    assert _file_has_marker(safe)
    assert ActiveResponseSOAR._is_known_drill_artifact(safe)

    unsafe = tmp_path / "unsafe.zip"
    unsafe.write_bytes(_zip_bytes(marker=marker, unsafe=True).read())
    assert not _file_has_marker(unsafe)
    assert not ActiveResponseSOAR._is_known_drill_artifact(unsafe)
