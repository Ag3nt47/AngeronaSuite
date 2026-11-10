"""Refresh current workflows, reviewed DEMO figures and interface references.

Uses the retained manual and managed python-docx runtime. It neither imports
Angerona nor reads host preferences. Run only after public assets and source
references are frozen, then render and visually verify the resulting document.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
from io import BytesIO
import json
from zipfile import ZipFile

from docx import Document
from docx.oxml.ns import qn

import update_master_manual_display_recovery_115 as recovery
import update_master_manual_operator_115 as base


def _load_with_reviewed_figures():
    """Replace the four previously named DEMOs before python-docx loads them."""
    stream = BytesIO()
    required = {"word/media/" + leaf for leaf, _description in base.DEMOS[:-1]}
    reviewed = {"word/media/" + leaf: path for leaf, path in base.DEMO_PATHS.items()}
    with ZipFile(base.MANUAL) as original, ZipFile(stream, "w", compression=8) as updated:
        assert required <= set(original.namelist()), "Retained DEMO figure names changed"
        for item in original.infolist():
            data = original.read(item.filename)
            if item.filename in reviewed:
                data = reviewed[item.filename].read_bytes()
            updated.writestr(item, data)
    stream.seek(0)
    return Document(stream)


def _workflow_nodes(doc):
    generated = Document()
    base.add_workflows(generated)
    base.style_document(generated)
    next_id = max((int(node.get("id", "0")) for node in doc._element.iter(qn("wp:docPr"))), default=0)
    nodes = [deepcopy(node) for node in generated._element.body if node.tag != qn("w:sectPr")]
    for node in nodes:
        for link in node.iter(qn("w:hyperlink")):
            relation = generated.part.rels[link.get(qn("r:id"))]
            assert relation.is_external and relation.target_ref.startswith("https://")
            link.set(qn("r:id"), doc.part.relate_to(relation.target_ref, relation.reltype, is_external=True))
        for image in node.iter(qn("a:blip")):
            image_id = image.get(qn("r:embed"))
            assert image_id is not None and image.get(qn("r:link")) is None
            part = generated.part.related_parts[image_id]
            destination_id, _image = doc.part.get_or_add_image(BytesIO(part.blob))
            image.set(qn("r:embed"), destination_id)
        for properties in node.iter(qn("wp:docPr")):
            next_id += 1
            properties.set("id", str(next_id))
    return nodes


def main():
    summary_before = hashlib.sha256(base.SUMMARY.read_bytes()).hexdigest()
    doc = _load_with_reviewed_figures()
    assert any(paragraph.text == base.MARKER for paragraph in doc.paragraphs)
    nodes = _workflow_nodes(doc)
    base.take_block(doc, base.MARKER)
    modules = [paragraph for paragraph in doc.paragraphs
               if paragraph.style.name == "Heading 1" and paragraph.text == "18 Complete module reference"]
    assert len(modules) == 1
    for node in nodes:
        modules[0]._p.addprevious(node)
    count = recovery.refresh_controls(doc)
    history = [paragraph for paragraph in doc.paragraphs
               if paragraph.text.startswith("Added the current community tool hub,")]
    assert len(history) == 1
    addition = (
        " Later presentation maintenance added function accents, compact expandable setup, "
        "primary scan observations and the single dashboard action row with fixed STOP. "
        "Separate-tool startup now shares a cooperative source-check deadline and preserves "
        "known negative integrity findings. Scoped fixture and native tool-launch checks do "
        "not establish a fresh Core, completed host scan or real-world detection rate."
    )
    if addition not in history[0].text:
        history[0].add_run(addition)
    doc.core_properties.comments = (
        "Source maintenance 9 November 2026; compact operator workflows, current public "
        "source references and reviewed DEMO figures. Historical evidence remains at the end."
    )
    doc.save(base.MANUAL)
    base.normalize_figures(base.MANUAL)
    assert hashlib.sha256(base.SUMMARY.read_bytes()).hexdigest() == summary_before
    ordered = [paragraph.text for paragraph in doc.paragraphs if paragraph.style.name == "Heading 1"]
    assert ordered[-1] == "21 Update history and earlier evidence"
    print(json.dumps({"control_sites": count, "manual": base.MANUAL.name,
                      "summary_sha256_preserved": summary_before,
                      "expected_figures": 12, "visual_qa_required": True}))


if __name__ == "__main__":
    main()
