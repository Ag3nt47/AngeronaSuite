"""Refresh the retained 1.15 manual after the reviewed display-recovery fixes.

Runs only with python-docx and the generated, public source index. It never
imports Angerona, reads host settings or rebuilds older manual chapters.
Render every changed page and verify unchanged-page mappings before delivery.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import json

from docx import Document
from docx.oxml.ns import qn

import update_master_manual_operator_115 as base


def insert_after(doc, prefix, text):
    if any(p.text == text for p in doc.paragraphs):
        return
    matches = [p for p in doc.paragraphs if p.text.startswith(prefix)]
    assert len(matches) == 1, (prefix, len(matches))
    paragraph = doc.add_paragraph(text)
    matches[0]._p.addnext(paragraph._p)


def refresh_controls(doc):
    # Build new paragraphs and tables separately so retained chapters and
    # already-reviewed formatting stay untouched. Rebind only HTTPS links.
    generated = Document()
    base.add_controls(generated)
    base.style_document(generated)
    nodes = [deepcopy(node) for node in generated._element.body
             if node.tag != qn("w:sectPr")]
    for node in nodes:
        for hyperlink in node.iter(qn("w:hyperlink")):
            old_id = hyperlink.get(qn("r:id"))
            relation = generated.part.rels[old_id]
            assert relation.is_external and relation.target_ref.startswith("https://")
            hyperlink.set(qn("r:id"), doc.part.relate_to(
                relation.target_ref, relation.reltype, is_external=True))
    base.take_block(doc, "20 Complete interface control reference")
    history = [p for p in doc.paragraphs
               if p.style.name == "Heading 1"
               and p.text == "21 Update history and earlier evidence"]
    assert len(history) == 1
    for node in nodes:
        history[0]._p.addprevious(node)
    return sum(len(table.rows) - 1 for table in generated.tables)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manual-only", action="store_true",
                        help="Preserve an already rendered and reviewed security summary")
    options = parser.parse_args()
    doc = Document(base.MANUAL)
    assert any(p.text == base.MARKER for p in doc.paragraphs)
    insert_after(doc, "Module Health starts collapsed;", base.DISPLAY_RECOVERY)
    insert_after(doc, "The EKG strip requires advancing authenticated progress", base.HEALTH_DISPLAY)
    insert_after(doc, "The dashboard Red Team button opens a separate ordinary-user application",
                 base.TOOL_STARTUP_REVIEW)
    state = [p for p in doc.paragraphs
             if p.text.startswith("Start with the assessment banner, current alerts")]
    assert len(state) == 1
    if base.CHILL_STATE not in state[0].text:
        state[0].add_run(" " + base.CHILL_STATE)
    count = refresh_controls(doc)
    history_addition = (
        " Follow-up maintenance added bounded Qt presentation recovery, private standalone-tool "
        "startup receipts and exact retry conditions, and cached Black Box health-table rendering "
        "that preserves evidence distinctions and review position. These changes do not establish "
        "the cause of a prior blank display or GUI pause."
    )
    history = [p for p in doc.paragraphs
               if p.text.startswith("Added the current community tool hub,")]
    assert len(history) == 1
    if history_addition not in history[0].text:
        history[0].add_run(history_addition)
    doc.core_properties.comments = (
        "Source maintenance 9 November 2026; complete public references, bounded presentation "
        "recovery and truthful remaining acceptance limits. Historical evidence remains at the end."
    )
    doc.save(base.MANUAL)
    base.normalize_figures(base.MANUAL)
    if not options.manual_only:
        base.build_summary()
    print(json.dumps({"control_sites": count, "manual": base.MANUAL.name,
                      "summary": base.SUMMARY.name, "visual_qa_required": True}))


if __name__ == "__main__":
    main()
