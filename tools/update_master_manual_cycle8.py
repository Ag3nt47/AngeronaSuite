"""Append the verified Cycle 8 implementation record to the master manual."""
from __future__ import annotations

import sys
from pathlib import Path

from docx import Document
from docx.enum.text import WD_BREAK


def bullets(doc, values):
    for value in values:
        doc.add_paragraph(value, style="List Bullet")


def update(source: Path, destination: Path) -> None:
    doc = Document(source)
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)
    doc.add_heading(
        "Cycle 8. Local Fleet Preview and Response Safety", level=1
    )
    doc.add_paragraph(
        "Verification date: 29 July 2026. This section records the next "
        "offline-first enterprise tranche and preserves the distinction between "
        "a locally testable preview and production enterprise deployment."
    )

    doc.add_heading("Operator experience and configuration", level=2)
    bullets(doc, (
        "Settings now has one canonical owner for every configuration area. "
        "The Mobile Integration controls moved out of Advanced Console, which "
        "continues to provide operational diagnostics rather than duplicate state.",
        "The searchable Information tab provides capability definitions, "
        "step-by-step procedures, verification criteria, privacy boundaries, and "
        "Take me there navigation to the owning setting or operational window.",
        "Explicit Close, Cancel, and native X actions use the same "
        "reduced-motion-aware reverse panel transition as opening.",
        "Ordinary startup no longer rewrites the highest-privilege scheduled "
        "task. Registration changes only after an explicit operator setting change.",
    ))

    doc.add_heading("Authenticated local fleet preview", level=2)
    bullets(doc, (
        "The opt-in service binds only to the loopback interface and remains "
        "disabled by default. It refuses public or Local Area Network binds.",
        "Requests authenticate the complete path and query, payload digest, "
        "timestamp, and bounded nonce with a protected per-install secret. "
        "Stale, replayed, malformed, or tampered requests fail closed.",
        "The local SQLite control plane requires tenant predicates on inventory "
        "and event operations, rejects identity-key conflicts, deduplicates "
        "events, enforces quarantine/revocation state, and signs ingestion receipts.",
        "This preview does not claim production mutual Transport Layer Security "
        "(mTLS), certificate lifecycle, internet exposure, central high "
        "availability, or Single Sign-On (SSO). Those remain deployment gates.",
    ))

    doc.add_heading("Typed enterprise response boundary", level=2)
    bullets(doc, (
        "Response operations must be registered with an exact identifier, risk, "
        "argument validator, rollback description, and bounded result handler. "
        "There is no generic remote shell.",
        "Dry-run proposals validate and describe rollback but never invoke the "
        "handler. Live operations require a distinct non-requester approval; "
        "high and critical operations require two distinct approvers.",
        "Proposal expiry, target and argument binding, idempotency, conflict "
        "rejection, bounded results, and HMAC-authenticated receipts are enforced.",
    ))

    doc.add_heading("Engineering efficiency and verification", level=2)
    bullets(doc, (
        "Ruff 0.16.0 adds a fast correctness gate and found a latent ARP "
        "Watchdog return-type spelling defect, which was corrected.",
        "pytest-xdist 3.8.0 is available for isolated test groups. The complete "
        "suite remains serial because Windows Access Control List (ACL) tests "
        "intentionally mutate permissions and are not process-parallel-safe.",
        "pip-audit 2.10.1 reports no known vulnerability in installed "
        "dependencies. Public-repository scanning found no committed real "
        "credential, private key, user-profile path, database, cache, or runtime data.",
        "Final repository evidence: 353 tests passed, 2 intentional "
        "platform-dependent skips, 0 failures; Python compilation, Ruff, "
        "dependency audit, and whitespace checks passed.",
    ))

    for section in doc.sections:
        for paragraph in section.footer.paragraphs:
            if "Angerona" in paragraph.text and paragraph.runs:
                paragraph.runs[0].text = (
                    "Angerona | Cycle 8 consolidated 2026-07-29 | Page "
                )
                break
    destination.parent.mkdir(parents=True, exist_ok=True)
    doc.save(destination)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: update_master_manual_cycle8.py SOURCE.docx DESTINATION.docx")
        return 2
    update(Path(sys.argv[1]), Path(sys.argv[2]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
