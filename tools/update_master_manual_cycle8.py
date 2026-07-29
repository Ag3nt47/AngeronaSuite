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

    doc.add_heading("Privacy-minimized identity defense", level=2)
    bullets(doc, (
        "Bounded local authentication analytics detect password spray, "
        "distributed account targeting, repeated failures, new privileged "
        "sign-in sources, and interactive service-account use.",
        "Account and source values are HMAC-tokenized before retention. The "
        "analytics contract never accepts passwords, tokens, or credential material.",
    ))

    doc.add_heading("Privacy-minimized network behavior", level=2)
    bullets(doc, (
        "A fixed-memory Network Detection and Response (NDR) layer detects "
        "periodic beacon timing, private lateral fanout, broad external fanout, "
        "and large asymmetric uploads.",
        "Process and destination identities are HMAC-tokenized before retention. "
        "The layer does not accept or store packet payloads.",
    ))

    doc.add_heading("Durable exposure lifecycle", level=2)
    bullets(doc, (
        "Host-applicable vulnerabilities have a durable local lifecycle with "
        "ownership, deadlines, optimistic concurrency, mitigation, bounded risk "
        "acceptance, exception expiry, and due-item queries.",
        "Resolved or closed findings require a SHA-256 closure artifact identity; "
        "state changes produce authenticated audit receipts.",
    ))

    doc.add_heading("Signed plugin lifecycle and interoperability", level=2)
    bullets(doc, (
        "Reviewed capability extensions can be staged from exact verified source "
        "and manifest snapshots, revalidated before activation, versioned, "
        "revoked, and quarantined. The lifecycle manager never imports plugin code.",
        "Trust changes, source or manifest tampering, unsigned content, and "
        "entrypoint collisions fail closed before ModuleManager import.",
        "Privacy-reviewed OCSF, STIX, OTLP, and Angerona envelopes use a durable "
        "signed queue with idempotency, bounded retry backoff, and dead letters. "
        "External egress remains denied by default.",
    ))

    doc.add_heading("Enterprise governance baseline", level=2)
    bullets(doc, (
        "Repository policy now defines supported editions and honest claims, "
        "semantic and protocol compatibility, downgrade/deprecation behavior, "
        "and six accepted architecture decisions.",
        "Detection-content governance defines owner/reviewer roles, telemetry, "
        "fixtures, ATT&CK mapping, false-positive risk, privacy, signing, and "
        "promotion gates. Support operations define ownership, severity, response "
        "targets, diagnostic privacy, escalation, and disclosure.",
    ))

    doc.add_heading("Safe fleet hunts and collections", level=2)
    bullets(doc, (
        "Fleet hunts use a closed artifact catalog, explicit device/group "
        "targets, host/byte/time/expiry budgets, independent approval, and "
        "two-person approval for restricted evidence.",
        "Authenticated atomic state survives restart and fails on tampering. "
        "Terminal results are budget-checked and signed. Arbitrary commands, "
        "scripts, paths, and remote shells are forbidden.",
        "The authenticated hunt workspace stores typed queries, bounded analyst "
        "notes, findings, decisions, and immutable result/evidence references "
        "with optimistic concurrency. It has no executable cells.",
        "Sanitized notebook export redacts identities and paths, omits device "
        "tokens and raw artifacts, and excludes restricted results by default.",
        "Per-host progress and coded failures persist as authenticated records "
        "with non-regressing timestamps and byte counters. Exact host and total "
        "byte budgets apply before insertion; bounded summaries expose the "
        "latest state without retaining raw device identity.",
        "Verified result references promote idempotently into a deterministic "
        "investigating case. Evidence remains reference-only and every promoted "
        "item receives an authenticated custody chain.",
        "Safe live-response sessions bind one target, requester, exact capability "
        "set and a maximum 30-minute expiry. Read-only sessions require an "
        "independent approval; host-changing sessions require two.",
        "Only registered read-only query handlers and separately approval-gated "
        "Response Broker operations are available. Executable fields, target "
        "escape, unregistered capabilities, expiry, and duplicate execution fail "
        "closed. The privacy-minimized transcript forms an authenticated hash chain.",
        "Read-only query handlers execute outside the session-manager lock so a "
        "slow collector cannot block close or expiry. Results arriving after "
        "the session ends are recorded as discarded and are not returned.",
    ))

    doc.add_heading("Reliability and release evidence", level=2)
    bullets(doc, (
        "A short bounded atomic-replacement retry tolerates temporary antivirus "
        "sharing locks on hunt state while persistent or unrelated failures "
        "remain visible.",
        "Registered deterministic recovery drills enforce explicit retryable "
        "errors, attempt limits, delay caps, total time budgets, and "
        "content-addressed outcomes. Current fixtures cover transient database "
        "locks, collector outage, unknown errors, service restart, and dead letters.",
        "The fixed local release gate runs serial tests, bytecode compilation, "
        "Ruff, dependency audit, and documentation drift without accepting "
        "operator-supplied commands or invoking a shell.",
        "Its bounded evidence pack binds the complete source commit and source "
        "epoch to redacted summaries, command/output digests, limitations, and "
        "a canonical manifest digest. Publisher signing and long-duration "
        "physical-host soaks remain separate gates.",
    ))

    doc.add_heading("Encrypted backup, restore, and audit export", level=2)
    bullets(doc, (
        "Selected canonical data-root files and consistent SQLite snapshots "
        "stream into an Advanced Encryption Standard Galois/Counter Mode "
        "(AES-GCM) authenticated archive. Filenames, paths, manifests, and "
        "payloads remain inside the encrypted stream.",
        "Backup rejects traversal, symlink or reparse-point input, an in-root "
        "archive destination, missing required data, byte overflow, wrong keys, "
        "tampering, and digest mismatch.",
        "Restore is planned separately and binds the exact archive, target, "
        "manifest, item list, requester, and expiry. It requires Angerona "
        "offline plus two distinct non-requester approvals, stages every item, "
        "and retains replaced files in a rollback scope.",
        "An interrupted replacement restores the previous file. Protected key "
        "recovery, scheduling, retention, and full disaster-recovery exercises "
        "remain operational gates.",
        "Backup policy is disabled by default and side-effect free. It computes "
        "cadence status, exact selections, destination class, a minimum verified "
        "copy floor, count/age retention, and an HMAC-authenticated deletion "
        "proposal; it never schedules work or removes an archive.",
        "Named site-loss, database-corruption, control-plane-compromise, bad "
        "policy/update, and lost-signing-key scenarios define a Recovery Point "
        "Objective (RPO), Recovery Time Objective (RTO), minimum verified copies, "
        "owner, and review date.",
        "Recovery drill evidence measures backup age and recovery duration, "
        "requires archive, manifest, service-health, and rollback verification, "
        "lists every objective violation, and authenticates the final result. "
        "Operational alternate-site and key-recovery exercises remain open.",
        "Audit export filters an exact tenant, scope, inclusive time range and "
        "record limit. Restricted fields are removed, sensitive values and "
        "actors are tokenized, free text is redacted, and truncation is explicit.",
        "Exported audit records form a cryptographic custody chain; an "
        "HMAC-authenticated manifest binds the chain head, record digest, scope, "
        "time range, privacy policy, and requester token.",
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
        "Final repository evidence: 409 tests passed, 2 intentional "
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
