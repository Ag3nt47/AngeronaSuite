"""Append or replace the October 22 live-debug chapter using only stdlib OOXML.

Historical chapter XML, styles, media and relationships remain unchanged. The
current cover, document control, Chapter 1 inventory and version labels are updated. The
update is deterministic and idempotent; use --check for a read-only content
check. Rendering remains a separate document QA step.
"""
from __future__ import annotations

import argparse
from html import unescape
from pathlib import Path
import re
from xml.etree import ElementTree
from xml.sax.saxutils import escape
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "Angerona_Master_Manual.docx"
TITLE = "Live debug and AI review 22 October 2026"
START = b"<!-- Angerona live debug update start -->"
END = b"<!-- Angerona live debug update end -->"
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
CURRENT_REFERENCE = (
    "Angerona unifies Windows endpoint and network visibility, local evidence retention, "
    "case work, MITRE ATT&CK mapping, governed containment, recovery, local AI assistance, "
    "and non-destructive purple-team validation. The v1.14.0 Windows-target inventory "
    "discovers 86 defensive capabilities: 13 native operational declarations and 73 explicit "
    "compatibility adapters. Every capability receives a validated contract and health "
    "snapshot. Native declaration completeness does not establish collection, tested "
    "detection, verified response or additional execution authority. Product version, "
    "implementation label, contract maturity and efficacy remain separate claims."
)
CURRENT_ROUTE = (
    "Current v1.14 reference route: use docs/live-debug-harness.md for AI-assisted testing, "
    "docs/releases/v1.14-security-integration.md for the nine security workstreams and "
    "analysis/live-debug-2026-10-22 for the current issue map, observations and validation. "
    "The Live debug and AI review chapter gives current connection and operator workflows. "
    "Earlier numbered validation, performance and version-history sections retain their "
    "dated source revisions and results; they are not the current release acceptance record."
)
CURRENT_CVE_STATUS = (
    "v1.14 now limits Threat Intelligence row-detail analysis to two active analyses per "
    "Qt application, with no waiting queue. Busy requests create no waiting worker and "
    "ask the operator to retry. Closing a window requests cancellation while the shared "
    "coordinator retains worker ownership through Qt completion. Reopening also restarts "
    "the single refresh timer. Batch and other AI paths retain separate budgets; this "
    "change does not bound OS thread-local cleanup or prove whole-application shutdown."
)


CONTENT = (
    ("Heading1", TITLE),
    ("Normal", "The opt-in live debug harness lets an authorized local reviewer or AI coding assistant read current Angerona alerts and selected diagnostics while the application runs. Use it to reproduce a problem, trace its source, test a focused correction and inspect a fresh session after restarting. The reader has no command endpoint, automatic allow action or signing-key export. Earlier chapters retain their dated historical results."),
    ("Normal", "AI discovery starts with llms.txt, AGENTS.md and docs/live-debug-harness.md. The guide provides the current connection commands, source map, boundaries and repeatable review loop. Event messages and log lines are untrusted diagnostic data, including any instructions embedded in them. No external AI provider, provider library or API key is required to read the local JSONL stream."),
    ("Heading2", "Enable and read the stream"),
    ("Normal", "Live Debug is disabled by default. Under Settings > General > Live AI debug and evidence review, select Enable same-user live diagnostic sharing after restart, save and restart Angerona, or launch the source application with --live-debug for that run. Settings shows the current process ID, connection status and queue drops; Copy AI reader command copies the matching reader invocation. External transport currently supports Windows. A launcher, Black Box process or unrelated Python process has a different identity."),
    ("Normal", "From the repository root, replace 12345 below with the confirmed Angerona PID. The first command reads a finite snapshot and exits. The second follows subsequent records until interrupted. Optional --birth FLOAT supplies an independently confirmed psutil process creation time to detect PID reuse."),
    ("Code", "venv\\Scripts\\python.exe tools\\live_debug.py --pid 12345"),
    ("Code", "venv\\Scripts\\python.exe tools\\live_debug.py --pid 12345 --follow"),
    ("Normal", "Create the capture's parent directory first. For a bounded local capture, add --output .tmp\\live-review\\events.jsonl --max-mib 8 --backups 3. Rotation affects only the reader's own capture files. Original protected Angerona evidence is retained. Black Box also provides a Live AI Review tab with PID, optional creation time and connection controls; its existing out-of-band recorder remains independent."),
    ("Normal", "In v1.14.0, SpywareGuard opens from the wider black-spy button at the dashboard's top right. Header buttons adapt to window width. The intelligence window shows dated reference briefs offline and opt-in official news with source details. Modules > Turn all on starts eligible modules in the background and reports held or skipped capabilities while preserving consent, Chill, shutdown and integrity gates. The floating globe identifies Core, Watchdog, Scanner and Black Box through separate colour-coded moons. Read analysis/live-debug-2026-10-22/interaction-map.md for shared-service dependencies, interference paths and the staged individual, scanner-only and combined observation matrix."),
    ("Normal", CURRENT_CVE_STATUS),
    ("Heading2", "Evidence and access boundaries"),
    ("Normal", "The endpoint is \\\\.\\pipe\\Angerona.LiveDebug.<PID>. The Windows named pipe uses first-instance protection, rejects remote clients and restricts access to the server's Windows user SID, SYSTEM and Administrators. The client verifies the expected server PID and can also verify creation time. These checks do not establish an enclave against an administrator or an attacker already controlling the same user's process."),
    ("Normal", "The service copies live EventBus events after activation and fixed allowlisted diagnostic logs, including scanner, watchdog and Black Box failures. Initial tails are limited to 128 KiB per file and continue in bounded resumable chunks. Fair worker turns retain unfinished parsing, coalesce blank lines and expose gaps or collection errors. The default ingress queue holds 512 records, history retains 2,000 records and at most four clients connect. There is no replay of the complete historical EventBus ledger."),
    ("Normal", "Connection metadata identifies the PID, creation time, run ID, cursor and retained range. Event, diagnostic, coverage and gap records carry sequence information; a heartbeat can repeat the current cursor. A service restart creates a new live session. Check continuity and collection errors before comparing captures. Missing, inaccessible or dropped evidence remains unknown coverage; an empty feed does not prove that the host is secure."),
    ("Normal", "The producer copies allowlisted detail fields and applies best-effort secret redaction to free text. This cannot recognize every credential or private value, so review a capture before sharing it externally. Redacted exports are advisory views; they are not the original signed event or a verified response receipt. The feature does not automatically upload evidence to an AI provider."),
    ("Normal", "Programmatic LiveDebugClient.connect, read and close belong to one reader worker, never the Qt thread. cancel is a fast cancellation signal; it does not close or retire pending native IO. The reader's finally block closes its client after cancellation, and the Qt owner retains its worker and thread until retirement is confirmed. A stop deadline reports pending ownership rather than destroying a running reader. Finite snapshots must reach the initial retained cursor or report incomplete coverage; --duration limits follow mode only."),
    ("Heading2", "Review and validation loop"),
    ("Normal", "1. Confirm the checkout revision, running process identity and enabled setting. Connect and record status, queue drops, log collection errors and any gap. Reproduce the reported action using ordinary benign inputs. Keep the original evidence and Adversary Combat action receipts intact."),
    ("Normal", "2. Annotate the observation locally as a supported threat, a supported false positive or unknown. Authentication establishes event provenance, not the correctness of every heuristic conclusion. A reviewer annotation never becomes an automatic allow rule, ignored alert, threshold change or response authorization."),
    ("Normal", "3. Trace the evidence to the smallest responsible code path. Distinguish collection failure, configuration exposure, active detector evidence and verified action results. For a UI stall, investigate callback work and native Qt or scheduling behavior; a sampled Python stack alone does not establish a deadlock."),
    ("Normal", "4. Build an isolated bounded regression using temporary data and inert events. Apply a minimally scoped fix while preserving source trust, exact target identity, signatures and response-policy checks. Do not broadly exempt a task or process because its name looks familiar. Do not exercise real containment or a hostile payload merely to test the reader."),
    ("Normal", "5. Run affected tests and broaden checks across detector, event, response and GUI boundaries. Pin source-copy imports in every executing child. Record actual child identity, native exit and retained-handle retirement; job-zero and exit codes alone are insufficient. Publish reviewed completed commits through AGENTS.md, retaining failed evidence and uncertainty."),
    ("Normal", "6. Restart the updated application and reconnect to the new process/session. Production code is not hot-reloaded through the debug pipe. With UGCAP enabled, intentional changes require a separately reviewed golden baseline and a clean verification before normal operation. Repeat the same benign action, compare evidence and continue while a reproducible issue remains."),
    ("Heading2", "Integrity maintenance and remaining uncertainty"),
    ("Normal", "The October 22 callable-integrity fix replaces marshal-based fingerprints with canonical format v2. A regression exercises the exact process_allowlist.executable_sha256 callable during a concurrent file read without changing its code. The previous dump changes when a constant gains a temporary reference; v2 remains stable while still detecting changed code, constants, nested code, names, exception tables, defaults and closures. Independently approved older fingerprint manifests deliberately remain mismatched until explicitly reviewed and reapproved."),
    ("Normal", "Windows state-directory ACL collection now prefers a direct read-only SID-based API audit, avoiding routine icacls subprocess startup and localized principal matching. Access denial, unsupported ACL entries and incomplete collection remain unknown health evidence. Confirmed broad write grants remain security weaknesses. Existing authenticated alert records are not rewritten or silently cleared."),
    ("Normal", "These reproductions establish the corrected source behaviors. They cannot conclusively attribute an inaccessible historical alert or prove the cause of a five-second native Qt stall from screenshots. Inspect a restarted ordinary session and retain new diagnostics if the reported behavior continues. The feature and limits are documented in docs/live-debug-harness.md; current validation belongs to the reviewed source revision, not to earlier totals in this manual."),
    ("Heading2", "All requested security integrations belong to v1.14"),
    ("Normal", "The v1.14 scope includes verified readiness, an independent witness, privilege separation, authenticated approvals, process-bound network admission, identity and browser producers, guided prevention, independent recovery and release trust with efficacy evaluation. The current acceptance register is docs/releases/v1.14-security-integration.md. It distinguishes tested implementations, ongoing integration and independently provisioned deployment requirements. Publication follows observation and bug fixes; a version label or declared feature does not establish working enforcement."),
    ("Normal", "ATT&CK Coverage now shows declared, collecting, detection-tested and response-verified stages. Collection requires a current registered sensor generation, completed fresh work, health of at least 90 and no unknown or reported event overflow. Stopping or replacing a producer withdraws its readiness. Scoped detection proof expires after 24 hours and response proof after one hour; clock discontinuities withdraw proof. A practice marker and its verified cleanup prove that bounded control only, not the real exploit or every technique mapped to the detector. The tested-coverage percentage is separate from the declaration count."),
    ("Normal", "UGCAP > Independent Witness provides opt-in enrollment and cached status for a separately administered private HTTPS witness. Its fixed endpoint must end /v1/ugcap-witness. Explicitly provision the host signing identity, exchange public enrollment and mTLS information with the separate administrator, and enroll the exact TLS leaf certificate pin plus witness Ed25519 PUBLIC PEM. Private PKI and separate host/witness signing-key roles remain required. The tools/ugcap_witness_server.py --initialize operation creates first retained state explicitly; ordinary restart cannot silently reset missing state. No external witness is deployed or configured by this update."),
    ("Normal", "Applying witness settings or provisioning a host key invalidates cached assurance. Attach the enrolled vault, supply its passcode AND fresh required TPM-backed hardware proof, then complete a full UGCAP Verify now cycle. Only a fresh authenticated local checkpoint and matching enrolled witness receipt can satisfy the gate. Check witness now subsequently heartbeats an already verified checkpoint; it cannot initialize, advance, reset or reconcile a retained head. Missing or stale required witness evidence keeps the workspace held. No passcode or source contents are transmitted."),
    ("Normal", "An intentional golden-baseline or vault identity change also requires separately administered witness enrollment or reconciliation. Do not disable a required witness, delete existing state or reset its head merely to obtain green status. Checkpoints expose an old valid host snapshot against an unchanged independent witness; rollback of the entire witness appliance still requires a further independent freshness floor."),
    ("Normal", "Authenticated approval proofs bind an exact operation digest, a short lifetime, a nonce and an enrolled issuer/subject/key identity. Multiple labels for one operator or key do not supply multiple independent approvals. Durable revocations and pre-execution attempt records prevent stale or uncertain actions from being replayed; independent postcondition failure is recorded as verification failure. These checks govern explicitly integrated typed operations. Existing configuration paths are not all globally converted merely by importing the approval library; consult the acceptance register for remaining critical-change routing."),
    ("Normal", "The installed response-service boundary is separate from the ordinary-user desktop and sensor graph. Its native pipe authenticates the actual Windows peer token and verifies the installed service before sending requests. Source Python, a caller-supplied name or a same-user bearer secret does not become privileged authority. Immutable publisher/package pins, protected state and a restricted SCM identity must be provisioned independently. The initial service surface is diagnostic only; unavailable native process-egress enforcement remains visibly unavailable. A path firewall rule or observed connection cannot prove PID-birth-bound socket admission."),
    ("Normal", "Settings > General and Full Setup expose separate opt-ins for local Windows session events and current-user Chromium extension manifest inventory. Identity Session Guard performs collection on its worker. Windows event access denial, log clearing, retention loss and cursor rollback remain coverage gaps. Manifests supply unverified extension IDs, versions and declared permissions; they do not prove an extension is enabled or has those permissions granted. Neither collector reads credential values, cookies, browser history or page contents. An external identity-provider connector requires a separately authenticated configured source; none is invented or enabled by default."),
    ("Normal", "Open Adaptation > Independent Recovery while Immutable Recovery Assurance Guard is running and the workspace has no UGCAP hold. Enroll the separately trusted recovery authority's 32-byte Ed25519 PUBLIC key in base64 form. Explicitly select the authorized local encrypted archive and its signed copy statement. Supply its original 32-byte encryption key and 32-byte proof/audit key, or leave both fields empty to request this user's existing protected recovery-drill keys. The workflow does not generate substitute keys. One-shot inputs are copied to bounded worker requests and wiped best effort; Python/Qt temporary copies cannot be fully erased."),
    ("Normal", "A drill extracts the selected authenticated file inventory into a new private directory and rereads its bytes; it never overwrites the live workspace. The latest tested archive's signed revision, checked age and measured restore duration are shown separately from latest signed-copy evidence. A revision is the enrolled signer's association with that archive. The proof does not reconstruct or verify a full Git checkout or system revision. At most 16 plaintext private test directories are retained; capacity requires operator review and no automatic deletion occurs. Physical independence and survival of host loss remain separately verified deployment properties."),
    ("Normal", "Recurring recovery tests require explicit consent, a previously verified selected archive and reusable original keys already in protected storage. Choose an interval from 1 through 720 hours. The existing recovery worker owns scheduling; a UGCAP hold pauses admission, and worker/process stop disables recurrence and clears queued one-shot material. Closing the panel leaves admitted work with its guard owner. Native filesystem calls cannot be forcibly preempted, so a pending cancellation cannot be reported as completed."),
    ("Normal", "Guided prevention extends the adaptation review toward logging, App Control, memory integrity, vulnerable-driver blocking and Secure Boot. Each control must distinguish requested configuration from effective runtime evidence, describe compatibility and recovery, and use an enrolled typed privileged backend for mutation. Firmware changes, unreviewed App Control policies and unavailable native enforcement stay held. A changed registry value or successful command is insufficient evidence that a reboot-dependent protection is running."),
    ("Normal", "For replay quality, tools/evaluate_detections.py accepts --training-cohort PATH in addition to the evaluation cohort and active/candidate packages. It rejects duplicate evaluation payloads and exact event overlap with declared training sets or rule fixtures, regardless of renamed record IDs, revisions or changed labels. It binds the resulting cohort and package digests while retaining false positives and missed detections. Synthetic replay does not prove independent label review, semantic disjointness, exclusion of undeclared training or live-host efficacy. Release signing remains behind its separately administered authority gate; the repository does not generate replacement signing identities."),
    ("Normal", "The October 22 live loop also corrected two observation/closure issues. QApplication.quit can be cancelled by the dashboard's intentional close-to-tray handler, so the owned test deadline exits its Qt event loop directly and still runs normal application cleanup. Separately, the Black Box reverse animation can hide a window before final close; its standalone entry now exits only after an accepted close confirms that readers have retired. Preserve actual process exit evidence and distinguish a harness mistake from a detector failure."),
)


def _paragraph(style: str, text: str, *, first: bool = False) -> bytes:
    paragraph_properties = []
    run_properties = []
    if style in {"Heading1", "Heading2"}:
        paragraph_properties.extend((f'<w:pStyle w:val="{style}"/>', '<w:keepNext/>'))
        run_properties.append('<w:color w:val="000000"/>')
    elif style == "Code":
        paragraph_properties.append('<w:spacing w:after="100" w:line="240" w:lineRule="auto"/>')
        run_properties.append('<w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="19"/>')
    else:
        paragraph_properties.append('<w:pStyle w:val="Normal"/>')
    if first:
        paragraph_properties.append('<w:pageBreakBefore/>')
    body = (
        '<w:p><w:pPr>' + ''.join(paragraph_properties) + '</w:pPr><w:r>'
        + ('<w:rPr>' + ''.join(run_properties) + '</w:rPr>' if run_properties else '')
        + '<w:t xml:space="preserve">' + escape(text) + '</w:t></w:r></w:p>'
    )
    return body.encode("utf-8")


def _updated_document(raw: bytes) -> bytes:
    # Update only the current cover/control values. Dated historical chapters
    # retain their versions, module counts and validation claims.
    front_updates = (
        ("Current release: v1.14.0 with Live AI Review, integrated defensive diagnostics, 86 discovered capabilities and the October 22 interaction map.",
         "Current development: v1.14.0 with Live AI Review, nine integrated security workstreams, 86 discovered capabilities and the October 22 observation/acceptance register."),
        ("Current release: v1.13.0 with October dashboard responsiveness, default-on adaptive routine scan pacing, and a review of all 87 module source files covering 84 discovered capabilities.",
         "Current development: v1.14.0 with Live AI Review, nine integrated security workstreams, 86 discovered capabilities and the October 22 observation/acceptance register."),
        ("9 October 2026", "22 October 2026"),
        ("1.13.0", "1.14.0"),
        ("October 2026 maintenance. See section 13.3 for local validation; publication and exact-commit CI remain governed by the canonical publisher and GitHub Actions.",
         "v1.14.0 source update. Validation is recorded in analysis/live-debug-2026-10-22; signed package and clean-VM release gates remain separate."),
        ("Current repository code, the unchanged 84-capability inventory, and analysis/loop/cycle34 evidence as of 30 August 2026",
         "Current repository code, the 86-capability inventory and analysis/live-debug-2026-10-22; historical chapters retain their dated evidence"),
    )
    front_end = raw.find(b">Contents</w:t>")
    if front_end < 0:
        raise ValueError("manual contents heading is missing")
    front, remainder = raw[:front_end], raw[front_end:]
    for old, new in front_updates:
        old_bytes, new_bytes = escape(old).encode(), escape(new).encode()
        pattern = rb'(<w:t(?:\s[^>]*)?>)' + re.escape(old_bytes) + rb'(</w:t>)'
        match = re.search(pattern, front)
        if match is not None:
            front = front[:match.start(0)] + match.group(1) + new_bytes + match.group(2) + front[match.end(0):]
    raw = front + remainder
    # Change the present-tense product inventory once, preserving dated reports.
    references = []
    matches = re.finditer(rb'<w:p(?:\s[^>]*)?(?<!/)>.*?</w:p>', raw, re.DOTALL)
    for match in matches:
        text = unescape(''.join(node.decode('utf-8') for node in re.findall(
            rb'<w:t(?:\s[^>]*)?>(.*?)</w:t>', match.group(0), re.DOTALL)))
        if text.startswith("Angerona unifies Windows endpoint and network visibility,"):
            references.append((match, text))
    if len(references) != 1:
        raise ValueError("current product inventory paragraph is missing or ambiguous")
    match, reference = references[0]
    if reference != CURRENT_REFERENCE:
        replacement = _paragraph("Normal", CURRENT_REFERENCE)
        if escape(CURRENT_ROUTE).encode() not in raw:
            replacement += _paragraph("Normal", CURRENT_ROUTE)
        raw = raw[:match.start()] + replacement + raw[match.end():]
    elif escape(CURRENT_ROUTE).encode() not in raw:
        raw = raw[:match.end()] + _paragraph("Normal", CURRENT_ROUTE) + raw[match.end():]
    old_cve_status = (
        "A global per-CVE detail-worker cap remains proposed so bursts across many "
        "distinct CVEs cannot exceed the already bounded per-item UI work."
    )
    for match in re.finditer(rb'<w:p(?:\s[^>]*)?(?<!/)>.*?</w:p>', raw, re.DOTALL):
        text = unescape(''.join(node.decode('utf-8') for node in re.findall(
            rb'<w:t(?:\s[^>]*)?>(.*?)</w:t>', match.group(0), re.DOTALL)))
        if text == old_cve_status:
            raw = raw[:match.start()] + _paragraph("Normal", CURRENT_CVE_STATUS) + raw[match.end():]
            break
    if START in raw or END in raw:
        if raw.count(START) != 1 or raw.count(END) != 1:
            raise ValueError("ambiguous existing live-debug chapter markers")
        start, end = raw.index(START), raw.index(END)
        if end < start:
            raise ValueError("reversed live-debug chapter markers")
        raw = raw[:start] + raw[end + len(END):]
    elif TITLE.encode() in raw:
        raise ValueError("unmarked live-debug chapter already exists; manual review required")
    insertion = raw.rfind(b"<w:sectPr")
    if insertion < 0 or not raw.rstrip().endswith(b"</w:sectPr></w:body></w:document>"):
        raise ValueError("unexpected final OOXML section structure")
    chapter = START + b"".join(
        _paragraph(style, text, first=index == 0)
        for index, (style, text) in enumerate(CONTENT)
    ) + END
    result = raw[:insertion] + chapter + raw[insertion:]
    ElementTree.fromstring(result)
    return result


def update(*, check: bool = False) -> None:
    if MANUAL.resolve().parent != ROOT.resolve():
        raise ValueError("manual path must stay in the repository root")
    with ZipFile(MANUAL) as archive:
        entries = [(info, archive.read(info.filename)) for info in archive.infolist()]
    document = next(data for info, data in entries if info.filename == "word/document.xml")
    updated = _updated_document(document)
    def updated_label(name: str, data: bytes) -> bytes:
        if name.startswith(("word/header", "word/footer")) and name.endswith(".xml"):
            return data.replace(b"v1.13.0", b"v1.14.0").replace(b"9 October 2026", b"22 October 2026")
        return data
    if check:
        if document != updated or any(updated_label(info.filename, data) != data for info, data in entries):
            raise ValueError("master manual live-debug chapter is missing or stale")
        print("Master manual live-debug chapter content is current; render QA is separate")
        return
    destination = MANUAL.with_suffix(".live-debug.tmp")
    try:
        with ZipFile(destination, "w") as archive:
            for info, data in entries:
                if info.filename == "word/document.xml":
                    data = updated
                elif info.filename == "docProps/core.xml":
                    data = re.sub(
                        rb"(<dcterms:modified\b[^>]*>).*?(</dcterms:modified>)",
                        rb"\g<1>2026-10-22T00:00:00Z\g<2>", data,
                    )
                else:
                    data = updated_label(info.filename, data)
                archive.writestr(info, data)
        with ZipFile(destination) as archive:
            if archive.testzip() is not None:
                raise ValueError("updated manual ZIP validation failed")
            body = ElementTree.fromstring(archive.read("word/document.xml")).find(W + "body")
            titles = ["".join(p.itertext()) for p in body.findall(W + "p")]
            if titles.count(TITLE) != 1:
                raise ValueError("live-debug chapter title is not unique")
        destination.replace(MANUAL)
    finally:
        if destination.exists():
            destination.unlink()
    print("Updated master manual live-debug chapter; render QA is separate")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    update(check=parser.parse_args().check)
