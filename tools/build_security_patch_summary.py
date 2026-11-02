"""Build the short 1.15 Word patch summary after final review.

Use managed-runtime python-docx. Generation still requires rendering and visual
review before delivery; source tests do not attest signed/hardware deployment.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from docx import Document
from lxml import etree
from docx.enum.table import WD_ALIGN_VERTICAL
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs/releases/Angerona_1.15_Security_Patch_Summary.docx"
STAMP = datetime(2026, 11, 2, tzinfo=timezone.utc)


HISTORY_HEADINGS = (
    "1 November recorder admission and shutdown follow up",
    "1 November remediation custody follow up",
    "1 November recorder commit boundary follow up",
    "1 November optional audit admission follow up",
    "1 November telemetry storage and dialog recovery",
    "1 November persistence baseline classification",
)
HISTORY_MAX_BYTES = 256 * 1024
HYPERLINK_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink"


def _history_text(node):
    return "".join(item.text or "" for item in node.iter(qn("w:t")))


def _maintenance_history(document):
    """Collect the maintained sections; missing/ambiguous history must hold."""
    blocks = list(document.element.body)
    headings = []
    for index, block in enumerate(blocks):
        style = block.find("./" + qn("w:pPr") + "/" + qn("w:pStyle"))
        if style is not None and style.get(qn("w:val")) == "Heading1":
            headings.append((_history_text(block), index))

    def unique(title):
        rows = [index for text, index in headings if text == title]
        if len(rows) != 1:
            raise ValueError("retained report heading missing or ambiguous: " + title)
        return rows[0]

    positions = [unique(title) for title in HISTORY_HEADINGS]
    runtime = [index for text, index in headings if text in {
        "Current runtime and shutdown follow up", "1 November runtime and shutdown follow up"}]
    residual = [index for text, index in headings if text == "Residual exposure and next steps"]
    if (len(runtime) != 1 or not residual or positions != sorted(positions)
            or not runtime[0] < positions[0] or not positions[-1] < residual[0]
            or [text for text, index in headings if positions[0] <= index < residual[0]] != list(HISTORY_HEADINGS)):
        raise ValueError("retained report section order or boundary held")
    selected = blocks[positions[0]:residual[0]]
    prior = blocks[runtime[0] + 1:positions[0]]
    observation = [node for node in prior if _history_text(node).startswith("Earlier post-setup observation:")]
    validation = [node for node in prior if _history_text(node).startswith("Validation: Overlapping cohorts stay separate:")]
    if len(observation) != 1 or len(validation) != 1:
        raise ValueError("corrected historical observation/validation missing or ambiguous")
    if sum(len(etree.tostring(node)) for node in selected + observation + validation) > HISTORY_MAX_BYTES:
        raise ValueError("retained report history exceeds 256 KiB")
    return {"part": document.part, "blocks": selected,
            "observation": observation[0], "validation": validation[0]}


def _read_maintenance_history(path, expected_sha256=None):
    path = Path(path)
    if not path.exists():
        if path == OUTPUT and expected_sha256 is None:
            return None  # First generation only; an existing report must validate.
        raise ValueError("maintained report source is missing")
    with path.open("rb") as handle:
        raw = handle.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError("maintained report package exceeds 8 MiB")
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("maintained report source hash differs")
    with ZipFile(BytesIO(raw)) as package:
        entries = package.infolist()
        if (len(entries) > 1024 or len({item.filename for item in entries}) != len(entries)
                or sum(item.file_size for item in entries) > 16 * 1024 * 1024
                or any(item.file_size > 4 * 1024 * 1024 for item in entries)):
            raise ValueError("maintained report ZIP bounds held")
    return _maintenance_history(Document(BytesIO(raw)))


def _history_fingerprint(node, part):
    """Compare copied XML using hyperlink targets instead of package-local IDs."""
    if node.tag not in {qn("w:p"), qn("w:tbl")}:
        raise ValueError("unsupported retained report block")
    unsupported = {qn("w:" + name) for name in (
        "sectPr", "drawing", "pict", "object", "altChunk", "footnoteReference",
        "endnoteReference", "commentRangeStart", "commentRangeEnd", "commentReference")}

    def project(item):
        if item.tag in unsupported:
            raise ValueError("unsupported related history content requires review")
        attributes = []
        for key, value in item.attrib.items():
            if key.startswith("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"):
                if key != qn("r:id") or item.tag != qn("w:hyperlink"):
                    raise ValueError("unsupported retained report relationship")
                relationship = part.rels[value]
                if relationship.reltype != HYPERLINK_REL or not relationship.is_external:
                    raise ValueError("retained report link must be an external hyperlink")
                value = relationship.target_ref
            attributes.append((key, value))
        return (item.tag, tuple(sorted(attributes)), item.text, item.tail,
                tuple(project(child) for child in item))
    return project(node)


def _append_history_block(document, node, source_part):
    before = _history_fingerprint(node, source_part)
    copied = deepcopy(node)
    for item in copied.iter():
        relationship_id = item.get(qn("r:id"))
        if relationship_id is not None:
            relationship = source_part.rels[relationship_id]
            item.set(qn("r:id"), document.part.relate_to(
                relationship.target_ref, HYPERLINK_REL, is_external=True))
    document.element.body.insert(len(document.element.body) - 1, copied)
    if _history_fingerprint(copied, document.part) != before:
        raise ValueError("retained report block changed during relationship transfer")


def _only_page_break(node):
    return (node.tag == qn("w:p") and not _history_text(node)
            and len(list(node.iter(qn("w:br")))) == 1
            and next(node.iter(qn("w:br"))).get(qn("w:type")) == "page")


def paragraph(doc, text, *, lead=None):
    result = doc.add_paragraph()
    if lead:
        result.add_run(lead + " ").bold = True
    result.add_run(text)
    return result


def link(doc, title, url):
    result = doc.add_paragraph()
    result.paragraph_format.space_after = Pt(3)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), doc.part.relate_to(url,
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", is_external=True))
    run, properties = OxmlElement("w:r"), OxmlElement("w:rPr")
    color = OxmlElement("w:color")
    color.set(qn("w:val"), "175A8E")
    properties.append(color)
    run.append(properties)
    value = OxmlElement("w:t")
    value.text = title
    run.append(value)
    hyperlink.append(run)
    result._p.append(hyperlink)


def residual_page(doc, title, sections, references):
    doc.add_page_break()
    doc.add_heading("Residual exposure and next steps", 1)
    doc.add_heading(title, 2)
    for label, text in sections:
        paragraph(doc, text, lead=label + ":")
    for name, url in references:
        link(doc, name, url)


def residual_matrix(doc):
    doc.add_page_break()
    doc.add_heading("Cross cutting exposure and priorities", 1)
    paragraph(doc, "Priority reflects the next engineering or deployment dependency, not a prediction that a compromise occurred. Configuration and lifecycle receipts stay separate from detector efficacy and independently administered trust.")
    rows = [
        ("Native availability", "Final self-exit mitigation; scoped logs", "Only the final exit path changed after cleanup. Native fault cause, complete capture and I/O/teardown guarantees remain unproved.", "P0"),
        ("Same-user source", "Preserved edits; scoped keys and IPC", "A same-SID attacker can modify writable source, settings and unsealed evidence. Source anchors are not independent trust.", "P1"),
        ("Kernel trust", "Provider-specific canaries; explicit gaps", "A hostile kernel can suppress or forge observations. A green userspace heartbeat cannot attest kernel truth.", "P1"),
        ("Peer suspension", "WER precursor correlation; EKG deadlines", "Simultaneous user-mode peer freeze can stop both detection and recovery. No certified PPL boundary is deployed.", "P1"),
        ("Driver policy", "Enrolled audit/approve/enforce workflow", "Unsigned policy can be removed by an administrator; loaded drivers, boot fallback and reboot effects need acceptance.", "P1"),
        ("Network egress", "Exact-target transaction custody", "Already open or inherited sockets and trusted hosts remain outside path-rule proof; no PID-bound ALE/flow teardown.", "P1"),
        ("Independent history", "Remote signatures and fresh head checks", "Authority compromise or whole-root rollback, unsealed intervals and archive exhaustion remain separate risks.", "P1"),
        ("Coverage and load", "Visible loss/state and bounded work", "Unavailable providers, heuristic false positives, CPU cost and delayed UI can reduce review effectiveness.", "P2"),
    ]
    table = doc.add_table(rows=1, cols=4)
    table.autofit = False
    widths = (1.05, 1.65, 3.75, .55)
    for column, width in zip(table.columns, widths):
        column.width = Inches(width)
    for cell, value in zip(table.rows[0].cells, ("Boundary", "Implemented control", "Remaining exposure", "Next")):
        cell.text = value
    header = OxmlElement("w:tblHeader")
    table.rows[0]._tr.get_or_add_trPr().append(header)
    for values in rows:
        for cell, value in zip(table.add_row().cells, values):
            cell.text = value
    for index, row in enumerate(table.rows):
        row._tr.get_or_add_trPr().append(OxmlElement("w:cantSplit"))
        for column_index, (cell, width) in enumerate(zip(row.cells, widths)):
            cell.width = Inches(width)
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER
            properties = cell._tc.get_or_add_tcPr()
            margins = OxmlElement("w:tcMar")
            for edge in ("top", "bottom", "left", "right"):
                element = OxmlElement("w:" + edge)
                element.set(qn("w:w"), "90")
                element.set(qn("w:type"), "dxa")
                margins.append(element)
            properties.append(margins)
            borders = OxmlElement("w:tcBorders")
            for edge in ("top", "bottom", "left", "right"):
                element = OxmlElement("w:" + edge)
                element.set(qn("w:val"), "single")
                element.set(qn("w:sz"), "4")
                element.set(qn("w:color"), "D9D9D9")
                borders.append(element)
            properties.append(borders)
            if index == 0:
                shade = OxmlElement("w:shd")
                shade.set(qn("w:fill"), "ECECEC")
                properties.append(shade)
            for p in cell.paragraphs:
                p.paragraph_format.space_after = Pt(1)
                p.paragraph_format.line_spacing = 1.0
                if column_index == 3:
                    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
                for run in p.runs:
                    run.font.size = Pt(9.5)
                    run.bold = index == 0
    paragraph(doc, "P0: diagnose the native shutdown fault. The earlier dump implicated QObject/widget destruction without an exact cause. Newer preserved Python frames map to the old final CRT exit; that dump disappeared before parsing, so no new native PC or unwind is verified. Self-targeted final exit after durable STOP and bounded cleanup is a mitigation, not cause proof or guaranteed I/O/child retirement. Missing-file actor/cause remains unknown.")
    paragraph(doc, "P1: finish independent/signed deployment and disposable-host acceptance before claiming active protection for these boundaries. P2: profile Core/inventory CPU, improve bounded WER-cache diagnostics and validate longer realistic workloads without relaxing identity or policy.")
    paragraph(doc, "Coverage includes gaps, not just positive detections. The reviewed host had native ETW/Sysmon unavailable, HVCI exposure and held listener attestation; none proves an attack. RWX/JIT, timing and tool matches need corroboration. Model text, imported reports and AI review annotations never grant response authority.")
    link(doc, "Sanitized validation, capture gaps and remaining work",
        "https://github.com/Ag3nt47/AngeronaSuite/blob/main/analysis/hardening-v1.15-2026-10-30.md")


def residual_appendix(doc):
    residual_page(doc, "Kernel telemetry blinding and vulnerable drivers", [
        ("Attacker prerequisites", "A vulnerable-driver attack generally needs a path to load a kernel driver or abuse an already loaded vulnerable component. Administrative or kernel execution puts the attacker beyond the ordinary source process boundary. A valid vendor signature does not by itself make a driver safe."),
        ("Implemented mitigation", "Canaries distinguish actual ETW/Sysmon provenance from process polling and userspace pipeline echoes. A nonce-bound benign process challenge has retained native identity, bounded deadlines and recorder acknowledgment. The optional v2 driver-policy service admits fixed reviewed materials, independent approvals and exact native configuration outcomes."),
        ("What remains possible", "An attacker controlling the kernel can remove callbacks, interfere with delivery or fabricate inputs while user-mode peers stay alive. A forged matching event may defeat a software-only loopback; the canary is not independent kernel attestation. The current driver profile is unsigned/removable and may be changed by an administrator. It does not unload an active driver or restore stripped callbacks."),
        ("Detector limits", "A missed echo establishes a scoped availability problem with unconfirmed cause. A provider that never became available cannot prove new blinding. The observed userspace completions did not exercise a successful native ETW/Sysmon loopback. Fresh EKG liveness and zero queue drops cannot close that gap."),
        ("Deployment needed", "Trusted signed installation, protected service identity/materials, native rights, supported ConfigCI/CiTool, separately reviewed audit history and enforce/reboot/removal recovery acceptance. Microsoft blocklist/HVCI controls require their actual supported OS configuration; this source update does not enable them."),
        ("Validation versus modeling", "Focused tests exercise contracts, provenance, native-owner failure paths and service composition. No vulnerable driver was loaded, no policy was activated, no kernel callbacks were challenged and no signed clean-VM enforcement/reboot acceptance was performed."),
        ("Priority next steps", "P1: validate the signed installed policy lifecycle in disposable supported Windows builds, then verify a genuine native-provider round trip and loss/restart handling. Preserve kernel_prevention_verified:false until a separately defined prevention claim has evidence."),
    ], [("Microsoft recommended driver block rules", "https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules")])

    residual_page(doc, "WER precursors and user mode peer suspension", [
        ("Attacker prerequisites", "The attacker needs effective access to the target process or an allowed dump/suspension path. A local administrator or compromised peer may have materially greater process-control access than an ordinary unrelated process. The exact OS protection level and permissions determine what is possible."),
        ("Implemented mitigation", "A bounded fast path correlates creation/access observations with cached native-owned PID, birth, role and image context. One post-acquisition clock preserves strict expiry/authentication. Immutable cached admission, generation, expiry and loss diagnostics perform no supplier/native query or lease renewal. Stronger correlation requires source identities/GUIDs; heartbeats require exact-generation evidence."),
        ("What remains possible", "Post-event observation can arrive after the vulnerable action. A sufficiently privileged attacker may suspend the Core, Watchdog, Scanner and recovery peers together, preventing local detection or respawn. A frozen Core can leave its last UI state visible until another independent observer detects staleness. No guaranteed pre-dump interceptor is deployed."),
        ("Detector limits", "Dump parameters and suspend-capable access do not prove threads stopped. Getter-time copied admission can expire before reading; fields are not one atomic process/queue receipt. Upstream delivery stays unverified. Copied zero-loss counters do not prove continuous availability or prevention. Historical cache-warning causes remain unresolved."),
        ("Deployment needed", "Certified ELAM-backed antimalware PPL requires the appropriate signing and native installation prerequisites. The implemented virtual-account service separation is useful custody isolation but is not PPL or WinTCB protection. An independently administered observer is needed for stronger assurance against simultaneous local peer failure."),
        ("Validation versus modeling", "Tests cover bounded queues, exact generation/provenance, lifecycle custody and wording. The benign Full capture showed live peers and no WER precursor or actual suspension finding. It was not a coordinated freeze experiment or proof that a privileged attack would be blocked."),
        ("Priority next steps", "P1: complete signed service acceptance and determine certification feasibility. P2: investigate measured lease-expiry gaps without extending trust, then test benign provider loss/freeze detection in a disposable authorized environment with unchanged identity checks."),
    ], [("Microsoft protected antimalware service requirements", "https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-")])

    residual_page(doc, "Containment replacement races and residual egress", [
        ("Attacker prerequisites", "A malicious process must remain active or control a cooperating process, executable namespace or existing network handle during the response window. Privilege, file sharing and process-handle rights constrain which replacement or socket-transfer paths are possible."),
        ("Implemented mitigation", "The response path holds a native process handle plus executable and ancestor identity leases across durable intent, firewall dispatch, postcondition, completion and compensation. File/path admission refuses reparses, remote ambiguity, unsupported hardlinks and other uncertain identity cases. Unknown native completion/close results retain their owners and fence replacement."),
        ("What remains possible", "Detection still precedes admission; earlier exfiltration cannot be undone. The file held for the transaction is not proof of the original mapped image. A path firewall outcome does not bind each socket to PID and birth. Existing or duplicated/inherited sockets, a cooperating already trusted host process and traffic outside the admitted adapter scope remain distinct gaps."),
        ("Detector limits", "Observed connections and configuration readback do not prove packet drops, complete interface/profile scope or termination of an established flow. A failed/unknown postcondition cannot become a completed containment receipt. Suspending a PID alone is not a complete egress guarantee."),
        ("Deployment needed", "The accepted response service/native rights and exact action policy must be deployed. Stronger process-bound enforcement needs a separately designed and accepted native ALE/WFP admission path and established-flow handling, including IPv4/IPv6, interface changes, inheritance and recovery. The current update does not supply that backend."),
        ("Validation versus modeling", "Focused containment tests exercise identity retention, races, journals, compensation and uncertain cleanup. They do not demonstrate a native PID-bound connect decision, inherited-socket revocation or TCP teardown on the reviewed host. Source Observe kept mutation authority held during observation."),
        ("Priority next steps", "P1: define the native process/socket contract and implement it behind enrolled authority, then validate actual traffic outcomes and rollback in a disposable installation. Keep path-rule and socket-admission receipts separate. Preserve emergency managed-only recovery and avoid blanket firewall resets."),
    ], [("Microsoft CreateFileW sharing and handle semantics", "https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew")])

    residual_page(doc, "OS downgrade hardware freshness and whole root replay", [
        ("Attacker prerequisites", "An OS servicing downgrade needs control of an applicable privileged servicing/recovery path, affected OS state or storage. Local evidence replay needs the ability to restore a coherent older data/key state. Authority-root rollback and hardware cloning are separate threat boundaries."),
        ("Implemented mitigation", "The audit parses only bounded recognized direct servicing operations from the registry-selected local queue and compares fixed critical disk version resources. It separates Windows.old recovery copies from scheduled replacement. Independent providers are composed before state admission. TPM code verifies pinned fresh counter/extend/counter certifications bound to a typed checkpoint."),
        ("What remains possible", "Unsupported/custom queues, unavailable files and unobserved servicing paths limit detection. A signed older binary can still be vulnerable. A local matching HMAC/database replay cannot prove its own age. A compromised or rolled-back independent authority can undermine freshness. No automatic physical TPM enrollment or protected NV writer is supplied."),
        ("Detector limits", "VERSIONINFO is a best-effort disk sample, not signer, loaded-image, security-build applicability or prevention proof. TPM PolicyNV is a precheck, not atomic digest compare-and-swap. Split writes or reply loss need reconciliation. A software vTPM or cloned authority cannot be assumed physically independent; trusted time and complete authority-root rollback resistance are not established."),
        ("Deployment needed", "Supported vendor OS mitigations remain necessary. Hardware use needs authenticated physical EK/AK enrollment, exact issuer-pinned NV names/policy, suitable platform-created non-ORDERLY counter/extend indexes and a protected serialized single-use-policy writer. These are external provisioning and acceptance tasks, not dashboard toggles."),
        ("Validation versus modeling", "Offline tests cover parser bounds, registry references, signed certification formats, nonce consumption, typed binding and pure policy plans. No downgrade was staged, no reboot or physical TPM call/write was performed, and no hardware floor was active in the observed source instance."),
        ("Priority next steps", "P1: complete independently reviewed physical enrollment/writer and crash-reconciliation design before runtime binding. Test vendor-supported servicing/recovery and real signed hardware observations in disposable systems. Retain unavailable paths and older recovery artifacts without blocking dashboard startup or silently resetting baselines."),
    ], [("Microsoft guidance for blocking VBS rollback", "https://support.microsoft.com/en-us/servicing/os/windows/2024/07/guidance-for-blocking-rollback-of-virtualization-based-security-vbs-related-security-updates")])

    residual_page(doc, "Same user compromise sealed history and service custody", [
        ("Attacker prerequisites", "A malicious package, extension, infostealer or other process executing as the interactive user can reach data and processes permitted to that SID. A source checkout, its batch launcher and locally writable trust anchors share that boundary. Administrator, service-account and authority compromise are stronger separate cases."),
        ("Implemented mitigation", "Independent recorder signatures commit exact timestamp/module/severity/message/details/HMAC bytes and ordered row commitments. Dedicated remote admission enforces predecessor, next epoch and nonoverlap, even with a stolen host request credential. The signing key stays remote. Installed engine admission checks exact service/token/package/root custody before keys or sensors; its enrolled console is status-only."),
        ("What remains possible", "A same-user attacker may alter unsealed history, future local events, source code or the UI; stealing the request credential may allow new malicious append requests. Seals authenticate committed bytes, not truthful sensors. A compromised signing authority or coherent rollback of its whole trusted root can defeat that independence. Removing local archives creates explicit loss, not recoverable original evidence."),
        ("Detector limits", "The worker checks bounded historical ranges, not all history every cycle. Witnessing defaults off and pauses on unavailability or exhausted storage; the default 128 epochs may fill in about two hours. There is no automatic rollover, Python secure erasure or deployed key-ratchet claim. Same-SID diagnostic access remains inside the user's trust boundary; advisory review cannot authorize mutation."),
        ("Deployment needed", "A separately administered authority outside host snapshot/restore jobs, distinct request/signing keys, pinned private HTTPS, mTLS, fresh signed heads and a remote continuity floor. Authority-root freshness needs its own independent generation floor or accepted hardware. Service custody needs real signed installer/SCM provisioning and credentials under the actual service account."),
        ("Validation versus modeling", "Tests cover exact bytes, stolen-credential append restrictions, missing/changed rows, bounded SQL, pending/reply-loss reconciliation, protected enrollment and STOP custody. Synthetic screenshots exercise no real keys/services. Neither an independent production authority nor isolated signed service was deployed during the Full capture."),
        ("Priority next steps", "P1: accept the independent deployment and protected service credential lifecycle on clean hosts, then define export/retention/rollover without discarding unreviewed history. Test authority backup/restore/revocation and crash recovery. Keep archival authenticity, current freshness and event truth as separate results."),
    ], [("Microsoft service security contexts", "https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts"),
        ("Independent recorder enrollment and limits", "https://github.com/Ag3nt47/AngeronaSuite/blob/main/docs/recorder-integrity.md")])
    residual_matrix(doc)


def native_metadata_followup(doc, history=None):
    """Prepared source only; final observation and render review stay separate."""
    doc.add_page_break()
    doc.add_heading("1 November runtime and shutdown follow up", 1)
    paragraph(doc, "Earlier recorder private-DACL, file-identity and single-owner transfer controls remain. Uncertain cleanup retains custody; parent path checks are not directory leases. Witnessing stays optional with protected private keys, and failed witnessing does not stop local protection.", lead="Retained custody:")
    paragraph(doc, "Normal Python/Qt messages default to 64 KiB (configurable 4–256 KiB), with default 8 MiB per-file/process-role budgets. Full Setup maps the existing controls; Block/Allow/change and pending retry preserve bytes without blocking startup. Native/external writes, upstream allocations, OS quotas and file-identity leases remain outside this budget; generation headers do not attest hooks.", lead="Logging:")
    paragraph(doc, "Early read-only AI refusal precedes full hashes while final trust/transport/hash TTL remain strict. Cached stages include inline callbacks, not isolated cost. Exact owned launches receive one 180-second readiness window, not healthy status, duplicate spawn or expiry kill. Waiter errors are not exit proof; adopted PIDs and cross-peer startup remain separate.", lead="Admission:")
    paragraph(doc, "Mixed history retains dates/gaps without a live overlay; UGCAP exceptions are contained. Nonmodal recovery confirmation requires Yes for cleanup. Final self-exit follows durable STOP, bounded cleanup and Qt quit, not proved fault repair. Port-only CAGT leads and SOAR burst counts remain advisory without response authority; severity, thresholds and genuine active-event contracts stay unchanged.", lead="Review and STOP:")
    if history is not None:
        _append_history_block(doc, history["observation"], history["part"])
    else:
        paragraph(doc, 'Combined post-setup Full60/STOP met bounded lifecycle acceptance: native exit zero, 40 observed generations retired and source/preferences unchanged; 69 sensor states remain unknown. Sixteen new HIGH CAGT leads were observations without response authority. Neither this nor the preceding Full120 contained a SOAR aggregate: its wording is offline-tested only. Earlier modal-held and 39-generation observations remain separate. Fault copies exclude final teardown; P0 cause and Optimus attribution remain unproved.', lead="Earlier post-setup observation:")
    if history is not None:
        _append_history_block(doc, history["validation"], history["part"])
    else:
        paragraph(doc, 'Overlapping cohorts stay separate: AI 327 passes/three skips; logging 291/one; models 53; runtime 275/one; exit/storage 252 (completed JUnit checked). New advisory 317 and setup/logging 94 passed. The earlier published revision 9675347 had eleven passes/four setup-schema failures; those local fixes alone did not establish new hosted acceptance or exploit prevention.', lead="Validation:")
    link(doc, "Sanitized advisory and setup evidence with residual limits",
        "https://github.com/Ag3nt47/AngeronaSuite/blob/main/analysis/hardening-v1.15-2026-11-01-advisory-bursts.md")


def workspace_scan_followup(doc):
    doc.add_page_break()
    doc.add_heading("2 November workspaces and scan review", 1)
    paragraph(doc, "Supported content windows can remain open together with native Minimize and Maximize controls and active-window F11 fullscreen. Owners retain actual workers through close, reject stale callbacks and reopen Settings from fresh configuration. Security confirmations keep their own approval rules.", lead="Concurrent review:")
    paragraph(doc, "Spyware Scan starts from the Entire PC preset of supported checks. Current task, file, check progress and overall workflow progress describe distinct work. Unknown totals stay indeterminate; a remaining deadline is not an estimated completion time. Native checks may finish while toolkit aggregation remains pending.", lead="Scan progress:")
    paragraph(doc, "Dedicated Spyware Scan has a saved 3,600-second default budget with a 30–14,400-second range. Its next-run override neither saves preferences nor extends an active run. Standalone Run scan retains its existing 300-second default and 30–900-second saved range. Older settings lacking the dedicated field use its default without an automatic file rewrite. Expiry retains partial evidence and coverage gaps.", lead="Separate scan budgets:")
    paragraph(doc, "Large after-action previews now remain valid JSON with explicit omissions. Copy complete JSON is bounded at 2 MiB; atomic Export complete JSON is bounded at 64 MiB with depth and node limits. Failed operations preserve prior clipboard or file contents. Neither a preview nor a toolkit finding grants response authority.", lead="Complete evidence access:")
    paragraph(doc, "Auto Adapt presents the proposed before and after state, reasons and adjustable preset choices before approval. Editing invalidates the approved plan. Activity history and transaction details show results; Undo restores the managed firewall baseline only after identity and postcondition checks. It is not whole-system rollback.", lead="Adaptation and rollback:")
    paragraph(doc, "Settings failure recovery restores only 21 owned nonsecret environment keys. It preserves unrelated concurrent changes and credentials removed by the secret store. It no longer clears or restores a stale snapshot of the whole process environment. This is scoped failure recovery, not a global atomic environment transaction.", lead="Credential and settings boundary:")
    paragraph(doc, "Original native-hash producer proof expires after 30 monotonic seconds and is bound to the producer generation; retaining it again cannot renew it. Generic synthetic SOAR wrappers stay held without original proof. Exact companion identity and actual native custody remain required. The registry shares the process failure domain.", lead="Response admission:")
    paragraph(doc, "Crash admission is bounded to 480 KiB per signed record, 256 records, 64 MiB sampled retained bytes and a 1,024-entry enumeration ceiling, with a sampled 2 GiB reserve. Publication does not overwrite existing records. Incomplete traceback holds automatic HEAL. These bounds do not reserve capacity across writers or add a normal dashboard-startup gate.", lead="Recovery storage:")
    paragraph(doc, "Administrator sign-in enrollment is explicit and installed-only, with exact package, SID, task definition and security readback. It stores no password and supplies no restart or on-demand policy. Source Observe remains held. Production pins, independent signing and actual installed task acceptance are unprovisioned; this is not PPL or kernel protection.", lead="Privileged deployment:")
    paragraph(doc, "Final focused validation passed 450 tests in 114.68 seconds with no failures, errors or skips, covering scan reporting, workspaces, Settings, setup, adaptation and installed-startup controls. A narrow-view regression now accounts for group-box frame margins. Hidden-window tests restore the normal visible cadence and separately check that short headlines correctly stop scrolling. Earlier 280, 10 and 53-test cohorts retain their own scope and are not added together. Lint, compilation, live observation and hosted checks have separate acceptance records.", lead="Validation scope:")
    paragraph(doc, "A preceding combined scan finished in approximately 45 minutes and retained one finding, two references and 24 coverage gaps. It predates the latest display corrections and is neither confirmed-breach nor clean-host evidence. Historical failed and passing observations below keep their own scope; the baseline's 15 green hosted checks attest that earlier commit only.", lead="Observed scan:")
    link(doc, "Current maintenance evidence and remaining acceptance",
         "https://github.com/Ag3nt47/AngeronaSuite/blob/main/analysis/hardening-v1.15-2026-11-02-workspaces-and-scan-review.md")


def build(*, service_reviewed=False, history_source=OUTPUT, history_sha256=None):
    if not service_reviewed:
        raise ValueError("final service/custody review must complete before producing the summary")
    history = _read_maintenance_history(history_source, history_sha256)
    doc = Document()
    section = doc.sections[0]
    section.page_width, section.page_height = Inches(8.5), Inches(11)
    section.top_margin = section.bottom_margin = Inches(.65)
    section.left_margin = section.right_margin = Inches(.75)
    section.footer_distance = Inches(.25)
    normal = doc.styles["Normal"]
    normal.font.name, normal.font.size = "Calibri", Pt(10.5)
    normal.font.color.rgb = RGBColor.from_string("222222")
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.04
    for name, size in (("Title", 24), ("Subtitle", 11), ("Heading 1", 13), ("Heading 2", 12)):
        style = doc.styles[name]
        style.font.name, style.font.size = "Calibri", Pt(size)
        style.font.color.rgb = RGBColor(0, 0, 0)
        style.font.underline = False
        style.paragraph_format.keep_with_next = True
        style.paragraph_format.space_before = Pt(8 if name.startswith("Heading") else 0)
        style.paragraph_format.space_after = Pt(5)
        for border in list(style.element.get_or_add_pPr().findall(qn("w:pBdr"))):
            border.getparent().remove(border)
    props = doc.core_properties
    props.title = "Angerona 1.15 Security Patch Summary"
    props.subject = "Five exploit classes: implemented mitigations and deployment boundaries"
    props.author = props.last_modified_by = "Angerona maintainers"
    props.created = props.modified = STAMP
    props.revision = 1
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    footer.add_run("Angerona 1.15.0 | Security patch summary | ").font.size = Pt(8)
    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), "PAGE")
    footer._p.append(field)

    doc.add_paragraph("Angerona 1.15 Security Patch Summary", "Title")
    doc.add_paragraph("Fixes and residual exposure with deployment requirements", "Subtitle")
    paragraph(doc, "Version 1.15.0 | 2 November 2026")
    paragraph(doc, "This major update strengthens five user-mode security boundaries. These are implemented source controls, not a claim that every exploit is blocked or that Windows vulnerabilities have been patched. Source Observe, installed authority and independent services remain distinct.")
    paragraph(doc, "A native shutdown access violation remains an unresolved P0 availability finding. The later logging patch improves observability; one subsequent normal exit does not establish a crash fix.", lead="Development status:")

    doc.add_heading("1 Kernel telemetry blinding and vulnerable drivers", 1)
    paragraph(doc, "Provider-specific ETW/Sysmon canaries retain a benign nonce probe, native generation, collector provenance and recorder acknowledgment. Missing echoes and unavailable collectors stay explicit even if the heartbeat is alive. The kernel control tick continues in Chill.", lead="Implemented:")
    paragraph(doc, "Enrolled installed v2 driver policy uses pinned materials, server-owned plans, two independent OS-bound approvals, durable capabilities and native readback. The policy is unsigned and removable; default v1 stays diagnostic-only.", lead="Policy workflow:")
    paragraph(doc, "No accepted host policy, intact-callback proof, HVCI activation or guaranteed driver prevention is claimed.", lead="Boundary:")

    doc.add_heading("2 WER dump and suspension precursors", 1)
    paragraph(doc, "WER creation/access records correlate with cached native-owned PID/birth/role context, acquired before one shared admission/correlation clock. Typed gaps preserve strict expiry/authentication. Stronger correlation requires source identities/GUIDs; incomplete records remain leads or gaps.", lead="Implemented:")
    paragraph(doc, "Post-event correlation cannot guarantee pre-dump blocking. User-mode peers share a suspension failure domain. Certified ELAM/PPL protection is not supplied.", lead="Boundary:")

    doc.add_heading("3 Executable replacement during containment", 1)
    paragraph(doc, "OS process, executable and ancestor identity leases remain held through durable intent, firewall dispatch, postconditions, completion and managed compensation. Ambiguous paths and uncertain cleanup are held with native owners retained.", lead="Implemented:")
    paragraph(doc, "The acquired file is not original mapped-image proof. PID-bound ALE admission, inherited-socket control and established-flow teardown require a native backend.", lead="Boundary:")

    doc.add_page_break()
    doc.add_heading("4 OS downgrade and whole root rollback", 1)
    paragraph(doc, "Bounded servicing review follows recognized direct operations in the registry-selected local queue and compares fixed critical disk VERSIONINFO resources. Older recovery copies are separate from scheduled replacements. Independent freshness is bound before persisted-state admission.", lead="Implemented:")
    paragraph(doc, "The TPM adapter verifies issuer-pinned physical enrollment and fresh counter/extend/counter certifications bound to a checkpoint. It builds policy-write plans; it does not enroll a device or write NV. Policy prechecks are not atomic compare-and-swap.", lead="Hardware preparation:")
    paragraph(doc, "Vendor mitigations, physical enrollment and a protected serialized external writer remain required. Disk versions do not prove signer, loaded image or patch applicability. Whole-authority rollback is separate.", lead="Boundary:")

    doc.add_heading("5 Same user tampering and history forgery", 1)
    paragraph(doc, "Optional independent Ed25519 signatures commit exact recorder row bytes. Remote admission enforces the next predecessor/epoch/nonoverlapping range; a durable pending claim reconciles reply loss. Protected request-key enrollment and retained workers preserve custody through STOP.", lead="Implemented:")
    paragraph(doc, "Installed engine admission checks the actual virtual account, SCM process, restricted token, package and protected root before keys or sensors. Its console is status-only. Signed installer provisioning and acceptance remain separate.", lead="Service separation:")
    paragraph(doc, "Witnessing defaults off. Its 16 MiB/128-epoch archive preserves and pauses when full, potentially after roughly two hours at a 60-second cadence. Source Observe shares its user's failure domain. No Python secure-erasure or certified PPL claim is made.", lead="Boundary:")

    doc.add_heading("Validation and operational findings", 1)
    paragraph(doc, "Focused cohorts: native/service/status 183 passes; recorder 64; credential composition 71 plus one POSIX skip; TPM 83; retrieval 11; watchdog nine; socket presentation 39; crash-log observability 55. Cohorts overlap and are not summed. Broad selfcheck: 28 phase passes and one existing host Ollama listener-attestation failure; its 30-step defensive drill passes.")
    paragraph(doc, "The earlier 180-second Full observation retained a 4,446-record initial gap. A later logging-enabled 120-second session retained a separate 2,898-record gap and 268 new events, with 75/75 workers running but native ETW/Sysmon unavailable and 69 collector states unknown. No confirmed breach was established. CPU cost and UI delays remain; the sessions are not a controlled benchmark.")
    paragraph(doc, "That session's STOP retired all retained generations with actual Core exit zero and unchanged source/preferences. Observation acceptance still failed on two process-inventory bounds; count versus deadline cause is unknown. A prior session's native shutdown crash remains unresolved. Both crash logs later disappeared for an unproved reason; private diagnostic text is preserved. The 55-pass logging patch verifies arming visibility, not complete capture or crash repair. The subsequent follow-up records the final changed-source lifecycle result separately.")
    link(doc, "Release scope, evidence and deployment limits",
        "https://github.com/Ag3nt47/AngeronaSuite/blob/main/docs/releases/v1.15.0.md")
    link(doc, "Master Manual security flow",
        "https://github.com/Ag3nt47/AngeronaSuite/blob/main/docs/security-flow.md")
    workspace_scan_followup(doc)
    native_metadata_followup(doc, history)
    if history is not None:
        for block in history["blocks"]:
            _append_history_block(doc, block, history["part"])
    first_residual_block = len(doc.element.body) - 1
    residual_appendix(doc)
    if history is not None:
        # Preserve an original trailing break; otherwise keep our new layout
        # break but exclude only that exact owned node from the history check.
        added_break = doc.element.body[first_residual_block]
        if not _only_page_break(added_break):
            raise ValueError("new residual boundary is ambiguous")
        if history["blocks"] and _only_page_break(history["blocks"][-1]):
            added_break.getparent().remove(added_break)
            added_break = None
        retained = _maintenance_history(doc)
        retained_blocks = retained["blocks"]
        if added_break is not None:
            if not retained_blocks or retained_blocks[-1] is not added_break:
                raise ValueError("new residual boundary moved into maintained history")
            retained_blocks = retained_blocks[:-1]
        for name in ("observation", "validation"):
            if _history_fingerprint(retained[name], doc.part) != _history_fingerprint(history[name], history["part"]):
                raise ValueError("historical report paragraph lost or changed")
        if (len(retained_blocks) != len(history["blocks"])
                or any(_history_fingerprint(actual, doc.part) != _history_fingerprint(original, history["part"])
                       for actual, original in zip(retained_blocks, history["blocks"]))):
            raise ValueError("maintained report history lost or changed")
    return doc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT)
    parser.add_argument("--history-source", type=Path, default=OUTPUT,
                        help="Maintained report supplying retained historical sections; defaults to the canonical report")
    parser.add_argument("--history-sha256", help="Optional exact SHA256 for an explicit reviewed history source")
    parser.add_argument("--service-reviewed", action="store_true",
                        help="Required after final service/custody review; render QA is still separate")
    args = parser.parse_args()
    data = BytesIO()
    build(service_reviewed=args.service_reviewed, history_source=args.history_source,
          history_sha256=args.history_sha256).save(data)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(data) as source, ZipFile(args.output, "w", compression=ZIP_DEFLATED, compresslevel=9) as target:
        for name in sorted(source.namelist()):
            info = ZipInfo(name, date_time=(2026, 11, 2, 0, 0, 0))
            info.compress_type, info.create_system = ZIP_DEFLATED, 0
            target.writestr(info, source.read(name))
    print(f"{args.output} (render every page before delivery)")


if __name__ == "__main__":
    main()
