"""Incrementally maintain the 1.15 operator manual and security patch summary.

Uses python-docx only; never imports the application or reads host preferences.
The retained manual is the base, rather than superseded 1.9 source documents.
Run with the managed document runtime. Render and inspect every page separately.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
from zipfile import ZipFile

from docx import Document
from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "Angerona_Master_Manual.docx"
SUMMARY = ROOT / "docs/releases/Angerona_1.15_Security_Patch_Summary.docx"
MARKER = "17 Current operator workflows for version 1 15"
DATE = "9 November 2026"
CURRENT_VALIDATION = (
    "Run the current harness and inspect its authenticated report, source revision, native process "
    "generations, response receipts, closure and retirement proof. Earlier 52-step campaign results "
    "are retained in chapter 21 as historical manual evidence; their exact revision and date were "
    "not reverified here. They do not establish current 1.15 standalone acceptance."
)
DISPLAY_RECOVERY = (
    "Tray and orb restore show the real Qt dashboard before optional animation. If a paint is not "
    "observed, two bounded presentation attempts include a plain restore with owned effects retired. "
    "A nonmodal notice offers Retry display, normal Safe STOP and instructions. Fixed private "
    "diagnostics and at most 16 memory records explain the attempt. No external recovery child, "
    "settings reset or engine-policy change occurs; a Qt paint is not readable-pixel or protection proof."
)
HEALTH_DISPLAY = (
    "Black Box freezes the complete health-table display, including source dates and duplicate rows. "
    "Unchanged rows avoid repeated item allocation and sorting; hidden views defer rendering until "
    "shown. Changed rows preserve selection and scroll position. Invalid or failed refreshes remain "
    "visible as gaps; this optimization does not identify the cause of an earlier GUI pause."
)
TOOL_STARTUP_REVIEW = (
    "A separate tool launch failure now retains a private phase/error-type receipt and a notification "
    "with a modeless startup review. Retry tool requires the same current owner to be fully retired "
    "and repeats source-seal, owned-Job and authenticated-IPC checks. Closing review preserves the "
    "receipt; no sensor or response policy is changed to force a launch."
)
CHILL_STATE = (
    "Chill's held count describes selected startup work deferred by the current pause intent. "
    "Selected checkboxes stay enabled, and checks already in flight may finish."
)
BASE_URL = "https://github.com/Ag3nt47/AngeronaSuite/blob/main/"
DEMOS = (
    ("suggested-tools-demo.png", "Suggested community tools and their separate adapter scopes"),
    ("community-source-sandbox-demo.png", "Separate editable source copies with diff and revert controls"),
    ("rules-playbooks-demo.png", "Rules and Playbooks tactics board and explicit runtime routing"),
    ("suite-map-3d-demo.png", "Suite Map showing synthetic components volumes and observed links"),
    ("dashboard-demo.png", "Compact dashboard with Current Assessment above one action row and a fixed STOP control"),
)
DEMO_PATHS = {leaf: ROOT / "docs/screenshots" / leaf for leaf, _ in DEMOS[:-1]}
DEMO_PATHS["dashboard-demo.png"] = ROOT / "assets/screenshots/dashboard-demo.png"


def plain(text):
    return re.sub(r"[`*]", "", text).replace("\\|", "|")


def inline(paragraph, text):
    cursor = 0
    for match in re.finditer(r"\[([^\]]+)\]\(([^)]+)\)", text):
        paragraph.add_run(plain(text[cursor:match.start()]))
        label, url = match.groups()
        if url.startswith("../../"):
            url = BASE_URL + url[6:]
        if not url.startswith("https://"):
            paragraph.add_run(plain(label))
        else:
            if label.startswith("src/"):
                label = "Open source"
            hyperlink = OxmlElement("w:hyperlink")
            hyperlink.set(qn("r:id"), paragraph.part.relate_to(
                url, "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink", is_external=True))
            run = OxmlElement("w:r")
            properties = OxmlElement("w:rPr")
            style = OxmlElement("w:rStyle")
            style.set(qn("w:val"), "Hyperlink")
            properties.append(style)
            run.append(properties)
            value = OxmlElement("w:t")
            value.text = plain(label)
            run.append(value)
            hyperlink.append(run)
            paragraph._p.append(hyperlink)
        cursor = match.end()
    paragraph.add_run(plain(text[cursor:]))


def para(doc, text, style=None):
    p = doc.add_paragraph(style=style)
    inline(p, text)
    return p


def heading(doc, title, level=1):
    # New headings use plain descriptive words. Exact UI labels remain in body.
    title = re.sub(r"[^\w\s]", " ", title, flags=re.UNICODE)
    return doc.add_heading(" ".join(title.split()), level)


def table(doc, headings, rows, widths):
    t = doc.add_table(rows=1, cols=len(headings))
    t.autofit = False
    for column, width in zip(t.columns, widths):
        column.width = Inches(width)
    for cell, text in zip(t.rows[0].cells, headings):
        cell.text = text
    repeat = OxmlElement("w:tblHeader")
    t.rows[0]._tr.get_or_add_trPr().append(repeat)
    for values in rows:
        cells = t.add_row().cells
        for cell, text in zip(cells, values):
            inline(cell.paragraphs[0], text)
    for row in t.rows:
        no_split = OxmlElement("w:cantSplit")
        row._tr.get_or_add_trPr().append(no_split)
        for i, cell in enumerate(row.cells):
            cell.width = Inches(widths[i])
    return t


def style_document(doc):
    doc.core_properties.author = "Angerona Project"
    doc.core_properties.modified = datetime(2026, 11, 9, tzinfo=timezone.utc)
    for name in ("Title", "Subtitle", "Heading 1", "Heading 2", "Heading 3", "Heading 4"):
        s = doc.styles[name]
        s.font.color.rgb = RGBColor(0, 0, 0)
        s.font.name = "Calibri"
        properties = s._element.find(qn("w:pPr"))
        if properties is not None:
            for name in ("pBdr", "shd"):
                for element in properties.findall(qn("w:" + name)):
                    properties.remove(element)
        if s._element.rPr is not None:
            for color in s._element.rPr.findall(qn("w:color")):
                color.attrib.pop(qn("w:themeColor"), None)
        s.paragraph_format.keep_with_next = True
    doc.styles["Normal"].font.name = "Calibri"
    doc.styles["Normal"].font.size = Pt(11)
    doc.styles["Normal"].paragraph_format.space_after = Pt(6)
    for p in doc.paragraphs:
        if p.style.name.startswith(("Title", "Heading", "Subtitle")):
            if p.style.name.startswith("Heading"):
                p.text = " ".join(re.sub(r"[^\w\s]", " ", p.text).split())
            p.paragraph_format.keep_with_next = True
            for run in p.runs:
                run.font.color.rgb = RGBColor(0, 0, 0)
                run.font.underline = False
            properties = p._p.find(qn("w:pPr"))
            if properties is not None:
                for name in ("pBdr", "shd"):
                    for element in properties.findall(qn("w:" + name)):
                        properties.remove(element)
    for section in doc.sections:
        for p in section.header.paragraphs:
            for run in p.runs:
                run.font.color.rgb = RGBColor(0, 0, 0)
    for t in doc.tables:
        properties = t._tbl.tblPr
        borders = properties.find(qn("w:tblBorders"))
        if borders is None:
            borders = OxmlElement("w:tblBorders")
            properties.append(borders)
        for side in ("top", "left", "bottom", "right", "insideH", "insideV"):
            element = borders.find(qn("w:" + side))
            if element is None:
                element = OxmlElement("w:" + side)
                borders.append(element)
            for key, value in {"val": "single", "sz": "4", "color": "D9D9D9"}.items():
                element.set(qn("w:" + key), value)
        for index, row in enumerate(t.rows):
            props = row._tr.get_or_add_trPr()
            for height in props.findall(qn("w:trHeight")):
                props.remove(height)
            for cell in row.cells:
                cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
                cp = cell._tc.get_or_add_tcPr()
                margins = cp.find(qn("w:tcMar"))
                if margins is None:
                    margins = OxmlElement("w:tcMar")
                    cp.append(margins)
                for side, size in (("top", "65"), ("bottom", "65"), ("left", "85"), ("right", "85")):
                    item = OxmlElement("w:" + side)
                    item.set(qn("w:w"), size)
                    item.set(qn("w:type"), "dxa")
                    margins.append(item)
                shade = cp.find(qn("w:shd"))
                if shade is None:
                    shade = OxmlElement("w:shd")
                    cp.append(shade)
                shade.set(qn("w:fill"), "E5EDF3" if index == 0 else ("F5F7FA" if index % 2 else "FFFFFF"))
                for p in cell.paragraphs:
                    p.paragraph_format.space_after = Pt(3)
                    p.paragraph_format.space_before = Pt(0)
                    p.paragraph_format.keep_with_next = False
                    for run in p.runs:
                        run.font.size = Pt(10)
                        run.font.color.rgb = RGBColor(0, 0, 0)
                        if index == 0:
                            run.bold = True
    for t in doc.tables:
        if len(t.rows) > 1:
            properties = t.rows[0]._tr.get_or_add_trPr()
            for old in properties.findall(qn("w:tblHeader")):
                properties.remove(old)
            repeat = OxmlElement("w:tblHeader")
            repeat.set(qn("w:val"), "true")
            properties.append(repeat)
    # The retained installation table can fill its final page exactly. Its
    # otherwise empty spacer would occupy a blank page before this explicit
    # chapter break; no paragraph is required between a body table and heading.
    for paragraph in doc.paragraphs:
        if paragraph.style.name == "Heading 1" and paragraph.text == "5 Operator interface and menu map":
            previous = paragraph._p.getprevious()
            if (previous is not None and previous.tag == qn("w:p")
                    and not element_text(previous).strip()
                    and len(previous.findall(".//" + qn("w:drawing"))) == 0
                    and previous.getprevious() is not None
                    and previous.getprevious().tag == qn("w:tbl")):
                previous.getparent().remove(previous)


def element_text(element):
    return "".join(node.text or "" for node in element.iter(qn("w:t")))


def take_block(doc, title, *, level=1):
    body = doc._element.body
    children = list(body)
    start = next(i for i, node in enumerate(children)
                 if element_text(node).strip() == title
                 and node.find("./" + qn("w:pPr") + "/" + qn("w:pStyle")) is not None
                 and node.find("./" + qn("w:pPr") + "/" + qn("w:pStyle")).get(qn("w:val")) == f"Heading{level}")
    stop = len(children) - 1
    for i in range(start + 1, len(children)):
        style = children[i].find("./" + qn("w:pPr") + "/" + qn("w:pStyle"))
        if style is not None:
            match = re.fullmatch(r"Heading(\d)", style.get(qn("w:val"), ""))
            if match and int(match[1]) <= level:
                stop = i
                break
    block = children[start:stop]
    for node in block:
        body.remove(node)
    return block


def add_demo(doc, index):
    leaf, description = DEMOS[index]
    paragraph = doc.add_paragraph()
    paragraph.paragraph_format.keep_with_next = True
    run = paragraph.add_run()
    run.add_picture(str(DEMO_PATHS[leaf]), width=Inches(6.4))
    para(doc, "DEMO only. " + description + ". Synthetic records perform no host actions.", "Caption")


WORKFLOWS = (
    ("17 1 Read the dashboard and choose a working posture", (
        "Angerona is a local endpoint detection and response (EDR), network detection and response (NDR), and security orchestration automation and response (SOAR) workbench. It joins conditional sensors, evidence review and scoped response. A source checkout normally starts without administrator rights in Observe and development mode; the accepted signed installation is a separate deployment boundary.",
        "Start with the assessment banner, current alerts and collector coverage. Enabled is a saved selection, running is a worker lifecycle, health is a module report, and assurance describes tested prerequisites. A running idle SOAR worker can correctly show that response policy is disabled. Open its inspector instead of treating green worker health as permission or proof of prevention. " + CHILL_STATE,
        "Module Health starts collapsed; other dashboard panels open to fit the window. The title, posture and Current Assessment sit above one action row. STOP stays fixed at the right while the other controls scroll horizontally on narrow windows; Tab reveals the focused control. Supported work windows can remain open together and minimize or maximize. Optional motion cannot consume or duplicate an action.",
        "Function accents identify monitoring and inspection in blue, analysis and research in violet, configuration and recovery in amber, and controlled response in red. Labels, severity colors, coverage warnings and permission checks retain their own meaning. Secondary help and provenance expand on demand while progress, findings and primary controls remain visible.",
        DISPLAY_RECOVERY,
        "The EKG strip requires advancing authenticated progress from the exact observed process generation. A stale or unavailable source flatlines red. A pulse shows recent liveness, not complete telemetry or a clean host. GUI lag samples and a native stack ending in the Qt event loop do not establish a deadlock by themselves.",
        HEALTH_DISPLAY,
        "Use Notifications to review deferred prompts without blocking the dashboard. Select or open an item for its existing review controls. A deferred removable-device prompt is not consent to trust, unlock or scan that device. Device identity and PIN checks remain separate. STOP or tray Quit records deliberate shutdown and fences automatic peer relaunch; an uncertain owned child remains explicitly unresolved until its retirement is proven.",
    )),
    ("17 2 Complete setup and optional settings", (
        "Full Setup and Settings expose operating posture, storage and recovery, local AI, response policy, external tools, rules, diagnostics and optional integrations. Review defaults before enabling a feature. The complete settings reference records code defaults, not the current user's saved preferences or proof that a collector can run on this platform.",
        "Community YARA rules and community SOAR playbooks have separate global runtime switches and both default off. Individually importing, testing or activating a draft does not enable either switch. Save through the tool settings view; a failed background save preserves prior preferences and restores the visible saved switch state.",
        "The administrator option defaults off. An operator enables it and accepts the operating system prompt for that session. Elevation does not bypass an unenrolled backend, grant kernel protection or make every listed module operational. Keep credentials in protected stores and review the warning beneath each authority-related option.",
        "Settings code sandboxes open separate editable copies. Saving or resetting a copy does not rewrite installed Core, silently activate imported code or bypass signed release/source review. Record intentional custom changes so update or recovery review can preserve them.",
    )),
    ("17 3 Suggested community tools and editable copies", (
        "Open the GitHub icon for Curated scanners, Source Library and analysis, Suggested tools, Rules and Playbooks, and Settings. Select an entry to read its upstream link, exact pinned revision, adapter capability, excluded behavior and credits. An adapter integrates a defined subset; the presence of Caldera, Velociraptor or Wazuh does not install their whole platforms or enroll another host.",
        "Zero-Breach is the maintained pinned scanner. Atomic Red Team supplies compatible metadata mapped to reviewed controls; its arbitrary attack commands and prerequisites are not run. Sigma matching accepts only the supported logsource, fields, modifiers and conditions. Sysmon Modular supports configuration review. YARA-X uses the existing pinned engine for supported inert-buffer checks. External result adapters remain advisory and cannot grant response authority.",
        "Import public HTTPS GitHub source at an immutable commit, inspect its files and licenses, and explicitly review that exact import. Install selected prepares only its supported integration. Run self-check checks the stated adapter and fixtures; it does not certify a host scan. Uninstall preserves reports, source imports, editable copies and preferences. Explicit Zero-Breach uninstall intent prevents automatic preparation from undoing that decision until an explicit restore.",
        "Create editable copy opens a bounded working copy. Save copy, Show diff, Revert selected copy and Validate or analyze data affect that copy. This source sandbox is not an operating system isolation boundary. Editing a script does not execute it or replace the managed scanner. VM analysis is a separate backend with its own prerequisites, quotas and retained worker custody; current VMware acceptance remains held at its documented configuration-custody boundary.",
    )),
    ("17 4 Build YARA rules and SOAR tactics", (
        "Open Rules and Playbooks for an X/O tactics board, guided builder, source discovery, draft editor and result details. The board explains input, validation, policy and response paths. It is a planning visualization, not an enforcement receipt.",
        "Choose a predefined source or a public HTTPS GitHub URL, fetch a pinned catalog, review the source and check compatible entries. Batch install creates drafts. Foreign workflow JSON, analyzers and Python, PowerShell or shell scripts remain inert when they do not match Angerona's supported schema. Per-item licenses remain part of the review.",
        "Save draft preserves a separate revision. Validate checks syntax, source binding and supported schema; Sample test tests that exact draft. A checkmark requires the expected positive and negative sample outcomes where such fixtures are defined. Compilation alone is not detection accuracy. Read the red X or held reason instead of substituting a green indicator.",
        "Activate validated and Rollback compile the complete candidate YARA set in a bounded ordinary-user owned helper before commit, then recheck current source review. Separate namespaces avoid name replacement. Raw source and compile-input hashes remain distinct. Compatible YARA excludes includes and imported modules; the current aggregate is limited to 32 sources and 64 KiB.",
        "Compatible declarative SOAR uses the closed angerona-playbook/v1 JSON schema for notification or a containment request. Original evidence, opt-in, corroboration, exact-target and Combat gates remain in force. Disable removes one item's routing while retaining revisions; turning its global switch off stops new routing of that kind. Rollback cannot bypass source revocation, validation or response policy.",
    )),
    ("17 5 Use the standalone Red Team application", (
        "The dashboard Red Team button opens a separate ordinary-user application with the existing campaign, progress, history and after-action workflow. Core retains prepared plans, enrolled detectors, validation leases, signed reports and response policy. Closing the tool is not a Core shutdown, and watchdog recovery does not silently relaunch this explicitly started tool.",
        TOOL_STARTUP_REVIEW,
        "The separate tool shares a 90-second bootstrap deadline beginning before Core's source check and inherited unchanged by the child. Both source checks and authenticated native admission remain required. After initialization, the first Qt paint has 15 seconds within a 105-second whole-startup cap. Source sealing checks the deadline and STOP cancellation between bounded operations. An observed cancellation, expiry or invalid clock cannot produce a verified seal; a known negative source-change receipt stays preserved. Cooperative checks cannot interrupt native I/O that is already blocked.",
        "Open Simulation setup to adjust profiles, intensity, marker location and custom inert markers. The current target, containment readiness, overall wheel, result bar, verdict and Launch and Stop controls remain visible while setup is folded. Collapsing setup preserves selections and never changes response authority.",
        "Private authenticated directional IPC binds the current parent, launcher and actual child process generations. Queued UI requests retain that owner epoch. Process probes use fixed inert commands; marker writes receive permission for one newly created Core-owned file. Repository code and child-selected paths are not execution authority. Exact Job ownership covers actual descendants on Windows.",
        "The progress wheel and caught versus missed bar describe the current validated workflow; the pass/fail badge follows those scoped results. Open diagnostic detail for each outcome, its detector observation, response receipt and coverage gap. An empty response queue alone cannot finish a session: the admitted detector must complete a fresh cycle, followed by a fresh response-queue observation under the original deadline.",
        "A failed report-integrity check keeps the immutable after-action report unavailable until genuine evidence loads. Cleanup does not manufacture detection or response credit. A practice marker, its name or its content does not make a live unregistered object safe; only an exact enrolled inert target can receive the scoped practice exception. Catch percentages must not be presented as an independently measured real-world detection rate.",
    )),
    ("17 6 Navigate the three dimensional Suite Map", (
        "SUITE MAP 3D is a software-drawn local view of Core, EventBus, modules, companions, cached mounted volumes, host-visible peripheral functions and retained observed endpoints. Scroll to zoom, drag to orbit, Shift-drag to pan, hover or select for details, and use Take me there to reach the owning existing controls. Filters, search, animation and Reset view aid navigation.",
        "Bright links describe observed publications or endpoint metadata; dashed links describe architecture. Moving particles do not prove subscriber delivery, recorder persistence, an active socket or a blocked attack. Cached health is not a liveness attestation. The view discloses event losses, omitted nodes, source age and unavailable inventories.",
        "A displayed drive is not automatically trusted or scanned. Navigate to the existing device review and retain its consent and PIN boundary. Unmounted storage and firmware or cable implants invisible to the operating system cannot be invented by the map. Rendering stops while hidden or closed; existing cached data avoids GUI-thread host scans.",
    )),
    ("17 7 Spyware Scan and attached device review", (
        "SpywareGuard keeps research/news first, then progress and reported hits, current task/file/timing, and cached computer information with separately labeled scanner usage and permissions. The red Spyware Scan control defaults to Entire PC; open Scan setup to change scope and included checks. Recent native records are separate from this scan's findings or a confirmed breach. Overall and per-reader progress have different meanings; file completion requires a supplied count. Unknown ETA or current file remains unknown.",
        "Native SpywareGuard checks and Zero-Breach are separate coverage sources. Missing permissions, readers, deadline expiry, cancellation or retained incomplete reports must remain visible in the after-action result. No listed findings after incomplete coverage is not a clean-PC result. Investigate, trace, patch, isolate or kill controls require their own supported target, evidence, policy and privilege; report text is not that authority.",
        "Unlimited report count removes the slot-count limit only. Byte, inventory and free-space budgets still protect storage. Existing reports are retained when a new admission is held; export and verify before explicitly removing originals. Startup scratch pressure should leave the recovery interface available, with detailed diagnostics, rather than silently deleting evidence or pretending the engine started.",
        "Optional research downloads use configured HTTPS sources and disclose live-fetch age or failure separately from bundled reference briefs. Feed details expands the article summary and source checks. A rotating banner does not make a stale brief current. Attached storage and peripherals use host-visible metadata and supported scan readers. Suspicion or an opaque accessory is not proof of a hidden hardware implant.",
    )),
    ("17 8 Telemetry continuity forensic evidence and local analysis", (
        "Provider-specific benign canaries require a native ETW or Sysmon echo with the current collection generation and authenticated durable evidence. A general heartbeat or polling echo cannot satisfy that native proof. Current ETWR publishes process-start events; native DLL and network ETW coverage is not supplied by enabling that one provider path. Sysmon image, network and DNS coverage remains conditional on its actual installation and configuration.",
        "AMSI Bridge inspects already observed script text. It accepts the bounded ETWR cmdline alias and explicit supported text fields; this is not a registered global AMSI provider or pre-execution interception. The unstable native in-process compatibility option stays off by default. A real malicious AMSI API verdict can carry already authenticated native ETWR PID, raw FILETIME, image and source proof only after checking the same bytes before and after scanning.",
        "That positive finding can enter separately opted-in forensic capture without granting process-response authority. Missing, stale, remote, drill, lossy or changed provenance preserves the critical content observation but holds automatic capture. No current-PID lookup substitutes for missing historical birth. Legacy active detectors without original raw FILETIME still leave this forensic path unavailable.",
        "Forensics retains an exact noninheritable native read/query process handle across bounded strings and owner-PID socket capture. It excludes protected system, Windows, self and Angerona targets. This is bounded evidence extraction, not a full process dump. AES-GCM frames, a random case key wrapped for the current user, authenticated terminal receipts and file/directory identity checks protect copied evidence at rest. Explicit operator export to a new directory is the only plaintext path.",
        "Finite clocks, deadlines, capacity and complete writes are checked. A failed frame encryption or write permanently poisons that writer: later append or terminal receipt calls cannot reuse the consumed AEAD nonce, and partial ciphertext remains without a valid completion claim. Ambiguous native close retains the exact owner and never retries its possibly recycled handle number. Further forensic capture is held until Core restart; other modules and normal STOP are not held for a file/process handle owned by Core. Current-user DPAPI and Python key handling do not defeat same-user or kernel compromise or guarantee RAM erasure.",
        "Native Sysmon DNS records now reach the lexical decoder through its source checks. Beacon cadence uses parsed addresses, PID birth and explicit continuity epochs; stable sockets and incomplete snapshots cannot fabricate repeat callbacks. These lexical/timing observations remain leads unless the existing separate corroboration and response conditions are met.",
        "SentinelLens is a bounded advisory read model. It normalizes supported imports, links anomaly evidence and explains possible next steps without executing remediation. Accepted queue work drains before stop; a failed builder retains its prior snapshot, retries, and discloses an unpublished suffix instead of claiming a clean flush. Imported data and graph proximity do not establish live source authenticity or malicious causation.",
    )),
    ("17 9 Signal optional integration and shutdown", (
        "Mobile Response Bridge remains separately opted in. It requires the configured exact native executable hash/publisher, account/operator identity and protected PIN. Commands retain sender, freshness, replay, one-use token and action scope checks. A local CLI invocation receipt does not prove Signal connectivity or recipient delivery, and a version self-test makes no such claim.",
        "A full invocation lease covers executable preflight, the fixed system Authenticode helper, the CLI operation and final executable-pin close. The child begins suspended, enters its owned Job, then runs. Output readers, native process/tree signals and closes are checked before a result can be verified. Unknown retirement preserves exact resources, fences further Signal launches and remains visible to Core shutdown; no process-name search or foreign target grants ownership.",
        "An unproven external tree prevents a false completed STOP receipt. A file-close-only reference after its tree and reader are proven retired holds this optional capability without blocking global restart forever. Failed notifications remain in a bounded retry digest; sending a digest cannot erase newer arrivals or mint replacement response permissions. No live Signal send, inbox or recipient acknowledgement was exercised by the documented offline review.",
    )),
    ("17 10 Adaptation recovery and preserved custom changes", (
        "Auto Adapt separates audit, a golden baseline, proposed exact changes, explicit approval, native readback and supported rollback. The change list and activity history explain what was proposed and what actually happened. Adjust scope before approval, then inspect receipts and residual drift. Unelevated firewall access-denied results are a visible prerequisite gap, not a reason to widen every module's authority.",
        "Source peers bind heartbeat counters to exact native invocation generations and stop advancing when supervision work exceeds its deadline. Source seals hold changed peers without silently overwriting intentional edits. GitHub repair uses the existing verified Safe Startup boundary and preserved originals. The 48-file recovery profile needs an explicit reviewed transition from an older updater that understands only the former 39-file profile.",
        "Canonical Windows storage derives from the actual process token so a helper's private USERPROFILE cannot redirect update/recovery roots. Reserved background helpers preserve failure exits and custody diagnostics without foreground MessageBoxes. An interactive failed launch still explains recovery; unknown source, ownership or authority must not be bypassed merely to paint a trusted-looking protection state.",
        "Public GitHub update checks default to their saved opt-in and prompt before installation. Download into staging, inspect source changes and custom additions, preserve settings, and activate through the reviewed update path. Source version 1.15.0 is not a new signed installed binary. Signed release signing, privileged service enrollment, native policy and hardware/witness acceptance remain their own deployments.",
    )),
    ("17 11 Individual module tests and supported recovery", (
        "Self-Test reports each module's own diagnostic and sample limits. Read the positive/negative fixture, unavailable dependency or permission, expected postcondition and actual result. A generic lifecycle check cannot substitute for observing the module's security job, and a mock provider result cannot establish a live provider.",
        "Bounded module workers and spare test slots let other eligible modules proceed while a slow test uses its own budget. A timeout remains incomplete or failed for that scope; it does not turn the whole session into an automatic pass or authorize an unsafe retry. The stored per-module time budget is separate from native custody and OS limits.",
        "Self-Test settings expose module-specific guidance, test code and separate editable copies. Automatic supported recovery is restricted to the explicitly selected module list; its code default is empty. Re-test and inspect the exact result after a supported repair. Do not clear alerts, replace evidence baselines or hot-load arbitrary code to make a result green.",
        "The complete module reference links every declared dedicated test for inspection. Supported repair guidance is conditional on the module and current manager generation; it is not a universal automatic patch engine or permission to bypass disabled policy, missing native collectors or unenrolled privilege.",
    )),
)


def add_workflows(doc):
    heading(doc, MARKER)
    para(doc, f"Current source guidance as of {DATE}. The public application version remains 1.15.0. Historical tests and dated implementation versions later in this manual retain their original scope. Fresh runtime, full repository tests, hosted checks and accepted signed deployment require their own evidence.")
    demos = {0: 4, 2: 0, 3: 2, 5: 3}
    for index, (title, paragraphs) in enumerate(WORKFLOWS):
        heading(doc, title, 2)
        for text in paragraphs:
            para(doc, text)
        if index == 2:
            para(doc, "Upstream references and licensing context: [Zero-Breach Toolkit](https://github.com/interplains/zero-breach-toolkit), [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team), [SigmaHQ](https://github.com/SigmaHQ/sigma), [Sysmon Modular](https://github.com/olafhartong/sysmon-modular), [YARA-X](https://github.com/virustotal/yara-x), [Apache Caldera](https://github.com/apache/caldera), [Velociraptor](https://github.com/Velocidex/velociraptor), and [Wazuh](https://github.com/wazuh/wazuh). Retain the selected pinned source and its own license; project inclusion is not an endorsement or complete platform integration.")
        if index in demos:
            add_demo(doc, demos[index])
        if index == 2:
            add_demo(doc, 1)
    heading(doc, "Threat scenarios and the expected review path", 2)
    scenarios = (
        ("Office document creates a script host", "Preserve native parent/child and script text, correlate available sources and examine the exact alert. A lexical or graph marker is a lead; supported corroborated active evidence may request Combat. Post-observation text inspection does not prove that execution was prevented."),
        ("A signed vulnerable driver may blind telemetry", "Inspect provenance, OS policy state and independent native canary gaps. A live worker can be deaf. Enrolled WDAC/HVCI prevention is conditional; no source-mode kernel immunity or intact-callback attestation exists."),
        ("A flagged executable changes during containment", "Retain native process/file/ancestor leases through intent, dispatch and postcondition or hold the action. Path firewall success does not prove PID-bound socket admission or established/inherited-flow teardown."),
        ("A newly attached device is suspicious", "Use Notifications and device review, validate identity and supported coverage, and keep consent/PIN and response gates. Host metadata cannot establish hidden cable firmware behavior. A displayed device is not a completed scan."),
        ("A verified breach requests network lockdown", "Native breach qualification and the existing opted-in authority decide whether a managed containment request can proceed. Review critical evidence and receipts; Lift Lockdown restores only managed changes. An imported report or dramatic red UI is not proof or a new firewall grant."),
        ("An attacker replays old local state", "Local integrity alone cannot establish whole-root freshness. An independently enrolled witness or hardware-backed floor must be available and bound to admission. OS servicing/version observations are partial evidence and do not replace vendor security updates."),
    )
    for title, text in scenarios:
        heading(doc, title, 3)
        para(doc, text)


def add_modules(doc):
    heading(doc, "18 Complete module reference")
    para(doc, "This complete static reference covers 86 built-in declarations. It explains declared roles, referenced settings and dedicated diagnostic code. A declaration or passed isolated fixture is not live collection, prevention, containment or a certification. Use the inspector's current prerequisites, health, selected policy and assurance. Links target the maintained source; individual module implementation versions may differ from application version 1.15.0.")
    for line in (ROOT / "docs/reference/modules.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            heading(doc, line[3:], 2)
        elif line.strip() and not line.startswith(("#", "This source index", "Open a module", "Declared modules")):
            para(doc, line)


def add_settings(doc):
    heading(doc, "19 Complete settings reference")
    para(doc, "The 164 stored fields below show code defaults and source comments, not any user's current preferences. An empty key or unset path is not permission to guess a credential. Use supported Settings/Full Setup controls, read the authority warning, and keep native/hardware/backend prerequisites separate. The Source link on each field opens its definition. Related workflow explanations above describe effects, gates and rollback.")
    rows = []
    for line in (ROOT / "docs/reference/settings.md").read_text(encoding="utf-8").splitlines():
        if line.startswith("| ["):
            values = [part.strip() for part in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
            assert len(values) == 4
            if not values[3]:
                field = re.search(r"`([^`]+)`", values[0])
                key = field[1] if field else ""
                notes = {
                    "data_dir": "Root for managed application data; source, installed and platform profiles have separate custody.",
                    "ollama_host": "Configured local model HTTP endpoint; transport/identity attestation and privacy policy remain separate.",
                    "ollama_model": "Exact model selection for local triage; a name is not proof that the model is available or verified.",
                    "module_states": "Stored per-module selections; enabled policy is distinct from running state, health and assurance.",
                    "selftest_timeout_seconds": "Time allowed for each module diagnostic; a longer budget does not waive custody or make a timeout pass.",
                    "selftest_auto_recover_modules": "Explicit modules eligible for supported automatic recovery; an empty list grants none.",
                    "github_tools_enabled": "Allows the managed tools feature; individual source, installation and execution gates remain separate.",
                    "github_tools_auto_prepare": "Permits configured automatic preparation; explicit managed uninstall intent remains effective.",
                    "github_tools_allow_download": "Allows supported public pinned downloads; no host capture upload or arbitrary execution permission.",
                    "github_tools_job_limit_mib": "Managed tool job storage budget in MiB; full admission preserves existing evidence.",
                    "github_tools_report_limit_mib": "Scanner report byte budget in MiB; independent of report-count selection.",
                    "github_tools_report_count": "Managed report slot limit or Unlimited count; other finite byte/inventory/free-space limits still apply.",
                    "github_tools_timeout_seconds": "Managed tool operation time budget; terminal coverage and retirement are reported separately.",
                    "spyware_scan_timeout_seconds": "Priority combined scan time budget; expiry preserves incomplete coverage instead of declaring a clean host.",
                }
                values[3] = notes.get(key, "Stored " + key.replace("_", " ") + " configuration. Read its linked definition and owning Settings topic for effective scope, validation and prerequisites.")
            rows.append(values)
    assert len(rows) == 164
    table(doc, ("Stored field and source", "Type", "Code default", "Meaning or constraint"), rows, (1.65, 0.6, 1.65, 2.6))


def purpose(label, kind, group="", source_href=""):
    text = label.casefold().replace("…", "").strip()
    exact_sources = {
        ("src/angerona/gui/spyware_guard_page.py", "pause"):
            "Pauses or resumes Research Wire headline scrolling, rotation and refresh animation only. It does not pause scanners, sensors or an already queued news download.",
        ("src/angerona/gui/spyware_guard_page.py", "feed details"):
            "Shows or hides the cached research summary, last feed check and per-source status. It does not fetch news, change network consent, approve indicators or pause a scan.",
        ("src/angerona/gui/spyware_guard_page.py", "news offline · enable research network access in policy / beacon."):
            "Dynamic research headline with a disabled offline placeholder. When an item is available, opens its cached read-only Intelligence brief. Network access is reviewed separately in News settings or Policy / Beacon; the headline does not enable it or fetch a report.",
        ("src/angerona/gui/spyware_guard_page.py", "import definitions"):
            "Queues worker validation and a preview of a local JSON pack of literal SHA-256, IP and domain indicators. Import does not activate the pack, run code or authenticate an external publisher.",
        ("src/angerona/gui/spyware_guard_page.py", "activate imported pack"):
            "Makes the exact reviewed imported indicator pack active after current generation, integrity, version, freshness and persistence checks. This is local data authorization; existing containment policy and target-evidence checks still apply, and publisher identity remains unverified.",
        ("src/angerona/gui/spyware_guard_page.py", "roll back to previous pack"):
            "Reactivates the exact retained previous indicator pack after current identity, freshness and persistence checks. Changes SpywareGuard definition data only; it does not undo process, firewall or operating-system actions.",
        ("src/angerona/gui/spyware_guard_page.py", "fetch & extract"):
            "Queues a public HTTPS research report for validated fetching and indicator extraction under research-network consent. Candidates retain provenance and need review before activation. It does not install a pinned tool, runtime or executable report.",
        ("src/angerona/gui/rules_playbooks.py", "detectionforge"):
            "Opens the existing DetectionForge authoring tab in Local SOC. Opening it does not fetch, install or activate a rule; authoring and activation retain that workflow’s review and permission gates.",
        ("src/angerona/gui/rules_playbooks.py", "create guided soar draft"):
            "Saves the builder’s severity, exact module filters and fixed notify or request_containment action as a declarative SOAR draft. Validation, testing and activation are separate; the global SOAR switch and original-evidence/response-policy gates remain required.",
        ("src/angerona/gui/curated_tools.py", "stop scan"):
            "Requests cancellation of the current native/toolkit scan. Cancellation stays pending until owned worker retirement is proven; partial progress and reports are preserved. It does not invoke Core STOP or quit the dashboard.",
        ("src/angerona/gui/main_window.py", "open angerona"):
            "Restores the main dashboard through Angerona’s normal Qt display-recovery route. It does not start another Core, approve a pending prompt or change protection policy.",
        ("src/angerona/gui/adaptation_workbench.py", "prepare automatically"):
            "Queues a fresh audit, exact plan, no-write sandbox and recommendation for the selected intent. Selected Enroll baseline can capture recovery; applying host changes still needs separate review and approval.",
        ("src/angerona/gui/adaptation_workbench.py", "reset circuit breaker"):
            "After confirmation, resets Adaptation’s cooldown history so profile changes can be considered again. Review Activity first; normal audit, plan and apply approvals still apply. This does not roll back host settings.",
        ("src/angerona/gui/red_team_console.py", "analogy coaching (flight instructor) — explain each step in plain english while it runs"):
            "Analogy coaching is reserved and hidden in this version. Launch keeps it off; this control cannot enable coaching or change a run.",
        ("src/angerona/gui/red_team_console.py", "■  stop & clean"):
            "Requests cancellation of this simulation, retirement of its owned work and cleanup of its registered inert targets. Completion waits for native ownership checks; it does not stop Core or close the dashboard.",
        ("src/angerona/gui/pages.py", "🛡  scan center"):
            "Opens the Scan Center view for folder/drive scans, optional Microsoft Defender requests and network reviews. Opening it does not start a scan; select the desired action and scope there.",
        ("src/angerona/gui/pages.py", "restore privacy defaults"):
            "Stages local-only privacy settings by switching optional cloud, mobile and remote egress controls off in this Settings view. Click Save to apply; this is not host rollback or a containment undo action.",
        ("src/angerona/gui/pages.py", "confirm & reset usb pin"):
            "Confirms a new protected USB PIN and revokes current Angerona USB approvals. Existing devices must pass review again; this does not approve a device, restore a security baseline or execute containment.",
        ("src/angerona/gui/pages.py", "explain trust and delivery details"):
            "Opens an explanation of the integration's trust and delivery boundaries. This is information only: it does not change trusted identities, send a message, grant response authority or verify delivery.",
        ("src/angerona/gui/display_recovery.py", "retry display"):
            "Hides this notice and requests two bounded Qt presentation attempts for the existing dashboard. The second retires owned visual effects and restores a plain window. It starts no recovery child and changes no engine, sensor, trust or response policy.",
        ("src/angerona/gui/display_recovery.py", "safe stop"):
            "Requests the existing tray-Quit shutdown path without an additional confirmation in this notice. Deliberate standdown and native-retirement checks keep their normal scope. It does not repair source or permit restart while an owned child lifetime remains unproven.",
        ("src/angerona/gui/display_recovery.py", "close notice"):
            "Closes only this presentation notice. Core continues under its existing settings; no scan, repair, trust decision or pending device approval is made.",
        ("src/angerona/gui/red_team_bridge.py", "retry tool"):
            "Requests the separate Red Team tool again only when this is still the current owner, its exact prior native lifetime is retired and Core is not stopping. The retry repeats source-seal, owned Job and authenticated IPC checks; it does not relax detection or response policy.",
        ("src/angerona/gui/red_team_bridge.py", "close"):
            "Closes only this startup-review window. The private failure receipt and pending notification remain; it does not restart the tool, stop Core, erase evidence or grant response authority.",
        ("src/angerona/gui/github_tools.py", "import pinned source"):
            "Downloads and validates the resolved pinned source archive in an owned background operation, then imports it into the managed catalog for review. Download, storage and cancellation limits apply. Importing does not activate its code or run its commands.",
        ("src/angerona/gui/pages.py", "🧹  clean & close"):
            "Requests this drill's supplied marker-cleanup callback in its owned worker, then closes the report. Active work queues cleanup until it can finish. Only supported owned drill artifacts are eligible; this is not blanket deletion or proof that the host is clean.",
        ("src/angerona/gui/recorder_integrity_controls.py", "create or show this host's public enrollment key"):
            "Explicitly requests this profile's protected host request identity, creating it when needed, and shows only its public key. Empty enrollment IDs are staged in the form. The private key remains in the OS credential store; this does not enroll the independent authority or grant trust.",
        ("src/angerona/gui/live_debug_panel.py", "add local review"):
            "Adds a verdict, reason and review time to the selected diagnostic row in this local view. The annotation can accompany a separate explicit export. It does not rewrite original source evidence, save an export automatically or change trust and response policy.",
        ("src/angerona/gui/red_team_console.py", "📥  import signed device report"):
            "Reads the chosen local JSON and submits its evidence to the enrolled-device assessment checks, then displays the accepted report. Rejected evidence remains refused. Importing does not enroll a new device, execute its commands or establish native attack detection or containment.",
        ("src/angerona/gui/patch_center.py", "review rollback"):
            "First builds a rollback review for the selected attempt. With its matching reviewed plan present, this control reads Apply reviewed rollback; that click requests service rollback with explicit approval. Review the exact plan, current authority and native result; this is not always a read-only action.",
        ("src/angerona/gui/rules_playbooks.py", "disable"):
            "Disables selected rule/playbook active data while preserving drafts and the previous revision. Global switches stay unchanged. It does not disable sensors, undo containment or grant response authority.",
        ("src/angerona/gui/telemetry_storage_controls.py", "block for this run"):
            "Pauses new telemetry storage admission for this run within current targets. Existing database, WAL, queue and history remain preserved. Save Settings persists the choice; this is not host isolation.",
    }
    for (suffix, expected_label), definition in exact_sources.items():
        if source_href.split("#", 1)[0].endswith(suffix) and text == expected_label:
            return definition
    exact_groups = {
        ("Suite map", "reset view"):
            "Resets only the Suite Map camera to its starting view. Orbit, pan and zoom can be adjusted again. It does not restore a security baseline, undo host changes, restart Core or alter evidence.",
        ("Storage controls", "block new recovery data"):
            "Requests blocking new recovery-cache and VSS work for this run while preserving existing copies. Read the result; Save Settings persists the choice. It does not isolate a host or process.",
        ("Threat intel page", "↩ stage rollback"):
            "Stages captured rollback instructions as text for review. It does not execute commands or restore host state. Any later supported execution requires its separate approval and target checks.",
        ("Ugcap page", "provision / show host public key"):
            "Gets or creates this host's Ed25519 witness identity in the OS credential store, then shows its public enrollment key. The private key stays in that store; this does not enroll an authority or grant trust.",
    }
    if (group, text) in exact_groups:
        return exact_groups[(group, text)]
    if kind == "Tab":
        return "Shows this topic within the current window. Read its current state and available controls; opening a tab grants no execution or response authority."
    if kind == "Menu":
        return "Opens the named group of commands. Each selected command retains its own prerequisites and review conditions."
    if kind in {"QCheckBox", "QRadioButton"}:
        return "Selects this option in the owning panel. Read its warning and save/apply requirements; a checked control alone does not establish runtime readiness."
    if "generated label" in text:
        return "Context-dependent label or icon. The linked declaration identifies the exact owner and handler; read the selected item before using it."
    if group == "Notification inbox" and text == "dismiss":
        return "Invokes this notification producer's dismiss action when it offers one. This is separate from Review and does not approve, trust or scan a pending device."
    if group == "Normal log controls":
        if text == "block for this run":
            return "Pauses normal Python and Qt crash-log appends for this run without deleting existing logs. Native fault output remains separate. Save Settings to persist the choice."
        if text == "allow within limits":
            return "Resumes normal Python and Qt appends within the displayed file, process and complete-message limits. Uncertain writes remain held; existing logs are preserved."
        if text == "apply now / retry":
            return "Applies the displayed logging pause and byte limits to this run, or retries a busy writer. Read the acceptance result; save Settings separately to persist the choice."
    if group == "Adaptation workbench":
        if text.startswith("auto adapt"):
            return "Opens security-intent selection, then automates a fresh audit, exact plan and no-write simulation. Preview is the default; applying still requires final exact-plan approval."
        if "adapt host with this preview" in text:
            return "Requests approval of this exact current firewall plan. It requires an enrolled recovery baseline and fresh rollback snapshot; changed or expired review invalidates approval."
        if text.startswith("roll back"):
            return "Requests confirmation before restoring the exact authenticated selected Windows Firewall snapshot. Fresh postconditions must verify the restore."
        if text.startswith("restore host baseline"):
            return "Requests restoration of the authenticated original Windows Firewall recovery baseline after identity and approval checks. Hardware and service observations are not restorable policy."
        if text.startswith("capture immutable host baseline"):
            return "Requests explicit enrollment of the current complete Windows Firewall policy as the permanent recovery default. An existing baseline is never silently replaced."
        if text.startswith("pin selected as known-good"):
            return "Records an exact selected drift exception with the operator's reason, then audits again. It does not silently approve unrelated findings."
        if text.startswith("dismiss false positive"):
            return "Records an exact selected drift exception and tuning feedback after collecting a reason, then reruns the audit. Review the new report and retained exception."
    rules = (
        (("stop", "quit"), "Requests the named operation or application to stop. Deliberate Core STOP inhibits automatic peer relaunch; native retirement must still be proven."),
        (("close", "hide"), "Closes or hides this view according to its owning handler. Closing a modeless detail view does not stop Core or grant consent to a pending prompt."),
        (("cancel",), "Requests cancellation or leaves this dialog undecided. Committed changes, preserved evidence and unknown native retirement are not silently undone."),
        (("rollback", "roll back", "restore", "revert", "undo", "reset"), "Returns the selected state or copy to its supported baseline/revision. Read the scope; live changes require the original identity, current validation and a supported undo receipt."),
        (("delete", "remove", "uninstall"), "Removes the selected managed item within this workflow. Review the retained originals, evidence and confirmation; removal is not a clean-host claim."),
        (("self", "test", "validate", "check", "verify"), "Checks this selected capability, data or prerequisite. Read the exact fixture, positive/negative outcome, held reason and coverage; a pass is limited to that test."),
        (("install", "prepare", "download", "fetch"), "Prepares the selected pinned source, runtime or data under its download/storage policy. Preparation alone does not activate arbitrary code or establish host protection."),
        (("save", "export", "copy"), "Stores or copies the indicated draft, settings, report or selected details. Read the destination/scope and preserve private evidence; a saved copy does not grant runtime authority."),
        (("scan", "run", "start"), "Starts the named supported workflow with its selected scope and policy. Follow measured progress, current task, cancellation and the actual terminal coverage report."),
        (("settings", "configure", "setup"), "Opens configuration for this feature. Review defaults, prerequisites and warnings, save explicitly where required, and retain protected credential handling."),
        (("activate", "enable", "apply", "approve", "allow", "trust"), "Requests the named selected change. Review its exact source/object, preview and authority; separate policy, validation, consent and native postconditions remain effective."),
        (("disable", "block", "isolate", "kill", "suspend", "contain", "lockdown", "patch"), "Requests the named scoped protection or response action. It needs the supported current target, evidence, opt-in/privilege and a truthful result receipt."),
        (("detail", "review", "preview", "inspect", "investigate", "trace", "history", "report", "view", "open", "show", "info", "help", "credits", "source", "diff"), "Opens the named evidence, explanation, original source or comparison. Review is read-side context and does not itself approve a target, execute code or confer trust."),
        (("refresh", "reload", "retry"), "Reads current state or repeats this supported operation. Preserved failure evidence and coverage gaps remain; retry does not bypass verification."),
        (("clear", "select", "filter", "sort", "next", "previous", "browse", "choose", "search"), "Changes the indicated selection, filter, input or visible records in this panel. Inspect the resulting scope before starting an action."),
    )
    matches = []
    for order, (words, definition) in enumerate(rules):
        for word in words:
            match = re.search(r"(?<!\w)" + re.escape(word) + r"(?!\w)", text)
            if match is not None:
                matches.append((match.start(), order, definition))
    if matches:
        # "Open download portal" opens a page; "Allow ... next scan" changes
        # admission. A later noun must not override the label's first action.
        selected = min(matches)[2]
        first = re.search(r"\b([a-z][a-z-]*)\b", text)
        effectful = {"create", "provision", "import", "download", "clean", "reset", "restore",
                     "save", "apply", "enable", "disable", "delete", "remove", "add", "enroll",
                     "send", "start", "run", "launch", "install", "prepare", "fetch", "approve",
                     "trust", "uninstall", "revoke", "record", "pin"}
        if first and first[1] in effectful and "Review is read-side context" in selected:
            return (
                "Invokes the linked handler for the current item. Review its exact scope, approval, "
                "network and storage requirements before proceeding; this reference does not establish "
                "that the action is side-effect-free or grant execution, trust or response authority."
            )
        return selected
    return "Uses the named control in this owning view. The linked handler is the exact source reference; inspect its current selection, warning and result before acting."


def add_controls(doc):
    source_text = (ROOT / "docs/reference/interface-controls.md").read_text(encoding="utf-8")
    declared = re.search(r"Declared control sites: \*\*(\d+)\*\*", source_text)
    assert declared, "The generated control inventory must declare its exact count"
    count = int(declared[1])
    heading(doc, "20 Complete interface control reference")
    para(doc, f"This index covers all {count} declared control sites across the GUI sources: buttons, actions, toggles, options, tabs and menus. Shared builders and generated labels can produce more than one live control. The descriptions define the action family; the linked line identifies its exact implementation and contextual scope. Current selections, dynamic labels, unavailable providers and separate authority warnings must be read in the actual view. This inventory is not a claim that every optional integration is deployed.")
    group, rows, total = None, [], 0
    kinds = {"QPushButton": "button", "QAction": "action", "QCheckBox": "toggle", "QRadioButton": "option"}
    def flush():
        if group and rows:
            heading(doc, group, 2)
            table(doc, ("Control", "What it does and how to read it", "Code"), rows, (1.7, 4.15, 0.65))
    for line in source_text.splitlines():
        if line.startswith("## "):
            flush()
            group, rows = line[3:], []
        elif line.startswith("| ") and not line.startswith(("| Control", "| ---")):
            values = [part.strip() for part in re.split(r"(?<!\\)\|", line.strip().strip("|"))]
            assert len(values) == 4
            label, kind, owner, source = values
            match = re.search(r"\]\(([^)]+)\)", source)
            assert match
            url = match[1]
            number = re.search(r"#L(\d+)$", url)
            code = f"[L{number[1]}]({url})" if number else f"[Source]({url})"
            rows.append((plain(label) + " (" + kinds.get(kind, kind.casefold()) + ")", purpose(plain(label), kind, group, url), code))
            total += 1
    flush()
    assert total == count


def normalize_figures(path):
    import hashlib
    import xml.etree.ElementTree as ET
    assets = {p.name: p for p in (ROOT / "assets").glob("security-flow-*.png")}
    assets.update(DEMO_PATHS)
    hashes = {hashlib.sha256(p.read_bytes()).digest(): leaf for leaf, p in assets.items()}
    with ZipFile(path) as source:
        parts = {item.filename: source.read(item.filename) for item in source.infolist()}
    mapping = {}
    for name, data in parts.items():
        if name.startswith("word/media/"):
            leaf = hashes.get(hashlib.sha256(data).digest())
            if leaf is None:
                raise ValueError("Unreviewed embedded manual image")
            mapping[name] = "word/media/" + leaf
    relpath = "word/_rels/document.xml.rels"
    relationships = ET.fromstring(parts[relpath])
    ET.register_namespace("", "http://schemas.openxmlformats.org/package/2006/relationships")
    for item in relationships:
        target = item.attrib.get("Target", "")
        if "word/" + target in mapping:
            item.set("Target", mapping["word/" + target][5:])
    parts[relpath] = ET.tostring(relationships, encoding="utf-8", xml_declaration=True)
    temporary = path.with_suffix(".docx.tmp")
    with ZipFile(temporary, "w", compression=8) as output:
        for name, data in parts.items():
            output.writestr(mapping.get(name, name), data)
    temporary.replace(path)


def update_manual(source):
    doc = Document(source)
    if any(p.text == MARKER for p in doc.paragraphs):
        return False
    history = take_block(doc, "17. Version history and changelog")
    dated = []
    for title in ("Operator update 8 October 2026", "Operator update 9 October 2026",
                  "All requested security integrations belong to v1.14", "Current validation record"):
        if any(p.text == title for p in doc.paragraphs):
            dated += take_block(doc, title, level=1 if title.startswith("Operator") else 2)
    titles = [p.text for p in doc.paragraphs if p.style.name == "Heading 2" and re.match(r"[123] November ", p.text)]
    for title in titles:
        dated += take_block(doc, title, level=2)
    for p in doc.paragraphs:
        if p.style.name == "Title":
            p.text = "Angerona Master Manual"
        if p.text == "3 November 2026":
            p.text = DATE
        if p.text == "OPERATOR REFERENCE":
            p.text = "OPERATOR REFERENCE"
            for run in p.runs:
                run.font.color.rgb = RGBColor(0, 0, 0)
        if p.text == "Master Manual":
            p.text = "Operator procedures and complete reference"
            p.style = doc.styles["Subtitle"]
        if p.text == "Local-first detection, investigation, response, recovery, and validation":
            p.text = "Conditional telemetry reviewed response and explicit recovery limits"
            p.style = doc.styles["Subtitle"]
        if p.text == "17. Version history and changelog":
            p.text = "21. Update history and earlier evidence at the end"
    for row in doc.tables[1].rows:
        if row.cells[0].text == "Release state":
            row.cells[1].text = "Version 1.15.0 source maintenance as of 9 November 2026. Signed installed releases and their acceptance remain separate. Current workflows and complete references precede the final update history."
        if row.cells[0].text == "Source of truth":
            row.cells[1].text = "Maintained repository source and the complete declaration/control references in this revision. Current runtime, full-suite and hosted validation require evidence for their exact commit. Earlier dated tests and historical implementation labels retain their original scope."
    doc.tables[0].cell(0, 0).text = "Angerona is a local endpoint detection and response (EDR), network detection and response (NDR), and security orchestration automation and response (SOAR) suite. This manual explains workflows, evidence review, conditional response authority and recovery for source version 1.15.0. Declarations and historical fixtures do not certify live protection."
    doc.core_properties.subject = "Source 1.15.0 operator workflows and complete reference"
    doc.core_properties.comments = "Maintained 9 November 2026; current workflows and complete declaration references precede dated historical evidence."
    for section in doc.sections:
        for p in section.footer.paragraphs:
            if "Angerona Suite  |  v" in p.text:
                p.text = f"Angerona Suite  |  v1.15.0  |  {DATE}"
    add_workflows(doc)
    add_modules(doc)
    add_settings(doc)
    add_controls(doc)
    # Preserve the entire original history and dated evidence, including tables.
    body = doc._element.body
    for node in history + dated:
        text = element_text(node)
        if text == "17. Version history and changelog":
            for item in node.iter(qn("w:t")):
                item.text = "21 Update history and earlier evidence"
                break
        elif text.startswith("17."):
            for item in node.iter(qn("w:t")):
                if item.text and item.text.startswith("17."):
                    item.text = "21." + item.text[3:]
                    break
        if node in dated:
            props = node.find(qn("w:pPr"))
            if props is not None:
                style = props.find(qn("w:pStyle"))
                if style is not None and style.get(qn("w:val")) == "Heading1":
                    style.set(qn("w:val"), "Heading2")
            if text == "Current validation record":
                for item in node.iter(qn("w:t")):
                    item.text = "Earlier validation record from 3 November 2026"
                    break
        body.insert(len(body) - 1, node)
    heading(doc, "9 November 2026 source maintenance", 2)
    para(doc, "Added the current community tool hub, separate editable copies, rules/playbook tactics builder and global switches, standalone Red Team ownership, Suite Map, complete module/settings/control references, truthful Signal and post-observation AMSI/forensic behavior, and source-storage/background-helper recovery corrections. These source changes remain within 1.15.0. Hosted checks and fresh runtime results belong to their exact reviewed commit; this history does not invent a universal protection or detection-rate claim.")
    # Rebuild the plain contents in actual heading order. Match real heading
    # styles when relocating blocks, never their duplicate contents labels.
    contents = next(p for p in doc.paragraphs if p.text == "Contents" and p.style.name == "Heading 1")
    child = contents._p.getnext()
    while child is not None:
        style = child.find("./" + qn("w:pPr") + "/" + qn("w:pStyle"))
        if style is not None and style.get(qn("w:val")) == "Heading1":
            break
        following = child.getnext()
        body.remove(child)
        child = following
    headings = [p.text for p in doc.paragraphs if p.style.name == "Heading 1"
                and p.text not in {"Contents", "Document control"}]
    cursor = contents._p
    for title in headings:
        p = doc.add_paragraph(title)
        cursor.addnext(p._p)
        cursor = p._p
    for t in list(doc.tables):
        if len(t.rows) == 1 and len(t.columns) == 1:
            p = doc.add_paragraph(t.cell(0, 0).text)
            t._tbl.addprevious(p._p)
            t._tbl.getparent().remove(t._tbl)
    for paragraph in doc.paragraphs:
        if paragraph.text.startswith("The final live campaign required five automatic rounds."):
            paragraph.text = CURRENT_VALIDATION
    style_document(doc)
    ordered = [p.text for p in doc.paragraphs if p.style.name == "Heading 1"]
    assert ordered[-1] == "21 Update history and earlier evidence"
    assert ordered.index("18 Complete module reference") < ordered.index("19 Complete settings reference")
    assert ordered.index("19 Complete settings reference") < ordered.index("20 Complete interface control reference")
    assert ordered.index("20 Complete interface control reference") < ordered.index("21 Update history and earlier evidence")
    doc.save(MANUAL)
    normalize_figures(MANUAL)
    return True


PATCH_SECTIONS = (
    ("Kernel callback stripping and vulnerable drivers", "Provider-specific ETW/Sysmon canaries bind benign native probes, collector generations and authenticated persistence. Missing echoes and unavailable collectors remain explicit even when a peer heartbeat advances. Driver provenance and optional policy source support reviewed materials, enrollment, approvals and native readback under their own deployment gates.", "A Ring 3 agent cannot prove intact kernel callbacks, force HVCI or prevent every signed vulnerable driver. WDAC enforcement, protected service authority and real host policy acceptance are conditional deployments. The default diagnostic path is not a kernel enforcement backend. Update Windows and use the operating system's supported protections."),
    ("WER dump precursors and frozen peers", "Bounded WER process/access correlation uses cached exact owned PID, birth and role context with authenticated source and shared deadlines. Freshness and ownership gaps remain explicit. Component EKGs require counter progress from the observed generation, not mere PID presence; Black Box pulses from its real event loop.", "Post-event correlation cannot guarantee pre-dump blocking. An administrator/kernel attacker can suspend multiple user-mode peers before they recover one another. This source update supplies neither an accepted ELAM enrollment nor a certified antimalware PPL boundary. It must not automatically kill legitimate WER solely from a broad name match."),
    ("Executable replacement and containment races", "Reviewed Combat transactions retain native process, executable and ancestor identity leases across durable intent, dispatch, postconditions and managed compensation. Ambiguous target/custody keeps the action held. Standalone Red Team requests retain exact parent/child generation, bounded capabilities and authenticated directional IPC; cleanup cannot manufacture response credit.", "The retained file is not proof of the process's original mapped image. A path firewall rule does not establish PID-birth-bound ALE admission or prove all inherited/established sockets were torn down. A production native egress backend and its accepted postconditions remain separate. Historical graph descendants do not authorize a blanket process-tree kill."),
    ("OS downgrade and whole root replay", "Bounded servicing review examines recognized queued operations and critical disk version resources. Optional independent witness and TPM source protocols bind freshness to enrolled checkpoints before protected state admission. Hardware preparation can verify externally provisioned certification material and construct constrained writer plans.", "A version read is not signer, loaded-image, vulnerability applicability or vendor patch proof. The source adapter does not provision a TPM writer or enroll hardware. Local SQLite/HMAC integrity alone cannot detect replay of the entire matching trusted root. Independent administration, protected hardware writers, serialized freshness and actual deployment acceptance remain required."),
    ("Same user compromise and historical evidence", "Optional independent recorder signatures bind exact row bytes, predecessor/epoch/range and durable pending claims. Installed-engine source validates its virtual account, service process, restricted token, package and protected root before sensitive work. Source seals and generation-bound supervision hold changed peers while preserving intentional edits for recovery review.", "Source Observe still shares its user's failure domain. A same-user or kernel attacker can reach local keys, memory and the initial trust anchor. Witnessing is optional and external; finite epoch/archive capacity can pause new work. No Python secure-erasure, forward-secure MAC, whole-authority rollback immunity or signed deployed PPL claim is made merely by this version label."),
    ("Exact forensic identity and encrypted capture", "Separately opted-in capture requires fresh authenticated active original raw process birth; it never substitutes whichever process now owns a PID. Native read/query handles remain held across bounded strings/socket evidence. AES-GCM frames, current-user-wrapped per-case keys, authenticated terminal receipts, directory/file custody, finite deadlines and complete export writes protect copied artifacts and identify partial work. Any frame encryption or write failure permanently poisons that writer, preventing a retry or terminal receipt from reusing its consumed AEAD nonce; partial ciphertext stays preserved.", "This is bounded strings/socket evidence, not a full memory dump. System/Windows/self targets are excluded and denied/native/PPL reads can leave gaps. Current-user DPAPI does not resist that same user's compromise or kernel access. Explicit plaintext export creates sensitive copies. Ambiguous close holds further capture, with exact owners retained, but does not block unrelated modules or normal STOP for Core-owned handles. A rare descriptor-transfer failure during artifact construction remains a cleanup gap; it supplies neither plaintext nor an authenticated completion claim."),
    ("AMSI DNS beacon and advisory analysis", "The script consumer accepts the actual ETWR command-line alias. A real AMSI malicious API verdict may retain already authenticated native PID/raw FILETIME/image/source proof only after exact pre/post content checks. Sysmon22 reaches the lexical DNS decoder. Beacon cadence uses parsed addresses, birth-bound history and continuity epochs. SentinelLens retains and retries unpublished advisory analysis.", "AMSI is post-observation, not a global provider or pre-execution hook; the unstable native compatibility option stays off by default. Missing original identity holds forensic capture without discarding the content finding. Current ETWR process starts do not imply native ETW DLL/network coverage. Lexical DNS, timing and graph proximity remain leads; they do not authorize response by themselves."),
    ("Community source rules and optional remote integration", "Pinned source review, separate editable copies, constrained adapters and data-only routing preserve scope. Community YARA and SOAR globals default off. Validation/activation recheck the exact draft, source and candidate aggregate under bounded owned-worker custody. Signal now retains its full preflight/helper/reader/tree/close lifetime, preserves failed digest batches, and reports local invocation separately from delivery.", "Community review is operator intent, not a vendor signature or a safe-code certificate. Editable copies are not an OS sandbox; full third-party platforms are not absorbed by an adapter. Imported prose and LLM output cannot confer mutation authority. Live Signal send, inbox and recipient delivery were not tested in the offline review; its configuration, pins, protected PIN and command scopes remain required."),
    ("Recovery availability storage and deliberate shutdown", "Canonical Windows storage uses the actual process token rather than a helper's private USERPROFILE. Background reserved helpers preserve failure exits without foreground MessageBoxes. Source peer seals, bounded recovery alternatives, retained diagnostics and explicit profile migration preserve code/evidence. STOP closes admission and records deliberate standdown; uncertain external child retirement stays visible. Bounded Qt recovery and tool-startup receipts preserve retry checks. Black Box skips unchanged health-table work.", "A recovery dashboard does not run sensors or prove protection. Unknown source, native ownership or trust must remain held rather than loading arbitrary code to claim a successful launch. Disk budgets bound future admissions without erasing existing evidence. Signed binaries, kernel/service deployment and independent release acceptance remain separate from source maintenance."),
)


def build_summary():
    doc = Document()
    doc.core_properties.title = "Angerona 1.15 Security Patch Summary"
    doc.core_properties.subject = "Implemented source fixes and remaining deployment exposure"
    doc.core_properties.comments = "Source version 1.15.0 maintenance, 9 November 2026."
    doc.core_properties.created = datetime(2026, 11, 9, tzinfo=timezone.utc)
    for s in doc.sections:
        s.page_width, s.page_height = Inches(8.5), Inches(11)
        s.top_margin = s.bottom_margin = Inches(0.75)
        s.left_margin = s.right_margin = Inches(0.85)
    doc.add_paragraph("Angerona 1 15 Security Patch Summary", "Title")
    para(doc, "Implemented source fixes and remaining deployment exposure", "Subtitle")
    para(doc, f"Source application version 1.15.0 | {DATE}")
    para(doc, "Version 1.15 strengthens process identity, telemetry continuity, evidence custody, governed response and recovery. These changes reduce specific failure paths; they do not patch Windows itself, supply kernel immunity or prove that every exploit is blocked. This report explains what the source implements, how it can help an operator, and which exposures still require operating system protections or separately accepted deployments.")
    para(doc, "The release state is source maintenance. A new source/application label does not replace the existing signed release baseline. Current full repository tests, fresh Core observation and GitHub checks must be attached to their exact reviewed revision; older or overlapping fixture cohorts are not a final acceptance claim. Raw host captures and private evidence are excluded from this public report.")
    heading(doc, "What operators should do first")
    for text in (
        "Keep Windows and supporting security controls updated. Read the current operating posture and coverage gaps before enabling response, driver policy, hardware freshness or remote commands.",
        "Retain original alerts and reports, review supported exact targets and response receipts, and distinguish a held collector or incomplete scan from a clean result. Keep custom source changes separate and preserved when reviewing updates or recovery.",
        "Use module-specific tests, current native collection proof and bounded live observation to establish the capability you actually need. A green thread, shape, parser check or mock detector result is not a whole-PC protection certification.",
    ):
        para(doc, text, "List Bullet")
    for title, change, residual in PATCH_SECTIONS:
        heading(doc, title)
        para(doc, "Applied change. " + change)
        para(doc, "Remaining exposure. " + residual)
    heading(doc, "Capability and deployment matrix")
    matrix = (
        ("Native telemetry canaries", "Scoped implemented path", "Requires current actual collector, nonce echo and durable receipt; not kernel integrity."),
        ("WDAC and vulnerable-driver enforcement", "Conditional deployment", "External privilege/enrollment, approvals and native readback; default diagnostic path is not enforcement."),
        ("ELAM or protected antimalware PPL", "Not supplied as accepted deployment", "Needs appropriate signing, installation and Windows protection authority."),
        ("Process and executable leases", "Implemented reviewed transactions", "Mapped-image proof, full inherited socket control and native ALE admission remain separate."),
        ("TPM and independent witness freshness", "Conditional external authority", "Hardware provisioning and protected serialized writer/witness administration are not created by source code."),
        ("Encrypted forensic evidence", "Opt-in bounded capture", "Requires original exact identity and native permission; same-user/key compromise and plaintext exports remain sensitive."),
        ("AMSI script inspection", "Post-observation consumer", "Native in-process compatibility option off by default; no global pre-execution provider claim."),
        ("Signal bridge", "Optional source integration", "Local invocation/retirement tests are not live account, send/receive or delivery verification."),
        ("Community tools and playbooks", "Constrained adapters and data", "No automatic arbitrary script authority or complete external-platform installation."),
    )
    table(doc, ("Capability", "Current source scope", "Acceptance still required"), matrix, (1.65, 1.75, 3.4))
    heading(doc, "Verification and residual priorities")
    para(doc, "Focused offline tests exercise genuine refusal and completion paths, with injected native/provider faults explicitly identified. One final hidden owned-child forensic query test proved its own native birth, image, exit and handle retirement without reading foreign memory or sockets. Those scoped observations cannot be expanded into a host-wide success percentage. Live Signal transport, independently trusted policy/hardware/service deployment and a real globally registered AMSI provider remain unverified or unavailable as described above.")
    para(doc, "The most consequential remaining risk is an attacker controlling the kernel or the same user context as a source deployment. Improve that boundary through supported Windows mitigations and a separately accepted signed privileged deployment, independent freshness authority and native egress enforcement. Keep optional integrations disabled until their prerequisites and operational recovery have been reviewed. Do not treat automatic source repair or a local hash check as resistance to a hostile kernel.")
    para(doc, "Read the [master manual](" + BASE_URL + "docs/master-manual.md) for complete module, settings and control references. The [security flow](" + BASE_URL + "docs/security-flow.md), [community tools](" + BASE_URL + "docs/community-tools.md) and [recovery guide](" + BASE_URL + "docs/resilience-recovery.md) explain the corresponding evidence, review and deployment gates.")
    style_document(doc)
    doc.styles["Heading 1"].paragraph_format.space_before = Pt(12)
    doc.styles["Heading 1"].paragraph_format.space_after = Pt(6)
    doc.styles["Normal"].paragraph_format.space_after = Pt(4)
    SUMMARY.parent.mkdir(parents=True, exist_ok=True)
    doc.save(SUMMARY)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=MANUAL)
    options = parser.parse_args()
    changed = update_manual(options.source)
    build_summary()
    print("Updated 1.15 manual" if changed else "Current manual revision already present")
    print("Security patch summary written; render and inspect both artifacts before publication")


if __name__ == "__main__":
    main()
