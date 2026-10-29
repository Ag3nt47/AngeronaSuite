"""Update the security-flow chapter while preserving unrelated DOCX ZIP parts.

Run with the managed document runtime for --build-assets (Pillow). Ordinary
update/--check uses only the standard library. Rendering is a separate required
publication gate; this script never declares visual QA complete.
"""
from __future__ import annotations

import argparse
import ast
from html import unescape
import re
import struct
from pathlib import Path
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
MANUAL = ROOT / "Angerona_Master_Manual.docx"
DOCS = (ROOT / "docs/security-flow.md", ROOT / "docs/safe-startup-recovery.md",
        ROOT / "docs/zero-breach-toolkit.md")
ASSETS = ("security-flow-overview.png", "security-flow-startup.png", "security-flow-response.png",
          "security-flow-tools.png", "security-flow-breach.png")
START = b"<!-- ANGERONA_SECURITY_FLOW_START -->"
END = b"<!-- ANGERONA_SECURITY_FLOW_END -->"
TITLE = "Security flow integrations and recovery"
REVISION_DATE = "29 October 2026"
REVISION_UTC = b"2026-10-29T00:00:00Z"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL = "http://schemas.openxmlformats.org/package/2006/relationships"
CONTENT = "http://schemas.openxmlformats.org/package/2006/content-types"


def capability_rows():
    rows = []
    for path in sorted((ROOT / "src/angerona/modules").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        constants = {}
        for statement in tree.body:
            if isinstance(statement, ast.Assign):
                for target in statement.targets:
                    if isinstance(target, ast.Name):
                        try:
                            constants[target.id] = ast.literal_eval(statement.value)
                        except (ValueError, TypeError):
                            pass
        for node in tree.body:
            if not isinstance(node, ast.ClassDef) or not any(
                isinstance(base, ast.Name) and base.id == "BaseModule" for base in node.bases
            ):
                continue
            values = {}
            for field in node.body:
                if isinstance(field, ast.Assign):
                    for target in field.targets:
                        if isinstance(target, ast.Name):
                            try:
                                values[target.id] = (constants[field.value.id]
                                    if isinstance(field.value, ast.Name) and field.value.id in constants
                                    else ast.literal_eval(field.value))
                            except (ValueError, TypeError):
                                pass
            rows.append((str(values.get("name", node.name)), path.relative_to(ROOT).as_posix(),
                         str(values.get("capability_mode", "inherited contract")),
                         str(values.get("response_authority", "inherited contract"))))
    return rows


def refresh_inventory(check=False):
    path = DOCS[0]
    text = path.read_text(encoding="utf-8")
    marker = "<!-- CAPABILITY_SOURCE_INVENTORY -->"
    if text.count(marker) != 1:
        raise ValueError("capability inventory marker is missing or ambiguous")
    prefix = text.split(marker)[0] + marker
    rows = capability_rows()
    lines = [f"\n\n**{len(rows)} built-in capability declarations.**\n",
             "| Capability | Source | Declared mode | Declared response authority |",
             "| --- | --- | --- | --- |"]
    for name, relative, mode, authority in rows:
        clean = lambda value: value.replace("|", "/").replace("\n", " ")
        lines.append(f"| {clean(name)} | [{Path(relative).name}](../{relative}) | {clean(mode)} | {clean(authority)} |")
    result = prefix + "\n".join(lines) + "\n"
    if check and result != text:
        raise ValueError("capability inventory differs from current source declarations")
    if not check:
        path.write_text(result, encoding="utf-8", newline="\n")


def build_assets():
    from PIL import Image, ImageDraw, ImageFont

    fonts = Path("C:/Windows/Fonts")
    font = lambda size, bold=False: ImageFont.truetype(str(fonts / ("arialbd.ttf" if bold else "arial.ttf")), size)
    colors = dict(ink="#17263B", blue="#235A86", pale="#EDF4FA", border="#8BA4BA", muted="#41566C")

    def diagram(name, title, subtitle, steps, foot, row_height=184, stop_branch=None):
        width, height = 1600, 280 + 4 * row_height + 150
        canvas = Image.new("RGB", (width, height), "white")
        draw = ImageDraw.Draw(canvas)
        draw.text((62, 42), title, fill=colors["ink"], font=font(49, True))
        draw.text((64, 108), subtitle, fill=colors["muted"], font=font(28))
        y0 = 200
        for index, (heading, lines) in enumerate(steps):
            column, row = index % 2, index // 2
            x, y = 62 + column * 770, y0 + row * row_height
            draw.rounded_rectangle((x, y, x + 704, y + row_height - 44), radius=14,
                                   fill=colors["pale"], outline=colors["border"], width=2)
            draw.text((x + 22, y + 17), heading, fill=colors["blue"], font=font(33, True))
            for n, line in enumerate(lines):
                draw.text((x + 22, y + 64 + n * 35), line, fill=colors["ink"], font=font(29))
            if column == 0:
                mid = y + (row_height - 44) // 2
                draw.line((x + 716, mid, x + 748, mid), fill=colors["blue"], width=4)
                draw.polygon(((x + 748, mid), (x + 737, mid - 8), (x + 737, mid + 8)), fill=colors["blue"])
            if column == 1 and row < 3:
                bottom, center = y + row_height - 44, x + 352
                next_center, next_top = 62 + 352, y + row_height
                middle = bottom + 22
                draw.line(((center, bottom), (center, middle), (next_center, middle),
                           (next_center, next_top)), fill=colors["blue"], width=3)
                draw.polygon(((next_center, next_top), (next_center - 7, next_top - 10),
                              (next_center + 7, next_top - 10)), fill=colors["blue"])
        footer_y = y0 + 4 * row_height + 4
        if stop_branch:
            # An explicit operator branch is separate from the numbered
            # evidence/response sequence and fits the existing footer space.
            if stop_branch == "left":
                origin = (62, y0 + 2 * row_height + (row_height - 44) // 2)
                route = (origin, (30, origin[1]), (30, 904), (94, 904), (94, 955))
            else:
                origin = (1536, y0 + row_height + (row_height - 44) // 2)
                route = (origin, (1568, origin[1]), (1568, 904), (94, 904), (94, 955))
            draw.line(route, fill=colors["blue"], width=3)
            draw.polygon(((94, 955), (87, 945), (101, 945)), fill=colors["blue"])
            draw.text((440, 914), "Operator STOP / tray Quit branch", fill=colors["blue"], font=font(29, True))
            stop_steps = (
                ("Persist stop intent", "HMAC before teardown"),
                ("Fence new starts", "AI • modules • respawn"),
                ("Retire owned work", "AI • helpers • owned jobs"),
                ("Exit this run", "Normal launch resumes"),
            )
            for index, (heading, detail) in enumerate(stop_steps):
                x = 64 + index * 386
                draw.text((x, 962), heading, fill=colors["blue"], font=font(27, True))
                draw.text((x, 1000), detail, fill=colors["ink"], font=font(23))
                if index < 3:
                    arrow = x + 330
                    draw.line((arrow, 982, arrow + 34, 982), fill=colors["blue"], width=3)
                    draw.polygon(((arrow + 34, 982), (arrow + 24, 975), (arrow + 24, 989)), fill=colors["blue"])
            footer_y = 1070
        for n, line in enumerate(foot):
            draw.text((64, footer_y + n * 38), line, fill=colors["muted"], font=font(28, n == 0))
        output = ROOT / "assets" / name
        output.parent.mkdir(exist_ok=True)
        canvas.save(output, optimize=True)

    diagram(ASSETS[0], "Angerona security flow", "User-mode workbench • evidence, authority and readiness are separate", [
        ("1  Paint and verify startup", ["Native shell before Python / Qt checks", "Source Observe or signed installed scope"]),
        ("2  Collect observations", ["Process • files • memory • network • logs", "Platform, privilege, age and loss stay visible"]),
        ("3  Authenticate evidence", ["Producer schema • continuity • replay", "Record authentication is a separate check"]),
        ("4  Detect and correlate", ["86 declared capabilities • shared services", "Lead, exposure, detection and gap differ"]),
        ("5  Investigate and authorize", ["Dashboard • cases • optional advisory AI", "Typed target • policy • approval • capability"]),
        ("6  Act and verify outcome", ["Authorized adapter • durable action journal", "Exact target • result receipt • supported Undo"]),
        ("7  Retain and recover", ["Cases and keys differ from disposable cache", "Bounded budgets • preserved originals"]),
        ("8  Show liveness and recovery", ["Real heartbeat EKG • stale = red flatline", "Native Retry / Close • protection unverified"]),
    ], ["Ring 3 boundary: no kernel immunity or universal coverage claim.",
        "A ready window does not prove live sensors, installed authority or successful response."], stop_branch="left")
    diagram(ASSETS[1], "Safe Startup recovery flow", "Native dashboard paints first • engine remains unverified", [
        ("1  Read explicit controls", ["STOP state • recovery / GitHub controls", "Automatic retries never clear STOP"]),
        ("2  Paint independent dashboard", ["Verified operational pins • native OS UI", "Run + PID/birth receipt • 20 s bound"]),
        ("3  Check and repair in background", ["Probe phase 30 s • overall 100 s", "85 / 87 / 1223 never mean source defect"]),
        ("4  Try safe launch alternatives", ["Ordinary • software Qt • no Tk window", "Verified repair • exclusive mutation only"]),
        ("5  Preserve and recover source", ["Last ready • exact GitHub HEAD / parent", "Private originals • no concurrent overwrite"]),
        ("6  Prove dashboard readiness", ["Fresh nonce • live PID generation", "Event loop responding • full gates retained"]),
        ("7  Review after recovery", ["Keep working • review later", "Try preserved edits at NEXT startup only"]),
        ("8  Recovery remains available", ["Bounded phase logs • missing logs explicit", "Retry / Close • protection unverified"]),
    ], ["Diagnostic history and recommended free-space reserves do not block the dashboard.",
        "Source trust, process custody and actual private data writes remain checked.",
        "Recovery never clears alerts, replaces keys or silently enrolls an altered baseline."])
    diagram(ASSETS[2], "Governed response flow", "Observations and AI text do not grant mutation authority", [
        ("1  Establish evidence", ["Enrolled producer and typed event contract", "Freshness • continuity • explicit coverage"]),
        ("2  Bind the exact target", ["PID + birth / file identity + digest", "Recheck at action time • refuse ambiguity"]),
        ("3  Apply policy and scope", ["Observe vs supported response capability", "Risk, platform and deployment prerequisites"]),
        ("4  Verify operator authority", ["Authenticated approval where required", "Role and operation are independently checked"]),
        ("5  Write durable intent", ["Retain custody and original recovery data", "Do not replace unknown pending transactions"]),
        ("6  Execute authorized adapter", ["Narrow operation • no model shell commands", "Privilege/service boundary remains explicit"]),
        ("7  Verify observed outcome", ["Completed • partial • denied • failed • held", "A UI success label cannot replace evidence"]),
        ("8  Support review and Undo", ["Signed/authenticated receipt and history", "Reconcile only proven original/target state"]),
    ], ["Installed Protect needs trusted signing, identities and native deployment acceptance.",
        "User-mode source tests cannot create privileged or independent authorities."], stop_branch="right")
    diagram(ASSETS[3], "Curated toolkit security flow", "Pinned third-party code • isolated interpreter • findings remain leads", [
        ("1  Select the reviewed artifact", ["Fixed release • digest • retained licenses", "Source Library imports stay data-only"]),
        ("2  Prepare after the dashboard", ["Bundled standard-library engine • no pip", "Optional fixed-release restore • saved policy"]),
        ("3  Admit a separate owned job", ["Ordinary source execution • private TEMP", "Installed/elevated broker remains held"]),
        ("4  Choose supported checks", ["Default • full • browser • targeted", "Local phone • preview • quick • records"]),
        ("5  Apply resource controls", ["Deadline • priority • managed output caps", "Native writers monitored • no OS quota"]),
        ("6  Validate the retained report", ["Schema • coverage • findings • gaps", "Preserve modified or unknown originals"]),
        ("7  Investigate the evidence", ["Tool text is data, never action authority", "Native breach proof is a separate boundary"]),
        ("8  Revert only managed state", ["Engine revert differs from report cleanup", "Preferences • reports • credits retained"]),
    ], ["Advanced menus, dependencies, feed updates and acquisition retain execution holds.",
        "Code Apache-2.0 • data CC0 • optional rules retain MSTIC / Felix Bilstein credits."])
    diagram(ASSETS[4], "Verified breach and lockdown flow", "A visible warning, authority to act and verified containment are separate", [
        ("1  Qualify native evidence", ["Fresh LIVE • enrolled/current producer", "Active attack • exact original contract"]),
        ("2  Latch a case for review", ["Breached warning • critical report • borders", "Health / practice / tool leads cannot qualify"]),
        ("3  Review the next steps", ["Investigate / Trace remain read-only", "Patch needs a reviewed bound operation"]),
        ("4  Prove response authority", ["Signed installed Protect • Administrator", "Original scope • policy • source is held"]),
        ("5  Request managed lockdown", ["Same Combat worker • durable journal", "All interfaces • directions • IPv4 / IPv6"]),
        ("6  Verify scope and policy", ["Enabled profiles • effective-policy checks", "Unknown state stays held / unverified"]),
        ("7  Lift verified managed rules", ["Authenticated Undo • prove rule absence", "Preserve other policy • same-case standdown"]),
        ("8  Resolve the breach review", ["Lift and review resolution are separate", "New case rechecks • STOP does not lift"]),
    ], ["Rule receipts do not attest packet drops, kernel truth or hostile-admin resistance.",
        "Emergency local-console recovery matches exact managed receipts, never a blanket reset."])


def plain(text):
    text = re.sub(r"!?\[([^\]]*)\]\([^)]+\)", r"\1", text)
    return text.replace("**", "").replace("`", "").replace("\\|", "/")


def paragraph(text, style="Normal", *, first=False, small=False):
    props = f'<w:pStyle w:val="{style}"/>'
    if first:
        props += '<w:pageBreakBefore/>'
    if style.startswith("Heading"):
        props += '<w:keepNext/>'
    props += '<w:spacing w:after="120" w:line="264" w:lineRule="auto"/>'
    size = 19 if small else 22
    run = f'<w:rPr><w:color w:val="000000"/><w:sz w:val="{size}"/></w:rPr>'
    if style.startswith("Heading"):
        run = '<w:rPr><w:color w:val="000000"/></w:rPr>'
    return f'<w:p><w:pPr>{props}</w:pPr><w:r>{run}<w:t xml:space="preserve">{escape(plain(text))}</w:t></w:r></w:p>'.encode()


def table(rows):
    count = len(rows[0])
    # Three/four-column technical tables are set intentionally and allowed to wrap.
    widths = {2: [2200, 7160], 3: [2400, 3480, 3480], 4: [2000, 2600, 2400, 2360]}[count]
    border = ''.join(f'<w:{edge} w:val="single" w:sz="4" w:color="D9D9D9"/>'
                     for edge in ("top", "left", "bottom", "right", "insideH", "insideV"))
    body = ['<w:tbl><w:tblPr><w:tblW w:w="9360" w:type="dxa"/><w:tblLayout w:type="fixed"/>'
            f'<w:tblBorders>{border}</w:tblBorders><w:tblCellMar><w:top w:w="100" w:type="dxa"/>'
            '<w:left w:w="110" w:type="dxa"/><w:bottom w:w="100" w:type="dxa"/>'
            '<w:right w:w="110" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>']
    body += [f'<w:gridCol w:w="{width}"/>' for width in widths]
    body.append('</w:tblGrid>')
    for index, row in enumerate(rows):
        body.append('<w:tr><w:trPr><w:cantSplit/>' + ('<w:tblHeader/>' if index == 0 else '') + '</w:trPr>')
        for width, value in zip(widths, row):
            shade = 'DCE7F0' if index == 0 else ('F4F6F8' if index % 2 == 0 else 'FFFFFF')
            cell = paragraph(value, small=True).decode()
            if index == 0:
                cell = cell.replace('<w:rPr>', '<w:rPr><w:b/>')
            body.append(f'<w:tc><w:tcPr><w:tcW w:w="{width}" w:type="dxa"/>'
                        f'<w:shd w:fill="{shade}"/><w:vAlign w:val="center"/></w:tcPr>{cell}</w:tc>')
        body.append('</w:tr>')
    body.append('</w:tbl>')
    return ''.join(body).encode() + paragraph("")


def picture(name, number):
    data = (ROOT / "assets" / name).read_bytes()
    width, height = struct.unpack('>II', data[16:24])
    cx, cy = 5943600, round(5943600 * height / width)
    rid = f"rIdAngeronaSecurityFlow{number}"
    description = name.replace("-", " ").replace(".png", "")
    return f'''<w:p><w:pPr><w:keepNext/><w:spacing w:after="120"/></w:pPr><w:r><w:drawing>
<wp:inline xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing" distT="0" distB="0" distL="0" distR="0">
<wp:extent cx="{cx}" cy="{cy}"/><wp:docPr id="{9000 + number}" name="{name}" descr="{description}"/>
<a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">
<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="0" name="{name}"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill>
<a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="{cx}" cy="{cy}"/></a:xfrm>
<a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline>
</w:drawing></w:r></w:p>'''.encode()


def markdown_parts(text, *, include_catalog=False):
    lines = text.splitlines()
    output, buffer = [], []
    def flush():
        if buffer:
            output.append(paragraph(" ".join(buffer)))
            buffer.clear()
    index = 0
    while index < len(lines):
        line = lines[index].strip()
        if line.startswith('<!-- CAPABILITY_SOURCE_INVENTORY'):
            flush()
            if not include_catalog:
                break
        elif line.startswith('<!--'):
            pass
        elif line.startswith('```'):
            flush()
            index += 1
            while index < len(lines) and not lines[index].lstrip().startswith('```'):
                output.append(paragraph(lines[index], small=True))
                index += 1
            if index == len(lines):
                raise ValueError("manual source has an unclosed fenced block")
        elif line.startswith('!['):
            flush()
            for number, name in enumerate(ASSETS, 1):
                if name in line:
                    output.append(picture(name, number))
                    display_number = {ASSETS[0]: 1, ASSETS[3]: 2, ASSETS[2]: 3,
                                      ASSETS[4]: 4, ASSETS[1]: 5}[name]
                    output.append(paragraph("Figure " + str(display_number) + " " + name.replace('security-flow-', '').replace('.png', '') + " flow", "Caption"))
        elif line.startswith('#'):
            flush()
            level = len(line) - len(line.lstrip('#'))
            heading = line.lstrip('# ').replace("1 ", "1 ", 1)
            output.append(paragraph(heading, "Heading" + str(min(level + 1, 3))))
        elif line.startswith('|'):
            flush()
            rows = []
            while index < len(lines) and lines[index].strip().startswith('|'):
                cells = [value.strip() for value in lines[index].strip().strip('|').split('|')]
                if not all(re.fullmatch(r'[-: ]+', cell) for cell in cells):
                    rows.append(cells)
                index += 1
            output.append(table(rows))
            continue
        elif line.startswith('- '):
            flush()
            output.append(paragraph("• " + line[2:]))
        elif not line:
            flush()
        else:
            buffer.append(line)
        index += 1
    flush()
    return b''.join(output)


def chapter():
    result = paragraph(TITLE, "Heading1", first=True)
    result += paragraph("Current operating guidance " + REVISION_DATE)
    result += paragraph("This chapter explains the suite from launch to evidence, governed response, retention and recovery. Source Observe and signed installed Protect have distinct authority. A visible dashboard does not attest working sensors or protection. The current security flow and Safe Startup sections below apply to the maintained source profile; earlier dated validation results remain historical evidence.")
    result += markdown_parts(DOCS[0].read_text(encoding="utf-8"))
    result += paragraph("Complete built in capability inventory", "Heading2")
    result += paragraph("The repository guide docs/security-flow.md lists every built-in BaseModule source declaration with its explicit mode and response authority, where declared. Capability Center provides the validated live contract, platform, freshness, loss, dependencies and actual coverage for each capability. Catalog membership or a compatibility declaration is not independent efficacy evidence.")
    result += table([("Capability", "Built in source file")] + [
        (name, relative) for name, relative, _mode, _authority in capability_rows()
    ])
    result += markdown_parts(DOCS[2].read_text(encoding="utf-8"))
    result += markdown_parts(DOCS[1].read_text(encoding="utf-8"))
    result += paragraph("Primary platform and toolkit references", "Heading2", first=True)
    for url in (
        "https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/user-mode-and-kernel-mode",
        "https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria",
        "https://docs.github.com/en/rest/git/blobs",
        "https://docs.github.com/en/rest/git/commits",
        "https://docs.github.com/en/rest/git/trees",
        "https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile?view=windowsserver2025-ps",
        "https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwpolicy2-get_localpolicymodifystate",
        "https://github.com/interplains/Zero-Breach-Toolkit/releases/tag/v0.1.10",
        "https://github.com/interplains/Zero-Breach-Toolkit/blob/81bd556ba604685dbd1c0ecb48138c10f43cccf8/scan/CONTRACT.md",
        "https://github.com/interplains/Zero-Breach-Toolkit/blob/81bd556ba604685dbd1c0ecb48138c10f43cccf8/PRIVACY.md",
    ):
        # Keep this short reference list compact without reducing its type size
        # or pushing a lone final URL onto another page.
        result += paragraph(url, small=True).replace(b'w:after="120"', b'w:after="0"', 1)
    return START + result + END


def replace_paragraph(document, before, after, properties=None):
    for match in re.finditer(rb'<w:p(?:\s[^>]*)?(?<!/)>.*?</w:p>', document, re.DOTALL):
        text = unescape(''.join(part.decode('utf-8') for part in re.findall(
            rb'<w:t(?:\s[^>]*)?>(.*?)</w:t>', match.group(0), re.DOTALL)))
        if text == before:
            replacement = paragraph(after)
            retained = re.search(rb'<w:pPr>.*?</w:pPr>', match.group(0), re.DOTALL)
            props = properties if properties is not None else (retained.group(0) if retained else None)
            if props is not None:
                replacement = re.sub(rb'<w:pPr>.*?</w:pPr>', lambda _: props, replacement, count=1, flags=re.DOTALL)
            return document[:match.start()] + replacement + document[match.end():]
    return document


def canonical_version():
    """Read the product version without loading any application code."""
    tree = ast.parse((ROOT / 'src/angerona/__init__.py').read_text(encoding='utf-8-sig'))
    values = [ast.literal_eval(node.value) for node in tree.body
              if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == '__version__'
                      for target in node.targets)]
    if len(values) != 1 or not isinstance(values[0], str) or not re.fullmatch(r'\d+\.\d+\.\d+', values[0]):
        raise ValueError('canonical product version is missing or ambiguous')
    return values[0]


def current_version_parts(mapping):
    """Patch current display versions in place, retaining runs and dated history."""
    version_text = canonical_version()
    version = version_text.encode('ascii')
    document = mapping['word/document.xml']
    anchors = (
        'Current development: v',
        ' source update. Validation is recorded in analysis/live-debug-2026-10-22;',
        'Angerona unifies Windows endpoint and network visibility,',
    )
    counts = [0, 0, 0, 0]
    previous_text = ''
    frontmatter_open = True
    cover_dates = 0

    def patch(match):
        nonlocal previous_text, frontmatter_open, cover_dates
        raw = match.group(0)
        text = unescape(''.join(part.decode('utf-8') for part in re.findall(
            rb'<w:t(?:\s[^>]*)?>(.*?)</w:t>', raw, re.DOTALL)))
        follows_version_label = previous_text == 'Version'
        previous_text = text
        if text == 'Document control':
            frontmatter_open = False
        if frontmatter_open and re.fullmatch(r'\d{1,2} [A-Za-z]+ \d{4}', text):
            cover_dates += 1
            return re.sub(rb'(?<=>)\d{1,2} [A-Za-z]+ \d{4}(?=</w:t>)',
                          REVISION_DATE.encode('ascii'), raw, count=1)
        for index, anchor in enumerate(anchors):
            # The source-update wording is a stable frontmatter anchor; only its
            # current version changes. Dated v1.14 integration prose stays intact.
            selected = (text.startswith('v') and (anchor in text or ' source maintenance. Current validation:' in text)
                        if index == 1 else text.startswith(anchor))
            if selected:
                counts[index] += 1
                if index == 1:
                    return replace_single_run_text(raw,
                        f'v{version_text} source maintenance. Current validation: '
                        'analysis/curated-tools-breach-2026-10-29.md. '
                        'Signed-package and clean-VM acceptance remain separate.')
                return re.sub(rb'(?<=v)\d+\.\d+\.\d+', lambda _: version, raw, count=1)
        if text.startswith('Current repository code, the 86-capability inventory and '):
            return replace_single_run_text(raw,
                'Current repository code, the 86-capability inventory and '
                'analysis/curated-tools-breach-2026-10-29.md; '
                'October 22 validation and historical chapters retain their dated scope.')
        if follows_version_label and re.fullmatch(r'\d+\.\d+\.\d+', text):
            counts[3] += 1
            return re.sub(rb'(?<=>)\d+\.\d+\.\d+(?=</w:t>)', lambda _: version, raw, count=1)
        return raw

    mapping['word/document.xml'] = re.sub(rb'<w:p(?:\s[^>]*)?(?<!/)>.*?</w:p>', patch, document, flags=re.DOTALL)
    if counts != [1, 1, 1, 1]:
        raise ValueError(f'current manual version anchors are missing or ambiguous: {counts}')
    if cover_dates != 1:
        raise ValueError('current manual cover revision date is missing or ambiguous')
    for name, anchor in (
        ('word/header1.xml', b'ANGERONA  |  MASTER MANUAL  |  v'),
        ('word/footer2.xml', b'Angerona Suite  |  v'),
    ):
        raw = mapping[name]
        if raw.count(anchor) != 1:
            raise ValueError(f'current manual version anchor is ambiguous: {name}')
        mapping[name], changed = re.subn(re.escape(anchor) + rb'\d+\.\d+\.\d+',
            lambda _: anchor + version, raw, count=1)
        if changed != 1:
            raise ValueError(f'current manual display version is missing: {name}')
    mapping['word/footer2.xml'], count = re.subn(
        rb'(?<=  \|  )\d{1,2} [A-Za-z]+ \d{4}(?=</w:t>)',
        REVISION_DATE.encode('ascii'), mapping['word/footer2.xml'], count=1)
    if count != 1:
        raise ValueError('current manual footer revision date is missing')


def replace_single_run_text(paragraph_bytes, text):
    """Retain the original frontmatter run format and reject split anchors."""
    pattern = rb'(<w:t(?:\s[^>]*)?>).*?(</w:t>)'
    if len(re.findall(pattern, paragraph_bytes, re.DOTALL)) != 1:
        raise ValueError('current frontmatter text must have exactly one text run')
    return re.sub(pattern, lambda match: match[1] + escape(text).encode('utf-8') + match[2],
                  paragraph_bytes, count=1, flags=re.DOTALL)


def update(check=False):
    refresh_inventory(check)
    with ZipFile(MANUAL) as archive:
        entries = [(info, archive.read(info.filename)) for info in archive.infolist()]
    mapping = {info.filename: data for info, data in entries}
    original_mapping = dict(mapping)
    current_version_parts(mapping)
    document = mapping['word/document.xml']
    if START in document or END in document:
        if document.count(START) != 1 or document.count(END) != 1:
            raise ValueError("security flow chapter markers are ambiguous")
        first, last = document.index(START), document.index(END)
        if last < first:
            raise ValueError("security flow chapter markers are reversed")
        document = document[:first] + document[last + len(END):]
    document = replace_paragraph(document,
        "Run Windows Protect with elevation when full telemetry and response are required. Use macOS and Linux according to their Observe contracts.",
        "Windows Protect requires the trusted signed installed distribution and its accepted authority; elevating a writable source checkout does not establish Protect. Normal source startup is unelevated Observe/development. Use macOS and Linux according to their platform contracts.")
    current_posture = "Windows Protect requires the trusted signed installed distribution and its accepted authority; elevating a writable source checkout does not establish Protect. Normal source startup is unelevated Observe/development. Use macOS and Linux according to their platform contracts."
    # The retained manual's operating-posture list uses numId 12. Keep its exact
    # numbering/spacing when upgrading a manual produced by an earlier updater.
    document = replace_paragraph(document, current_posture, current_posture,
        b'<w:pPr><w:numPr><w:ilvl w:val="0"/><w:numId w:val="12"/></w:numPr>'
        b'<w:spacing w:before="0" w:after="20" w:line="252" w:lineRule="auto"/></w:pPr>')
    # Preserve every other historical paragraph and package part.
    insertion = document.rfind(b'<w:sectPr')
    if insertion < 0:
        raise ValueError("manual has no final section properties")
    updated = document[:insertion] + chapter() + document[insertion:]
    ET.fromstring(updated)
    if check:
        if updated != original_mapping['word/document.xml']:
            raise ValueError("master manual security-flow chapter differs from reviewed guides/assets")
        for name in ('word/header1.xml', 'word/footer2.xml'):
            if mapping[name] != original_mapping[name]:
                raise ValueError(f'master manual current display version is stale: {name}')
        for name in ASSETS:
            if mapping.get('word/media/' + name) != (ROOT / 'assets' / name).read_bytes():
                raise ValueError("master manual security-flow media is stale")
        print("Master manual chapter, inventory and diagrams are current; visual render QA remains separate")
        return
    relationships = mapping['word/_rels/document.xml.rels']
    for number, name in enumerate(ASSETS, 1):
        rid = f'rIdAngeronaSecurityFlow{number}'
        relationships = re.sub(rb'<Relationship\b[^>]*\bId="' + rid.encode() + rb'"[^>]*/>', b'', relationships)
        addition = f'<Relationship Id="{rid}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="media/{name}"/>'.encode()
        relationships = relationships.replace(b'</Relationships>', addition + b'</Relationships>')
    types = mapping['[Content_Types].xml']
    if b'Extension="png"' not in types:
        types = types.replace(b'</Types>', b'<Default Extension="png" ContentType="image/png"/></Types>')
    mapping['word/document.xml'] = updated
    mapping['word/_rels/document.xml.rels'] = relationships
    mapping['[Content_Types].xml'] = types
    mapping['docProps/core.xml'] = re.sub(rb'(<dcterms:modified\b[^>]*>).*?(</dcterms:modified>)',
        lambda match: match.group(1) + REVISION_UTC + match.group(2), mapping['docProps/core.xml'])
    for name in ASSETS:
        mapping['word/media/' + name] = (ROOT / 'assets' / name).read_bytes()
    temporary = MANUAL.with_suffix('.security-flow.tmp')
    try:
        with ZipFile(temporary, 'w') as archive:
            for info, original in entries:
                archive.writestr(info, mapping.pop(info.filename, original))
            for name, data in mapping.items():
                archive.writestr(name, data)
        with ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise ValueError("master manual ZIP validation failed")
            ET.fromstring(archive.read('word/document.xml'))
        temporary.replace(MANUAL)
    finally:
        if temporary.exists():
            temporary.unlink()
    print("Updated master manual security flow; render every page before publication")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--build-assets', action='store_true')
    options = parser.parse_args()
    if options.check and options.build_assets:
        parser.error('--check cannot rebuild assets')
    if options.build_assets:
        build_assets()
    update(options.check)


if __name__ == '__main__':
    main()
