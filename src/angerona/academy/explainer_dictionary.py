"""explainer_dictionary.py — The Interactive Explainer Dictionary.

A static, structured lookup from a Shark Attack Engine stage name (the same
``stage`` strings ``shark/shark_attack.py`` already records in
``shark_history.json``) to everything needed to teach it: what a real
adversary would actually be trying to accomplish, what part of Angerona is
built to notice it and how, and how that maps onto tools a working SOC
analyst would recognize.

This is deliberately just data — no network calls, no AI. FlightInstructor
(security_academy.py) uses it as grounding context so the LLM explains real,
accurate mechanics instead of improvising plausible-sounding nonsense.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass(frozen=True)
class TechniqueEducation:
    stage: str
    attck_ref: str              # MITRE ATT&CK id(s), or "" if not applicable
    attacker_intent: str        # what a real adversary is trying to accomplish
    defense_architecture: str   # what in Angerona catches it, and how
    enterprise_context: str     # the professional-tool equivalent
    technical: str              # dense, precise explanation
    analogy: str                # plain-language, jargon-free explanation


TECHNIQUE_LIBRARY: Dict[str, TechniqueEducation] = {

    "Initial Access": TechniqueEducation(
        stage="Initial Access",
        attck_ref="ATT&CK T1204 (User Execution) / TA0001 (Initial Access)",
        attacker_intent=(
            "Get a first foothold on the machine — usually by getting a user to "
            "open something they shouldn't (an email attachment, a fake invoice, "
            "a cracked-software installer). The file itself doesn't have to be "
            "clever; it just has to look legitimate enough to be opened."
        ),
        defense_architecture=(
            "YARA Scanner sweeps the Downloads folder on an interval, matching "
            "file contents against known-bad signatures in rules.yar. It's "
            "signature-based: it catches what it already has a rule for, which "
            "is exactly why the drill uses the industry-standard EICAR test "
            "string — every AV engine on earth ships an EICAR rule."
        ),
        enterprise_context=(
            "This is the same job CrowdStrike Falcon's or Windows Defender's "
            "on-access/on-demand scanner does at enterprise scale — the "
            "difference is those also do real-time on-open hooking and cloud "
            "reputation lookups, where YARA Scanner here polls on an interval."
        ),
        technical=(
            "A file lands in a user-writable, commonly-abused directory. "
            "Detection here is purely content-signature matching (YARA rule "
            "compilation against byte patterns) — it has zero awareness of "
            "provenance (who downloaded it, from where), so it cannot catch "
            "anything it doesn't already have a rule for."
        ),
        analogy=(
            "Picture a security guard who only recognizes faces from a mugshot "
            "book. If the delivery driver isn't in the book, they walk right "
            "in — no matter how suspicious they look. The guard is genuinely "
            "useful, but only as good as the book."
        ),
    ),

    "Discovery": TechniqueEducation(
        stage="Discovery",
        attck_ref="ATT&CK T1057 (Process Discovery) / T1049 (System Network Connections Discovery)",
        attacker_intent=(
            "Before doing anything else, map the terrain: what's running, what "
            "security tools are present, what's talking to the network. Almost "
            "every real intrusion does this early — it's cheap, low-risk "
            "reconnaissance."
        ),
        defense_architecture=(
            "Nothing in Angerona currently watches for this, and that's "
            "intentional to call out: psutil-level process/connection reads are "
            "indistinguishable from what Task Manager, Resource Monitor, and a "
            "hundred legitimate admin tools do dozens of times a minute. "
            "Flagging every read would drown the alert feed in noise."
        ),
        enterprise_context=(
            "Enterprise EDRs (CrowdStrike, SentinelOne) catch this differently: "
            "not by flagging the read itself, but by correlating WHO is reading "
            "(a Word macro spawning cmd.exe to run 'whoami' is suspicious; "
            "Task Manager doing the same read is not) and WHAT ELSE that "
            "process just did. That kind of behavioral correlation is a much "
            "bigger engineering lift than a single-module signature check."
        ),
        technical=(
            "psutil.pids() / psutil.net_connections() are ordinary, read-only "
            "Win32 API calls (backed by NtQuerySystemInformation / iphlpapi). "
            "There is no OS-level signal that distinguishes a legitimate caller "
            "from an attacker's caller — the distinguishing signal is context "
            "(parent process, timing, what happens next), which no single "
            "module here currently tracks."
        ),
        analogy=(
            "Someone walking through a building looking at room numbers isn't "
            "suspicious on its own — everyone does that. It only becomes "
            "meaningful in context: are they walking with a badge, or checking "
            "every locked door on the way?"
        ),
    ),

    "Persistence (simulated)": TechniqueEducation(
        stage="Persistence (simulated)",
        attck_ref="ATT&CK TA0003 (Persistence), e.g. T1547 (Boot or Logon Autostart Execution)",
        attacker_intent=(
            "Survive a reboot or a user logging off. Real techniques here "
            "range from a registry Run key, to a scheduled task, to a Startup "
            "folder shortcut, to more exotic WMI event subscriptions."
        ),
        defense_architecture=(
            "File Integrity Monitor baselines SHA-256 hashes of watched "
            "directories (Documents, and the Windows hosts-file directory) "
            "and diffs on a 30-second cycle — new/changed/deleted files all "
            "raise an alert. It watches the FILE SYSTEM, not the registry or "
            "Task Scheduler, which is exactly why this drill only ever drops a "
            "marker file: it's testing FIM's coverage honestly, without "
            "actually creating a real autorun entry."
        ),
        enterprise_context=(
            "Splunk SOAR and CrowdStrike both build detections directly on "
            "registry Run-key writes, scheduled-task creation events (via "
            "Sysmon Event ID 1 for process creation + Event ID 12/13/14 for "
            "registry, or native ETW providers) — a materially deeper data "
            "source than file-hash diffing alone."
        ),
        technical=(
            "FIM's coverage is bounded by its watch list and poll interval: "
            "a 30s window means worst-case ~30s detection latency, and "
            "anything outside DEFAULT_WATCH (file_integrity.py) is invisible "
            "to it entirely — including the registry, which this drill "
            "deliberately never touches."
        ),
        analogy=(
            "FIM is like a smoke detector for one specific room. It will "
            "absolutely catch a fire that starts there — but it has no idea "
            "what's happening in the room next door (the registry), because "
            "that's not where its sensor is pointed."
        ),
    ),

    "Noise Injection": TechniqueEducation(
        stage="Noise Injection",
        attck_ref="(not an ATT&CK technique — this is a defensive test, not an attacker behavior)",
        attacker_intent=(
            "None — this step doesn't simulate an attacker at all. It runs a "
            "real, legitimate, CPU/IO-heavy task (hashing and zipping "
            "throwaway data) purely to check that Angerona's own automation "
            "doesn't overreact to 'looks expensive' as if it meant 'looks "
            "malicious'."
        ),
        defense_architecture=(
            "Nothing should fire on this by design. If Active Response SOAR "
            "or SOAR Automation ever killed this process, that would be a "
            "genuine false positive worth investigating — heavy CPU/IO usage "
            "alone is not, and should never be, a kill signal on its own."
        ),
        enterprise_context=(
            "This mirrors 'purple team' false-positive testing that mature "
            "SOC teams run deliberately: intentionally triggering benign-but-"
            "loud behavior (a big backup job, a legitimate compiler run) to "
            "make sure detections are keyed on genuine behavioral signals, "
            "not just resource usage."
        ),
        technical=(
            "8MB of os.urandom() data is hashed and zipped, entirely in one "
            "Python process, in memory and to one throwaway file — no network "
            "activity, no process spawning, no persistence. There is nothing "
            "here that SHOULD look malicious to a well-tuned detector."
        ),
        analogy=(
            "A moving crew hauling heavy boxes looks intense, but it isn't "
            "suspicious — unless you also see them jimmying a lock. Effort "
            "alone isn't evidence."
        ),
    ),

    "Exfiltration": TechniqueEducation(
        stage="Exfiltration",
        attck_ref="ATT&CK TA0010 (Exfiltration), e.g. T1041 (Exfiltration Over C2 Channel)",
        attacker_intent=(
            "Get data OFF the machine. Modern exfiltration overwhelmingly "
            "rides ordinary HTTPS (port 443) specifically because it blends "
            "into normal traffic and sails past detections that only watch "
            "for exotic ports."
        ),
        defense_architecture=(
            "Network Monitor flags two independent signals: connections to a "
            "hardcoded list of ports historically abused by malware/C2 tooling "
            "(HIGH), and — since the network gap was surfaced by this very "
            "drill — first contact with any external host not seen in the "
            "last hour, regardless of port (MEDIUM). The second signal is "
            "what actually catches ordinary-looking HTTPS traffic to a brand "
            "new destination."
        ),
        enterprise_context=(
            "This is the exact job Wireshark (packet-level) and a NDR/SASE "
            "product or a Splunk-fed firewall log pipeline do at enterprise "
            "scale: baselining 'known-good' destinations and flagging first "
            "contact with anything new, rather than trusting a port number."
        ),
        technical=(
            "A raw socket.create_connection() to a real external host on 443, "
            "sending a small fixed marker. No TLS handshake is completed "
            "(the test doesn't need real encrypted transport), but the TCP "
            "3-way handshake itself is enough for the OS connection table — "
            "and therefore Network Monitor's polling of it — to see it."
        ),
        analogy=(
            "A guard who only watches the back alley (the 'suspicious ports') "
            "will miss someone walking straight out the well-lit front door "
            "(port 443) carrying a box, because the front door looks normal. "
            "The fix isn't watching the door harder — it's noticing this is "
            "the FIRST time this particular person has ever walked through it."
        ),
    ),
}

_FALLBACK = TechniqueEducation(
    stage="Unknown",
    attck_ref="",
    attacker_intent="No educational entry exists yet for this stage.",
    defense_architecture="Not documented.",
    enterprise_context="Not documented.",
    technical="No technical explanation on file for this stage.",
    analogy="No analogy on file for this stage.",
)


def lookup(stage: str) -> TechniqueEducation:
    """Never raises — an unknown stage returns a clearly-labeled fallback
    instead of crashing a coaching session."""
    return TECHNIQUE_LIBRARY.get(stage, _FALLBACK)


def explain(stage: str, style: str = "analogy") -> str:
    """One-line-per-field, terminal-friendly rendering of a technique's
    education entry, in either the "technical" or "analogy" register."""
    edu = lookup(stage)
    body = edu.technical if style == "technical" else edu.analogy
    lines = [
        f"── {edu.stage} " + ("(no ATT&CK mapping)" if not edu.attck_ref else f"[{edu.attck_ref}]"),
        f"   Attacker intent      : {edu.attacker_intent}",
        f"   Defense architecture : {edu.defense_architecture}",
        f"   Enterprise parallel  : {edu.enterprise_context}",
        f"   {'Technical' if style == 'technical' else 'In plain terms'}"
        f"{'':<8}: {body}",
    ]
    return "\n".join(lines)


def all_stages() -> list[str]:
    return list(TECHNIQUE_LIBRARY.keys())
