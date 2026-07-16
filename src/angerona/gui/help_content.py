"""gui/help_content.py — end-user Help / Info content (self-contained).

Plain-language guidance for every operator-facing feature: what it is, how to turn
it on, how to test it, and how to fix it when it misbehaves. Kept as pure data +
tiny helpers so it can be surfaced anywhere — a Help window, the console ``guide``
command, or ARIA — without any GUI dependency. No imports beyond stdlib.
"""
from __future__ import annotations

# topic key → (title, body). Bodies are plain text with simple bullet lines.
TOPICS: "dict[str, tuple[str, str]]" = {
    "getting-started": (
        "Getting started",
        "Angerona is a local, defensive security suite. It watches your Windows PC, "
        "scores your posture (0–100), and never sends data off the machine unless you "
        "explicitly turn on a cloud/online feature.\n"
        "• The dashboard shows Modules running, Alerts, and your Threat level.\n"
        "• The bottom Console takes commands OR plain questions — anything that isn't a "
        "command goes to ARIA, your built-in assistant.\n"
        "• Type 'guide <topic>' for any subject below, or just ask ARIA "
        "(e.g. \"how do I turn on voice?\").\n"
        "Topics: aria · actions · voice · signal · teams · trusted-apps · testing · "
        "troubleshooting · threat-level · privacy",
    ),
    "aria": (
        "ARIA — your assistant",
        "ARIA is a local assistant melded into the bottom Console (and the ARIA tab).\n"
        "• Ask anything about Angerona, security, or your device — she answers from the "
        "local model (Ollama/llama3), grounded in your live environment and runbooks.\n"
        "• She's also a coach: ask \"how do I set up X\", \"test my sensors\", or "
        "\"why is my threat level high?\" for step-by-step help.\n"
        "• If the local model is off, she can use an online AI when you add a key "
        "(Settings ▸ API Keys); otherwise she says so.\n"
        "Speed: the model is kept warm so replies are quick after the first one.",
    ),
    "actions": (
        "ARIA actions (safe, confirm-first)",
        "ARIA can DO things, not just talk — every change is confirm-then-execute.\n"
        "• Reads run immediately: \"list modules\", \"recent alerts\", \"threat level\", "
        "\"top processes\", \"connections\", \"coverage\", \"incidents\", \"run diagnostics\".\n"
        "• Changes are staged behind a token: \"suspend pid 1234\", \"kill 4812\", "
        "\"disable the memory scanner module\", \"trust my running apps\". ARIA replies with "
        "a preview + a token; say \"confirm\" (or \"confirm <token>\") to run it, or "
        "\"cancel\" to drop it. Nothing changes until you confirm.\n"
        "• Planning: ask \"what should I do?\" / \"strategize\" for a prioritized action plan.",
    ),
    "voice": (
        "Voice conversation",
        "Talk to ARIA hands-free.\n"
        "1. Settings ▸ enable Voice. ARIA will speak her replies using the built-in "
        "Windows voice (no install needed).\n"
        "2. To talk to her, install speech-to-text: 'pip install vosk sounddevice' "
        "(optionally set ANGERONA_VOSK_MODEL to a downloaded model).\n"
        "3. Say \"hey aria …\" then your request, e.g. \"hey aria, what's my posture?\" or "
        "\"hey aria, suspend pid 1234\" then \"hey aria, confirm\".\n"
        "Nothing is sent to the cloud; speech stays on your machine.",
    ),
    "signal": (
        "Signal — talk to ARIA from your phone",
        "Message ARIA from Signal, end-to-end encrypted.\n"
        "1. Install signal-cli and register/link your Signal number.\n"
        "2. Settings ▸ Mobile Response Bridge: enable it, set the signal-cli path, your "
        "host number, and your phone (destination) number. Set the PIN.\n"
        "3. From your phone: 'STATUS' for posture, 'HELP' for commands, or just chat — any "
        "plain message is answered by ARIA. Containment (KILL/SUSPEND/LOCKDOWN) needs the "
        "token + PIN shown in the alert.\n"
        "Only your configured number is accepted; other senders are logged as spoof attempts.",
    ),
    "teams": (
        "Microsoft Teams bot",
        "Chat with ARIA inside Teams (two-way).\n"
        "1. Azure Portal → create an 'Azure Bot'; note the Microsoft App ID and create a "
        "client secret.\n"
        "2. Set the bot's Messaging endpoint to https://<your-tunnel>/api/messages and "
        "expose Angerona's local endpoint with a dev tunnel/ngrok (HTTPS).\n"
        "3. Add the Microsoft Teams channel; install the bot to your Teams.\n"
        "4. Settings ▸ Teams Bot: enable, paste the App ID, set your allowed Teams user, "
        "port (default 3978). Put the secret in .env as ANGERONA_TEAMS_APP_PASSWORD and "
        "'pip install pyjwt' for inbound security.\n"
        "Only your allow-listed user is answered; chat/reads only (no remote changes).",
    ),
    "trusted-apps": (
        "Trusted apps (stop false flags)",
        "Some normal apps (browsers, Electron apps like Claude/VS Code/Discord) use "
        "read-write-execute memory legitimately, which can look suspicious.\n"
        "• Type 'trust-running' in the console (or tell ARIA \"trust my running apps\") to "
        "trust the programs you're using now by exact path.\n"
        "• 'trust-running all' also includes system-path apps.\n"
        "• Or trust one at a time in Settings ▸ Trusted Processes, or via Resolve Center ▸ "
        "Allow on a specific alert.\n"
        "Common JIT apps are already trusted out of the box.",
    ),
    "testing": (
        "Testing your protection",
        "• 'RUN SELF-TEST' (header) or console 'test [module]' checks a sensor's pipeline "
        "end-to-end.\n"
        "• 'RUN RED TEAM SIMULATION' fires a safe, benign ATT&CK drill against your own "
        "host (inert markers, nothing malicious).\n"
        "• Console 'aar' re-scores the last drill. Interval scanners (FIM ~30s, YARA ~5min) "
        "may report a catch a bit later — re-run 'aar' after a few minutes.\n"
        "• DRILL and CHAOS run automatically to prove your sensors aren't blinded.",
    ),
    "troubleshooting": (
        "Troubleshooting",
        "• Threat level stuck High on your own apps → 'trust-running', or Resolve Center ▸ "
        "Ignore/Allow the false positives.\n"
        "• A module shows 'stopped' or 'quarantined' → console 'module <name> restart'.\n"
        "• ARIA says the local AI is unavailable → make sure Ollama is running "
        "(ollama serve · ollama pull llama3), or add an online key in Settings ▸ API Keys.\n"
        "• Check state with console 'threat', 'modules', 'resources', 'iocs'.\n"
        "• Logs live in the diagnostics folder: runtime_alerts.log, crash.log, "
        "not_responding.log.\n"
        "• Ask ARIA \"why is my threat level high?\" or \"run diagnostics\".",
    ),
    "threat-level": (
        "How the threat level works",
        "The level (Secure / High / Critical) reflects REAL detections in the last ~10 "
        "minutes — not Angerona's own health or drills.\n"
        "• Self-health events (a module restarting, a drill probe, SOAR summaries) do NOT "
        "raise it.\n"
        "• Genuine detections (credential theft, ransomware behaviour, C2 beacons) do.\n"
        "• Clear false positives in Resolve Center (Ignore/Allow) to return to Secure.",
    ),
    "privacy": (
        "Privacy & data",
        "Angerona is local-first. Nothing leaves your machine unless you turn on a feature "
        "that clearly sends data:\n"
        "• Online AI fallback (only with a key you add) · Teams/Signal/channel push (only "
        "to endpoints you configure) · cloud threat-intel lookups you initiate.\n"
        "Everything else — detection, ARIA's local answers, voice — runs entirely on-device.",
    ),
}

_ALIASES = {
    "start": "getting-started", "help": "getting-started", "overview": "getting-started",
    "assistant": "aria", "action": "actions", "commands": "actions",
    "stt": "voice", "tts": "voice", "mic": "voice",
    "phone": "signal", "mobile": "signal",
    "microsoft": "teams", "bot": "teams",
    "trust": "trusted-apps", "trusted": "trusted-apps", "allowlist": "trusted-apps",
    "test": "testing", "drill": "testing", "selftest": "testing",
    "fix": "troubleshooting", "problem": "troubleshooting", "debug": "troubleshooting",
    "threat": "threat-level", "posture": "threat-level",
}


def topics() -> "list[str]":
    return list(TOPICS)


def resolve(name: str) -> "str | None":
    key = (name or "").strip().lower().replace(" ", "-").replace("_", "-")
    if key in TOPICS:
        return key
    return _ALIASES.get(key)


def get(name: str = "getting-started") -> str:
    """Return a rendered help topic (title + body), or a topic index if unknown."""
    key = resolve(name)
    if key is None:
        return ("Angerona guide — available topics:\n  " + " · ".join(topics())
                + "\nType 'guide <topic>' or ask ARIA.")
    title, body = TOPICS[key]
    return f"── {title} ──\n{body}"


def overview() -> str:
    return get("getting-started")
