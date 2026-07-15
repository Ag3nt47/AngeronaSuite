"""angerona.connectors — opt-in external I/O for ARIA.

Every connector here is OFF by default and degraded-safe: voice (TTS/STT),
channel push (Slack/Teams/ntfy), inbox triage (IMAP phishing heuristics), and
research-on-command (vetted lookups via Claude-for-Chrome). Nothing engages a
mic, sends outbound, or reaches the network until the operator opts in.
"""
