# Angerona — launch posts

Copy/paste drafts for seeding the first wave of traffic once the repo is public.
Tone is deliberately low-hype: the security/dev audience rewards precision and
honest limitations, and punishes marketing adjectives. Swap in your real GitHub
URL and a screenshot/GIF before posting.

> Tip: post a **screenshot or 20-second GIF** of the dashboard with every one of
> these. A visual is the single biggest thing that converts a click into a star.
> Best windows: Tue–Thu mornings US-Eastern for HN/Reddit. Reply to every comment
> in the first few hours — early engagement is what drives ranking.

---

## Hacker News — "Show HN"

**Title (≤ 80 chars, no emoji, no hype):**

```
Show HN: Angerona – a local-first EDR/NDR/SOAR for Windows, in Python
```

**First comment (post immediately after submitting, as the author):**

I built Angerona because I wanted to actually *see* what endpoint detection and
response does, end to end, without a black-box agent or a cloud tenant.

It's a modular Windows security suite with a native PySide6 GUI. It pulls
telemetry through supported Windows APIs — ETW, WMI, AMSI, WFP, Sysmon — so there's
no custom kernel driver to install. Detections map to MITRE ATT&CK and show up on a
live heatmap. A local LLM (Ollama/llama3) triages alerts; cloud escalation is
opt-in and only fires if you supply your own key.

A few things that were fun to build:

- **Auto-discovered modules** — drop a `BaseModule` subclass in `modules/` and it
  appears in the app; ~60 ship today (FIM, YARA, packet inspection, LSASS
  credential-dump detection, C2 beacon detection, shadow-copy/ransomware precursor
  detection, USB monitoring, etc.).
- **Active defense (SOAR)** — under a corroborated attack it suspends/kills the
  offending process and firewall-isolates its network, behind a protected-process
  allowlist and 2-signal corroboration so it can't freeze Windows itself.
- **A built-in red-team drill** ("Shark Attack") that runs benign, non-destructive
  techniques to exercise detect-and-respond, then writes an after-action report.
- **Incident kill-chain timeline** that groups alerts per process along the ATT&CK
  chain so you can see how far an attack got.

Honest limitations: it's Windows-only, single-host (not a fleet console), the AI
triage is only as good as your local model, and it's a solo project — treat it as a
learning/lab tool, not a certified enterprise product. Feedback from blue-teamers
especially welcome.

Repo: https://github.com/Ag3nt47/AngeronaSuite

---

## Reddit — r/blueteam / r/cybersecurity

**Title:**

```
I built a local-first EDR/NDR/SOAR for Windows in Python (open source, no cloud, no kernel driver)
```

**Body:**

Sharing a side project: **Angerona**, a modular endpoint security suite for Windows
with a native desktop GUI.

- Telemetry via ETW / WMI / AMSI / WFP / Sysmon — no custom kernel driver.
- ~60 auto-discovered detection modules; detections map to **MITRE ATT&CK** with a
  live heatmap.
- LSASS credential-dump, C2 beacon, ransomware-precursor (shadow-copy delete), and
  USB/removable-media detection.
- **SOAR active defense**: corroborated threats get contained (suspend→kill) and
  network-isolated, with a protected-process allowlist so it won't touch lsass/csrss/etc.
- **Local AI triage** (Ollama); cloud is opt-in with your own key.
- Built-in **non-destructive red-team drill** + after-action report, an incident
  **kill-chain timeline**, and a one-click **IR triage bundle**.

It's local-first and single-host — a lab / learning tool, not a fleet EDR. MIT
licensed. Would love feedback on the detection logic and false-positive handling.

Repo + screenshots: https://github.com/Ag3nt47/AngeronaSuite

*(r/netsec note: their rules favor technical write-ups over "I made a tool" posts —
link a specific detection deep-dive, e.g. the C2-beacon cadence heuristic or the
active-defense corroboration model, rather than the repo alone.)*

---

## X / Mastodon (short)

```
Angerona: a local-first EDR/NDR/SOAR for Windows, in Python.

• ETW/AMSI/WFP/Sysmon telemetry, no kernel driver
• ~60 modules, MITRE ATT&CK heatmap
• LSASS/C2-beacon/ransomware detection
• SOAR active defense + local-LLM triage
• built-in red-team drill

MIT, open source 👇
github.com/Ag3nt47/AngeronaSuite
```

---

## Where else to seed (low effort, good ROI)

- **awesome-lists** — open a PR adding Angerona to `awesome-security`,
  `awesome-incident-response`, `awesome-yara`, `awesome-edr` (one line each).
- **GitHub Topics** — set them (see README) *before* posting anywhere; search
  traffic compounds over time.
- **Tag a Release** (v1.7.1) with notes — it's an indexable, shareable surface and
  makes the project look maintained.
- **Reply fast** on HN/Reddit for the first 2–3 hours; that engagement is what
  pushes you onto Trending / front pages.
