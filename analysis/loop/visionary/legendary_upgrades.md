# Angerona — Legendary Upgrades (vision + built MVPs)

Angerona already has the *breadth* of a commercial EDR (~60 modules, ATT&CK
heatmap, SOAR active defense, red-team console, local-AI triage, provenance
graph, flight recorder). The legendary leap isn't module #61 — it's
**unification and intelligence**: turning independent detectors into one system
that correlates, learns, explains, and self-improves.

All seven concepts below were built as **additive, read-only, gated MVPs** — a
`core/` engine + `self_test()` each, with **no wiring into app startup**, so
there is zero behavior/detection risk until deliberately enabled. Each `self_test`
passes.

## 1. Angerona Cortex — unified correlation brain  ★ flagship  (`core/cortex.py`)
A live entity graph: every event contributes a decay-weighted signal to the
entities it touches (process, file, user, IP…), and a per-entity **malice score**
rises as independent weak signals converge on the same entity. Three MEDIUMs from
three modules across three tactics on one pid fuse into one HIGH — with an
explainable "why" (which signals/modules/tactics). Streamlines + combines
`attack_tracker` + `provenance_graph` + `incident_timeline` + `evidence_lattice`
+ SOAR into one verdict.
- **self_test:** fused proc:42 = **65.5** > lone HIGH (16.8) > lone MEDIUM (8.4). The 1+1=3.
- **Next:** `cortex.attach(bus)` at startup + a "Cortex" view; drive the threat level off top-entity score.

## 2. Self-hardening purple-team loop  (`core/purple_loop.py`)
Compares what the red-team **simulated** against what Angerona actually
**detects** (`attack_coverage`) to find gaps, and drafts a **review-gated**
candidate Sigma rule per gap — proposals only, never auto-installed or executed.
The safe core of "an EDR that closes its own blind spots."
- **self_test:** 5 gaps → 5 review-gated proposals; every proposal is an inert skeleton.

## 3. Angerona Copilot — talk to your EDR  (`core/copilot.py`)
Natural-language, fully local, read-only query layer over the Cortex graph + event
feed: "what's the biggest threat?", "why is the posture critical?", "what did
proc:42 touch?", "how good is our coverage?". Deterministic offline intent parser;
optional local-Ollama for free-form. (The MCP server already exposes the read-only
query tools this builds on.)
- **self_test:** top-threats, why-critical (chain), entity activity, coverage all answered offline.

## 4. Standards spine — Sigma + OCSF + D3FEND
- **`core/sigma_engine.py`** — a Sigma-subset matcher (selections, `contains/startswith/endswith/re`, list-OR, `condition`, `and not filter`). Import the huge public Sigma library → hundreds of detections, standards-native. *self_test: selection + modifiers + filter + list-OR verified.*
- **`core/ocsf_export.py`** — maps Angerona events → OCSF **Detection Finding** (class 2004) with severity, ATT&CK technique, observables → real SIEM/XDR interop via the existing forwarder. *self_test verified.*
- **`core/d3fend_map.py`** — ATT&CK technique → D3FEND **countermeasure** + whether Angerona implements it (a defensive scorecard for the heatmap). *self_test: 19 techniques, 88% countermeasures implemented.*

## 5. One Angerona Score + next best action  (`core/angerona_score.py`)
Collapses threat level + posture + coverage % + Cortex top-entity + unresolved
counts into one explainable **0–100 safety score** (band SECURE→CRITICAL) plus a
single ranked **"do this now"** recommendation. One gauge instead of five.
- **self_test:** quiet → 88/SECURE; under attack → 0/CRITICAL → "Contain the top Cortex entity…".

---

## Recommended build order to production
1. **Wire Cortex** (`attach(bus)` + a Cortex view) — it's the multiplier the Score, Copilot and purple-loop all read from.
2. **Angerona Score** on the header (reads Cortex + coverage) — instant "one pane of glass".
3. **Sigma engine** as a discovery module (import community rules) — biggest detection-breadth win.
4. **Copilot** chat pane (reads Cortex + storage) — drops the skill floor.
5. **OCSF export** into `siem_forwarder`; **D3FEND overlay** on the heatmap; **purple-loop** panel in the red-team console.

Status: all MVP engines built + self-tested (additive, read-only, unwired). No detection behavior changed.
