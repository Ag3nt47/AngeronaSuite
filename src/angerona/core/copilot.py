"""core/copilot.py — Angerona Copilot: talk to your EDR (local, read-only).

A natural-language query layer over Angerona's own state — the Cortex entity
graph and the recent event feed. It answers questions like "what's the biggest
threat right now?", "why is the threat level critical?", "what did powershell
touch?", or "how good is our coverage?" using a deterministic intent parser (no
network), and can optionally hand genuinely free-form questions to the local
Ollama model. Read-only: it reports; it does not act.

The intent parser is fully offline and unit-tested; the optional LLM path is
best-effort and never required.
"""
from __future__ import annotations

import re

_INTENTS = [
    ("top_threats", re.compile(r"\b(top|biggest|worst|main)\b.*\b(threat|risk|entit|process)|what.?s (critical|dangerous|bad)|whats bad", re.I)),
    ("why_critical", re.compile(r"\bwhy\b.*\b(critical|high|threat|bad|flagged|score)", re.I)),
    ("entity_activity", re.compile(r"\b(what did|what has|activity of|show me|touch|access(ed)?)\b", re.I)),
    ("coverage", re.compile(r"\b(coverage|blind spot|gap|do we detect|what.?s not covered)\b", re.I)),
    ("technique", re.compile(r"\b(lateral movement|persistence|credential|beacon|ransomware|exfil|T\d{4})\b", re.I)),
    ("secure", re.compile(r"\b(are we (safe|secure|ok)|status|posture|how are we)\b", re.I)),
]

_TECH_KEYWORDS = {
    "lateral movement": "T1021", "persistence": "T1547", "credential": "T1003",
    "beacon": "T1071", "ransomware": "T1486", "exfil": "T1041",
}


def classify(question: str) -> str:
    q = question or ""
    for name, rx in _INTENTS:
        if rx.search(q):
            return name
    return "unknown"


def _fmt_entity(e: dict) -> str:
    return (f"{e.get('entity')} — score {e.get('score')}/100, "
            f"{e.get('signals')} signals from {len(e.get('modules', []))} module(s) "
            f"({', '.join(e.get('modules', [])[:4])}); techniques "
            f"{', '.join(e.get('techniques', [])[:5]) or '—'}")


def answer(question: str, *, cortex_snapshot: dict | None = None,
           events: list | None = None, coverage: dict | None = None,
           allow_llm: bool = False) -> dict:
    """Answer a question from Angerona's own state. Returns {intent, answer, data}."""
    intent = classify(question)
    snap = cortex_snapshot or {}
    top = snap.get("top", []) if isinstance(snap, dict) else []

    if intent == "top_threats":
        if not top:
            return _r(intent, "Nothing notable right now — no entity has a meaningful malice score.")
        lines = [f"{i+1}. {_fmt_entity(e)}" for i, e in enumerate(top[:5])]
        return _r(intent, "Top entities by malice score:\n" + "\n".join(lines), {"top": top[:5]})

    if intent == "why_critical":
        if not top:
            return _r(intent, "The posture isn't being driven critical by any single entity right now.")
        e = top[0]
        why = "\n  - ".join(e.get("why", [])[:5]) or "(no detail recorded)"
        return _r(intent, f"The hottest entity is {e.get('entity')} (score {e.get('score')}/100). "
                          f"It converged {e.get('signals')} signals across "
                          f"{len(e.get('modules', []))} modules and techniques "
                          f"{', '.join(e.get('techniques', [])) or '—'}:\n  - {why}", {"entity": e})

    if intent == "entity_activity":
        # Prefer an explicit entity token (proc:42, pid 42, foo.exe); otherwise the
        # last non-stopword — never the leading "what/did/show" verbs.
        m = re.search(r"(proc:\d+|pid\s*\d+|[\w.-]+\.exe)", question, re.I)
        if m:
            needle = re.sub(r"pid\s*", "proc:", m.group(1).lower())
        else:
            _stop = {"what", "did", "has", "have", "the", "show", "does", "touch",
                     "access", "accessed", "activity", "this", "that", "recently"}
            toks = [t for t in re.findall(r"[a-z0-9_.:-]{3,}", question.lower()) if t not in _stop]
            needle = toks[-1] if toks else ""
        hits = [e for e in top if needle and needle in e.get("entity", "").lower()]
        if not hits and needle:
            hits = [e for e in top if needle in " ".join(e.get("why", [])).lower()]
        if hits:
            return _r(intent, "Activity:\n" + "\n".join(_fmt_entity(e) for e in hits[:5]), {"hits": hits[:5]})
        return _r(intent, f"No tracked activity matching '{needle or question.strip()}'.")

    if intent == "coverage":
        cov = coverage or {}
        pct = cov.get("coverage_pct")
        if pct is None:
            return _r(intent, "Coverage data isn't available in this context.")
        return _r(intent, f"Detection coverage is {pct}% of the mapped techniques "
                          f"({cov.get('covered', '?')}/{cov.get('techniques', '?')} covered). "
                          "See the Coverage tab / purple-team loop for the gaps.", cov)

    if intent == "technique":
        key = next((k for k in _TECH_KEYWORDS if k in question.lower()), None)
        tid = _TECH_KEYWORDS.get(key) if key else None
        m = re.search(r"T\d{4}", question, re.I)
        tid = tid or (m.group(0).upper() if m else None)
        evs = events or []
        matched = [e for e in evs if tid and tid in str(getattr(e, "details", {}) or {})][:8]
        if matched:
            return _r(intent, f"{len(matched)} recent event(s) tied to {tid}:\n" +
                      "\n".join(f"  - [{getattr(e,'module','?')}] {getattr(e,'message','')[:90]}"
                                for e in matched), {"tid": tid})
        return _r(intent, f"No recent events tied to {tid or key or 'that technique'}.")

    if intent == "secure":
        try:
            from angerona.core import angerona_score
            r = angerona_score.live()
            return _r(intent, f"Angerona Score {r.score}/100 ({r.band}). Next: {r.next_action}",
                      {"score": r.score, "band": r.band})
        except Exception:
            score = top[0].get("score") if top else 0
            return _r(intent, f"Highest entity malice is {score}/100. "
                              + ("Under active correlation." if score else "Nothing notable."))

    # unknown → optional local LLM, else a helpful menu
    if allow_llm:
        llm = _ask_ollama(question, snap)
        if llm:
            return _r("llm", llm)
    return _r("unknown", "I can answer about: the top threats, why the posture is critical, "
                         "a specific process's activity, our detection coverage, or a technique "
                         "(e.g. 'lateral movement', 'T1003').")


def _r(intent: str, text: str, data: dict | None = None) -> dict:
    return {"intent": intent, "answer": text, "data": data or {}}


def _ask_ollama(question: str, snap: dict) -> str | None:
    import json
    import os
    import urllib.request
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
    model = os.environ.get("ANGERONA_MODEL", "llama3")
    facts = json.dumps({"cortex_top": snap.get("top", [])[:5]})[:4000]
    payload = json.dumps({
        "model": model, "stream": False, "keep_alive": "30m", "options": {"temperature": 0},
        "messages": [
            {"role": "system", "content": "You are a SOC analyst assistant answering ONLY from the "
             "provided Angerona state. Be concise. If the data doesn't answer it, say so."},
            {"role": "user", "content": f"State: {facts}\n\nQuestion: {question}"}]}).encode()
    try:
        req = urllib.request.Request(f"{host}/api/chat", data=payload,
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
        return ((data.get("message", {}) or {}).get("content", "") or "").strip() or None
    except Exception:
        return None


def self_test() -> tuple[bool, str]:
    """Offline: intent classification + answers from a stub Cortex snapshot."""
    snap = {"top": [
        {"entity": "proc:42", "score": 65.5, "signals": 3,
         "modules": ["CREDG", "BEAC", "VSSG"], "techniques": ["T1003", "T1071", "T1490"],
         "why": ["CREDG: lsass touch", "BEAC: beacon", "VSSG: shadow delete"]},
    ]}
    cov = {"coverage_pct": 61, "covered": 11, "techniques": 18}
    a = answer("what's the biggest threat right now?", cortex_snapshot=snap)
    b = answer("why is the threat level critical?", cortex_snapshot=snap)
    c = answer("what did proc:42 touch?", cortex_snapshot=snap)
    d = answer("how good is our coverage?", cortex_snapshot=snap, coverage=cov)
    ok = (a["intent"] == "top_threats" and "proc:42" in a["answer"]
          and b["intent"] == "why_critical" and "shadow delete" in b["answer"]
          and c["intent"] == "entity_activity" and "proc:42" in c["answer"]
          and d["intent"] == "coverage" and "61%" in d["answer"])
    return ok, ("copilot verified: top-threats, why-critical (chain), entity activity, coverage"
                if ok else f"failed: a={a['intent']} b={b['intent']} c={c['intent']} d={d['intent']}")
